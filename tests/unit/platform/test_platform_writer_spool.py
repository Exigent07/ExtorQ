"""Spool durability and writer delivery semantics (fake ClickHouse client, SYNTHETIC data).

* a batch committed by one process survives a hard crash of that process;
* the writer deletes spool rows only after the (fake) ClickHouse insert returned;
* transient errors never consume attempts and never lose records;
* data errors are bisected so only the poison record consumes attempts and is
  finally dead-lettered (counted in health); every RecordKind decodes to its table.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from clickhouse_connect.driver.exceptions import DatabaseError, OperationalError
from platform_samples import all_kind_records, event_data, record

from extorq.common.config import Settings
from extorq.contracts.common import HealthStatus, utc_now
from extorq.contracts.identity import canonical_json, iso_utc
from extorq.contracts.ingest import INGEST_RECORD_ADAPTER, RecordKind, record_identity
from extorq.pipeline.spool import NewRecord, Spool
from extorq.pipeline.writer import Writer, decode_row
from extorq.storage import rows


class FakeClickHouse:
    def __init__(self) -> None:
        self.tables: dict[str, list[dict[str, Any]]] = {}
        self.fail_transient = 0
        self.poison: set[str] = set()  # event_ids that trigger a data error
        self.inserts = 0
        self.closed = 0

    def insert(
        self, table: str, data: list[list[Any]], column_names: list[str], database: str
    ) -> None:
        self.inserts += 1
        if self.fail_transient:
            self.fail_transient -= 1
            raise OperationalError("synthetic: connection refused")
        batch = [dict(zip(column_names, row, strict=True)) for row in data]
        if any(r.get("event_id") in self.poison for r in batch):
            raise DatabaseError("Code: 53. DB::Exception: synthetic type mismatch")
        self.tables.setdefault(table, []).extend(batch)

    def close(self) -> None:
        self.closed += 1


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def enqueue(spool: Spool, raws: list[dict[str, Any]], batch_id: str = "b" * 32) -> None:
    records = []
    for raw in raws:
        rec = INGEST_RECORD_ADAPTER.validate_python(raw)
        records.append(
            NewRecord(
                kind=rec.kind,
                record_key=record_identity(rec),
                payload=canonical_json(
                    {"kind": rec.kind, "data": rec.data.model_dump(mode="json")}
                ),
            )
        )
    spool.commit_batch(
        producer_id="linux-ssh-lab-vm-01",
        batch_id=batch_id,
        content_sha256="0" * 64,
        ingested_at=iso_utc(utc_now()),
        records=records,
        extra=[],
        build_result=lambda a, d: {"accepted": a, "duplicates": d},
    )


@pytest.fixture
def setup(tmp_path: Path) -> tuple[Spool, FakeClickHouse, Writer, Clock]:
    spool = Spool(tmp_path / "spool.db")
    ch = FakeClickHouse()
    clock = Clock()
    settings = Settings(home=tmp_path, writer_max_attempts=2, writer_backoff_max_seconds=5)
    writer = Writer(
        settings, spool, lambda: ch, sleep=lambda _s: None, clock=clock, rng=lambda: 1.0
    )
    yield spool, ch, writer, clock
    spool.close()


def test_committed_batch_survives_a_hard_process_crash(tmp_path: Path) -> None:
    path = tmp_path / "spool.db"
    script = textwrap.dedent(f"""
        import os
        from extorq.pipeline.spool import NewRecord, Spool
        spool = Spool(__import__("pathlib").Path({str(path)!r}))
        spool.commit_batch(producer_id="p1", batch_id="c" * 32, content_sha256="0" * 64,
                           ingested_at="2026-11-21T00:00:00.000Z",
                           records=[NewRecord("event", f"k{{i}}", "{{}}") for i in range(50)],
                           extra=[], build_result=lambda a, d: {{"accepted": a}})
        os._exit(0)  # no close, no checkpoint: simulates a crash right after the 202
    """)
    subprocess.run([sys.executable, "-c", script], check=True, timeout=60)
    spool = Spool(path)
    try:
        assert spool.depth(max_age_seconds=0) == 50
        assert spool.lookup_batch("p1", "c" * 32) is not None
        assert spool.pragma("journal_mode") == "wal"
        assert spool.pragma("synchronous") == 2  # FULL
    finally:
        spool.close()


def test_pragma_allow_list(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "s.db")
    try:
        with pytest.raises(ValueError):
            spool.pragma("wal_checkpoint(TRUNCATE)")
    finally:
        spool.close()


def test_every_kind_decodes_to_its_table() -> None:
    for raw in all_kind_records():
        rec = INGEST_RECORD_ADAPTER.validate_python(raw)
        payload = canonical_json({"kind": rec.kind, "data": rec.data.model_dump(mode="json")})
        from extorq.pipeline.spool import SpoolRow

        row = SpoolRow(
            seq=1,
            kind=rec.kind,
            record_key=record_identity(rec),
            producer_id="p",
            batch_id="b",
            ingested_at="2026-11-21T12:00:01.000Z",
            enqueued_at=0.0,
            payload=payload,
            attempts=0,
        )
        table, ch_row = decode_row(row)
        assert table == rows.TABLE_BY_KIND[RecordKind(rec.kind)]
        assert ch_row["producer_id"] == "p"


def test_successful_write_deletes_rows_only_after_insert(setup: Any) -> None:
    spool, ch, writer, _clock = setup
    records = all_kind_records()
    assert len(records) == len(RecordKind)  # one record of every kind
    enqueue(spool, records)
    written = writer.process_once()
    assert written == len(records)
    assert spool.depth(max_age_seconds=0) == 0
    assert set(ch.tables) == set(rows.TABLE_BY_KIND.values())
    assert spool.counters()["written_total"] == len(records)


def test_transient_errors_keep_everything_and_consume_no_attempts(setup: Any) -> None:
    spool, ch, writer, clock = setup
    enqueue(spool, [record("event", event_data(str(i))) for i in range(5)])
    ch.fail_transient = 3
    for _ in range(3):
        assert writer.process_once() == 0
        assert spool.depth(max_age_seconds=0) == 5
    assert writer.stats.consecutive_failures == 3
    assert writer.status() in (HealthStatus.DEGRADED, HealthStatus.FAILED)
    assert ch.closed >= 3  # broken connections are dropped
    clock.now += 1
    assert writer.process_once() == 5
    assert writer.stats.consecutive_failures == 0
    assert spool.dead_letter_count() == 0


def test_poison_record_is_isolated_then_dead_lettered(setup: Any) -> None:
    spool, ch, writer, clock = setup
    raws = [record("event", event_data(str(i))) for i in range(8)]
    poison_id = raws[3]["data"]["event_id"]
    ch.poison = {poison_id}
    enqueue(spool, raws)
    assert writer.process_once() == 7  # bisection delivers the 7 good records
    assert spool.depth(max_age_seconds=0) == 1
    clock.now += 10
    writer.process_once()  # second (= max) attempt
    assert spool.depth(max_age_seconds=0) == 0
    assert spool.dead_letter_count() == 1
    assert writer.health().dead_letter_total == 1
    assert writer.status() is HealthStatus.DEGRADED
    stored_ids = {r["event_id"] for r in ch.tables["events"]}
    assert poison_id not in stored_ids and len(stored_ids) == 7


def test_undecodable_spool_row_is_dead_lettered_not_retried_forever(setup: Any) -> None:
    spool, _ch, writer, clock = setup
    spool.append(
        [
            NewRecord(
                kind="event", record_key="x", payload=json.dumps({"kind": "event", "data": {}})
            )
        ],
        producer_id="p",
        batch_id="b",
        ingested_at=iso_utc(utc_now()),
    )
    writer.process_once()
    clock.now += 10
    writer.process_once()
    assert spool.dead_letter_count() == 1


def test_writer_emits_pipeline_health_into_the_spool(setup: Any) -> None:
    _spool, ch, writer, _clock = setup
    writer.emit_health()
    writer.process_once()
    (health,) = ch.tables["pipeline_health"]
    assert health["component"] == "writer" and health["status"] == "ok"


def test_pre_2_0_spool_rows_are_permanent_errors(setup: Any) -> None:
    """A record spooled by a schema 1.x gateway (or of the retired simulation_run kind) can
    never be written by a 2.0 writer: it is dead-lettered, which is why ``make reset-data``
    clears the spool after an upgrade instead of letting the writer drain it."""
    spool, _ch, writer, clock = setup
    old = record("event", event_data("legacy"))
    old["data"]["schema_version"] = "1.1"
    legacy = [
        NewRecord(kind="event", record_key="legacy-event", payload=canonical_json(old)),
        NewRecord(
            kind="simulation_run",
            record_key="legacy-run",
            payload=json.dumps({"kind": "simulation_run", "data": {"run_id": "synth0001"}}),
        ),
    ]
    spool.append(legacy, producer_id="p", batch_id="b", ingested_at=iso_utc(utc_now()))
    assert writer.process_once() == 0
    clock.now += 10
    writer.process_once()
    assert spool.depth(max_age_seconds=0) == 0
    assert spool.dead_letter_count() == 2


def test_spool_clear_empties_every_table(setup: Any) -> None:
    spool, _ch, writer, clock = setup
    enqueue(spool, [record("event", event_data(str(i))) for i in range(3)], batch_id="c" * 32)
    spool.append(
        [NewRecord(kind="event", record_key="bad", payload="{}")],
        producer_id="p",
        batch_id="b",
        ingested_at=iso_utc(utc_now()),
    )
    writer.process_once()  # 3 written, 1 poisoned (attempt 1)
    clock.now += 10
    writer.process_once()  # poisoned record dead-lettered (attempt 2 = max)
    enqueue(spool, [record("event", event_data("queued"))], batch_id="d" * 32)
    before = spool.table_counts()
    assert before["records"] == 1 and before["dead_letter"] == 1
    assert before["dedup"] == 4 and before["batches"] == 2 and before["counters"] > 0
    cleared = spool.clear()
    assert cleared == before
    assert set(spool.table_counts().values()) == {0}
    assert spool.depth(max_age_seconds=0) == 0
    assert spool.counters() == {} and spool.dead_letter_count() == 0
    assert spool.lookup_batch("linux-ssh-lab-vm-01", "c" * 32) is None
    # dedup keys are gone: the same record is accepted again after a clean slate
    enqueue(spool, [record("event", event_data("0"))], batch_id="e" * 32)
    assert spool.depth(max_age_seconds=0) == 1


def test_spool_admin_main_requires_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from extorq.common.config import get_settings
    from extorq.pipeline import spool as spool_module

    path = tmp_path / "spool" / "spool.db"
    monkeypatch.setenv("EXTORQ_SPOOL_PATH", str(path))
    get_settings.cache_clear()
    try:
        assert spool_module.admin_main(confirm=False, status_only=True) == 0
        assert json.loads(capsys.readouterr().out)["exists"] is False
        assert not path.exists()  # status never creates a spool
        live = Spool(path)
        enqueue(live, [record("event", event_data("x"))])
        live.close()
        assert spool_module.admin_main(confirm=False) == 2  # clear without --yes
        assert "refusing" in capsys.readouterr().out
        assert spool_module.admin_main(confirm=True) == 0
        result = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert result["cleared"]["records"] == 1 and result["cleared"]["dedup"] == 1
        assert spool_module.admin_main(confirm=False, status_only=True) == 0
        status = json.loads(capsys.readouterr().out)
        assert status["exists"] is True and set(status["tables"].values()) == {0}
    finally:
        get_settings.cache_clear()

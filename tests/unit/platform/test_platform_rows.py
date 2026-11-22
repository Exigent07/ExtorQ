"""extorq.storage.rows: every RecordKind maps exactly onto its ClickHouse columns.

The column contract is replayed from the migration files themselves, in version order
(CREATE TABLE, ALTER TABLE ADD/DROP COLUMN, DROP TABLE), so it is the schema after every
migration (schema 2.0: 0008 removed the simulation storage). A schema change without a
mapping change fails here. All records are SYNTHETIC (see platform_samples.py).
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from platform_samples import (
    NOW,
    SSH_INSTANCE_ID,
    SSH_SERVICE_ID,
    alert,
    all_kind_records,
    event_data,
    finding_data,
    record,
    service_instance_data,
)

from extorq.contracts import INGEST_RECORD_ADAPTER, RecordKind
from extorq.contracts.identity import canonical_json
from extorq.storage import rows

MIGRATIONS = Path(__file__).resolve().parents[3] / "infra" / "clickhouse" / "migrations"
_CREATE = re.compile(
    r"CREATE TABLE IF NOT EXISTS extorq\.(?P<table>\w+)\s*\((?P<body>.*?)\)\s*ENGINE",
    re.S,
)
_ADD_COLUMN = re.compile(
    r"ALTER TABLE extorq\.(?P<table>\w+) ADD COLUMN IF NOT EXISTS (?P<column>\w+)\s"
)
_DROP_COLUMN = re.compile(
    r"ALTER TABLE extorq\.(?P<table>\w+) DROP COLUMN IF EXISTS (?P<column>\w+)\b"
)
_DROP_TABLE = re.compile(r"DROP TABLE IF EXISTS extorq\.(?P<table>\w+)\b")


def _strip_comments(sql: str) -> str:
    return "\n".join(line.split("--", 1)[0] for line in sql.splitlines())


def ddl_columns() -> dict[str, set[str]]:
    """Columns per table after replaying every migration in version order."""
    tables: dict[str, set[str]] = {}
    for path in sorted(MIGRATIONS.glob("[0-9][0-9][0-9][0-9]_*.sql")):
        sql = _strip_comments(path.read_text(encoding="utf-8"))
        events: list[tuple[int, str, re.Match[str]]] = [
            (m.start(), kind, m)
            for kind, pattern in (
                ("create", _CREATE),
                ("add", _ADD_COLUMN),
                ("drop_column", _DROP_COLUMN),
                ("drop_table", _DROP_TABLE),
            )
            for m in pattern.finditer(sql)
        ]
        for _pos, kind, match in sorted(events, key=lambda e: e[0]):
            table = match["table"]
            if kind == "create":
                columns = set()
                for line in match["body"].splitlines():
                    line = line.strip().rstrip(",")
                    if not line or line.startswith("INDEX "):
                        continue
                    columns.add(line.split()[0])
                tables.setdefault(table, columns)
            elif kind == "add":
                tables[table].add(match["column"])
            elif kind == "drop_column":
                tables.get(table, set()).discard(match["column"])
            else:
                tables.pop(table, None)
    return tables


COLUMNS = ddl_columns()
INGESTED = NOW + timedelta(seconds=2)


def test_every_record_kind_has_a_table_and_model() -> None:
    assert set(rows.TABLE_BY_KIND) == set(RecordKind)
    assert set(rows.MODEL_BY_KIND) == set(RecordKind)
    assert rows.TABLE_BY_KIND[RecordKind.SERVICE] == "services"
    assert rows.TABLE_BY_KIND[RecordKind.SERVICE_INSTANCE] == "service_instances"


@pytest.mark.parametrize("raw", all_kind_records(), ids=lambda r: r["kind"])
def test_row_keys_equal_ddl_columns(raw: dict) -> None:
    rec = INGEST_RECORD_ADAPTER.validate_python(raw)
    row = rows.to_row(
        rec.kind,
        rec.data,
        producer_id="synthetic-producer",
        batch_id="b" * 32,
        ingested_at=INGESTED,
    )
    table = rows.TABLE_BY_KIND[RecordKind(rec.kind)]
    assert set(row) == COLUMNS[table], (
        f"{table}: missing={COLUMNS[table] - set(row)} extra={set(row) - COLUMNS[table]}"
    )


def test_internal_and_alert_rows_match_ddl() -> None:
    a = alert()
    assert set(rows.alert_to_row(a)) == COLUMNS["alerts"]
    q = rows.quarantine_row(
        quarantine_id="q" * 32,
        received_at=NOW,
        producer_id="p",
        batch_id="b",
        record_index=0,
        record_kind=None,
        reason="r",
        payload_excerpt="{}",
        payload_sha256="0" * 64,
    )
    assert set(q) == COLUMNS["ingest_quarantine"]
    au = rows.audit_row(
        audit_id="a" * 32,
        occurred_at=NOW,
        remote_addr=None,
        claimed_producer=None,
        authenticated_producer=None,
        decision="unauthenticated",
        reason="missing_bearer_token",
        path="/v1/ingest",
    )
    assert set(au) == COLUMNS["ingest_audit"]


def test_event_service_and_container_columns() -> None:
    data = event_data(with_service=True)
    data["kubernetes"] = {"container_id": "containerd://" + "a" * 64, "pod_uid": "uid-1"}
    rec = INGEST_RECORD_ADAPTER.validate_python(record("event", data))
    row = rows.to_row("event", rec.data, producer_id="p", batch_id="b", ingested_at=INGESTED)
    assert row["service_id"] == SSH_SERVICE_ID
    assert row["service_name"] == "ssh"
    assert row["service_instance_id"] == SSH_INSTANCE_ID
    assert row["adapter_id"] == "ssh"
    assert row["k8s_container_id"] == "containerd://" + "a" * 64
    assert json.loads(row["payload"])["service"]["service_id"] == SSH_SERVICE_ID


def test_event_without_service_maps_service_columns_to_null() -> None:
    rec = INGEST_RECORD_ADAPTER.validate_python(record("event", event_data()))
    row = rows.to_row("event", rec.data, producer_id="p", batch_id="b", ingested_at=INGESTED)
    for column in (
        "service_id",
        "service_name",
        "service_instance_id",
        "adapter_id",
        "k8s_container_id",
    ):
        assert row[column] is None
    assert row["schema_version"] == "2.0"


def test_schema_2_0_has_no_simulation_storage() -> None:
    """Migration 0008 dropped the simulation table and columns; rows never carry them."""
    assert "simulation_runs" not in COLUMNS
    assert not {"simulation_run_id", "scenario_id"} & COLUMNS["events"]
    assert "simulation_run_ids" not in COLUMNS["alerts"]
    assert "simulation_runs" not in rows.TABLE_BY_KIND.values()
    event_row = rows.to_row(
        "event",
        INGEST_RECORD_ADAPTER.validate_python(record("event", event_data())).data,
        producer_id="p",
        batch_id="b",
        ingested_at=INGESTED,
    )
    assert not {"simulation_run_id", "scenario_id"} & set(event_row)
    assert "simulation_run_ids" not in rows.alert_to_row(alert())


def test_schema_1_records_are_refused_by_the_contracts() -> None:
    data = event_data()
    data["schema_version"] = "1.1"
    with pytest.raises(ValueError, match="schema_version"):
        INGEST_RECORD_ADAPTER.validate_python(record("event", data))
    with pytest.raises(ValueError):
        INGEST_RECORD_ADAPTER.validate_python({"kind": "simulation_run", "data": {}})


def test_service_row_values() -> None:
    raw = next(r for r in all_kind_records() if r["kind"] == "service")
    rec = INGEST_RECORD_ADAPTER.validate_python(raw)
    row = rows.to_row("service", rec.data, producer_id="p", batch_id="b", ingested_at=INGESTED)
    assert row["discovered_via"] == ["systemd_unit", "listening_socket"]
    assert row["telemetry_sources"] == ["linux.journald"]
    assert row["present"] == 1
    endpoints = json.loads(row["endpoints"])
    assert endpoints == [
        {
            "address": "0.0.0.0",  # noqa: S104 - synthetic observed bind address
            "attribution": "confirmed",
            "attribution_basis": "socket owner pid 812",
            "exposure": "any",
            "port": 22,
            "protocol": "tcp",
        }
    ]
    assert row["endpoints"] == canonical_json(endpoints)
    assert row["instance_count"] == 1
    assert row["version"] is None  # unknown stays unknown


def test_service_instance_user_maps_to_process_user_and_null_asset() -> None:
    rec = INGEST_RECORD_ADAPTER.validate_python(
        record("service_instance", service_instance_data(asset_id=None))
    )
    row = rows.to_row(
        "service_instance", rec.data, producer_id="p", batch_id="b", ingested_at=INGESTED
    )
    assert row["process_user"] == "root"
    assert "user" not in row
    assert row["asset_id"] is None
    assert row["pid"] == 812


def test_finding_service_id_and_alert_service_ids() -> None:
    rec = INGEST_RECORD_ADAPTER.validate_python(record("finding", finding_data()))
    row = rows.to_row("finding", rec.data, producer_id="p", batch_id="b", ingested_at=INGESTED)
    assert row["service_id"] == SSH_SERVICE_ID
    rec = INGEST_RECORD_ADAPTER.validate_python(record("finding", finding_data(with_service=False)))
    row = rows.to_row("finding", rec.data, producer_id="p", batch_id="b", ingested_at=INGESTED)
    assert row["service_id"] is None
    assert rows.alert_to_row(alert())["service_ids"] == [SSH_SERVICE_ID]
    assert rows.alert_to_row(alert(service_ids=[]))["service_ids"] == []


def test_row_versions_follow_ddl_formulas() -> None:
    raw = next(r for r in all_kind_records() if r["kind"] == "scan_run")
    scan = INGEST_RECORD_ADAPTER.validate_python(raw).data
    row = rows.to_row("scan_run", scan, producer_id="p", batch_id="b", ingested_at=INGESTED)
    assert row["row_version"] == rows.epoch_ms(NOW) * 10 + 1  # succeeded beats running


def test_kind_model_mismatch_and_unknown_kind_are_row_errors() -> None:
    raw = next(r for r in all_kind_records() if r["kind"] == "service")
    service = INGEST_RECORD_ADAPTER.validate_python(raw).data
    with pytest.raises(rows.RowError):
        rows.to_row(
            "service_instance", service, producer_id="p", batch_id="b", ingested_at=INGESTED
        )
    with pytest.raises(rows.RowError):
        rows.to_row("nope", service, producer_id="p", batch_id="b", ingested_at=INGESTED)


def test_timestamps_truncate_to_milliseconds_and_reject_out_of_range() -> None:
    assert rows._time(datetime(2026, 1, 1, 0, 0, 0, 999999, tzinfo=UTC), "t") == datetime(
        2026, 1, 1, 0, 0, 0, 999000, tzinfo=UTC
    )
    with pytest.raises(rows.RowError):
        rows._time(datetime(1960, 1, 1, tzinfo=UTC), "t")
    with pytest.raises(rows.RowError):
        rows._uint(70000, 16, "port")


def test_lone_surrogate_strings_are_rejected() -> None:
    # The contracts already refuse them; the row layer re-checks (defence in depth).
    data = event_data()
    data["message"] = "bad \ud800 surrogate"
    with pytest.raises(ValueError, match="unicode"):
        INGEST_RECORD_ADAPTER.validate_python(record("event", data))
    with pytest.raises(rows.RowError):
        rows._check_utf8({"message": "bad \ud800 surrogate"})
    with pytest.raises(rows.RowError):
        rows._check_utf8({"labels": {"k": "\udfff"}})

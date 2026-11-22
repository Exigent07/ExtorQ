"""Collector SDK: atomic emit + checkpoints + snapshots, sender delivery semantics,
runner failure isolation, health sanitisation, sim-record and asset upserts.

Everything runs against the in-process FakeGateway (no network) with SYNTHETIC
records from platform_samples.py.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fake_gateway import FakeGateway
from platform_samples import (
    LINUX_ASSET,
    event_data,
    record,
    service_data,
    service_instance_data,
)

from extorq.common.config import Settings
from extorq.contracts.service import Service, ServiceInstance
from extorq_collectors.sdk import (
    Collector,
    CollectorConfig,
    CollectorContext,
    StateStore,
    asset_upsert,
    load_collector_configs,
)
from extorq_collectors.sdk.config import ConfigLoadError, load_collector_files
from extorq_collectors.sdk.runner import CollectorWorker, Runner, sanitize_details
from extorq_collectors.sdk.sender import MAX_BATCH_RECORDS, Sender
from extorq_collectors.sdk.simulation import SimulationRecordError, record_simulation
from extorq_collectors.sdk.state import read_status

HEARTBEAT = "extorq_collectors.sdk.examples.heartbeat:HeartbeatCollector"


def make_config(collector_id: str = "synthetic-linux", **extra: Any) -> CollectorConfig:
    data: dict[str, Any] = {
        "collector_id": collector_id,
        "producer_id": "linux-ssh-lab-vm-01",
        "asset_id": LINUX_ASSET,
        "module": HEARTBEAT,
        "interval_seconds": 60,
    }
    data.update(extra)
    return CollectorConfig.model_validate(data)


@pytest.fixture
def store(tmp_path: Path) -> StateStore:
    s = StateStore(tmp_path / "state.db")
    yield s
    s.close()


@pytest.fixture
def ctx(store: StateStore) -> CollectorContext:
    return CollectorContext(make_config(), store)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


# ── atomic emit / checkpoints / snapshots ─────────────────────────────


def test_emit_commits_records_and_checkpoints_together(
    ctx: CollectorContext, store: StateStore
) -> None:
    count = ctx.emit(
        [record("event", event_data("a")), record("event", event_data("b"))],
        {"journal.cursor": "c2"},
    )
    assert count == 2
    assert store.outbox_depth() == 2
    assert ctx.checkpoints.get("journal.cursor") == "c2"
    assert ctx.events_emitted == 2


def test_emit_validates_everything_before_committing(
    ctx: CollectorContext, store: StateStore
) -> None:
    bad = event_data("bad")
    bad["attributes"] = {"x": float("nan")}  # contracts reject NaN (F-IC-1)
    with pytest.raises(ValueError):
        ctx.emit([record("event", event_data("ok")), record("event", bad)], {"cursor": "9"})
    assert store.outbox_depth() == 0
    assert ctx.checkpoints.get("cursor") is None


def test_emit_rolls_back_when_the_transaction_fails(
    ctx: CollectorContext, store: StateStore
) -> None:
    with store.transaction() as conn:
        conn.execute(
            "CREATE TRIGGER boom BEFORE INSERT ON checkpoints WHEN NEW.key = 'boom' "
            "BEGIN SELECT RAISE(ABORT, 'synthetic failure'); END"
        )
    diff = ctx.diff_snapshot("units", {"a.service": {"sha": "1"}})
    assert diff.added
    with pytest.raises(sqlite3.IntegrityError):
        ctx.emit([record("event", event_data("x"))], {"boom": "1"})
    assert store.outbox_depth() == 0
    assert not store.has_snapshot("units")  # snapshot did not advance without the records


def test_emit_accepts_service_models(ctx: CollectorContext, store: StateStore) -> None:
    service = Service.model_validate(service_data())
    instance = ServiceInstance.model_validate(service_instance_data())
    assert ctx.emit([service, instance]) == 2
    with store.transaction() as conn:
        kinds = [r[0] for r in conn.execute("SELECT kind FROM outbox ORDER BY seq")]
    assert kinds == ["service", "service_instance"]


def test_diff_snapshot_added_changed_removed_and_persisted_only_on_emit(
    ctx: CollectorContext,
) -> None:
    first = ctx.diff_snapshot("units", {"a": {"v": 1}, "b": {"v": 1}})
    assert first.baseline and set(first.added) == {"a", "b"}
    ctx.emit([])  # commits the staged snapshot
    second = ctx.diff_snapshot("units", {"a": {"v": 2}, "c": {"v": 1}})
    added, changed, removed = second
    assert set(added) == {"c"} and set(changed) == {"a"} and set(removed) == {"b"}
    assert second.previous["a"] == {"v": 1}
    assert not second.baseline
    ctx.discard_staged()  # e.g. a failed cycle: nothing persisted
    again = ctx.diff_snapshot("units", {"a": {"v": 2}, "c": {"v": 1}})
    assert set(again.changed) == {"a"} and set(again.removed) == {"b"}


# ── sender ────────────────────────────────────────────────────────────


def _fill(ctx: CollectorContext, n: int) -> None:
    ctx.emit([record("event", event_data(f"m{i}")) for i in range(n)])


def test_sender_batches_at_most_500_and_deletes_only_after_202(
    ctx: CollectorContext, store: StateStore
) -> None:
    _fill(ctx, 1203)
    gw = FakeGateway()
    report = Sender(store, gw.client(), "linux-ssh-lab-vm-01").send_pending()
    assert report.drained and report.accepted == 1203
    assert max(len(b["records"]) for b in gw.batches) <= MAX_BATCH_RECORDS == 500
    assert len(gw.batches) == 3
    assert store.outbox_depth() == 0


def test_sender_honours_retry_after_and_keeps_records(
    ctx: CollectorContext, store: StateStore
) -> None:
    _fill(ctx, 3)
    gw = FakeGateway(script=[("status", 503, {"Retry-After": "7"})])
    clock = FakeClock()
    sender = Sender(store, gw.client(), "linux-ssh-lab-vm-01", clock=clock, rng=lambda: 0.0)
    report = sender.send_pending()
    assert not report.drained and report.error and "503" in report.error
    assert store.outbox_depth() == 3
    assert sender.state.next_attempt_at - clock.now >= 7.0
    clock.now += 3
    assert sender.send_pending().accepted == 0  # still backing off, nothing sent
    clock.now += 5
    report = sender.send_pending()
    assert report.drained and report.accepted == 3


def test_sender_backoff_grows_exponentially_with_jitter(
    ctx: CollectorContext, store: StateStore
) -> None:
    sender = Sender(store, FakeGateway().client(), "p", rng=lambda: 1.0)
    delays = []
    for failures in range(1, 9):
        sender.state.consecutive_failures = failures
        delays.append(sender.backoff())
    assert delays[:4] == [1.0, 2.0, 4.0, 8.0]
    assert max(delays) == 60.0
    sender_low = Sender(store, FakeGateway().client(), "p", rng=lambda: 0.0)
    sender_low.state.consecutive_failures = 4
    assert sender_low.backoff() == 4.0  # equal jitter: [ceiling/2, ceiling]


def test_lost_202_is_resent_with_the_same_batch_id_and_not_duplicated(
    ctx: CollectorContext, store: StateStore
) -> None:
    _fill(ctx, 4)
    gw = FakeGateway(script=[("lost",)])
    clock = FakeClock()
    sender = Sender(store, gw.client(), "linux-ssh-lab-vm-01", clock=clock)
    first = sender.send_pending()
    assert first.error and store.outbox_depth() == 4  # processed upstream, ack lost
    clock.now += 120
    second = sender.send_pending()
    assert second.drained and second.replayed == 1
    assert len(gw.batches) == 1 and len(gw.accepted_records) == 4
    assert store.outbox_depth() == 0


def test_401_keeps_everything_buffered(ctx: CollectorContext, store: StateStore) -> None:
    _fill(ctx, 2)
    gw = FakeGateway(script=[("status", 401)])
    sender = Sender(store, gw.client(), "linux-ssh-lab-vm-01", clock=FakeClock())
    report = sender.send_pending()
    assert "401" in (report.error or "")
    assert store.outbox_depth() == 2 and store.dead_count() == 0


def test_403_bisects_so_only_the_unauthorized_record_is_dead_lettered(
    ctx: CollectorContext, store: StateStore
) -> None:
    records = [record("event", event_data(f"r{i}")) for i in range(9)]
    records[5] = record(
        "event",
        event_data(
            "forbidden",
            asset_id="macos:workstation-01",
            asset_type="macos_host",
            source_type="macos.unified_log",
            event_type="system.log.notable",
            category="other",
        ),
    )
    ctx.emit(records)

    def deny(rec: dict[str, Any]) -> str | None:
        return "asset_not_allowed" if rec["data"]["asset_id"] != LINUX_ASSET else None

    gw = FakeGateway(deny=deny)
    report = Sender(store, gw.client(), "linux-ssh-lab-vm-01").send_pending()
    assert report.drained
    assert len(gw.accepted_records) == 8
    assert report.dead_lettered == 1 and store.dead_count() == 1
    assert store.outbox_depth() == 0


# ── runner ────────────────────────────────────────────────────────────


class ExplodingCollector(Collector):
    collector_type: ClassVar[str] = "linux_ssh"
    source_types: ClassVar[tuple[str, ...]] = ("linux.journald",)

    def collect(self, ctx: CollectorContext) -> None:
        ctx.diff_snapshot("units", {"x": {"v": 1}})
        raise RuntimeError("source unavailable password=hunter2-synthetic")


class WeirdDetailsCollector(Collector):
    collector_type: ClassVar[str] = "linux_ssh"
    source_types: ClassVar[tuple[str, ...]] = ("linux.journald",)

    def collect(self, ctx: CollectorContext) -> None:
        ctx.emit([record("event", event_data("weird"))])
        ctx.health_details = {
            "Bad Key!": {"nested": [1, 2]},
            "ratio": float("nan"),
            "items": ["x" * 900],
            "token": "ghp_" + "a" * 36,
        }


def _settings(tmp_path: Path) -> Settings:
    return Settings(home=tmp_path)


def test_runner_isolates_failures_and_reports_health_for_each(tmp_path: Path) -> None:
    gw = FakeGateway()
    settings = _settings(tmp_path)
    good = CollectorWorker(
        make_config("synthetic-good"), settings, client_factory=lambda _c: gw.client()
    )
    bad = CollectorWorker(
        make_config("synthetic-bad"),
        settings,
        collector=ExplodingCollector(),
        client_factory=lambda _c: gw.client(),
    )
    for worker in (good, bad):
        worker.open()
    try:
        assert good.run_cycle().ok
        outcome = bad.run_cycle()
        assert not outcome.ok
        assert "hunter2" not in (outcome.error or "")  # redacted
        assert not bad.store.has_snapshot("units")  # failed cycle never advances snapshots
    finally:
        good.close()
        bad.close()
    health = {
        r["data"]["collector_id"]: r["data"]
        for r in gw.accepted_records
        if r["kind"] == "collector_health"
    }
    assert health["synthetic-good"]["status"] == "ok"
    assert health["synthetic-good"]["collector_type"] == "heartbeat"
    assert health["synthetic-good"]["details"]["selftest"] is True
    assert health["synthetic-bad"]["status"] == "failed"
    assert "[REDACTED" in health["synthetic-bad"]["last_error"]


def test_health_details_are_sanitised_not_dropped(tmp_path: Path) -> None:
    gw = FakeGateway()
    worker = CollectorWorker(
        make_config("synthetic-weird"),
        _settings(tmp_path),
        collector=WeirdDetailsCollector(),
        client_factory=lambda _c: gw.client(),
    )
    worker.open()
    try:
        assert worker.run_cycle().ok
    finally:
        worker.close()
    health = next(r["data"] for r in gw.accepted_records if r["kind"] == "collector_health")
    details = health["details"]
    assert details["bad_key"] == '{"nested":[1,2]}'
    assert details["ratio"] is None
    assert len(details["items"][0]) <= 512
    assert "ghp_" not in details["token"]
    assert health["events_collected"] == 1


def test_sanitize_details_bounds_keys() -> None:
    many = {f"k{i}": i for i in range(100)}
    clean = sanitize_details(many)
    assert len(clean) <= 49 and clean["details_truncated"] is True
    assert sanitize_details({"__": 1}) == {"detail": 1}


def test_runner_once_returns_nonzero_when_a_collector_fails(tmp_path: Path) -> None:
    gw = FakeGateway()
    configs = [make_config("synthetic-ok"), make_config("synthetic-fail", settings={"fail": True})]
    runner = Runner(
        configs, _settings(tmp_path), client_factory=lambda _c: gw.client(), drain_seconds=5
    )
    assert runner.run(once=True) == 1
    statuses = {
        r["data"]["collector_id"]: r["data"]["status"]
        for r in gw.accepted_records
        if r["kind"] == "collector_health"
    }
    assert statuses == {"synthetic-ok": "ok", "synthetic-fail": "failed"}
    ok_state = read_status(tmp_path / "var/collectors/synthetic-ok/state.db")
    assert ok_state["outbox_depth"] == 0 and ok_state["checkpoints"] == 2


def test_runner_once_succeeds_and_heartbeat_checkpoint_advances(tmp_path: Path) -> None:
    gw = FakeGateway()
    settings = _settings(tmp_path)
    for expected in (1, 2):
        runner = Runner(
            [make_config("synthetic-hb")],
            settings,
            client_factory=lambda _c: gw.client(),
            drain_seconds=5,
        )
        assert runner.run(once=True) == 0
        store = StateStore(tmp_path / "var/collectors/synthetic-hb/state.db")
        try:
            assert store.checkpoint("heartbeat.cycles") == str(expected)
        finally:
            store.close()


def test_runner_threads_survive_a_crashing_open(tmp_path: Path) -> None:
    gw = FakeGateway()
    configs = [
        make_config("synthetic-ok"),
        make_config("synthetic-missing", module="nonexistent.module:Nope"),
    ]
    runner = Runner(
        configs, _settings(tmp_path), client_factory=lambda _c: gw.client(), drain_seconds=5
    )
    assert runner.run(once=True) == 1
    assert any(r["data"]["collector_id"] == "synthetic-ok" for r in gw.accepted_records)
    assert threading.active_count() >= 1


# ── configuration ─────────────────────────────────────────────────────


def test_config_loader_rejects_duplicates_and_secret_settings(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(
        "collectors:\n  - {collector_id: dup, producer_id: p1, asset_id: linux:lab-vm-01,"
        " module: 'a.b:C', interval_seconds: 5}\n"
    )
    (tmp_path / "b.yaml").write_text(
        "- {collector_id: dup, producer_id: p1, asset_id: linux:lab-vm-01,"
        " module: 'a.b:C', interval_seconds: 5}\n"
    )
    with pytest.raises(ConfigLoadError, match="duplicate"):
        load_collector_configs(tmp_path)
    secret = tmp_path / "s.yaml"
    secret.write_text(
        "collector_id: s1\nproducer_id: p1\nasset_id: linux:lab-vm-01\nmodule: 'a.b:C'\n"
        "interval_seconds: 5\nsettings: {password: hunter2-synthetic}\n"
    )
    with pytest.raises(ConfigLoadError, match="secret"):
        load_collector_files([secret])


def test_shipped_heartbeat_example_config_is_valid() -> None:
    path = (
        Path(__file__).resolve().parents[3]
        / "collectors/src/extorq_collectors/sdk/examples/heartbeat.yaml"
    )
    (config,) = load_collector_files([path])
    assert config.producer_id == "extorq-selftest"
    assert config.module == HEARTBEAT


# ── sim-record ────────────────────────────────────────────────────────


def test_sim_record_started_then_completed_reuses_started_at(tmp_path: Path) -> None:
    gw = FakeGateway()
    settings = _settings(tmp_path)
    common = {"scenario": "VM-001", "asset": LINUX_ASSET, "run_id": "synthrun01"}
    started = record_simulation(
        settings,
        client_factory=gw.client,
        status="started",
        description="SYNTHETIC run",
        expected_rules=["VM-001"],
        **common,
    )
    assert started.buffered == 0 and started.report.accepted == 1
    done = record_simulation(settings, client_factory=gw.client, status="completed", **common)
    assert done.run.started_at == started.run.started_at
    assert done.run.finished_at is not None
    assert done.run.description == "SYNTHETIC run"
    assert done.run.expected_rule_ids == ["VM-001"]
    assert [r["data"]["status"] for r in gw.accepted_records] == ["started", "completed"]


def test_sim_record_refuses_unknown_start_and_mismatched_reuse(tmp_path: Path) -> None:
    gw = FakeGateway()
    settings = _settings(tmp_path)
    with pytest.raises(SimulationRecordError, match="started"):
        record_simulation(
            settings,
            client_factory=gw.client,
            status="completed",
            scenario="VM-002",
            asset=LINUX_ASSET,
            run_id="synthrun02",
        )
    record_simulation(
        settings,
        client_factory=gw.client,
        status="started",
        scenario="VM-002",
        asset=LINUX_ASSET,
        run_id="synthrun03",
    )
    with pytest.raises(SimulationRecordError, match="refusing"):
        record_simulation(
            settings,
            client_factory=gw.client,
            status="completed",
            scenario="K8S-001",
            asset="k8s:extorq-lab",
            run_id="synthrun03",
        )
    with pytest.raises(SimulationRecordError, match="status"):
        record_simulation(
            settings,
            client_factory=gw.client,
            status="bogus",
            scenario="VM-002",
            asset=LINUX_ASSET,
            run_id="synthrun04",
        )


def test_sim_record_stays_buffered_when_gateway_is_down(tmp_path: Path) -> None:
    gw = FakeGateway(script=[("status", 503, {"Retry-After": "300"})])
    result = record_simulation(
        _settings(tmp_path),
        client_factory=gw.client,
        delivery_seconds=0.5,
        status="started",
        scenario="VM-001",
        asset=LINUX_ASSET,
        run_id="synthrun05",
    )
    assert result.buffered == 1  # durable locally, delivered by the next flush/sim-record


# ── asset upsert ──────────────────────────────────────────────────────


def test_asset_upsert_sends_on_change_only_and_commits_with_emit(
    ctx: CollectorContext, store: StateStore
) -> None:
    first = asset_upsert(
        ctx, asset_type="linux_host", name="lab-vm-01", attributes={"os_version": "24.04"}
    )
    assert first is not None and first.asset_id == LINUX_ASSET
    ctx.emit([first])
    assert (
        asset_upsert(
            ctx, asset_type="linux_host", name="lab-vm-01", attributes={"os_version": "24.04"}
        )
        is None
    )
    ctx.discard_staged()
    changed = asset_upsert(
        ctx,
        asset_type="linux_host",
        name="lab-vm-01",
        attributes={"os_version": "24.10"},
        emit=True,
    )
    assert changed is not None and changed.first_seen == first.first_seen
    assert store.outbox_depth() == 2


def test_systemic_422_keeps_records_buffered_then_delivers(
    ctx: CollectorContext, store: StateStore
) -> None:
    # e.g. a gateway that does not accept schema 1.1 yet: version skew, not bad records
    _fill(ctx, 3)
    gw = FakeGateway(script=[("status", 422)])
    clock = FakeClock()
    sender = Sender(store, gw.client(), "linux-ssh-lab-vm-01", clock=clock)
    report = sender.send_pending()
    assert "422" in (report.error or "")
    assert store.outbox_depth() == 3 and store.dead_count() == 0
    clock.now += 120
    assert sender.send_pending().drained
    assert len(gw.accepted_records) == 3


def test_requeue_dead_moves_dead_letters_back_in_order(
    ctx: CollectorContext, store: StateStore
) -> None:
    _fill(ctx, 2)
    gw = FakeGateway(script=[("status", 418)])  # unknown 4xx -> dead letter
    report = Sender(store, gw.client(), "linux-ssh-lab-vm-01").send_pending()
    assert report.dead_lettered == 2 and store.outbox_depth() == 0
    assert store.requeue_dead() == 2
    assert store.dead_count() == 0
    report = Sender(store, gw.client(), "linux-ssh-lab-vm-01").send_pending()
    assert report.drained and report.accepted == 2
    assert [r["data"]["source"]["source_native_id"] for r in gw.accepted_records] == [
        "synthetic:m0",
        "synthetic:m1",
    ]


# ── session 3: string-only config secret check, degraded hint, committed snapshots ──


def _config_file(tmp_path: Path, settings_yaml: str) -> Path:
    path = tmp_path / "c.yaml"
    path.write_text(
        "collector_id: c1\nproducer_id: p1\nasset_id: linux:lab-vm-01\nmodule: 'a.b:C'\n"
        f"interval_seconds: 5\nsettings:\n{settings_yaml}"
    )
    return path


@pytest.mark.parametrize(
    "settings_yaml",
    [
        "  allow_gh_cli_token: true\n",  # C1 3.1: a boolean flag, not a token
        "  gh_cli_token_fallback: false\n  max_token: 4096\n  secret_count: 0\n",
        "  token_ttl: null\n  password_min_length: 12\n  rotated_token: 2026-11-21\n",
        "  token_file: var/secrets/github/readonly-pat\n  password_file: /run/secrets/x\n",
        "  nested: {client_secret: false, api_key: 7, items: [1, true, null]}\n",
    ],
)
def test_config_secret_check_ignores_non_string_values(tmp_path: Path, settings_yaml: str) -> None:
    (config,) = load_collector_files([_config_file(tmp_path, settings_yaml)])
    assert config.collector_id == "c1"


@pytest.mark.parametrize(
    ("settings_yaml", "path"),
    [
        ("  password: hunter2-synthetic\n", "password"),
        ("  allow_gh_cli_token: 'hunter2-synthetic'\n", "allow_gh_cli_token"),
        ("  ssh: {opts: ['-o', 'x', '--password hunter2-synthetic']}\n", "ssh.opts[2]"),
        ("  repos:\n    - token: 'abc-synthetic'\n", "repos[0].token"),
        ("  header: 'Authorization: Bearer synthetic-bearer-value-123'\n", "header"),
        (f"  pat: {'ghp_' + 'Ab1' * 12}\n", "pat"),
    ],
)
def test_config_secret_check_flags_string_secrets_by_path_never_value(
    tmp_path: Path, settings_yaml: str, path: str
) -> None:
    with pytest.raises(ConfigLoadError) as info:
        load_collector_files([_config_file(tmp_path, settings_yaml)])
    message = str(info.value)
    assert "secret" in message and f"({path})" in message
    for fragment in ("hunter2", "abc-synthetic", "synthetic-bearer", "Ab1Ab1"):
        assert fragment not in message


class DegradedCollector(Collector):
    collector_type: ClassVar[str] = "linux_ssh"
    source_types: ClassVar[tuple[str, ...]] = ("linux.journald",)

    def __init__(self) -> None:
        self.reasons: list[str] = []

    def collect(self, ctx: CollectorContext) -> None:
        ctx.emit([record("event", event_data(f"deg{len(ctx.degraded_reasons)}"))])
        for reason in self.reasons:
            ctx.mark_degraded(reason)


def test_mark_degraded_reports_degraded_but_keeps_last_success(tmp_path: Path) -> None:
    gw = FakeGateway()
    collector = DegradedCollector()
    worker = CollectorWorker(
        make_config("synthetic-degraded"),
        _settings(tmp_path),
        collector=collector,
        client_factory=lambda _c: gw.client(),
    )
    worker.open()
    try:
        collector.reasons = [
            "system_profiler timed out",
            "repo b rate limited token=hunter2-synthetic",
            "system_profiler timed out",  # duplicates collapse
        ]
        assert worker.run_cycle().ok  # partial success is still a success
        collector.reasons = []
        assert worker.run_cycle().ok  # the hint is per cycle
    finally:
        worker.close()
    first, second = [r["data"] for r in gw.accepted_records if r["kind"] == "collector_health"]
    assert first["status"] == "degraded"
    assert first["last_success_at"] is not None
    assert first["last_error"].startswith("degraded: system_profiler timed out; repo b")
    assert "hunter2" not in first["last_error"]
    assert first["details"]["degraded_reasons"] == [
        "system_profiler timed out",
        "repo b rate limited token=[REDACTED:secret]",
    ]
    assert second["status"] == "ok" and second["last_error"] is None
    assert "degraded_reasons" not in second["details"]
    assert second["last_success_at"] >= first["last_success_at"]
    status = read_status(tmp_path / "var" / "collectors" / "synthetic-degraded" / "state.db")
    assert status["last_health"]["status"] == "ok"


def test_mark_degraded_validates_and_bounds_reasons(ctx: CollectorContext) -> None:
    with pytest.raises(ValueError, match="non-empty"):
        ctx.mark_degraded("   ")
    for index in range(20):
        ctx.mark_degraded(f"reason {index}")
    assert len(ctx.degraded_reasons) == 8
    ctx.begin_cycle()
    assert ctx.degraded_reasons == ()


def test_failed_cycle_stays_failed_even_when_marked_degraded(tmp_path: Path) -> None:
    class HalfThenBoom(Collector):
        collector_type: ClassVar[str] = "linux_ssh"
        source_types: ClassVar[tuple[str, ...]] = ("linux.journald",)

        def collect(self, ctx: CollectorContext) -> None:
            ctx.mark_degraded("first source slow")
            raise RuntimeError("second source failed")

    gw = FakeGateway()
    worker = CollectorWorker(
        make_config("synthetic-boom"),
        _settings(tmp_path),
        collector=HalfThenBoom(),
        client_factory=lambda _c: gw.client(),
    )
    worker.open()
    try:
        assert not worker.run_cycle().ok
    finally:
        worker.close()
    (health,) = [r["data"] for r in gw.accepted_records if r["kind"] == "collector_health"]
    assert health["status"] == "failed"
    assert health["last_error"].startswith("RuntimeError: second source failed")
    assert health["details"]["degraded_reasons"] == ["first source slow"]


def test_committed_snapshot_is_a_read_only_copy_of_the_last_commit(
    ctx: CollectorContext, store: StateStore
) -> None:
    assert ctx.committed_snapshot("units") == {}
    ctx.diff_snapshot("units", {"a.service": {"state": "running", "n": 1}})
    assert ctx.committed_snapshot("units") == {}  # staged, not committed
    ctx.emit([])
    snapshot = ctx.committed_snapshot("units")
    assert snapshot == {"a.service": {"n": 1, "state": "running"}}
    snapshot["a.service"]["state"] = "tampered"
    snapshot["b.service"] = {}
    assert ctx.committed_snapshot("units") == {"a.service": {"n": 1, "state": "running"}}
    ctx.diff_snapshot("units", {"b.service": {"state": "running"}})
    assert set(ctx.committed_snapshot("units")) == {"a.service"}  # still the committed one
    assert ctx.discard_staged() == ["units"]

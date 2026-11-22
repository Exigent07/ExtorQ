"""Clean-slate reset (``make reset-data``): the pure parts, without a stack.

* ``extorq.storage.reset``: the table allow-list covers exactly the tables the migrations
  create (replayed from the DDL), the plan never touches unknown or protected tables, the
  TRUNCATE statements are built from allow-listed identifiers only, and ``reset`` refuses
  to run without confirmation.
* ``extorq_collectors.sdk.baseline``: which collector state is cleared and which cursors
  survive, per collector policy, applied to real SQLite state databases.
* ``scripts/reset_data.py``: state-directory planning and output parsing helpers.
* ``extorq.ingest.registry``: a producers.json written before schema 2.0 still loads.

All data is SYNTHETIC; nothing here talks to docker, ClickHouse or the gateway.
"""

from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from test_platform_rows import COLUMNS

from extorq.contracts.identity import canonical_json
from extorq.storage import reset
from extorq_collectors.sdk.base import CollectorContext
from extorq_collectors.sdk.baseline import (
    DEFAULT_POLICY,
    GITHUB_BASELINE_FIELDS,
    POLICIES,
    CollectorBusyError,
    clear_outbox,
    instance_locks,
    plan_state_reset,
    policy_for,
    rebaseline,
    reset_github_repo_checkpoint,
)
from extorq_collectors.sdk.config import CollectorConfig
from extorq_collectors.sdk.state import StagedSnapshot, StateStore

REPO = Path(__file__).resolve().parents[3]


def _load_script(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(f"extorq_{name}", REPO / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


reset_data = _load_script("reset_data")


# ── extorq.storage.reset ──────────────────────────────────────────────


def test_data_tables_are_exactly_the_tables_the_migrations_create() -> None:
    """A new table must be added to DATA_TABLES (or protected) deliberately."""
    assert set(reset.DATA_TABLES) == set(COLUMNS)
    assert len(reset.DATA_TABLES) == len(set(reset.DATA_TABLES))
    assert set(reset.PROTECTED_TABLES) == {"schema_migrations"}
    assert not set(reset.LEGACY_TABLES) & set(reset.DATA_TABLES)
    assert reset.LEGACY_TABLES == ("simulation_runs",)  # dropped by 0008


def test_plan_truncates_known_tables_only() -> None:
    existing = [*reset.DATA_TABLES[:-1], "schema_migrations", "simulation_runs", "mystery"]
    plan = reset.plan_reset(existing)
    assert plan.truncate == (*reset.DATA_TABLES[:-1], "simulation_runs")
    assert plan.missing == (reset.DATA_TABLES[-1],)
    assert plan.unknown == ("mystery",)
    assert plan.protected == ("schema_migrations",)
    assert "schema_migrations" not in plan.truncate and "mystery" not in plan.truncate
    after_0008 = reset.plan_reset([*reset.DATA_TABLES, "schema_migrations"])
    assert "simulation_runs" not in after_0008.truncate and after_0008.missing == ()


class FakeClickHouse:
    """Records commands; ``tables`` maps table -> physical rows (TRUNCATE zeroes it)."""

    def __init__(self, tables: dict[str, int], *, refill: dict[str, int] | None = None) -> None:
        self.tables = dict(tables)
        self.refill = refill or {}
        self.commands: list[str] = []

    def query(self, sql: str, parameters: dict[str, Any]) -> Any:
        assert "system.tables" in sql and parameters["database"] == "extorq"
        assert "View" in parameters["views"]
        rows = [[name, count] for name, count in sorted(self.tables.items())]
        return type("Result", (), {"result_rows": rows})()

    def command(self, sql: str) -> None:
        self.commands.append(sql)
        table = sql.rsplit(".", 1)[1]
        self.tables[table] = self.refill.get(table, 0)

    def close(self) -> None:
        pass


def test_reset_truncates_and_reports_counts_only() -> None:
    tables = {name: 10 + i for i, name in enumerate(reset.DATA_TABLES)}
    tables.update({"schema_migrations": 8, "simulation_runs": 3, "mystery": 5})
    client = FakeClickHouse(tables)
    report = reset.reset(client)
    assert client.commands == [
        f"TRUNCATE TABLE IF EXISTS extorq.{t}" for t in (*reset.DATA_TABLES, "simulation_runs")
    ]
    assert report.before == tables
    assert all(report.after[t] == 0 for t in report.truncated)
    assert report.after["schema_migrations"] == 8 and report.after["mystery"] == 5
    assert report.unknown == ("mystery",) and report.rows_remaining == {}
    data = json.loads(report.to_json())
    assert data["before"]["events"] == 10 and data["after"]["events"] == 0
    assert set(data) == {
        "database",
        "before",
        "after",
        "truncated",
        "missing",
        "unknown",
        "protected",
        "rows_remaining",
    }


def test_rows_arriving_after_truncation_are_reported() -> None:
    client = FakeClickHouse(dict.fromkeys(reset.DATA_TABLES, 1), refill={"analyst_actions": 2})
    assert reset.reset(client).rows_remaining == {"analyst_actions": 2}


@pytest.mark.parametrize("table", ["schema_migrations", "mystery", "events; DROP USER x", "Events"])
def test_truncation_refuses_identifiers_outside_the_allow_list(table: str) -> None:
    client = FakeClickHouse({})
    plan = reset.ResetPlan(truncate=(table,), missing=(), unknown=(), protected=())
    with pytest.raises(reset.ResetError):
        reset.truncate_tables(client, plan)
    assert client.commands == []


def test_reset_main_refuses_without_confirmation_before_connecting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import extorq.storage.clickhouse as clickhouse

    def no_connection(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("must not connect without --yes")

    monkeypatch.setattr(clickhouse, "get_client", no_connection)
    assert reset.main(confirm=False) == reset.EXIT_NOT_CONFIRMED
    assert "refusing" in json.loads(capsys.readouterr().out)["error"]


def test_reset_main_prints_one_json_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import extorq.storage.clickhouse as clickhouse

    client = FakeClickHouse(dict.fromkeys(reset.DATA_TABLES, 4))
    monkeypatch.setattr(clickhouse, "get_client", lambda role, **_k: client)
    assert reset.main(confirm=False, counts_only=True) == 0
    assert json.loads(capsys.readouterr().out)["tables"]["events"] == 4
    assert client.commands == []  # counting never truncates
    assert reset.main(confirm=True) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["after"]["events"] == 0


# ── collector state: policies and selection ───────────────────────────


@pytest.mark.parametrize(
    ("module", "policy"),
    [
        ("extorq_collectors.linux.collector:LinuxSSHCollector", "linux"),
        ("extorq_collectors.macos.collector:MacOSCollector", "macos"),
        ("extorq_collectors.kubernetes.collector:KubernetesInventoryCollector", "kubernetes"),
        ("extorq_collectors.github.collector:GitHubCollector", "github"),
        ("extorq_collectors.sdk.examples.heartbeat:HeartbeatCollector", "default"),
        ("extorq_collectors.linuxish.collector:Other", "default"),  # prefix, not substring
    ],
)
def test_policy_for_collector_module(module: str, policy: str) -> None:
    assert policy_for(module).name == policy


def test_shipped_collector_configs_have_specific_policies() -> None:
    from extorq_collectors.sdk.config import load_collector_configs

    configs = load_collector_configs(REPO / "config" / "collectors", include_disabled=True)
    assert configs
    for config in configs:
        assert policy_for(config.module) is not DEFAULT_POLICY, config.collector_id


def test_linux_plan_keeps_cursors_and_drops_schedules() -> None:
    plan = plan_state_reset(
        POLICIES["extorq_collectors.linux"],
        checkpoints={"journal.cursor": "s=abc;i=1f", "audit.inode": "42", "audit.offset": "9"},
        kv_keys=[
            "asset.first_seen.linux:lab-vm-01",
            "health.last",
            "linux.inventory.last_full",
            "linux.last_run.inventory",
            "linux.last_run.packages",
            "linux.last_run.posture",
            "linux.runtime",
            "linux.services.first_seen",
            "linux.services.known_units",
            "linux.services.last_event",
        ],
        snapshot_names=[
            "inventory.units",
            "inventory.cron",
            "posture.settings",
            "services.records",
        ],
    )
    assert plan.keep_checkpoints == ("audit.inode", "audit.offset", "journal.cursor")
    assert plan.rewrite_checkpoints == {}
    assert set(plan.drop_kv) == {
        "linux.inventory.last_full",
        "linux.last_run.inventory",
        "linux.last_run.packages",
        "linux.last_run.posture",
        "linux.services.last_event",
    }
    assert "asset.first_seen.linux:lab-vm-01" in plan.keep_kv and "health.last" in plan.keep_kv
    assert set(plan.drop_snapshots) == {
        "inventory.units",
        "inventory.cron",
        "posture.settings",
        "services.records",
    }
    assert plan.keep_snapshots == ()


def test_macos_plan_keeps_the_unified_log_window() -> None:
    plan = plan_state_reset(
        POLICIES["extorq_collectors.macos"],
        checkpoints={"unified_log.window": '{"end": "2026-11-22T10:00:00Z"}'},
        kv_keys=[
            "macos.sources",
            "macos.full_inventory",
            "macos.adapter_last_event",
            "health.last",
        ],
        snapshot_names=["launchd.items", "applications", "listeners.lsof"],
    )
    assert plan.keep_checkpoints == ("unified_log.window",)
    assert set(plan.drop_kv) == {
        "macos.sources",
        "macos.full_inventory",
        "macos.adapter_last_event",
    }
    assert set(plan.drop_snapshots) == {"launchd.items", "applications", "listeners.lsof"}


def test_kubernetes_plan_keeps_emitted_event_versions() -> None:
    plan = plan_state_reset(
        POLICIES["extorq_collectors.kubernetes"],
        checkpoints={"k8s.last_cycle": "2026-11-22T10:00:00+00:00"},
        kv_keys=["k8s.events_last_success", "k8s.last_full_refresh", "k8s.service_first_seen"],
        snapshot_names=["k8s-events", "objects:Pod", "services", "instances"],
    )
    assert plan.keep_snapshots == ("k8s-events",)
    assert set(plan.drop_snapshots) == {"objects:Pod", "services", "instances"}
    assert plan.drop_kv == ("k8s.last_full_refresh",)
    assert "k8s.events_last_success" in plan.keep_kv  # gap detection keeps working


def _github_state() -> dict[str, Any]:
    from extorq_collectors.github.state import RepoState

    state = RepoState(
        repo_id=1234,
        first_seen="2026-11-21T10:00:00.000Z",
        last_poll_at="2026-11-22T10:00:00.000Z",
        branch_heads={"main": "a" * 40},
        etags={"repo": 'W/"synthetic"', "runs:2026-11-22T09:00:00Z": 'W/"r"'},
        repo_meta={"id": 1234, "full_name": "exigent07/extorq-lab"},
        settings={"default_branch": "main", "visibility": "private"},
        branch_info={"main": {"sha": "a" * 40, "protected": False}},
        protection={"main": {"protection_status": "unprotected"}},
        runs_seen={"99": "1:completed:success|2026-11-22T09:30:00Z"},
        runs_cursor="2026-11-22T09:00:00Z",
        runs_listed_at="2026-11-22T10:00:00.000Z",
        change_seq=7,
        last_posture_at="2026-11-22T10:00:00.000Z",
        last_alerts_at="2026-11-22T10:00:00.000Z",
        last_asset_at="2026-11-22T10:00:00.000Z",
        last_activity_id=555,
        inventory_workflows=[".github/workflows/ci.yml"],
        inventory_branches=["main"],
    )
    return json.loads(state.to_json())


def test_github_checkpoint_reset_keeps_cursors_and_drops_posture_state() -> None:
    from extorq_collectors.github.state import RepoState, checkpoint_key

    key = checkpoint_key("Exigent07/extorq-lab")
    before = _github_state()
    rewritten = reset_github_repo_checkpoint(key, canonical_json(before))
    assert rewritten is not None
    after = RepoState.from_json(rewritten)  # the collector's own loader accepts it
    for name in (
        "repo_id",
        "first_seen",
        "last_poll_at",
        "branch_heads",
        "runs_seen",
        "runs_cursor",
        "runs_listed_at",
        "change_seq",
        "last_activity_id",
        "commit_retries",
    ):
        assert getattr(after, name) == before[name], name
    for name, default in GITHUB_BASELINE_FIELDS.items():
        assert getattr(after, name) == default, name
    assert set(GITHUB_BASELINE_FIELDS) <= set(before)  # field names exist in RepoState


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("github:repo:exigent07/extorq-lab", "not json"),
        ("github:repo:exigent07/extorq-lab", json.dumps({"version": 99})),
        ("github:repo:exigent07/extorq-lab", json.dumps([1, 2])),
        ("journal.cursor", json.dumps({"version": 1})),
    ],
)
def test_github_checkpoint_reset_leaves_unknown_documents_alone(key: str, value: str) -> None:
    assert reset_github_repo_checkpoint(key, value) is None


# ── collector state: applied to SQLite ─────────────────────────────────


def _populated_store(path: Path) -> None:
    store = StateStore(path)
    try:
        store.commit(
            [("event", '{"kind":"event"}'), ("asset", '{"kind":"asset"}')],
            {"journal.cursor": "s=synthetic;i=2a", "audit.offset": "128"},
            [
                StagedSnapshot("inventory.units", {"ssh.service": ("{}", "0" * 64)}),
                StagedSnapshot("k8s-events", {"uid-1": ('{"count":1}', "1" * 64)}),
            ],
        )
        store.commit([("event", '{"kind":"event","n":3}')])
        batch = store.next_batch(1, 10_000)
        assert batch is not None
        store.dead_letter(batch[0], 403, "synthetic refusal")
        for key in ("linux.last_run.posture", "linux.services.known_units", "health.last"):
            store.kv_set(key, {"synthetic": True})
    finally:
        store.close()


def test_rebaseline_linux_state(tmp_path: Path) -> None:
    path = tmp_path / "linux-ssh-lab-vm-01" / "state.db"
    _populated_store(path)
    result = rebaseline(
        path, collector_id="linux-ssh-lab-vm-01", policy=POLICIES["extorq_collectors.linux"]
    )
    assert (result.outbox_cleared, result.dead_cleared) == (2, 1)
    assert result.snapshots_dropped == ["inventory.units", "k8s-events"]
    assert result.kv_dropped == ["linux.last_run.posture"]
    assert result.checkpoints_kept == ["audit.offset", "journal.cursor"]
    store = StateStore(path)
    try:
        assert store.outbox_depth() == 0 and store.dead_count() == 0
        assert store.checkpoint("journal.cursor") == "s=synthetic;i=2a"  # cursor intact
        assert store.checkpoint("audit.offset") == "128"
        assert store.kv_get("linux.last_run.posture") is None
        assert store.kv_get("linux.services.known_units") == {"synthetic": True}
        assert not store.has_snapshot("inventory.units")
        config = CollectorConfig(
            collector_id="linux-ssh-lab-vm-01",
            producer_id="linux-ssh-lab-vm-01",
            asset_id="linux:lab-vm-01",
            module="extorq_collectors.linux.collector:LinuxSSHCollector",
            interval_seconds=30,
        )
        diff = CollectorContext(config, store).diff_snapshot("inventory.units", {"ssh.service": {}})
        assert diff.baseline  # the next cycle re-baselines: no change events
    finally:
        store.close()


def test_rebaseline_kubernetes_keeps_event_snapshot(tmp_path: Path) -> None:
    path = tmp_path / "k8s-inventory" / "state.db"
    _populated_store(path)
    result = rebaseline(
        path, collector_id="k8s-inventory", policy=POLICIES["extorq_collectors.kubernetes"]
    )
    assert result.snapshots_kept == ["k8s-events"]
    store = StateStore(path)
    try:
        assert store.has_snapshot("k8s-events") and store.snapshot("k8s-events")
        assert not store.has_snapshot("inventory.units")
    finally:
        store.close()


def test_rebaseline_github_rewrites_only_repository_checkpoints(tmp_path: Path) -> None:
    path = tmp_path / "github-repos" / "state.db"
    key = "github:repo:exigent07/extorq-lab"
    store = StateStore(path)
    store.commit([], {key: canonical_json(_github_state()), "other": "kept"})
    store.close()
    result = rebaseline(
        path, collector_id="github-repos", policy=POLICIES["extorq_collectors.github"]
    )
    assert result.checkpoints_rewritten == [key] and result.checkpoints_kept == ["other"]
    store = StateStore(path)
    try:
        value = json.loads(store.checkpoint(key) or "{}")
        assert value["branch_heads"] == {"main": "a" * 40} and value["settings"] is None
        assert value["etags"] == {} and value["last_posture_at"] is None
        assert store.checkpoint("other") == "kept"
    finally:
        store.close()


def test_rebaseline_refuses_while_an_instance_lock_is_held(tmp_path: Path) -> None:
    path = tmp_path / "macos-workstation-01" / "state.db"
    _populated_store(path)
    lock = path.with_name("macos-collector.lock")
    lock.touch()
    fd = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(CollectorBusyError):
            rebaseline(
                path,
                collector_id="macos-workstation-01",
                policy=POLICIES["extorq_collectors.macos"],
            )
    finally:
        os.close(fd)
    store = StateStore(path)
    try:
        assert store.outbox_depth() == 2  # nothing changed while the collector held its lock
    finally:
        store.close()
    with instance_locks(path.parent):  # released: the reset can proceed
        pass


def test_rebaseline_and_clear_outbox_require_existing_state(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        rebaseline(tmp_path / "none" / "state.db", collector_id="x", policy=DEFAULT_POLICY)
    with pytest.raises(FileNotFoundError):
        clear_outbox(tmp_path / "none" / "outbox.db")
    assert not (tmp_path / "none").exists()  # never created


def test_clear_outbox_keeps_everything_else(tmp_path: Path) -> None:
    path = tmp_path / "scanners" / "outbox.db"
    _populated_store(path)
    assert clear_outbox(path) == (2, 1)
    store = StateStore(path)
    try:
        assert store.outbox_depth() == 0 and store.dead_count() == 0
        assert store.checkpoint("journal.cursor") and store.has_snapshot("inventory.units")
    finally:
        store.close()


# ── scripts/reset_data.py helpers ─────────────────────────────────────


def _config(collector_id: str, module: str) -> CollectorConfig:
    return CollectorConfig(
        collector_id=collector_id,
        producer_id="synthetic-producer",
        asset_id="linux:lab-vm-01",
        module=module,
        interval_seconds=60,
    )


def test_plan_collector_state_maps_directories(tmp_path: Path) -> None:
    root = tmp_path / "collectors"
    for name in ("linux-ssh-lab-vm-01", "simulation-runner", "old-experiment"):
        (root / name).mkdir(parents=True)
        (root / name / "state.db").write_bytes(b"")
    configs = [
        _config("linux-ssh-lab-vm-01", "extorq_collectors.linux.collector:LinuxSSHCollector"),
        _config("github-repos", "extorq_collectors.github.collector:GitHubCollector"),
    ]
    plan = reset_data.plan_collector_state(root, configs)
    assert [(t.collector_id, t.policy_name) for t in plan.targets] == [
        ("linux-ssh-lab-vm-01", "linux")
    ]
    assert [p.name for p in plan.retired] == ["simulation-runner"]
    assert plan.unconfigured == ("old-experiment",)
    assert plan.without_state == ("github-repos",)


def test_removable_state_dir_only_holds_state_files(tmp_path: Path) -> None:
    root = tmp_path / "collectors"
    good = root / "simulation-runner"
    good.mkdir(parents=True)
    for name in ("state.db", "state.db-wal", "state.db-shm"):
        (good / name).write_bytes(b"")
    assert reset_data.removable_state_dir(good, root)
    (good / "notes.txt").write_text("keep me", encoding="utf-8")
    assert not reset_data.removable_state_dir(good, root)
    elsewhere = tmp_path / "simulation-runner"
    elsewhere.mkdir()
    assert not reset_data.removable_state_dir(elsewhere, root)
    link = root / "linked"
    link.symlink_to(elsewhere, target_is_directory=True)
    assert not reset_data.removable_state_dir(link, root)


def test_last_json_line_and_count_table() -> None:
    out = 'noise\n{"broken": \n{"database": "extorq", "tables": {"events": 3}}\n\n'
    assert reset_data.last_json_line(out)["tables"] == {"events": 3}
    with pytest.raises(reset_data.StepError):
        reset_data.last_json_line("no json here\n[1, 2]\n")
    lines = reset_data.count_table({"events": 12, "alerts": 1}, {"events": 0})
    assert lines[0].split() == ["table", "before", "after"]
    assert lines[1].split() == ["alerts", "1", "-"]
    assert lines[2].split() == ["events", "12", "0"]


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("uv run --frozen extorq-collect run --only a,b", "a,b"),
        ("uv run --frozen extorq-collect run --only=macos-workstation-01", "macos-workstation-01"),
        ("uv run --frozen extorq-collect run", None),
        ("uv run --frozen extorq-collect run --only", None),
        (None, None),
    ],
)
def test_only_selection(command: str | None, expected: str | None) -> None:
    assert reset_data.only_selection(command) == expected


# ── producer registry written before schema 2.0 ───────────────────────


def _registry_entry(producer_id: str, kinds: list[str]) -> dict[str, Any]:
    return {
        "producer_id": producer_id,
        # Distinct per producer: the registry rejects one credential shared by two producers.
        "token_sha256": hashlib.sha256(producer_id.encode()).hexdigest(),
        "allowed_kinds": kinds,
        "allowed_source_types": ["synthetic.*"],
        "allowed_asset_patterns": ["linux:*"],
    }


def test_registry_drops_retired_kinds_and_entries(tmp_path: Path) -> None:
    from extorq.ingest.registry import ProducerRegistry, drop_retired_kinds

    document = {
        "version": 1,
        "producers": [
            _registry_entry("linux-ssh-lab-vm-01", ["event", "asset"]),
            _registry_entry("simulation-runner", ["simulation_run"]),
            _registry_entry("mixed-producer", ["event", "simulation_run"]),
        ],
    }
    adjusted, notes = drop_retired_kinds(document)
    assert [e["producer_id"] for e in adjusted["producers"]] == [
        "linux-ssh-lab-vm-01",
        "mixed-producer",
    ]
    assert adjusted["producers"][1]["allowed_kinds"] == ["event"]
    assert len(notes) == 2 and all("0" * 64 not in note for note in notes)
    path = tmp_path / "producers.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    registry = ProducerRegistry(path)  # loads instead of failing the gateway start
    assert registry.producer_ids == ["linux-ssh-lab-vm-01", "mixed-producer"]
    assert drop_retired_kinds({"producers": "not a list"}) == ({"producers": "not a list"}, [])

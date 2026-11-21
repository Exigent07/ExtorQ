"""LinuxSSHCollector cycles against a fake dispatch boundary serving REAL captured responses."""

from __future__ import annotations

import copy
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from linux_testlib import (
    FIXTURES,
    FakeVM,
    events_of,
    load_json,
    load_ndjson,
    make_client,
    make_context,
    outbox,
)

from extorq.contracts import AdapterSupport
from extorq_collectors.linux.collector import CollectionError, LinuxSettings, LinuxSSHCollector
from extorq_collectors.services.registry import all_adapters, get_adapter

JOURNAL_FILES = (
    "sshd",
    "su_pam",
    "sudo",
    "systemd_pid1",
    "nginx",
    "lab_portal",
    "accounts",
    "dispatch_denials",
)


def _journal() -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for name in JOURNAL_FILES:
        for obj in load_ndjson(f"journal/{name}.ndjson"):
            merged[obj["__CURSOR"]] = obj
    return sorted(merged.values(), key=lambda e: int(e["__REALTIME_TIMESTAMP"]))


def _vm() -> FakeVM:
    return FakeVM(
        journal=_journal(),
        audit_log=(FIXTURES / "audit" / "vm002_create.log").read_bytes()
        + (FIXTURES / "audit" / "augenrules_load.log").read_bytes(),
        inventory=load_json("inventory/inventory_baseline.json"),
        packages=load_json("dispatch/packages.json"),
        posture=load_json("dispatch/posture.json"),
    )


def _setup(
    tmp_path: Path,
    ssh_files: tuple[Path, Path],
    fake: FakeVM,
    settings: dict[str, Any] | None = None,
) -> tuple[Any, LinuxSSHCollector]:
    ctx = make_context(tmp_path, settings)
    collector = LinuxSSHCollector(client=make_client(fake, ssh_files))
    collector.setup(ctx)
    return ctx, collector


def _cycle(ctx: Any, collector: LinuxSSHCollector, *, force_inventory: bool = False) -> None:
    if force_inventory:
        ctx.state.set("linux.last_run.inventory", "2000-01-01T00:00:00+00:00")
    ctx.begin_cycle()
    collector.collect(ctx)


def test_baseline_cycle(tmp_path: Path, ssh_files: tuple[Path, Path]) -> None:
    fake = _vm()
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    _cycle(ctx, collector)
    records = outbox(ctx)
    kinds = Counter(r["kind"] for r in records)
    assert kinds["asset"] == 1 and kinds["scan_run"] == 1 and kinds["finding"] == 6
    assert kinds["service"] == len(collector.service_records) > 15
    assert kinds["service_instance"] > 15 and kinds["inventory_item"] > 1000
    types = Counter(e["event_type"] for e in events_of(records))
    # Baseline inventory: no persistence/package/account "changes" for pre-existing state.
    assert not any(
        t.startswith(("persistence.", "package.", "account.", "network.listener")) for t in types
    )
    assert types["service.discovered"] == kinds["service"]
    assert types["auth.ssh.invalid_user"] == 9 and types["audit.config.changed"] >= 20
    statuses = {
        r["data"]["service_key"]: (r["data"]["adapter_support"], r["data"]["monitoring_status"])
        for r in records
        if r["kind"] == "service"
    }
    for unit in (
        "ssh.service",
        "nginx.service",
        "lab-portal.service",
        "init.scope",
        "auditd.service",
    ):
        assert statuses[unit] == ("implemented", "monitored"), unit
    assert statuses["systemd-resolved.service"] == ("planned", "unmonitored")
    assert statuses["cron.service"] == ("none", "unmonitored")
    assert ctx.checkpoints.get("journal.cursor") == fake.journal[-1]["__CURSOR"]
    assert ctx.checkpoints.get("audit.offset") == str(len(fake.audit_log))
    assert ctx.health_details["step.posture"].startswith("ok status=succeeded")


def test_adapter_events_carry_service_refs(tmp_path: Path, ssh_files: tuple[Path, Path]) -> None:
    ctx, collector = _setup(tmp_path, ssh_files, _vm())
    _cycle(ctx, collector)
    events = events_of(outbox(ctx))
    by_type: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        by_type.setdefault(event["event_type"], []).append(event)
    for event_type, adapter in (
        ("auth.ssh.invalid_user", "ssh"),
        ("http.request", "nginx"),
        ("http.server.error", "nginx"),
        ("app.auth.login_failed", "webapp-json"),
        ("system.service.state_changed", "systemd"),
        ("process.audit.exec", "auditd"),
    ):
        assert by_type[event_type], event_type
        assert all(
            e["service"] and e["service"]["adapter_id"] == adapter for e in by_type[event_type]
        ), event_type
    # Host-level records (sudo) are not attributed to a service.
    assert all(e["service"] is None for e in by_type["auth.sudo.command"])
    # nginx worker pids resolve to the master process instance of this boot.
    nginx = [e for e in by_type["http.request"] if e["service"]["instance_id"]]
    assert nginx, "worker pid -> instance attribution expected for the current boot"
    # Findings attributable to a service carry its id; others do not.
    findings = [r["data"] for r in outbox(ctx) if r["kind"] == "finding"]
    assert all(
        f["service_id"] is None for f in findings if not f["check_id"].startswith("linux.ssh.")
    )


def test_journal_resumes_from_cursor_without_duplicates(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    fake = _vm()
    full = fake.journal
    fake.journal = full[: len(full) // 2]
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    _cycle(ctx, collector)
    first = {
        e["event_id"]
        for e in events_of(outbox(ctx))
        if e["source"]["source_type"] in ("linux.journald", "linux.nginx", "linux.app")
    }
    fake.journal = full
    count_before = len(outbox(ctx))
    _cycle(ctx, collector)
    new = events_of(outbox(ctx)[count_before:])
    second = {
        e["event_id"]
        for e in new
        if e["source"]["source_type"] in ("linux.journald", "linux.nginx", "linux.app")
    }
    assert second and not (first & second)
    requested = [c for c in fake.commands if c.startswith("journal ")]
    assert requested[0].startswith("journal - ") and not requested[-1].startswith("journal - ")
    # A third cycle with no new entries sends no journal events.
    count_before = len(outbox(ctx))
    _cycle(ctx, collector)
    assert not [
        e
        for e in events_of(outbox(ctx)[count_before:])
        if e["source"]["source_type"] == "linux.journald"
    ]


def test_journal_cursor_lost_emits_gap(tmp_path: Path, ssh_files: tuple[Path, Path]) -> None:
    fake = _vm()
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    _cycle(ctx, collector)
    fake.vacuumed.add(ctx.checkpoints.get("journal.cursor"))  # journal rotated/vacuumed
    count_before = len(outbox(ctx))
    _cycle(ctx, collector)
    gaps = events_of(outbox(ctx)[count_before:], "extorq.collector.gap_detected")
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["source"]["source_type"] == "linux.journald"
    assert gap["attributes"]["gap_reason"] == "journal_cursor_not_found"


def test_audit_rotation_emits_gap_and_restarts_at_zero(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    fake = _vm()
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    _cycle(ctx, collector)
    fake.audit_inode = 999999  # audit.log rotated away under the checkpoint
    count_before = len(outbox(ctx))
    _cycle(ctx, collector)
    gaps = events_of(outbox(ctx)[count_before:], "extorq.collector.gap_detected")
    assert [g["attributes"]["gap_reason"] for g in gaps] == ["rotated_past_offset"]
    assert gaps[0]["source"]["source_type"] == "linux.auditd"
    assert ctx.checkpoints.get("audit.inode") == "999999"


def test_vm002_cycle_produces_persistence_and_service_events(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    fake = _vm()
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    _cycle(ctx, collector)
    fake.inventory = load_json("inventory/inventory_vm002_created.json")
    count_before = len(outbox(ctx))
    _cycle(ctx, collector, force_inventory=True)
    new = outbox(ctx)[count_before:]
    types = Counter(e["event_type"] for e in events_of(new))
    assert types["persistence.systemd.unit_created"] == 1
    assert types["persistence.systemd.unit_enabled"] == 1
    assert types["service.discovered"] == 1
    assert "service.removed" not in types  # fwupd stopped, but its unit file still exists
    created = events_of(new, "persistence.systemd.unit_created")[0]
    assert created["service"]["adapter_id"] == "systemd"
    assert created["attributes"]["subject_service_id"] is not None
    assert created["simulation"]["run_id"] == "0e49c82d82bc"
    tombstones = [
        r["data"] for r in new if r["kind"] == "service_instance" and not r["data"]["present"]
    ]
    assert any(t["process_name"] == "fwupd" and t["state"] == "stopped" for t in tombstones)
    # Removal of the unit file removes the service.
    fake.inventory = load_json("inventory/inventory_vm002_removed.json")
    count_before = len(outbox(ctx))
    _cycle(ctx, collector, force_inventory=True)
    later = outbox(ctx)[count_before:]
    assert [
        e["event_type"]
        for e in events_of(later)
        if e["event_type"].startswith(("service.", "persistence."))
    ] == ["persistence.systemd.unit_deleted", "service.removed"] or Counter(
        e["event_type"] for e in events_of(later)
    )["service.removed"] == 1
    assert any(r["kind"] == "service" and not r["data"]["present"] for r in later)


def test_service_records_only_on_change(tmp_path: Path, ssh_files: tuple[Path, Path]) -> None:
    ctx, collector = _setup(tmp_path, ssh_files, _vm())
    _cycle(ctx, collector)
    count_before = len(outbox(ctx))
    _cycle(ctx, collector, force_inventory=True)
    new = outbox(ctx)[count_before:]
    assert not [r for r in new if r["kind"] in ("service", "service_instance")]
    assert not events_of(new, "service.discovered")


def test_failed_step_is_isolated_and_discards_staged_snapshots(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    fake = _vm()
    fake.fail["inventory"] = (70, b"error: internal KeyError\n")
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    ctx.begin_cycle()
    with pytest.raises(CollectionError, match="inventory"):
        collector.collect(ctx)
    records = outbox(ctx)
    assert events_of(records, "auth.ssh.invalid_user")  # journal step still delivered
    assert ctx.health_details["step.inventory"].startswith("failed")
    assert not ctx.has_snapshot("inventory.units")
    del fake.fail["inventory"]
    _cycle(ctx, collector)
    assert ctx.has_snapshot("inventory.units")


def test_posture_failure_records_failed_scan(tmp_path: Path, ssh_files: tuple[Path, Path]) -> None:
    fake = _vm()
    fake.fail["posture"] = (70, b"error: posture failed\n")
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    ctx.begin_cycle()
    with pytest.raises(CollectionError, match="posture"):
        collector.collect(ctx)
    scans = [r["data"] for r in outbox(ctx) if r["kind"] == "scan_run"]
    assert [s["status"] for s in scans] == ["failed"]
    assert not [r for r in outbox(ctx) if r["kind"] == "finding"]


def test_disabled_adapter_is_unmonitored_and_unattributed(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    settings = {"adapters": {"enabled": ["ssh", "systemd", "auditd", "webapp-json"]}}
    ctx, collector = _setup(tmp_path, ssh_files, _vm(), settings)
    _cycle(ctx, collector)
    records = outbox(ctx)
    nginx = next(
        r["data"]
        for r in records
        if r["kind"] == "service" and r["data"]["service_key"] == "nginx.service"
    )
    assert nginx["monitoring_status"] == "unmonitored"
    assert nginx["coverage_note"].startswith("adapter available but not enabled")
    # Without the adapter, nginx lines are not parsed as service telemetry.
    assert not events_of(records, "http.request")


def test_nginx_prerequisite_problem_degrades_coverage(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    fake = _vm()
    inventory = copy.deepcopy(fake.inventory)
    assert inventory is not None
    for ctx_entry in inventory["configs"]["nginx"]["contexts"]:
        ctx_entry["directives"].pop("access_log", None)
    fake.inventory = inventory
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    _cycle(ctx, collector)
    nginx = next(
        r["data"]
        for r in outbox(ctx)
        if r["kind"] == "service" and r["data"]["service_key"] == "nginx.service"
    )
    assert nginx["monitoring_status"] == "degraded"
    assert "access_log is not sent to journald" in nginx["coverage_note"]


def test_settings_validation() -> None:
    base = Path("/repo")
    settings = LinuxSettings.from_config({}, base)
    assert (
        settings.ssh.port == 2222 and settings.ssh.known_hosts_file == base / "var/vm/known_hosts"
    )
    with pytest.raises(ValueError):
        LinuxSettings.from_config({"journal": {"max_entries": 99999}}, base)
    with pytest.raises(ValueError):
        LinuxSettings.from_config(
            {"adapters": {"webapp-json": {"apps": [{"name": "x", "unit": "x;rm -rf /"}]}}}, base
        )


def test_registry_implemented_and_planned_adapters() -> None:
    ids = {a.adapter_id: a.support for a in all_adapters()}
    for implemented in ("ssh", "nginx", "apache", "webapp-json", "systemd", "auditd"):
        assert ids[implemented] is AdapterSupport.IMPLEMENTED
    for planned in ("ftp", "postgresql", "mysql", "dns", "redis"):
        assert ids[planned] is AdapterSupport.PLANNED
    for adapter in all_adapters():
        assert adapter.never_collects, adapter.adapter_id  # data-minimisation promise
    ssh = get_adapter("ssh")
    assert ssh is not None and ssh.accepts({"SYSLOG_IDENTIFIER": "sshd"})
    assert not ssh.accepts({"SYSLOG_IDENTIFIER": "nginx_access"})


def test_lifecycle_events_link_subject_service(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    ctx, collector = _setup(tmp_path, ssh_files, _vm())
    _cycle(ctx, collector)
    lifecycle = events_of(outbox(ctx), "system.service.state_changed")
    ssh = [e for e in lifecycle if e["resource"]["name"] == "ssh.service"]
    assert ssh and all(e["attributes"]["subject_service_id"] for e in ssh)
    assert all(e["service"]["adapter_id"] == "systemd" for e in ssh)


def test_unreachable_vm_skips_remaining_ssh_steps(
    tmp_path: Path, ssh_files: tuple[Path, Path]
) -> None:
    fake = _vm()
    ctx, collector = _setup(tmp_path, ssh_files, fake)
    refused = (255, b"ssh: connect to host 127.0.0.1 port 2222: Connection refused\n")
    fake.fail["inventory"] = refused
    ctx.begin_cycle()
    with pytest.raises(CollectionError, match="SSHConnectionError"):
        collector.collect(ctx)
    assert ctx.health_details["step.journal"].startswith("skipped (transport failed")
    assert ctx.health_details["step.audit"].startswith("skipped")
    assert not [c for c in fake.commands if c.startswith(("journal", "audit", "posture"))]
    assert fake.commands.count("inventory") == 3  # bounded retries of the first step only

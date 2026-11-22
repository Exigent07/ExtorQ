"""Service discovery, inventory diffs and posture on REAL inventory/posture documents."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

from linux_testlib import ASSET, load_json, pctx

from extorq.contracts import PortAttribution
from extorq_collectors.linux import inventory as inv
from extorq_collectors.linux import posture
from extorq_collectors.linux.adapters.webapp_json import DEFAULT_APPS
from extorq_collectors.linux.discovery import discover, template_of, unit_from_cgroup
from extorq_collectors.sdk.base import SnapshotDiff

NOW = datetime(2026, 11, 21, 15, 0, tzinfo=UTC)


def _services(doc: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
    result = discover(doc, ASSET, webapps=DEFAULT_APPS, **kwargs)
    return {s.unit: s for s in result.services}


def test_cgroup_unit_mapping() -> None:
    assert unit_from_cgroup("/system.slice/nginx.service") == "nginx.service"
    assert unit_from_cgroup("/system.slice/systemd-udevd.service/udev") == "systemd-udevd.service"
    assert (
        unit_from_cgroup("/system.slice/system-getty.slice/getty@tty1.service")
        == "getty@tty1.service"
    )
    assert unit_from_cgroup("/init.scope") == "init.scope"
    assert unit_from_cgroup("/") is None and unit_from_cgroup(None) is None
    assert (
        template_of("getty@tty1.service") == "getty@.service" and template_of("a.service") is None
    )


def test_discovery_evidence_endpoints_and_adapters() -> None:
    services = _services(load_json("inventory/inventory_baseline.json"))
    ssh, nginx, portal = (
        services["ssh.service"],
        services["nginx.service"],
        services["lab-portal.service"],
    )
    # Socket-activated sshd: the kernel reports the socket's cgroup as ssh.socket.
    assert {e.endpoint.port for e in ssh.endpoints} == {22}
    assert all(e.endpoint.attribution is PortAttribution.CONFIRMED for e in ssh.endpoints)
    assert "ssh.socket activates ssh.service" in ssh.endpoints[0].endpoint.attribution_basis
    assert ssh.adapter.adapter_id == "ssh" and ssh.candidate.config_refs
    assert nginx.adapter.adapter_id == "nginx"
    assert [e.endpoint.exposure for e in nginx.endpoints] == ["any"]
    assert portal.adapter.adapter_id == "webapp-json"
    assert [(e.endpoint.port, e.endpoint.exposure) for e in portal.endpoints] == [
        (8080, "loopback")
    ]
    # Configuration + socket evidence link nginx to the application it fronts.
    assert nginx.candidate.attributes["upstream_services"] == ["lab-portal.service"]
    assert portal.candidate.attributes["fronted_by"] == ["nginx.service"]
    assert services["systemd-resolved.service"].adapter.support.value == "planned"
    assert services["cron.service"].adapter is None
    assert services["init.scope"].candidate.name == "systemd"
    # User sessions are not host services.
    assert not any(u.startswith(("session-", "user@")) for u in services)


def test_processes_are_not_assumed_network_services() -> None:
    services = _services(load_json("inventory/inventory_baseline.json"))
    cron = services["cron.service"]
    assert cron.running and cron.endpoints == [] and cron.candidate.is_network_service is None


def test_listener_owner_unknown_without_cgroup_evidence() -> None:
    doc = load_json("inventory/inventory_baseline.json")
    stripped = copy.deepcopy(doc)
    for listener in stripped["listeners"]:
        for key in ("cgroup", "uid", "inode"):
            listener.pop(key, None)
    services = _services(stripped)
    ssh_eps = services["ssh.service"].endpoints
    # Older dispatcher output: port 22 is only INFERRED (configuration), never confirmed.
    assert ssh_eps and all(e.endpoint.attribution is PortAttribution.INFERRED for e in ssh_eps)
    result = discover(stripped, ASSET, webapps=DEFAULT_APPS)
    assert any(lf.port == 68 for lf in result.unattributed)  # no evidence, stays unattributed


def test_session_listener_is_unattributed() -> None:
    doc = load_json("inventory/inventory_baseline.json")
    # SYNTHETIC listener (derived from the real document): a user-session process listening.
    doc["listeners"].append(
        {
            "proto": "tcp",
            "state": "LISTEN",
            "local_address": "0.0.0.0",  # noqa: S104 - observed bind address, not a bind
            "interface": None,
            "local_port": 8000,
            "processes": None,
            "uid": 1000,
            "inode": 1,
            "cgroup": "/user.slice/user-1000.slice/session-5.scope",
        }
    )
    result = discover(doc, ASSET, webapps=DEFAULT_APPS)
    assert [lf.port for lf in result.unattributed] == [8000]


def test_vm002_unit_becomes_service_and_known_units_persist() -> None:
    created = _services(load_json("inventory/inventory_vm002_created.json"))
    test_unit = next(s for u, s in created.items() if u.startswith("extorq-test-"))
    assert not test_unit.running and test_unit.adapter is None
    assert {e.value for e in test_unit.candidate.evidence} == {"systemd_unit"}
    # fwupd ran when the baseline was captured and had exited by the next capture: a service
    # seen earlier stays a (not running) service while its unit file exists.
    assert _services(load_json("inventory/inventory_baseline.json"))["fwupd.service"].running
    later = load_json("inventory/inventory_vm002_created.json")
    assert "fwupd.service" not in _services(later)
    known = _services(later, known_units=["fwupd.service", "gone.service"])
    assert "fwupd.service" in known and not known["fwupd.service"].running
    assert "gone.service" not in known


def test_instances_and_pid_map() -> None:
    result = discover(load_json("inventory/inventory_baseline.json"), ASSET, webapps=DEFAULT_APPS)
    nginx = result.by_unit()["nginx.service"]
    (master,) = nginx.main_processes
    workers = [
        pid
        for pid, (sid, _iid) in result.pid_instances.items()
        if sid == nginx.service_id and pid != master.pid
    ]
    assert len(workers) == 2  # worker pids resolve to the master's instance
    started = result.started_at(master)
    assert started is not None and started.year == 2026
    assert result.instance_key(master).endswith(f":{master.pid}:{master.start_ticks}")


def _diff(category: str, before: dict[str, Any], after: dict[str, Any]) -> SnapshotDiff:
    extract = inv.CATEGORIES[category][0]
    old, new = extract(before), extract(after)
    added = {k: v for k, v in new.items() if k not in old}
    removed = {k: v for k, v in old.items() if k not in new}
    changed = {k: v for k, v in new.items() if k in old and old[k] != v}
    previous = {**{k: old[k] for k in changed}, **removed}
    return SnapshotDiff(added, changed, removed, previous)


def _dctx() -> inv.DiffContext:
    return inv.DiffContext(parse=pctx(), event_time=NOW)


def test_vm002_inventory_diff_events() -> None:
    before = load_json("inventory/inventory_baseline.json")
    after = load_json("inventory/inventory_vm002_created.json")
    (created,) = inv.unit_events(_diff("units", before, after), _dctx())
    assert created.event_type == "persistence.systemd.unit_created"
    assert created.resource.path.startswith("/etc/systemd/system/extorq-test-0e49c82d82bc")
    assert created.attributes["exec_start"] == "/bin/true"
    assert created.attributes["vendor_unit"] is False
    assert len(created.attributes["sha256"]) == 64
    assert created.labels == {}  # a detection-test unit is ordinary telemetry
    (enabled,) = inv.enablement_events(_diff("enablement", before, after), _dctx())
    assert enabled.event_type == "persistence.systemd.unit_enabled"
    assert enabled.attributes["wanted_by"] == "multi-user.target"
    removed_doc = load_json("inventory/inventory_vm002_removed.json")
    (deleted,) = inv.unit_events(_diff("units", after, removed_doc), _dctx())
    assert deleted.event_type == "persistence.systemd.unit_deleted"
    # Identity: same diff content -> same event id (re-sent diffs collapse).
    again = inv.unit_events(_diff("units", before, after), _dctx())
    assert again[0].event_id == created.event_id


def test_legacy_dispatcher_arguments_are_not_emitted_or_treated_as_unit_changes() -> None:
    document = load_json("inventory/inventory_vm002_created.json")
    unit = next(
        item for item in document["systemd_units"] if item.get("exec_start") == ["/bin/true"]
    )
    path = unit["path"]
    unit["exec_start"] = ["-/bin/true synthetic-argument"]
    items = inv.unit_items(document)
    current = items[path]
    assert current["exec_start"] == ["/bin/true"]
    previous = {**current, "exec_start": ["-/bin/true synthetic-argument"]}
    migration = SnapshotDiff({}, {path: current}, {}, {path: previous})
    assert inv.unit_events(migration, _dctx()) == []

    removal = SnapshotDiff({}, {}, {path: previous}, {path: previous})
    (event,) = inv.unit_events(removal, _dctx())
    assert event.attributes["exec_start"] == "/bin/true"
    (tombstone,) = inv.inventory_records(
        "units",
        removal,
        {},
        asset_id=ASSET,
        collector_id="linux-test",
        snapshot_id="synthetic",
        observed_at=NOW,
        full=False,
    )
    assert tombstone.attributes["exec_start"] == ["/bin/true"]


def test_account_diff_and_privileged_groups() -> None:
    before = load_json("inventory/inventory_vm002_created.json")
    after = load_json("inventory/inventory_user_added.json")
    (created,) = inv.user_events(_diff("users", before, after), _dctx())
    assert created.event_type == "account.user.created"
    assert created.actor.name.startswith("extorq-test-") and created.attributes["uid"] == 999
    assert created.attributes["interactive_shell"] is False
    (deleted,) = inv.user_events(_diff("users", after, before), _dctx())
    assert deleted.event_type == "account.user.deleted"
    # SYNTHETIC change on top of the real document: a user added to sudo.
    escalated = copy.deepcopy(after)
    escalated["privileged_groups"]["sudo"].append("mallory")
    changes = inv.privileged_group_changes(_diff("privileged_groups", after, escalated))
    assert changes == {"privileged_members_added": ["sudo:mallory"]}


def test_listener_and_package_diffs() -> None:
    before = load_json("inventory/inventory_baseline.json")
    after = copy.deepcopy(before)
    after["listeners"] = [lf for lf in after["listeners"] if lf["local_port"] != 80]
    (closed,) = inv.listener_events(_diff("listeners", before, after), _dctx())
    assert closed.event_type == "network.listener.closed" and closed.network.dst_port == 80
    assert closed.attributes["unit"] == "nginx.service"
    pkgs = load_json("dispatch/packages.json")
    changed = copy.deepcopy(pkgs)
    changed["packages"][0]["version"] = "999-test"  # SYNTHETIC upgrade of a real package
    changed["packages"].pop(1)
    events = inv.package_events(_diff("packages", pkgs, changed), _dctx())
    assert sorted(e.event_type for e in events) == ["package.removed", "package.upgraded"]
    upgraded = next(e for e in events if e.event_type == "package.upgraded")
    assert upgraded.attributes["previous_version"] == pkgs["packages"][0]["version"]


def test_inventory_items_are_flat_and_valid() -> None:
    doc = load_json("inventory/inventory_baseline.json")
    for category, (extract, source, _type) in inv.CATEGORIES.items():
        if source != "inventory":
            continue
        current = extract(doc)
        diff = SnapshotDiff(current, {}, {}, {})
        items = inv.inventory_records(
            category,
            diff,
            current,
            asset_id=ASSET,
            collector_id="linux-ssh-lab-vm-01",
            snapshot_id="s1",
            observed_at=NOW,
            full=True,
        )
        assert len(items) == len(current) > 0
        for item in items:
            assert all(not isinstance(v, dict) for v in item.attributes.values())


def test_posture_on_real_document() -> None:
    doc = load_json("dispatch/posture.json")
    result = posture.evaluate(
        doc,
        asset_id=ASSET,
        producer_id="linux-ssh-lab-vm-01",
        started_at=NOW,
        finished_at=NOW,
        service_ids={"ssh.service": "1" * 32},
    )
    failed = {f.check_id for f in result.findings}
    assert failed == {
        "linux.updates.pending_security",
        "linux.firewall.ufw_enabled",
        "linux.sysctl.accept_redirects",
        "linux.sysctl.ipv6_accept_redirects",
        "linux.sysctl.send_redirects",
        "linux.sysctl.suid_dumpable",
    }
    assert result.scan_run.status.value == "succeeded"
    assert result.scan_run.coverage.checks_total == len(posture.CHECKS)
    updates = next(f for f in result.findings if f.check_id == "linux.updates.pending_security")
    assert updates.attributes["pending_count"] == 33
    # Stable identity across scans; scope identical so lifecycle comparisons are valid.
    again = posture.evaluate(
        doc,
        asset_id=ASSET,
        producer_id="linux-ssh-lab-vm-01",
        started_at=NOW,
        finished_at=NOW,
        service_ids={},
    )
    assert {f.finding_id for f in again.findings} == {f.finding_id for f in result.findings}
    assert again.scan_run.scope.scope_hash == result.scan_run.scope.scope_hash


def test_posture_service_attribution_and_setting_change() -> None:
    doc = load_json("dispatch/posture.json")
    weak = copy.deepcopy(doc)  # SYNTHETIC weakening of the real sshd configuration
    weak["checks"]["sshd"]["settings"]["passwordauthentication"]["value"] = "yes"
    result = posture.evaluate(
        weak,
        asset_id=ASSET,
        producer_id="linux-ssh-lab-vm-01",
        started_at=NOW,
        finished_at=NOW,
        service_ids={"ssh.service": "1" * 32},
    )
    pw = next(f for f in result.findings if f.check_id == "linux.ssh.password_authentication")
    assert pw.service_id == "1" * 32 and pw.severity.value == "high"
    base = posture.evaluate(
        doc,
        asset_id=ASSET,
        producer_id="linux-ssh-lab-vm-01",
        started_at=NOW,
        finished_at=NOW,
        service_ids={},
    )
    old = {k: {"value": v} for k, v in base.settings.items()}
    new = {k: {"value": v} for k, v in result.settings.items()}
    diff = SnapshotDiff(
        {},
        {k: v for k, v in new.items() if old.get(k) != v},
        {},
        {k: old[k] for k in new if k in old and old[k] != new[k]},
    )
    (event,) = posture.setting_events(diff, pctx(), NOW, {"ssh.service": "1" * 32})
    assert event.event_type == "config.security_setting.changed"
    assert event.attributes["previous_value"] == "no" and event.attributes["current_value"] == "yes"
    assert event.attributes["subject_service_id"] == "1" * 32


def test_posture_missing_inputs_are_skipped_not_passed() -> None:
    doc = load_json("dispatch/posture.json")
    broken = copy.deepcopy(doc)
    broken["checks"]["security_updates"] = {"available": False, "error": "apt lock held"}
    del broken["checks"]["ufw"]
    result = posture.evaluate(
        broken,
        asset_id=ASSET,
        producer_id="linux-ssh-lab-vm-01",
        started_at=NOW,
        finished_at=NOW,
        service_ids={},
    )
    assert result.scan_run.status.value == "partial"
    skipped = {s.check for s in result.scan_run.coverage.skipped}
    assert {"linux.updates.pending_security", "linux.firewall.ufw_enabled"} <= skipped

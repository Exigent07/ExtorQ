"""Regenerate the rule fixtures under rules/<domain>/tests/<RULE-ID>/.

Usage: ``uv run python tests/rules/generate_fixtures.py [--only vm001 --only k8s003 ...]``

One builder per rule. Fixtures mirror the detection-test matrix (docs/team/PLAN.md section
12): every rule has the matrix positive, the matrix negative control and the edge cases its
false-positive handling depends on. Provenance labels (``derived-captured`` / ``synthetic``)
and naming conventions are described in fixture_builder.py. Output is deterministic (fixed
timestamps, deterministic event ids), so committed files can be reviewed as diffs.
"""

from __future__ import annotations

import copy
import hashlib
import sys
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixture_builder import (
    ANY_IPV4,
    BASE,
    DERIVED_LABELS,
    K8S,
    LINUX,
    SYNTHETIC_LABELS,
    FixtureWriter,
    M,
    S,
    account_created,
    app_login,
    audit_watch,
    captured_events,
    commit_observed,
    cron_changed,
    http_probe,
    k8s_audit_events,
    k8s_state,
    labelled,
    launchd_event,
    linux_audit_events,
    linux_inventory_events,
    linux_journal_events,
    load_linux_inventory,
    macos_listener,
    nginx_request,
    reshape_audit,
    secret_exposed,
    software_installed,
    ssh_failed_connection,
    ssh_key_rejected_connection,
    ssh_success,
    unified_log_events,
    unified_log_record,
    unit_enabled,
    unit_event,
    workflow_event,
)

ROOT = Path(__file__).resolve().parents[2] / "rules"
QEMU_GATEWAY = "10.0.2.2"  # every connection from the Mac reaches the VM from here
KIND_POD_GATEWAY = "10.244.0.1"  # NodePort traffic reaches the cluster's pods from here

Builder = Callable[[], dict[str, FixtureWriter]]
BUILDERS: list[Builder] = []


def builder(func: Builder) -> Builder:
    BUILDERS.append(func)
    return func


def _fixture(name: str, *events_lists: list[Any]) -> FixtureWriter:
    fx = FixtureWriter(name)
    for events in events_lists:
        fx.extend(events)
    return fx


# ═══ Linux ═══════════════════════════════════════════════════════════


def vm001_matrix_burst(fx: FixtureWriter, start: datetime) -> None:
    """Matrix VM-001: eight connections with commonly guessed users and a throwaway key."""
    users = ["root", "admin", "oracle", "test", "ubuntu", "root", "admin", "test"]
    for i, user in enumerate(users):
        ssh_key_rejected_connection(
            fx,
            start + i * 0.35 * S,
            QEMU_GATEWAY,
            60211 + i,
            user,
            exists=user == "root",
            pid=5100 + i,
        )


@builder
def vm001() -> dict[str, FixtureWriter]:
    d = "linux/tests/VM-001"
    out: dict[str, FixtureWriter] = {}

    fx = FixtureWriter("vm001-matrix")
    vm001_matrix_burst(fx, BASE)
    out[f"{d}/positive_matrix_key_rejected_nat.jsonl"] = fx

    fx = FixtureWriter("vm001-burst-external")
    for i, user in enumerate(["admin", "admin", "oracle", "test", "ubuntu", "postgres"]):
        ssh_failed_connection(fx, BASE + i * 10 * S, "203.0.113.45", 50100 + i, user, pid=4000 + i)
    out[f"{d}/positive_burst_external.jsonl"] = fx

    fx = FixtureWriter("vm001-bucket-boundary")
    start = BASE + 4 * M + 40 * S  # 10:04:40 .. 10:05:20 straddles the 10:05 bucket boundary
    for i in range(6):
        ssh_failed_connection(
            fx, start + i * 8 * S, "198.51.100.7", 41000 + i, "deploy", pid=4200 + i
        )
    out[f"{d}/positive_bucket_boundary.jsonl"] = fx

    fx = FixtureWriter("vm001-two-connections")
    ssh_failed_connection(
        fx, BASE, "192.0.2.10", 43001, "root", invalid=False, attempts=6, pid=4400
    )
    ssh_failed_connection(
        fx, BASE + 20 * S, "192.0.2.10", 43002, "root", invalid=False, attempts=6, pid=4401
    )
    out[f"{d}/positive_failures_two_connections.jsonl"] = fx

    fx = FixtureWriter("vm001-matrix-control")
    for i in range(3):
        ssh_success(fx, BASE + i * 20 * S, QEMU_GATEWAY, 59923 + i, "extorq-admin", pid=4800 + i)
    out[f"{d}/negative_matrix_successful_logins.jsonl"] = fx

    fx = FixtureWriter("vm001-below")
    for i in range(4):
        ssh_failed_connection(
            fx, BASE + i * 30 * S, "203.0.113.46", 50200 + i, "admin", pid=4500 + i
        )
    out[f"{d}/negative_below_threshold.jsonl"] = fx

    fx = FixtureWriter("vm001-slow")
    for i in range(6):
        ssh_failed_connection(
            fx, BASE + i * 4 * M, "203.0.113.47", 50300 + i, "admin", pid=4600 + i
        )
    out[f"{d}/negative_slow.jsonl"] = fx

    fx = FixtureWriter("vm001-distributed")
    for i in range(6):
        ssh_failed_connection(
            fx, BASE + i * 5 * S, f"198.51.100.{20 + i}", 50400 + i, "admin", pid=4700 + i
        )
    out[f"{d}/negative_distributed.jsonl"] = fx

    # Captured: the sshd lines of a real burst on the VM (9 connections through the QEMU
    # gateway), the admin's logins and a later throwaway-key attempt, parsed by the Linux
    # collector's journal parser.
    out[f"{d}/positive_captured_vm_burst.jsonl"] = _fixture(
        "vm001-captured",
        labelled(
            linux_journal_events("sshd.ndjson", lambda e: e.event_type.startswith("auth.ssh.")),
            DERIVED_LABELS,
        ),
    )
    return out


@builder
def vm002() -> dict[str, FixtureWriter]:
    d = "linux/tests/VM-002"
    out: dict[str, FixtureWriter] = {}
    baseline = load_linux_inventory("inventory_baseline.json")
    created = load_linux_inventory("inventory_vm002_created.json")
    removed = load_linux_inventory("inventory_vm002_removed.json")

    # Captured matrix positive: unit written by the admin's sudo shell, reload, enable.
    out[f"{d}/positive_matrix_unit_created_enabled.jsonl"] = _fixture(
        "vm002-matrix",
        labelled(linux_inventory_events("units", baseline, created), DERIVED_LABELS),
        labelled(linux_inventory_events("enablement", baseline, created), DERIVED_LABELS),
        labelled(linux_audit_events("vm002_create.log"), DERIVED_LABELS),
    )

    fx = FixtureWriter("vm002-b")
    tunnel = "/etc/systemd/system/ssh-tunnel.service"
    # None of these auditd hits create or modify the unit: they corroborate nothing.
    audit_watch(
        fx, BASE - 30 * S, tunnel, "extorq_systemd", 813, syscall="unlinkat", exe="/usr/bin/rm"
    )
    audit_watch(fx, BASE - 25 * S, tunnel, "extorq_systemd", 814, success=False, nametype="NORMAL")
    audit_watch(
        fx, BASE - 20 * S, None, "extorq_systemd", 815, syscall="fsetxattr", exe="/usr/bin/install"
    )
    audit_watch(fx, BASE - 15 * S, tunnel, "extorq_systemd", 816, syscall="276", exe="/usr/bin/mv")
    unit_event(fx, "persistence.systemd.unit_modified", BASE, tunnel, "b" * 64, prev="c" * 64)
    out[f"{d}/positive_modified_inventory_only.jsonl"] = fx

    fx = FixtureWriter("vm002-rename")
    beacon = "/etc/systemd/system/beacon.service"
    audit_watch(
        fx,
        BASE,
        "/tmp/beacon.service",
        "extorq_systemd",
        817,
        syscall="renameat",
        exe="/usr/bin/mv",
        nametype="DELETE",
        paths=[
            "PARENT:/tmp/",
            "PARENT:/etc/systemd/system/",
            "DELETE:/tmp/beacon.service",
            f"CREATE:{beacon}",
        ],
    )
    unit_event(fx, "persistence.systemd.unit_created", BASE + 40 * S, beacon, "9" * 64)
    out[f"{d}/positive_renamed_into_place.jsonl"] = fx

    fx = FixtureWriter("vm002-enabled")
    unit_enabled(fx, BASE, "rsync.service")
    out[f"{d}/positive_enabled_only.jsonl"] = fx

    # Matrix negative control: restart of an existing unit (state changes only).
    fx = FixtureWriter("vm002-restart")
    for offset, state in ((0, "stopping"), (1, "stopped"), (2, "starting"), (3, "started")):
        fx.add(
            "system.service.state_changed",
            BASE + offset * S,
            asset=LINUX,
            source_type="linux.journald",
            action=f"unit_{state}",
            outcome="success",
            resource={"type": "systemd_unit", "name": "nginx.service"},
            message=f"nginx.service {state}",
            attributes={"state": state},
        )
    fx.add(
        "system.systemd.daemon_reload",
        BASE + 5 * S,
        asset=LINUX,
        source_type="linux.journald",
        action="daemon_reload",
        outcome="success",
        process={"pid": 1, "name": "systemd"},
        message="Reloading requested from client PID 7311 ('systemctl')",
    )
    out[f"{d}/negative_matrix_restart_existing_unit.jsonl"] = fx

    fx = FixtureWriter("vm002-unrelated")
    unit_event(
        fx,
        "persistence.systemd.unit_created",
        BASE,
        "/etc/systemd/system/nginx.service",
        "d" * 64,
        baseline=True,
    )
    audit_watch(fx, BASE + S, "/etc/ssh/sshd_config", "extorq_sshd", 812)
    cron_changed(fx, BASE + 3 * S, "/etc/crontab", "modified", "e" * 64, prev="f" * 64)
    # Captured cleanup of the matrix unit: inventory deletion + auditd unlinkat.
    fx.extend(labelled(linux_inventory_events("units", created, removed), DERIVED_LABELS))
    fx.extend(labelled(linux_audit_events("vm002_cleanup.log"), DERIVED_LABELS))
    out[f"{d}/negative_baseline_cleanup_unrelated.jsonl"] = fx
    return out


@builder
def vm003() -> dict[str, FixtureWriter]:
    d = "linux/tests/VM-003"
    out: dict[str, FixtureWriter] = {}
    before = load_linux_inventory("inventory_vm002_created.json")
    after = load_linux_inventory("inventory_user_added.json")
    removed = load_linux_inventory("inventory_vm002_removed.json")

    # Captured matrix positive: sudo useradd of a test account (inventory + auditd).
    out[f"{d}/positive_matrix_useradd_captured.jsonl"] = _fixture(
        "vm003-matrix",
        labelled(linux_inventory_events("users", before, after), DERIVED_LABELS),
        labelled(linux_audit_events("useradd.log"), DERIVED_LABELS),
    )

    fx = FixtureWriter("vm003-uid0")
    account_created(
        fx, BASE, "extorq-test-toor", 0, login_shell="/bin/bash", groups=["root", "sudo"]
    )
    out[f"{d}/positive_uid0_inventory_only.jsonl"] = fx

    fx = FixtureWriter("vm003-earlier-write")
    audit_watch(
        fx,
        BASE - 60 * M,
        "/etc/passwd",
        "extorq_identity",
        930,
        exe="/usr/sbin/usermod",
        nametype="NORMAL",
    )
    account_created(
        fx, BASE, "extorq-test-svc", 1002, login_shell="/bin/bash", groups=["extorq-test-svc"]
    )
    out[f"{d}/positive_unrelated_earlier_write.jsonl"] = fx

    # Matrix negative control: a temporary file in /tmp touches nothing that is collected;
    # the only telemetry of the test is the admin's SSH login.
    fx = FixtureWriter("vm003-matrix-control")
    ssh_success(fx, BASE, QEMU_GATEWAY, 59990, "extorq-admin")
    out[f"{d}/negative_matrix_temp_file.jsonl"] = fx

    fx = FixtureWriter("vm003-deleted")
    fx.extend(labelled(linux_inventory_events("users", after, removed), DERIVED_LABELS))
    fx.extend(labelled(linux_audit_events("userdel.log"), DERIVED_LABELS))
    fx.add(
        "account.user.created",
        BASE,
        asset=LINUX,
        action="account.created",
        outcome="success",
        actor={"type": "user", "name": "nginx", "id": "998"},
        message="local account created: nginx (baseline snapshot)",
        attributes={
            "uid": 998,
            "shell": "/usr/sbin/nologin",
            "groups": ["nginx"],
            "baseline": True,
        },
    )
    out[f"{d}/negative_deleted_and_baseline.jsonl"] = fx
    return out


def _with_cron_entry(doc: dict[str, Any], path: str, content: str, at: datetime) -> dict[str, Any]:
    """The captured inventory document with one cron file added or replaced (SYNTHETIC edit)."""
    edited = copy.deepcopy(doc)
    entries = [c for c in edited.get("cron") or [] if c.get("path") != path]
    entries.append(
        {
            "path": path,
            "exists": True,
            "mode": "0644",
            "uid": 0,
            "gid": 0,
            "size": len(content),
            "mtime": int(at.timestamp()),
            "kind": "file",
            "readable": True,
            "sha256": hashlib.sha256(content.encode()).hexdigest(),
        }
    )
    edited["cron"] = sorted(entries, key=lambda c: c["path"])
    edited["collected_at"] = at.isoformat().replace("+00:00", "Z")
    return edited


def _without_cron_entry(doc: dict[str, Any], path: str, at: datetime) -> dict[str, Any]:
    edited = copy.deepcopy(doc)
    edited["cron"] = [c for c in edited.get("cron") or [] if c.get("path") != path]
    edited["collected_at"] = at.isoformat().replace("+00:00", "Z")
    return edited


@builder
def vm004() -> dict[str, FixtureWriter]:
    d = "linux/tests/VM-004"
    out: dict[str, FixtureWriter] = {}
    baseline = load_linux_inventory("inventory_baseline.json")
    job = "/etc/cron.d/extorq-test-job"
    job_text = "# extorq detection test\n* * * * * root true\n"

    # Matrix positive: sudo tee writes the cron file; the next snapshot sees it.
    fx = FixtureWriter("vm004-matrix")
    audit_watch(fx, BASE, job, "extorq_cron", 940, exe="/usr/bin/tee")
    after = _with_cron_entry(baseline, job, job_text, BASE + 20 * S)
    fx.extend(labelled(linux_inventory_events("cron", baseline, after), SYNTHETIC_LABELS))
    out[f"{d}/positive_matrix_cron_d_tee.jsonl"] = fx

    fx = FixtureWriter("vm004-crontab")
    edited = _with_cron_entry(
        baseline,
        "/etc/crontab",
        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n"
        "*/5 * * * * root /usr/local/bin/extorq-test-beacon\n",
        BASE,
    )
    fx.extend(labelled(linux_inventory_events("cron", baseline, edited), SYNTHETIC_LABELS))
    out[f"{d}/positive_crontab_modified.jsonl"] = fx

    fx = FixtureWriter("vm004-package")
    sysstat = "/etc/cron.d/extorq-test-sysstat"
    audit_watch(fx, BASE, sysstat, "extorq_cron", 941, exe="/usr/bin/dpkg")
    after = _with_cron_entry(
        baseline, sysstat, "5-55/10 * * * * root command -v debian-sa1\n", BASE + 30 * S
    )
    fx.extend(labelled(linux_inventory_events("cron", baseline, after), SYNTHETIC_LABELS))
    out[f"{d}/positive_package_cron_file.jsonl"] = fx

    # Matrix negative control: crontab -l and a read-only listing: no write, no diff.
    fx = FixtureWriter("vm004-matrix-control")
    ssh_success(fx, BASE, QEMU_GATEWAY, 59991, "extorq-admin")
    fx.add(
        "process.audit.exec",
        BASE + 5 * S,
        asset=LINUX,
        source_type="linux.auditd",
        action="audit.execve",
        outcome="success",
        actor={"type": "user", "name": "extorq-admin", "id": "1000"},
        process={"executable": "/usr/bin/ls", "name": "ls", "command_line": "ls -l /etc/cron.d"},
        message="auditd extorq_root_exec: ls -l /etc/cron.d",
        attributes={"audit_key": "extorq_root_exec", "syscall": "execve", "success": True},
    )
    out[f"{d}/negative_matrix_crontab_listing.jsonl"] = fx

    fx = FixtureWriter("vm004-removal")
    with_job = _with_cron_entry(baseline, job, job_text, BASE - 10 * M)
    audit_watch(fx, BASE, job, "extorq_cron", 942, syscall="unlinkat", exe="/usr/bin/rm")
    without = _without_cron_entry(with_job, job, BASE + 20 * S)
    fx.extend(labelled(linux_inventory_events("cron", with_job, without), SYNTHETIC_LABELS))
    cron_changed(fx, BASE - 5 * M, "/etc/cron.d/e2scrub_all", "added", "a" * 64, baseline=True)
    out[f"{d}/negative_removal_and_baseline.jsonl"] = fx
    return out


@builder
def http001() -> dict[str, FixtureWriter]:
    d = "http/tests/HTTP-001"
    out: dict[str, FixtureWriter] = {}

    fx = FixtureWriter("http001-matrix")
    matrix_probe(fx, BASE)
    out[f"{d}/positive_matrix_probe_nat.jsonl"] = fx

    fx = FixtureWriter("http001-external")
    http_probe(fx, BASE, "203.0.113.70")
    out[f"{d}/positive_external_probe.jsonl"] = fx

    fx = FixtureWriter("http001-matrix-control")
    normal = ("/", "/login", "/static/app.css", "/static/app.js", "/healthz")
    for i in range(20):
        nginx_request(
            fx,
            BASE + i * 3 * S,
            QEMU_GATEWAY,
            normal[i % len(normal)],
            200,
            user_agent="curl/8.7.1",
        )
    out[f"{d}/negative_matrix_normal_requests.jsonl"] = fx

    fx = FixtureWriter("http001-ordinary")
    ordinary = (
        "/favicon.ico",
        "/static/app.css",
        "/images/logo.png",
        "/about",
        "/blog/2026",
        "/robots.txt",
        "/apple-touch-icon.png",
        "/docs/start",
        "/news",
        "/team",
        "/static/app.js",
        "/contact",
    )
    http_probe(fx, BASE, "203.0.113.71", routes=ordinary)
    out[f"{d}/negative_ordinary_404.jsonl"] = fx

    fx = FixtureWriter("http001-slow")
    http_probe(fx, BASE, "203.0.113.72", spacing_s=150.0)
    out[f"{d}/negative_slow_probe.jsonl"] = fx
    return out


MATRIX_PROBE_ROUTES = (
    ("/.env", 404),
    ("/.git/config", 404),
    ("/wp-login.php", 404),
    ("/phpmyadmin/", 404),
    ("/server-status", 403),
    ("/admin", 404),
    ("/actuator/health", 404),
    ("/cgi-bin/test.cgi", 404),
    ("/backup.zip", 404),
    ("/.aws/credentials", 404),
    ("/xmlrpc.php", 404),
    ("/config.json", 404),
)


def matrix_probe(fx: FixtureWriter, start: datetime) -> None:
    """Matrix HTTP-001: twelve probe-like paths from the Mac through the QEMU gateway."""
    for i, (route, status) in enumerate(MATRIX_PROBE_ROUTES):
        nginx_request(fx, start + i * 0.5 * S, QEMU_GATEWAY, route, status, user_agent="curl/8.7.1")


@builder
def app001() -> dict[str, FixtureWriter]:
    d = "app/tests/APP-001"
    out: dict[str, FixtureWriter] = {}

    fx = FixtureWriter("app001-matrix-vm")
    for i in range(6):
        app_login(fx, BASE + i * S, "lab-admin", QEMU_GATEWAY)
    out[f"{d}/positive_matrix_vm_guessing.jsonl"] = fx

    fx = FixtureWriter("app001-matrix-cluster")
    for i in range(6):
        app_login(fx, BASE + i * S, "lab-admin", KIND_POD_GATEWAY, k8s=True)
    out[f"{d}/positive_matrix_cluster_guessing.jsonl"] = fx

    fx = FixtureWriter("app001-spraying")
    for i, user in enumerate(["admin", "root", "test", "guest", "lab-admin", "operator"]):
        app_login(
            fx,
            BASE + i * 3 * S,
            user,
            "203.0.113.80",
            k8s=True,
            reason="unknown_user" if user != "lab-admin" else "invalid_password",
        )
    out[f"{d}/positive_spraying_k8s.jsonl"] = fx

    fx = FixtureWriter("app001-matrix-control")
    app_login(fx, BASE, "lab-admin", QEMU_GATEWAY)
    app_login(fx, BASE + 5 * S, "lab-admin", "127.0.0.1", success=True)  # inside the VM
    app_login(fx, BASE + 30 * S, "lab-admin", KIND_POD_GATEWAY, k8s=True, success=True)
    out[f"{d}/negative_matrix_failure_then_success.jsonl"] = fx

    fx = FixtureWriter("app001-negative")
    for i in range(4):
        app_login(fx, BASE + i * 5 * S, "lab-admin", "203.0.113.81")
    for i in range(6):
        app_login(fx, BASE + 10 * M + i * 6 * M, "alice", "203.0.113.82")
    out[f"{d}/negative_below_and_slow.jsonl"] = fx
    return out


def _corr002_sequence(
    fx: FixtureWriter,
    *,
    probe_ip: str,
    ssh_ip: str,
    unit: str,
    ssh_at: timedelta = 5 * M,
    persist_at: timedelta = 12 * M,
    user: str = "admin",
    probe_routes: tuple[str, ...] | None = None,
    baseline: bool = False,
) -> None:
    kwargs = {"routes": probe_routes} if probe_routes is not None else {}
    http_probe(fx, BASE, probe_ip, **kwargs)
    for i in range(4):
        ssh_failed_connection(fx, BASE + ssh_at + i * 9 * S, ssh_ip, 51000 + i, user, pid=5000 + i)
    path = f"/etc/systemd/system/{unit}"
    if not baseline:
        audit_watch(fx, BASE + persist_at, path, "extorq_systemd", 900)
    unit_event(
        fx,
        "persistence.systemd.unit_created",
        BASE + persist_at + 40 * S,
        path,
        "f" * 64,
        baseline=baseline,
    )


@builder
def corr002() -> dict[str, FixtureWriter]:
    d = "correlation/tests/CORR-002"
    out: dict[str, FixtureWriter] = {}

    # Matrix positive: the HTTP-001, VM-001 and VM-002 tests in order from the Mac.
    fx = FixtureWriter("corr002-matrix")
    matrix_probe(fx, BASE)
    vm001_matrix_burst(fx, BASE + 5 * M)
    unit = "/etc/systemd/system/extorq-test-persist.service"
    audit_watch(fx, BASE + 12 * M, unit, "extorq_systemd", 950, exe="/usr/bin/tee")
    unit_event(fx, "persistence.systemd.unit_created", BASE + 12 * M + 30 * S, unit, "7" * 64)
    unit_enabled(fx, BASE + 12 * M + 30 * S, "extorq-test-persist.service")
    out[f"{d}/positive_matrix_sequence_nat.jsonl"] = fx

    fx = FixtureWriter("corr002-matrix-control")
    vm001_matrix_burst(fx, BASE)
    out[f"{d}/negative_matrix_ssh_failures_alone.jsonl"] = fx

    fx = FixtureWriter("corr002-same-source")
    _corr002_sequence(fx, probe_ip="203.0.113.60", ssh_ip="203.0.113.60", unit="backdoor.service")
    out[f"{d}/positive_same_external_source.jsonl"] = fx

    fx = FixtureWriter("corr002-different-sources")
    _corr002_sequence(fx, probe_ip="198.51.100.20", ssh_ip="203.0.113.61", unit="updater.service")
    out[f"{d}/positive_different_sources.jsonl"] = fx

    fx = FixtureWriter("corr002-wrong-order")
    _corr002_sequence(
        fx,
        probe_ip="203.0.113.62",
        ssh_ip="203.0.113.62",
        unit="early.service",
        ssh_at=10 * M,
        persist_at=3 * M,
    )
    out[f"{d}/negative_wrong_order.jsonl"] = fx

    fx = FixtureWriter("corr002-too-slow")
    _corr002_sequence(
        fx,
        probe_ip="203.0.113.63",
        ssh_ip="203.0.113.63",
        unit="late.service",
        ssh_at=10 * M,
        persist_at=40 * M,
    )
    out[f"{d}/negative_too_slow.jsonl"] = fx

    fx = FixtureWriter("corr002-baseline")
    _corr002_sequence(
        fx, probe_ip="203.0.113.64", ssh_ip="203.0.113.64", unit="nginx.service", baseline=True
    )
    out[f"{d}/negative_missing_stage_baseline.jsonl"] = fx

    fx = FixtureWriter("corr002-below-probe")
    _corr002_sequence(
        fx,
        probe_ip="203.0.113.65",
        ssh_ip="203.0.113.65",
        unit="quiet.service",
        probe_routes=("/.env", "/.git/config", "/wp-login.php", "/admin.php"),
    )
    nginx_request(fx, BASE + 30 * S, "203.0.113.65", "/", 200)
    nginx_request(fx, BASE + 31 * S, "203.0.113.65", "/favicon.ico", 404)
    out[f"{d}/negative_below_probe_threshold.jsonl"] = fx

    fx = FixtureWriter("corr002-deletion")
    http_probe(fx, BASE, "203.0.113.66")
    for i in range(4):
        ssh_failed_connection(fx, BASE + 5 * M + i * 9 * S, "203.0.113.66", 51100 + i, "admin")
    audit_watch(
        fx,
        BASE + 12 * M,
        "/etc/systemd/system/old-agent.service",
        "extorq_systemd",
        901,
        syscall="unlinkat",
        exe="/usr/bin/rm",
    )
    out[f"{d}/negative_deletion_only.jsonl"] = fx

    # auditd hits that neither create nor modify a unit file: none of them is stage 3.
    fx = FixtureWriter("corr002-noncounting")
    http_probe(fx, BASE, "203.0.113.68")
    for i in range(4):
        ssh_failed_connection(fx, BASE + 5 * M + i * 9 * S, "203.0.113.68", 51200 + i, "admin")
    evil = "/etc/systemd/system/evil.service"
    audit_watch(fx, BASE + 10 * M, evil, "extorq_systemd", 910, success=False, nametype="NORMAL")
    audit_watch(
        fx, BASE + 11 * M, None, "extorq_systemd", 911, syscall="fsetxattr", exe="/usr/bin/install"
    )
    audit_watch(fx, BASE + 12 * M, "/etc/systemd/system/.evil.service.swp", "extorq_systemd", 912)
    audit_watch(fx, BASE + 13 * M, evil, "extorq_systemd", 913, syscall="56")
    audit_watch(
        fx,
        BASE + 14 * M,
        "/etc/systemd/system/old.service",
        "extorq_systemd",
        914,
        syscall="renameat",
        exe="/usr/bin/mv",
        nametype="DELETE",
        paths=[
            "PARENT:/etc/systemd/system/",
            "PARENT:/tmp/",
            "DELETE:/etc/systemd/system/old.service",
            "CREATE:/tmp/old.service",
        ],
    )
    out[f"{d}/negative_noncounting_audit_hits.jsonl"] = fx

    # Persistence seen by auditd only, plus a removal of another unit (context only).
    fx = FixtureWriter("corr002-removal-context")
    http_probe(fx, BASE, "203.0.113.69")
    for i in range(4):
        ssh_failed_connection(fx, BASE + 5 * M + i * 9 * S, "203.0.113.69", 51300 + i, "admin")
    audit_watch(fx, BASE + 12 * M, "/etc/systemd/system/beacon.service", "extorq_systemd", 920)
    audit_watch(
        fx,
        BASE + 13 * M,
        "/etc/systemd/system/old-agent.service",
        "extorq_systemd",
        921,
        syscall="unlinkat",
        exe="/usr/bin/rm",
    )
    out[f"{d}/positive_audit_create_removal_context.jsonl"] = fx
    return out


# ═══ Kubernetes ══════════════════════════════════════════════════════

RBAC_GROUP = "rbac.authorization.k8s.io"
ADMIN = ("kubernetes-admin", ["kubeadm:cluster-admins", "system:authenticated"])


def _derived(name: str, *files: str) -> FixtureWriter:
    fx = FixtureWriter(name)
    for file in files:
        fx.extend(k8s_audit_events(file))
    return fx


def _as_user(record: dict[str, Any], user: str, groups: list[str]) -> None:
    record["user"] = {"username": user, "groups": groups}
    record.pop("impersonatedUser", None)
    record.pop("authenticationMetadata", None)


def _response(record: dict[str, Any], code: int) -> None:
    if code < 300:
        record["responseStatus"] = {"metadata": {}, "code": code}
    else:
        record["responseStatus"] = {
            "metadata": {},
            "status": "Failure",
            "message": "forbidden (fixture)",
            "reason": "Forbidden",
            "code": code,
        }


@builder
def k8s001() -> dict[str, FixtureWriter]:
    d = "kubernetes/tests/K8S-001"

    def compliant_in_restricted(record: dict[str, Any]) -> None:
        reshape_audit(
            audit_id_key="k8s001-compliant",
            namespace="extorq-restricted",
            name="extorq-test-compliant",
        )(record)
        record["requestURI"] = "/api/v1/namespaces/extorq-restricted/pods?fieldManager=kubectl-run"
        record["requestObject"]["metadata"]["name"] = "extorq-test-compliant"
        record["annotations"]["pod-security.kubernetes.io/enforce-policy"] = "restricted:latest"

    compliant = FixtureWriter("k8s001-matrix-control")
    compliant.extend(k8s_audit_events("pod_create_allowed.json", mutate=compliant_in_restricted))
    return {
        f"{d}/positive_matrix_psa_privileged_pod.jsonl": _derived(
            "k8s001-a", "psa_denied_privileged_pod.json"
        ),
        f"{d}/positive_psa_dry_run.jsonl": _derived("k8s001-b", "psa_denied_dry_run.json"),
        f"{d}/positive_psa_ephemeral_container.jsonl": _derived(
            "k8s001-c", "psa_denied_ephemeral_container.json"
        ),
        f"{d}/negative_matrix_compliant_pod_admitted.jsonl": compliant,
        f"{d}/negative_admission_denied_not_psa.jsonl": _derived(
            "k8s001-e", "bootstrap_mirror_pod_admission_denied.json"
        ),
        f"{d}/negative_unrelated_audit.jsonl": _derived(
            "k8s001-f",
            "forbidden_impersonated_secret_list.json",
            "unauthenticated_401.json",
            "serviceaccount_create.json",
            "pod_patch_json.json",
            "anonymous_forbidden_secret_list.json",
        ),
    }


def _subject(kind: str, name: str, namespace: str | None = None) -> dict[str, str]:
    subject = {"kind": kind, "name": name}
    if kind != "ServiceAccount":
        subject["apiGroup"] = RBAC_GROUP
    if namespace:
        subject["namespace"] = namespace
    return subject


def _rbac_create_variant(
    base: str,
    *,
    at: datetime,
    name: str,
    user: str,
    groups: list[str],
    subjects: list[dict[str, str]],
    role_ref: tuple[str, str],
    namespace: str | None = None,
) -> list:
    """A captured RBAC create reshaped into another object/actor/time (SYNTHETIC)."""

    def mutate(record: dict[str, Any]) -> None:
        key = f"extorq-fixture:{base}:{namespace}:{name}:{user}:{at.isoformat()}"
        record["auditID"] = str(uuid.uuid5(uuid.NAMESPACE_URL, key))
        record["user"] = {"username": user, "groups": groups}
        record["objectRef"]["name"] = name
        kind = record["objectRef"]["resource"]
        if namespace is None:
            record["objectRef"].pop("namespace", None)
            uri = f"/apis/{RBAC_GROUP}/v1/{kind}?fieldManager=kubectl-create"
        else:
            record["objectRef"]["namespace"] = namespace
            uri = f"/apis/{RBAC_GROUP}/v1/namespaces/{namespace}/{kind}?fieldManager=kubectl-create"
        record["requestURI"] = uri
        meta = {"name": name, **({"namespace": namespace} if namespace else {})}
        for body in ("requestObject", "responseObject"):
            record[body]["metadata"] = dict(meta)
            record[body]["subjects"] = subjects
            record[body]["roleRef"] = {
                "apiGroup": RBAC_GROUP,
                "kind": role_ref[0],
                "name": role_ref[1],
            }
        record["requestReceivedTimestamp"] = at.isoformat().replace("+00:00", "Z")
        stage = at + timedelta(milliseconds=2)
        record["stageTimestamp"] = stage.isoformat().replace("+00:00", "Z")

    return k8s_audit_events(base, mutate=mutate)


BIRTH_CAPTURE = "k8s_cluster_birth_live.jsonl"


@builder
def k8s002() -> dict[str, FixtureWriter]:
    d = "kubernetes/tests/K8S-002"
    out: dict[str, FixtureWriter] = {}

    # Matrix positive: CRB of a test service account to cluster-admin (captured create) and
    # the inventory's view of the new object (synthetic state row, same risk flag).
    fx = _derived("k8s002-matrix", "rbac_crb_cluster_admin_create.json")
    created = fx.events[0]
    k8s_state(
        fx,
        created.event_time + 30 * S,
        "clusterrolebindings",
        "b2-fixture-crb",
        None,
        flags=["cluster_admin"],
        summary=created.attributes.get("request_summary"),
    )
    out[f"{d}/positive_matrix_crb_cluster_admin.jsonl"] = fx

    # Matrix negative control: RoleBinding of a test service account to the built-in view
    # role in one namespace (+ the inventory's view of it, no risk flag).
    fx = FixtureWriter("k8s002-matrix-control")
    events = _rbac_create_variant(
        "rbac_rolebinding_anonymous_create.json",
        at=BASE,
        name="extorq-test-view",
        namespace="extorq-apps",
        user=ADMIN[0],
        groups=ADMIN[1],
        subjects=[_subject("ServiceAccount", "extorq-test-sa", "extorq-apps")],
        role_ref=("ClusterRole", "view"),
    )
    fx.extend(events)
    k8s_state(fx, BASE + 30 * S, "rolebindings", "extorq-test-view", "extorq-apps", flags=[])
    out[f"{d}/negative_matrix_rolebinding_view.jsonl"] = fx

    out[f"{d}/positive_crb_patch_subjects.jsonl"] = _derived(
        "k8s002-a", "rbac_crb_patch_subjects.json"
    )
    out[f"{d}/positive_role_wildcard.jsonl"] = _derived(
        "k8s002-b", "rbac_role_wildcard_create.json"
    )
    out[f"{d}/negative_controller_denied_delete.jsonl"] = _derived(
        "k8s002-d",
        "rbac_clusterrole_aggregation_patch.json",
        "bootstrap_rbac_forbidden.json",
        "rbac_crb_delete.json",
    )
    fx = _derived("k8s002-c", "rbac_clusterrole_escalate_create.json")
    escalate = fx.events[0]
    k8s_state(
        fx,
        escalate.event_time + 30 * S,
        "ClusterRole",
        "b2-fixture-escalate",
        None,
        flags=list(escalate.attributes.get("risk_flags") or []),
    )
    out[f"{d}/positive_escalate_audit_and_state.jsonl"] = fx

    fx = FixtureWriter("k8s002-e")
    k8s_state(fx, BASE, "Role", "reader", "extorq-apps", flags=[])
    k8s_state(
        fx,
        BASE + M,
        "ClusterRole",
        "legacy-escalate",
        None,
        flags=["escalation_verbs"],
        baseline=True,
    )
    out[f"{d}/negative_benign_state.jsonl"] = fx
    out.update(_k8s002_bootstrap(d))
    return out


def _k8s002_bootstrap(d: str) -> dict[str, FixtureWriter]:
    """Cluster-birth cases around the genuine records of the cluster's creation."""
    out: dict[str, FixtureWriter] = {}
    live = labelled(captured_events(BIRTH_CAPTURE), DERIVED_LABELS)
    birth = next(e for e in live if e.kubernetes and e.kubernetes.resource == "namespaces")
    t0 = birth.event_time
    super_admin = ("kubernetes-super-admin", ["system:masters", "system:authenticated"])
    crb_base = "rbac_crb_cluster_admin_create.json"
    rb_base = "rbac_rolebinding_anonymous_create.json"
    admins_create = next(
        e for e in live if e.kubernetes and e.kubernetes.object_name == "kubeadm:cluster-admins"
    )

    def kubeadm_state(fx: FixtureWriter) -> None:
        """Inventory (state) view of the documented binding (SYNTHETIC record)."""
        fx.add(
            "k8s.resource.created",
            admins_create.event_time.replace(microsecond=0),
            asset=K8S,
            action="created",
            outcome="success",
            resource={"type": "clusterrolebindings", "name": "kubeadm:cluster-admins"},
            kubernetes={"cluster": "extorq-lab"},
            message="clusterrolebindings kubeadm:cluster-admins observed for the first time",
            attributes={
                "kind": "ClusterRoleBinding",
                "object_summary": admins_create.attributes["request_summary"],
                "risk_flags": ["cluster_admin"],
                "time_source": "creation_timestamp",
            },
        )

    out[f"{d}/negative_kubeadm_bootstrap_live.jsonl"] = _fixture("k8s002-birth-live", live)

    fx = _fixture("k8s002-birth-live-state", live)
    kubeadm_state(fx)
    out[f"{d}/negative_kubeadm_bootstrap_with_state.jsonl"] = fx

    fx = _fixture("k8s002-state-only", [birth])
    kubeadm_state(fx)
    out[f"{d}/positive_kubeadm_state_without_audit_create.jsonl"] = fx

    out[f"{d}/positive_kubeadm_create_no_birth.jsonl"] = _fixture(
        "k8s002-no-birth",
        [e for e in live if e.kubernetes and e.kubernetes.object_name == "kubeadm:cluster-admins"],
    )

    out[f"{d}/negative_annotation_only_patch.jsonl"] = _derived(
        "k8s002-annotate", "rbac_crb_annotate_patch.json"
    )

    def labels_only(record: dict[str, Any]) -> None:
        record["auditID"] = str(uuid.uuid5(uuid.NAMESPACE_URL, "extorq-fixture:label-only-patch"))
        record["requestObject"] = {"metadata": {"labels": {"extorq.io/owner": "platform"}}}
        record["responseObject"]["metadata"]["labels"] = {"extorq.io/owner": "platform"}

    out[f"{d}/positive_label_only_patch.jsonl"] = _fixture(
        "k8s002-labels", k8s_audit_events("rbac_crb_annotate_patch.json", mutate=labels_only)
    )

    # Around the observed birth, each variant misses exactly one exception condition.
    admins = [_subject("Group", "kubeadm:cluster-admins")]
    fx = _fixture("k8s002-exception-not-met", [birth])
    fx.extend(  # documented object and identity, but 15 minutes after the birth
        _rbac_create_variant(
            crb_base,
            at=t0 + 15 * M,
            name="kubeadm:cluster-admins",
            user=super_admin[0],
            groups=super_admin[1],
            subjects=admins,
            role_ref=("ClusterRole", "cluster-admin"),
        )
    )
    fx.extend(  # inside the window, bootstrap identity, look-alike name
        _rbac_create_variant(
            crb_base,
            at=t0 + 5 * S,
            name="kubeadm:cluster-admin",
            user=super_admin[0],
            groups=super_admin[1],
            subjects=admins,
            role_ref=("ClusterRole", "cluster-admin"),
        )
    )
    fx.extend(  # documented object inside the window, created by another identity
        _rbac_create_variant(
            rb_base,
            at=t0 + 3 * S,
            name="kubeadm:bootstrap-signer-clusterinfo",
            namespace="kube-public",
            user="system:serviceaccount:extorq-apps:default",
            groups=[
                "system:serviceaccounts",
                "system:serviceaccounts:extorq-apps",
                "system:authenticated",
            ],
            subjects=[_subject("User", "system:anonymous")],
            role_ref=("Role", "kubeadm:bootstrap-signer-clusterinfo"),
        )
    )
    out[f"{d}/positive_bootstrap_exception_not_met.jsonl"] = fx

    fx = _fixture("k8s002-content-differs", [birth])
    fx.extend(  # documented name, identity and time, but an extra subject
        _rbac_create_variant(
            crb_base,
            at=t0 - 80 * S / 1000,
            name="kubeadm:cluster-admins",
            user=super_admin[0],
            groups=super_admin[1],
            subjects=[*admins, _subject("User", "mallory")],
            role_ref=("ClusterRole", "cluster-admin"),
        )
    )
    out[f"{d}/positive_bootstrap_content_differs.jsonl"] = fx
    return out


def _exec_variant(
    key: str,
    *,
    at: datetime,
    verb: str = "get",
    subresource: str = "exec",
    code: int = 101,
    user: tuple[str, list[str]] | None = None,
    query: str | None = None,
) -> Callable[[dict[str, Any]], None]:
    """The captured kubectl exec record reshaped (time, verb, subresource, result, user)."""

    def mutate(record: dict[str, Any]) -> None:
        reshape_audit(audit_id_key=key, at=at, subresource=subresource)(record)
        record["verb"] = verb
        pod = record["objectRef"]["name"]
        ns = record["objectRef"]["namespace"]
        params = query or f"command=id&container={pod}&stderr=true&stdout=true"
        record["requestURI"] = f"/api/v1/namespaces/{ns}/pods/{pod}/{subresource}?{params}"
        _response(record, code)
        if user is not None:
            _as_user(record, *user)

    return mutate


@builder
def k8s003() -> dict[str, FixtureWriter]:
    d = "kubernetes/tests/K8S-003"
    out: dict[str, FixtureWriter] = {}
    out[f"{d}/positive_matrix_exec_captured.jsonl"] = _derived("k8s003-matrix", "pods_exec.json")

    fx = FixtureWriter("k8s003-repeated")
    fx.extend(k8s_audit_events("pods_exec.json", mutate=_exec_variant("k8s003-r1", at=BASE)))
    fx.extend(
        k8s_audit_events(
            "pods_exec.json",
            mutate=_exec_variant(
                "k8s003-r2",
                at=BASE + 4 * M,
                query="command=sh&container=b2-fixture-ok&stdin=true&stdout=true&tty=true",
            ),
        )
    )
    fx.extend(
        k8s_audit_events(
            "pods_exec.json",
            mutate=_exec_variant(
                "k8s003-r3",
                at=BASE + 9 * M,
                verb="create",
                subresource="attach",
                query="container=b2-fixture-ok&stdin=true&stdout=true&tty=true",
            ),
        )
    )
    out[f"{d}/positive_repeated_sessions.jsonl"] = fx

    fx = FixtureWriter("k8s003-matrix-control")
    fx.extend(
        k8s_audit_events(
            "pods_exec.json",
            mutate=_exec_variant(
                "k8s003-logs",
                at=BASE,
                subresource="log",
                code=200,
                query="container=b2-fixture-ok",
            ),
        )
    )
    out[f"{d}/negative_matrix_kubectl_logs.jsonl"] = fx

    fx = FixtureWriter("k8s003-excluded")
    sa = (
        "system:serviceaccount:extorq-apps:default",
        ["system:serviceaccounts", "system:serviceaccounts:extorq-apps", "system:authenticated"],
    )
    fx.extend(
        k8s_audit_events("pods_exec.json", mutate=_exec_variant("k8s003-sa", at=BASE, user=sa))
    )
    node = ("system:node:extorq-lab-control-plane", ["system:nodes", "system:authenticated"])
    fx.extend(
        k8s_audit_events(
            "pods_exec.json", mutate=_exec_variant("k8s003-node", at=BASE + M, user=node)
        )
    )
    fx.extend(
        k8s_audit_events(
            "pods_exec.json", mutate=_exec_variant("k8s003-denied", at=BASE + 2 * M, code=403)
        )
    )
    out[f"{d}/negative_service_account_and_denied.jsonl"] = fx
    return out


def _secret_list(
    key: str,
    *,
    at: datetime,
    user: tuple[str, list[str]],
    namespace: str | None,
    verb: str = "list",
    code: int = 200,
    resource: str = "secrets",
    name: str | None = None,
) -> Callable[[dict[str, Any]], None]:
    """The captured secret list reshaped: identity, scope, verb, result (SYNTHETIC)."""

    def mutate(record: dict[str, Any]) -> None:
        reshape_audit(audit_id_key=key, at=at, namespace=namespace, resource=resource, name=name)(
            record
        )
        record["verb"] = verb
        base = f"/api/v1/namespaces/{namespace}/{resource}" if namespace else f"/api/v1/{resource}"
        if name:
            record["requestURI"] = f"{base}/{name}"
        else:
            record["requestURI"] = base + ("?watch=true" if verb == "watch" else "?limit=500")
        _response(record, code)
        _as_user(record, *user)

    return mutate


@builder
def k8s004() -> dict[str, FixtureWriter]:
    d = "kubernetes/tests/K8S-004"
    out: dict[str, FixtureWriter] = {}
    base = "forbidden_impersonated_secret_list.json"
    workload_sa = (
        "system:serviceaccount:extorq-apps:default",
        ["system:serviceaccounts", "system:serviceaccounts:extorq-apps", "system:authenticated"],
    )

    out[f"{d}/positive_matrix_cluster_wide_list.jsonl"] = _fixture(
        "k8s004-matrix",
        k8s_audit_events(
            base, mutate=_secret_list("k8s004-a", at=BASE, user=ADMIN, namespace=None)
        ),
    )

    fx = FixtureWriter("k8s004-sweep")
    for i, ns in enumerate(["extorq-apps", "default", "kube-public", "extorq-system"]):
        fx.extend(
            k8s_audit_events(
                base,
                mutate=_secret_list(
                    f"k8s004-s{i}", at=BASE + i * 20 * S, user=workload_sa, namespace=ns
                ),
            )
        )
    out[f"{d}/positive_namespace_sweep_service_account.jsonl"] = fx

    out[f"{d}/negative_matrix_get_one_configmap.jsonl"] = _fixture(
        "k8s004-matrix-control",
        k8s_audit_events(
            base,
            mutate=_secret_list(
                "k8s004-cm",
                at=BASE,
                user=ADMIN,
                namespace="extorq-apps",
                verb="get",
                resource="configmaps",
                name="lab-portal-config",
            ),
        ),
    )

    fx = FixtureWriter("k8s004-excluded")
    controllers = [
        ("system:kube-controller-manager", ["system:authenticated"]),
        ("system:apiserver", ["system:authenticated", "system:masters"]),
        (
            "system:serviceaccount:kube-system:namespace-controller",
            ["system:serviceaccounts", "system:serviceaccounts:kube-system"],
        ),
    ]
    for i, user in enumerate(controllers):
        fx.extend(
            k8s_audit_events(
                base,
                mutate=_secret_list(
                    f"k8s004-x{i}", at=BASE + i * S, user=user, namespace=None, verb="watch"
                ),
            )
        )
    inventory_sa = (
        "system:serviceaccount:extorq-system:extorq-inventory",
        ["system:serviceaccounts", "system:serviceaccounts:extorq-system", "system:authenticated"],
    )
    fx.extend(
        k8s_audit_events(
            base,
            mutate=_secret_list(
                "k8s004-denied", at=BASE + 10 * S, user=inventory_sa, namespace=None, code=403
            ),
        )
    )
    for i, ns in enumerate(["extorq-apps", "extorq-system"]):
        fx.extend(
            k8s_audit_events(
                base,
                mutate=_secret_list(
                    f"k8s004-two{i}", at=BASE + (20 + i) * S, user=ADMIN, namespace=ns
                ),
            )
        )
    out[f"{d}/negative_system_identities_and_denied.jsonl"] = fx
    return out


def _pod_variant(
    key: str,
    *,
    at: datetime,
    namespace: str,
    name: str | None,
    user: tuple[str, list[str]] = ADMIN,
    code: int = 201,
    host_path: bool = False,
    privileged: bool = False,
    host_network: bool = False,
    policy: str = "privileged:latest",
    dry_run: bool = False,
) -> Callable[[dict[str, Any]], None]:
    """The captured admitted pod create reshaped: namespace, name, spec, creator, result."""

    def mutate(record: dict[str, Any]) -> None:
        reshape_audit(audit_id_key=key, at=at, namespace=namespace, name=name)(record)
        spec = record["requestObject"]["spec"]
        meta = record["requestObject"]["metadata"]
        if name is None:
            meta.pop("name", None)
            meta["generateName"] = "extorq-test-ds-"
        else:
            meta["name"] = name
        container = spec["containers"][0]
        if privileged:
            container["securityContext"] = {"privileged": True}
        if host_network:
            spec["hostNetwork"] = True
        if host_path:
            spec["volumes"] = [{"name": "host-root", "hostPath": {"path": "/var/log"}}]
            container["volumeMounts"] = [{"name": "host-root", "mountPath": "/host"}]
        uri = f"/api/v1/namespaces/{namespace}/pods"
        record["requestURI"] = uri + ("?dryRun=All" if dry_run else "?fieldManager=kubectl-run")
        record["annotations"]["pod-security.kubernetes.io/enforce-policy"] = policy
        _response(record, code)
        _as_user(record, *user)

    return mutate


@builder
def k8s005() -> dict[str, FixtureWriter]:
    d = "kubernetes/tests/K8S-005"
    out: dict[str, FixtureWriter] = {}
    base = "pod_create_allowed.json"

    fx = FixtureWriter("k8s005-matrix")
    fx.extend(
        k8s_audit_events(
            base,
            mutate=_pod_variant(
                "k8s005-a",
                at=BASE,
                namespace="extorq-test-psa",
                name="extorq-test-hostpath",
                host_path=True,
            ),
        )
    )
    k8s_state(
        fx, BASE + 20 * S, "pods", "extorq-test-hostpath", "extorq-test-psa", flags=["host_path"]
    )
    out[f"{d}/positive_matrix_hostpath_pod_admitted.jsonl"] = fx

    out[f"{d}/positive_person_in_platform_namespace.jsonl"] = _fixture(
        "k8s005-platform-person",
        k8s_audit_events(
            base,
            mutate=_pod_variant(
                "k8s005-b",
                at=BASE,
                namespace="extorq-system",
                name="extorq-test-capture",
                host_path=True,
            ),
        ),
    )

    out[f"{d}/negative_matrix_unprivileged_pod.jsonl"] = _fixture(
        "k8s005-matrix-control",
        k8s_audit_events(
            base,
            mutate=_pod_variant(
                "k8s005-c", at=BASE, namespace="extorq-test-psa", name="extorq-test-unprivileged"
            ),
        ),
    )

    fx = FixtureWriter("k8s005-platform")
    ds_controller = (
        "system:serviceaccount:kube-system:daemon-set-controller",
        ["system:serviceaccounts", "system:serviceaccounts:kube-system", "system:authenticated"],
    )
    for i, ns in enumerate(["kube-system", "extorq-system"]):
        fx.extend(
            k8s_audit_events(
                base,
                mutate=_pod_variant(
                    f"k8s005-ds{i}",
                    at=BASE + i * S,
                    namespace=ns,
                    name=None,
                    user=ds_controller,
                    privileged=True,
                    host_network=True,
                    host_path=True,
                ),
            )
        )
    kubelet = ("system:node:extorq-lab-control-plane", ["system:nodes", "system:authenticated"])
    fx.extend(
        k8s_audit_events(
            base,
            mutate=_pod_variant(
                "k8s005-mirror",
                at=BASE + 5 * S,
                namespace="kube-system",
                name="etcd-extorq-lab-control-plane",
                user=kubelet,
                host_network=True,
                host_path=True,
            ),
        )
    )
    fx.extend(
        k8s_audit_events(
            base,
            mutate=_pod_variant(
                "k8s005-dry",
                at=BASE + 10 * S,
                namespace="extorq-test-psa",
                name="extorq-test-dry",
                host_path=True,
                dry_run=True,
            ),
        )
    )
    fx.extend(k8s_audit_events("psa_denied_privileged_pod.json"))
    out[f"{d}/negative_platform_and_dry_run.jsonl"] = fx
    return out


# ═══ GitHub ══════════════════════════════════════════════════════════

WF_BASE = """name: ci
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955
      - run: make test
"""
CI = ".github/workflows/ci.yml"
WRITE_ALL = WF_BASE.replace("permissions:\n  contents: read", "permissions: write-all")
CHECKOUT_PIN = "actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955"


def _sha(label: str) -> str:
    return hashlib.sha1(label.encode()).hexdigest()  # noqa: S324 - deterministic fake commit id


@builder
def gh001() -> dict[str, FixtureWriter]:
    d = "github/tests/GH-001"
    out: dict[str, FixtureWriter] = {}
    fx = FixtureWriter("gh001-matrix")
    workflow_event(fx, BASE, _sha("gh001-matrix"), CI, WF_BASE, WRITE_ALL)
    out[f"{d}/positive_matrix_write_all.jsonl"] = fx

    fx = FixtureWriter("gh001-matrix-control")
    workflow_event(fx, BASE, _sha("gh001-revert"), CI, WRITE_ALL, WF_BASE)
    out[f"{d}/negative_matrix_permissions_reduced.jsonl"] = fx

    fx = FixtureWriter("gh001-c")
    no_perms = WF_BASE.replace("permissions:\n  contents: read\n", "")
    with_oidc = WF_BASE.replace(
        "permissions:\n  contents: read", "permissions:\n  contents: read\n  id-token: write"
    )
    workflow_event(
        fx,
        BASE,
        _sha("gh001-oidc"),
        ".github/workflows/deploy.yml",
        no_perms,
        with_oidc,
        repo_default=None,
    )
    out[f"{d}/positive_scope_unknown_default.jsonl"] = fx

    fx = FixtureWriter("gh001-d")
    workflow_event(
        fx, BASE, _sha("gh001-d1"), CI, WF_BASE, WF_BASE.replace("make test", "make lint test")
    )
    workflow_event(
        fx,
        BASE + M,
        _sha("gh001-d2"),
        CI,
        WF_BASE,
        WF_BASE.replace(
            "permissions:\n  contents: read", "permissions:\n  contents: read\n  issues: read"
        ),
    )
    workflow_event(
        fx,
        BASE + 2 * M,
        _sha("gh001-d3"),
        CI,
        WF_BASE,
        WF_BASE.replace("    branches: [main]", "    branches: [main, develop]\n  pull_request:"),
    )
    out[f"{d}/negative_benign_edits.jsonl"] = fx

    # Analyser >= 1.1.0 fails closed: an unparseable new version (here a duplicate mapping
    # key) is compared lexically with the old one (analysis = lexical_fallback).
    broken_escalation = WF_BASE.replace(
        "on:\n  push:\n    branches: [main]",
        "on:\n  push:\n    branches: [main]\n  push:\n    branches: [dev]",
    ).replace("permissions:\n  contents: read", "permissions: write-all")
    fx = FixtureWriter("gh001-lexical")
    workflow_event(fx, BASE, _sha("gh001-lexical"), CI, WF_BASE, broken_escalation)
    out[f"{d}/positive_lexical_fallback_write_all.jsonl"] = fx

    fx = FixtureWriter("gh001-lexical-benign")
    workflow_event(
        fx, BASE, _sha("gh001-lex-benign"), CI, WF_BASE, WF_BASE.replace("jobs:", "jobs:\njobs:")
    )
    out[f"{d}/negative_lexical_fallback_benign.jsonl"] = fx

    fx = FixtureWriter("gh001-prt")
    workflow_event(fx, BASE, _sha("gh001-prt"), ".github/workflows/pr.yml", None, PRT_CHECKOUT_HEAD)
    out[f"{d}/negative_privileged_trigger_only.jsonl"] = fx
    return out


PRT_CHECKOUT_HEAD = """name: pr-checks
on:
  pull_request_target:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
"""


@builder
def gh002() -> dict[str, FixtureWriter]:
    d = "github/tests/GH-002"
    out: dict[str, FixtureWriter] = {}
    fx = FixtureWriter("gh002-matrix")
    workflow_event(
        fx, BASE, _sha("gh002-matrix"), ".github/workflows/pr.yml", None, PRT_CHECKOUT_HEAD
    )
    out[f"{d}/positive_matrix_prt_checkout_head.jsonl"] = fx

    broken_workflow_run = """name: report
on:
  workflow_run:
    workflows: [ci]
    types: [completed]
jobs:
  report:
    runs-on: ubuntu-24.04
    steps:
      - run: git fetch origin ${{ github.event.workflow_run.head_branch }} && make report
      - run: echo done
jobs:
"""
    fx = FixtureWriter("gh002-lexical")
    workflow_event(
        fx, BASE, _sha("gh002-lexical"), ".github/workflows/report.yml", None, broken_workflow_run
    )
    out[f"{d}/positive_lexical_workflow_run_checkout.jsonl"] = fx

    fx = FixtureWriter("gh002-matrix-control")
    workflow_event(
        fx,
        BASE,
        _sha("gh002-control"),
        ".github/workflows/pr.yml",
        None,
        PRT_CHECKOUT_HEAD.replace("pull_request_target:", "pull_request:"),
    )
    out[f"{d}/negative_matrix_pull_request_checkout.jsonl"] = fx

    labeller = """name: label
on:
  pull_request_target:
permissions:
  contents: read
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955
      - uses: actions/labeler@8558fd74291d67161a8a78ce36a881fa63b766a9
"""
    fx = FixtureWriter("gh002-labeller")
    workflow_event(fx, BASE, _sha("gh002-labeller"), ".github/workflows/label.yml", None, labeller)
    out[f"{d}/negative_prt_without_pr_checkout.jsonl"] = fx
    return out


BUILDX_STEP = "      - uses: docker/setup-buildx-action@v3\n"


@builder
def gh003() -> dict[str, FixtureWriter]:
    d = "github/tests/GH-003"
    out: dict[str, FixtureWriter] = {}
    tagged = WF_BASE.replace("      - run: make test\n", BUILDX_STEP + "      - run: make test\n")
    fx = FixtureWriter("gh003-matrix")
    workflow_event(fx, BASE, _sha("gh003-matrix"), CI, WF_BASE, tagged)
    out[f"{d}/positive_matrix_tag_pinned_action.jsonl"] = fx

    pinned = WF_BASE.replace(
        "      - run: make test\n",
        "      - uses: docker/setup-buildx-action@e468171a9de216ec08956ac3ada2f0791b6bd435\n"
        "      - uses: actions/setup-node@v4\n"
        "      - run: make test\n",
    )
    fx = FixtureWriter("gh003-matrix-control")
    workflow_event(fx, BASE, _sha("gh003-control"), CI, WF_BASE, pinned)
    out[f"{d}/negative_matrix_sha_pinned_action.jsonl"] = fx

    broken = tagged.replace("jobs:", "jobs:\njobs:")
    fx = FixtureWriter("gh003-lexical")
    workflow_event(fx, BASE, _sha("gh003-lexical"), CI, WF_BASE, broken)
    out[f"{d}/negative_lexical_fallback_not_analysed.jsonl"] = fx
    return out


ISSUE_TRIAGE = """name: triage
on:
  issues:
    types: [opened]
permissions:
  issues: write
jobs:
  triage:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          echo "New issue: ${{ github.event.issue.title }}"
"""


@builder
def gh004() -> dict[str, FixtureWriter]:
    d = "github/tests/GH-004"
    out: dict[str, FixtureWriter] = {}
    path = ".github/workflows/triage.yml"
    fx = FixtureWriter("gh004-matrix")
    workflow_event(fx, BASE, _sha("gh004-matrix"), path, None, ISSUE_TRIAGE)
    out[f"{d}/positive_matrix_issue_title_in_run.jsonl"] = fx

    safe = ISSUE_TRIAGE.replace(
        '      - run: |\n          echo "New issue: ${{ github.event.issue.title }}"\n',
        "      - env:\n          TITLE: ${{ github.event.issue.title }}\n"
        '        run: |\n          echo "New issue: $TITLE"\n',
    )
    assert safe != ISSUE_TRIAGE
    fx = FixtureWriter("gh004-matrix-control")
    workflow_event(fx, BASE, _sha("gh004-control"), path, None, safe)
    out[f"{d}/negative_matrix_env_quoted_variable.jsonl"] = fx

    trusted = WF_BASE.replace(
        "      - run: make test\n",
        '      - run: echo "Building ${{ github.repository }} at ${{ github.sha }}"\n',
    )
    fx = FixtureWriter("gh004-trusted")
    workflow_event(fx, BASE, _sha("gh004-trusted"), CI, WF_BASE, trusted)
    out[f"{d}/negative_trusted_expressions.jsonl"] = fx
    return out


@builder
def gh005() -> dict[str, FixtureWriter]:
    d = "github/tests/GH-005"
    out: dict[str, FixtureWriter] = {}
    # Only the redacted form is ever stored (the collector never keeps the value).
    fx = FixtureWriter("gh005-matrix")
    sha = _sha("gh005-matrix")
    env_file = "deploy/extorq-test-4f2a.env"
    commit_observed(fx, BASE, sha, [env_file])
    secret_exposed(
        fx, BASE, sha, env_file, 1, "aws_access_key", "AWS_ACCESS_KEY_ID=[REDACTED:aws_access_key]"
    )
    secret_exposed(
        fx,
        BASE,
        sha,
        env_file,
        2,
        "aws_secret_key",
        "aws_secret_access_key=[REDACTED:aws_secret_key]",
    )
    out[f"{d}/positive_matrix_fake_aws_key.jsonl"] = fx

    fx = FixtureWriter("gh005-generic")
    sha = _sha("gh005-generic")
    commit_observed(fx, BASE, sha, ["deploy/app.yaml"])
    secret_exposed(
        fx, BASE, sha, "deploy/app.yaml", 12, "secret_assignment", "password: [REDACTED:secret]"
    )
    out[f"{d}/positive_generic_password_assignment.jsonl"] = fx

    fx = FixtureWriter("gh005-matrix-control")
    commit_observed(fx, BASE, _sha("gh005-control"), ["checksums/SHA256SUMS"])
    out[f"{d}/negative_matrix_checksum_commit.jsonl"] = fx
    return out


# ═══ macOS ═══════════════════════════════════════════════════════════

HOME = "/Users/labuser"
AGENTS = f"{HOME}/Library/LaunchAgents"
TEST_AGENT = {"Label": "com.extorq.test.agent", "ProgramArguments": ["/usr/bin/true"]}
#: Plist of the allowlisted-digest case; its SHA-256 is pinned in MAC-001.yaml (params).
REVIEWED_AGENT = {
    "Label": "com.example.reviewed",
    "ProgramArguments": ["/Applications/Example.app/Contents/MacOS/example-agent"],
    "RunAtLoad": True,
}


@builder
def mac001() -> dict[str, FixtureWriter]:
    d = "macos/tests/MAC-001"
    out: dict[str, FixtureWriter] = {}
    out[f"{d}/positive_matrix_user_agent_created.jsonl"] = _fixture(
        "mac001-matrix",
        [launchd_event("created", f"{AGENTS}/com.extorq.test.agent.plist", TEST_AGENT, BASE)],
    )
    reused = {
        "Label": "homebrew.mxcl.updater",
        "ProgramArguments": ["/tmp/extorq-test-updater"],
        "RunAtLoad": True,
    }
    out[f"{d}/positive_label_allowlisted_reused.jsonl"] = _fixture(
        "mac001-reused",
        [
            launchd_event(
                "created", f"{AGENTS}/homebrew.mxcl.updater.plist", reused, BASE, allowlisted=True
            )
        ],
    )
    out[f"{d}/positive_daemon_modified_unparseable.jsonl"] = _fixture(
        "mac001-daemon",
        [
            launchd_event(
                "modified",
                "/Library/LaunchDaemons/com.example.helper.plist",
                b"not a plist",
                BASE,
                scope="system",
                item_kind="daemon",
                previous_sha="c" * 64,
            )
        ],
    )
    out[f"{d}/negative_matrix_deleted_and_digest_allowlisted.jsonl"] = _fixture(
        "mac001-matrix-control",
        [
            launchd_event(
                "deleted",
                f"{AGENTS}/com.extorq.test.agent.plist",
                TEST_AGENT,
                BASE,
                previous_sha="a" * 64,
            ),
            launchd_event(
                "created", f"{AGENTS}/com.example.reviewed.plist", REVIEWED_AGENT, BASE + M
            ),
        ],
    )
    return out


@builder
def mac002() -> dict[str, FixtureWriter]:
    d = "macos/tests/MAC-002"
    out: dict[str, FixtureWriter] = {}
    payload = {
        "Label": "com.extorq.test.shell",
        "ProgramArguments": ["/bin/sh", "-c", "/tmp/extorq-test-payload"],
    }
    out[f"{d}/positive_matrix_sh_c_tmp.jsonl"] = _fixture(
        "mac002-matrix",
        [launchd_event("created", f"{AGENTS}/com.extorq.test.shell.plist", payload, BASE)],
    )
    env_python = {
        "Label": "com.example.updater",
        "ProgramArguments": [
            "/usr/bin/env",
            "python3",
            f"{HOME}/Library/Application Support/Example/updater.py",
        ],
        "StartInterval": 3600,
    }
    daemon_home = {"Label": "com.example.sync", "Program": f"{HOME}/bin/syncd", "KeepAlive": True}
    out[f"{d}/positive_env_python_and_daemon_home.jsonl"] = _fixture(
        "mac002-variants",
        [
            launchd_event("created", f"{AGENTS}/com.example.updater.plist", env_python, BASE),
            launchd_event(
                "created",
                "/Library/LaunchDaemons/com.example.sync.plist",
                daemon_home,
                BASE + M,
                scope="system",
                item_kind="daemon",
            ),
        ],
    )
    out[f"{d}/negative_matrix_usr_bin_true.jsonl"] = _fixture(
        "mac002-matrix-control",
        [
            launchd_event("created", f"{AGENTS}/com.extorq.test.agent.plist", TEST_AGENT, BASE),
            launchd_event("created", f"{AGENTS}/com.example.broken.plist", b"\x00broken", BASE + M),
        ],
    )
    return out


PYTHON = "/Library/Developer/CommandLineTools/usr/bin/python3"
CONTROL_CENTER = "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"


@builder
def mac003() -> dict[str, FixtureWriter]:
    d = "macos/tests/MAC-003"
    out: dict[str, FixtureWriter] = {}
    fx = FixtureWriter("mac003-matrix")
    macos_listener(fx, BASE, "opened", ANY_IPV4, 47123, executable=PYTHON, pid=7311)
    macos_listener(fx, BASE + 3 * M, "closed", ANY_IPV4, 47123, executable=PYTHON, pid=7311)
    out[f"{d}/positive_matrix_any_listener.jsonl"] = fx

    fx = FixtureWriter("mac003-unknown")
    macos_listener(fx, BASE, "opened", "::", 50505, executable=None, pid=None)
    out[f"{d}/positive_owner_unknown.jsonl"] = fx

    fx = FixtureWriter("mac003-matrix-control")
    macos_listener(fx, BASE, "opened", "127.0.0.1", 47123, executable=PYTHON, pid=7312)
    macos_listener(fx, BASE + S, "opened", ANY_IPV4, 5000, executable=CONTROL_CENTER, pid=640)
    macos_listener(fx, BASE + S, "opened", "::", 7000, executable=CONTROL_CENTER, pid=640)
    macos_listener(
        fx, BASE + 2 * S, "opened", "::", 52580, executable="/usr/libexec/rapportd", pid=635
    )
    macos_listener(
        fx,
        BASE + 3 * S,
        "opened",
        ANY_IPV4,
        57374,
        protocol="udp",
        executable="/opt/homebrew/bin/qemu-system-aarch64",
        pid=95469,
    )
    out[f"{d}/negative_matrix_loopback_and_allowlisted.jsonl"] = fx
    return out


ACCOUNT_GUID = "A1B2C3D4-0000-4000-8000-000000000001"
SUDO = "/usr/bin/sudo"
OPENDIRECTORYD = "/usr/libexec/opendirectoryd"


def _sudo(t: datetime, message: str, pid: int, message_type: str = "Error") -> dict[str, Any]:
    return unified_log_record(t, SUDO, message, pid=pid, message_type=message_type)


def _od_failure(t: datetime, pid: int) -> dict[str, Any]:
    record = unified_log_record(
        t,
        OPENDIRECTORYD,
        f"Authentication failed for <private> ({ACCOUNT_GUID}): ODErrorCredentialsInvalid",
        pid=pid,
        subsystem="com.apple.opendirectoryd",
        category="auth",
    )
    record["senderImagePath"] = (
        "/System/Library/OpenDirectory/Modules/PlistFile.bundle/Contents/MacOS/PlistFile"
    )
    record["formatString"] = (
        "Authentication failed for %@ (%{public,uuid_t}.16P): %{odtypes:ODError}d"
    )
    return record


def _sudo_line(account: str, what: str, command: str = "validate") -> str:
    return f"{account} : {what} ; TTY=ttys004 ; PWD={HOME} ; USER=root ; COMMAND={command}"


@builder
def mac004() -> dict[str, FixtureWriter]:
    d = "macos/tests/MAC-004"
    out: dict[str, FixtureWriter] = {}
    accounts = {ACCOUNT_GUID: "labuser"}
    records = []
    for i in range(3):
        t = BASE + i * 5 * S
        records.append(_od_failure(t, 375))
        records.append(
            _sudo(
                t + 200 * S / 1000, _sudo_line("labuser", "1 incorrect password attempt"), 7100 + i
            )
        )
    out[f"{d}/positive_matrix_three_wrong_passwords.jsonl"] = _fixture(
        "mac004-matrix", unified_log_events(records, accounts=accounts)
    )

    records = [
        _sudo(BASE, _sudo_line("labuser", "3 incorrect password attempts", "/usr/bin/true"), 7200),
        _sudo(
            BASE + 20 * S,
            "labuser : TTY=ttys004 ; PWD=/Users/labuser ; USER=root ; COMMAND=/usr/bin/true",
            7201,
            message_type="Default",
        ),
    ]
    out[f"{d}/positive_exhausted_prompt_then_success.jsonl"] = _fixture(
        "mac004-exhausted", unified_log_events(records, accounts=accounts)
    )

    records = [
        _od_failure(BASE, 375),
        _sudo(BASE + 200 * S / 1000, _sudo_line("labuser", "1 incorrect password attempt"), 7300),
        _sudo(
            BASE + 30 * S, _sudo_line("labuser", "a password is required", "/usr/bin/true"), 7301
        ),
        _sudo(BASE + 40 * S, _sudo_line("guest", "user NOT in sudoers", "/usr/bin/true"), 7302),
        unified_log_record(
            BASE + 60 * S,
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow",
            "-[LWDefaultScreenLockUI authFailWithMessage:numFailedAttempts:] | enter. "
            "INCORRECT password",
            pid=402,
            subsystem="com.apple.loginwindow.logging",
            category="Standard",
        ),
    ]
    out[f"{d}/negative_matrix_single_failure.jsonl"] = _fixture(
        "mac004-matrix-control", unified_log_events(records, accounts=accounts)
    )
    return out


@builder
def mac005() -> dict[str, FixtureWriter]:
    d = "macos/tests/MAC-005"
    out: dict[str, FixtureWriter] = {}
    fx = FixtureWriter("mac005-matrix")
    software_installed(
        fx,
        BASE,
        "/Applications/ExtorQ Test.app",
        bundle_id="com.extorq.test.app",
        version="1.0",
        signed=False,
        signature_type="unsigned",
    )
    out[f"{d}/positive_matrix_unsigned_bundle.jsonl"] = fx

    fx = FixtureWriter("mac005-adhoc")
    software_installed(
        fx,
        BASE,
        f"{HOME}/Applications/Tool.app",
        bundle_id=None,
        version="0.1",
        signed=True,
        signature_type="adhoc",
    )
    out[f"{d}/positive_adhoc_no_identity.jsonl"] = fx

    fx = FixtureWriter("mac005-matrix-control")
    software_installed(
        fx,
        BASE,
        "/Applications/ExtorQ Test Calculator.app",
        bundle_id="com.apple.calculator",
        version="11.0",
        signed=True,
        signature_type="apple_platform",
    )
    software_installed(
        fx,
        BASE + M,
        "/Applications/Slow Copy.app",
        bundle_id="com.example.slow",
        version="2.0",
        signed="unknown",
        signature_type=None,
    )
    software_installed(
        fx,
        BASE + 2 * M,
        "/Applications/ExtorQ Test.app",
        bundle_id="com.extorq.test.app",
        version="1.0",
        signed=False,
        signature_type=None,
        kind="removed",
    )
    out[f"{d}/negative_matrix_signed_copy_and_unknown.jsonl"] = fx
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", help="builder name, e.g. corr002 (repeatable)")
    args = parser.parse_args(argv)
    selected = [b for b in BUILDERS if not args.only or b.__name__ in set(args.only)]
    written = 0
    for build in selected:
        for rel, fx in build().items():
            fx.write(ROOT / rel)
            written += 1
            kinds = sorted({e.labels.get("extorq.fixture", "?") for e in fx.events})
            print(f"wrote {rel} ({len(fx.events)} events: {', '.join(kinds)})")
    print(f"{written} fixture files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

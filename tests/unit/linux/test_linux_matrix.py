"""Every Linux parser path the detection-test matrix (PLAN section 12) relies on.

=========  =====================================================================  ==========
rule       telemetry (event type, source)                                         tests
=========  =====================================================================  ==========
VM-001     auth.ssh.{invalid_user,preauth_closed,max_auth_exceeded,login_failed}  test_vm001_*
           (linux.journald); negative control auth.ssh.login_succeeded
VM-002     persistence.systemd.unit_created/enabled (linux.inventory) +           test_vm002_*
           file.audit.watch extorq_systemd (linux.auditd) + daemon reload
VM-003     account.user.created/deleted (linux.inventory) + file.audit.watch      test_vm003_*
           extorq_identity (linux.auditd) + useradd context (journald)
VM-004     persistence.cron.changed (linux.inventory) + file.audit.watch          test_vm004_*
           extorq_cron (linux.auditd)
HTTP-001   http.request (linux.nginx)                                             test_http_*
APP-001    app.auth.login_failed / login_succeeded (linux.app)                    test_app_*
=========  =====================================================================  ==========

Inputs are the REAL captures under tests/fixtures/linux/ (README); records that could not
be captured without running a detection test are SYNTHETIC variations of a real record,
built in the test and labelled as such.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

from linux_testlib import FIXTURES, entries, find, load_json, pctx

from extorq.contracts import validate_event_semantics
from extorq_collectors.linux import auditd, auth, http
from extorq_collectors.linux import inventory as inv
from extorq_collectors.linux.journal import parse_entry
from extorq_collectors.sdk import SnapshotDiff

NOW = datetime(2026, 11, 21, 15, 0, tzinfo=UTC)
PROBES = ("/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/server-status", "/admin")


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


def _valid(event: Any) -> None:
    assert (
        validate_event_semantics(
            event.event_type, event.category.value, event.source.source_type.value
        )
        is None
    )


# ── VM-001 ───────────────────────────────────────────────────────────────────


def test_vm001_burst_lines_carry_user_source_and_port() -> None:
    lines = [e for e in entries("journal/sshd.ndjson") if "extorq-test-c7cbc976ecaf" in e.message]
    events = [ev for e in lines for ev in auth.parse_sshd(e, pctx())]
    types = {ev.event_type for ev in events}
    assert types == {
        "auth.ssh.invalid_user",
        "auth.ssh.preauth_closed",
        "auth.ssh.max_auth_exceeded",
    }
    connections = {(ev.network.src_ip, ev.network.src_port) for ev in events if ev.network}
    assert len(connections) >= 8  # the burst used >= 8 distinct client connections
    for ev in events:
        _valid(ev)
        assert ev.actor is not None and ev.actor.name == "extorq-test-c7cbc976ecaf"
        assert ev.attributes.get("invalid_user") is True


def test_vm001_existing_account_refused_by_allowusers() -> None:
    real = find("journal/sshd.ndjson", "Invalid user extorq-test-c7cbc976ecaf")
    # SYNTHETIC (derived from a real line): OpenSSH's message for an existing account that
    # sshd_config's AllowUsers excludes (root, the matrix's first guessed user).
    refused = replace(
        real, message="User root from 10.0.2.2 not allowed because not listed in AllowUsers"
    )
    (event,) = auth.parse_sshd(refused, pctx())
    assert event.event_type == "system.log.notable" and event.action == "ssh.user_not_allowed"
    assert event.actor is not None and event.actor.name == "root"
    assert event.network is not None and event.network.src_ip == "10.0.2.2"
    assert event.attributes["invalid_user"] is True


def test_vm001_negative_control_key_logins_are_successes() -> None:
    (admin,) = auth.parse_sshd(
        find("journal/sshd.ndjson", "Accepted publickey for extorq-admin"), pctx()
    )
    assert admin.event_type == "auth.ssh.login_succeeded" and admin.outcome.value == "success"
    assert admin.attributes["auth_method"] == "publickey"
    assert admin.attributes["key_fingerprint"].startswith("SHA256:")
    # Lines of an accepted login that are not authentication results produce nothing.
    for needle in ("Postponed publickey", "Starting session:"):
        for entry in entries("journal/sshd.ndjson"):
            if needle in entry.message:
                assert auth.parse_sshd(entry, pctx()) == []


# ── VM-002 ───────────────────────────────────────────────────────────────────


def test_vm002_unit_created_enabled_and_deleted_hashes() -> None:
    before = load_json("inventory/inventory_baseline.json")
    after = load_json("inventory/inventory_vm002_created.json")
    gone = load_json("inventory/inventory_vm002_removed.json")
    (created,) = inv.unit_events(_diff("units", before, after), _dctx())
    (enabled,) = inv.enablement_events(_diff("enablement", before, after), _dctx())
    (deleted,) = inv.unit_events(_diff("units", after, gone), _dctx())
    for event in (created, enabled, deleted):
        _valid(event)
    assert created.attributes["exec_start"] == "/bin/true"
    assert created.attributes["vendor_unit"] is False and len(created.attributes["sha256"]) == 64
    assert enabled.resource is not None
    assert enabled.resource.name == "extorq-test-0e49c82d82bc.service"
    # A deleted unit has no content: the last known hash is the previous one.
    assert "sha256" not in deleted.attributes
    assert deleted.attributes["previous_sha256"] == created.attributes["sha256"]


def test_vm002_audit_watch_names_writer_and_path() -> None:
    result = auditd.parse_audit_chunk(
        (FIXTURES / "audit" / "vm002_create.log").read_bytes(), 0, pctx()
    )
    (watch,) = [e for e in result.events if e.event_type == "file.audit.watch"]
    _valid(watch)
    assert watch.attributes["audit_key"] == "extorq_systemd" and watch.attributes["success"]
    assert watch.attributes["nametype"] == "CREATE" and watch.attributes["syscall"] == "openat"
    assert watch.process is not None and watch.process.executable == "/usr/bin/dash"
    assert watch.actor is not None
    assert (watch.actor.name, watch.actor.id) == ("extorq-admin", "1000")


# ── VM-003 ───────────────────────────────────────────────────────────────────


def test_vm003_account_created_and_deleted() -> None:
    before = load_json("inventory/inventory_vm002_created.json")
    after = load_json("inventory/inventory_user_added.json")
    (created,) = inv.user_events(_diff("users", before, after), _dctx())
    (deleted,) = inv.user_events(_diff("users", after, before), _dctx())
    for event in (created, deleted):
        _valid(event)
        assert event.actor is not None and event.actor.name == "extorq-test-107bfaab09cf"
    assert created.attributes["uid"] == 999 and created.attributes["shell"] == "/usr/sbin/nologin"
    assert created.attributes["groups"] == ["extorq-test-107bfaab09cf"]
    assert created.attributes["interactive_shell"] is False


def test_vm003_identity_watch_and_useradd_context() -> None:
    result = auditd.parse_audit_chunk((FIXTURES / "audit" / "useradd.log").read_bytes(), 0, pctx())
    identity = [e for e in result.events if e.attributes.get("audit_key") == "extorq_identity"]
    assert identity and all(e.event_type == "file.audit.watch" for e in identity)
    assert any((e.resource.path or "").startswith("/etc/passwd") for e in identity if e.resource)
    assert {e.process.name for e in identity if e.process} == {"useradd"}
    (context,) = parse_entry(find("journal/accounts.ndjson", "new user: name="), pctx())
    assert context.event_type == "system.log.notable" and context.action == "account.useradd"


def test_vm003_systemd_dynamic_users_are_not_account_changes() -> None:
    """lab-portal runs with DynamicUser=yes: its uid-64881 identity comes and goes with the
    service (nss-systemd), which must never read as an account being created/deleted."""
    running = load_json("inventory/inventory_baseline.json")
    users = inv.user_items(running)
    assert users["lab-portal"]["dynamic_user"] is True  # real capture: uid 64881
    assert "dynamic_user" not in users["extorq-admin"]
    stopped = copy.deepcopy(running)
    stopped["users"] = [u for u in stopped["users"] if u["name"] != "lab-portal"]
    assert inv.user_events(_diff("users", running, stopped), _dctx()) == []
    assert inv.user_events(_diff("users", stopped, running), _dctx()) == []
    # SYNTHETIC: an ordinary account created in the dynamic uid range (no DynamicUser unit
    # names it) is still an account creation: the range alone is never an exemption.
    sneaky = copy.deepcopy(running)
    sneaky["users"].append(
        {
            "name": "svc-backup",
            "uid": 62000,
            "gid": 62000,
            "home": "/home/svc-backup",
            "shell": "/bin/bash",
            "groups": ["svc-backup"],
        }
    )
    (created,) = inv.user_events(_diff("users", running, sneaky), _dctx())
    assert created.actor is not None and created.actor.name == "svc-backup"


# ── VM-004 ───────────────────────────────────────────────────────────────────


def _with_cron_file(doc: dict[str, Any], path: str, sha256: str) -> dict[str, Any]:
    """SYNTHETIC: a new /etc/cron.d file shaped like the real e2scrub_all facts."""
    new = copy.deepcopy(doc)
    template = next(c for c in new["cron"] if c["path"] == "/etc/cron.d/e2scrub_all")
    new["cron"].append({**template, "path": path, "sha256": sha256, "size": 64})
    return new


def test_vm004_cron_file_added_modified_removed() -> None:
    base = load_json("inventory/inventory_baseline.json")
    path = "/etc/cron.d/extorq-test-abcd"
    added_doc = _with_cron_file(base, path, "a" * 64)
    (added,) = inv.cron_events(_diff("cron", base, added_doc), _dctx())
    _valid(added)
    assert added.event_type == "persistence.cron.changed"
    assert added.resource is not None and added.resource.path == path
    assert added.attributes["change"] == "added" and added.attributes["sha256"] == "a" * 64
    modified_doc = _with_cron_file(base, path, "b" * 64)
    (modified,) = inv.cron_events(_diff("cron", added_doc, modified_doc), _dctx())
    assert modified.attributes["change"] == "modified"
    assert modified.attributes["previous_sha256"] == "a" * 64
    (removed,) = inv.cron_events(_diff("cron", modified_doc, base), _dctx())
    assert removed.attributes["change"] == "removed" and "sha256" not in removed.attributes
    assert removed.attributes["previous_sha256"] == "b" * 64
    # Negative control (crontab -l, reading files): an unchanged inventory yields nothing.
    assert inv.cron_events(_diff("cron", base, copy.deepcopy(base)), _dctx()) == []


def test_vm004_cron_audit_watch() -> None:
    # SYNTHETIC: the real VM-002 unit-file write (audit serial 4064) re-keyed as the write of
    # /etc/cron.d/extorq-test-abcd by `tee`, the matrix's VM-004 action. No cron.d write has
    # happened on the VM, so there is no real extorq_cron record to capture.
    lines = [
        line
        for line in (FIXTURES / "audit" / "vm002_create.log").read_text().splitlines()
        if "msg=audit(1795271969.384:4064)" in line
    ]
    title = "tee /etc/cron.d/extorq-test-abcd".replace(" ", "\x00").encode().hex().upper()
    text = (
        "\n".join(lines)
        .replace('key="extorq_systemd"', 'key="extorq_cron"')
        .replace('comm="sh" exe="/usr/bin/dash"', 'comm="tee" exe="/usr/bin/tee"')
        .replace('name="/etc/systemd/system/"', 'name="/etc/cron.d/"')
        .replace(
            "/etc/systemd/system/extorq-test-0e49c82d82bc.service", "/etc/cron.d/extorq-test-abcd"
        )
    )
    text = text[: text.index("proctitle=") + len("proctitle=")] + title + "\n"
    (watch,) = auditd.parse_audit_chunk(text.encode(), 0, pctx()).events
    _valid(watch)
    assert watch.attributes["audit_key"] == "extorq_cron"
    assert watch.resource is not None and watch.resource.path == "/etc/cron.d/extorq-test-abcd"
    assert watch.process is not None and watch.process.executable == "/usr/bin/tee"
    assert watch.process.command_line is None
    assert "type=PROCTITLE" not in (watch.raw or "")


# ── HTTP-001 and APP-001 ─────────────────────────────────────────────────────


def test_http_probe_paths_and_normal_requests() -> None:
    lines = entries("journal/nginx.ndjson")
    events = [ev for e in lines for ev in http.parse_nginx_access(e, pctx())]
    routes = {ev.http.route: ev for ev in events if ev.http is not None}
    for probe in PROBES:
        assert probe in routes, probe
        _valid(routes[probe])
        assert routes[probe].network is not None and routes[probe].network.src_ip == "10.0.2.2"
    assert all(ev.http is not None and ev.http.status_code for ev in events)
    ok = [ev for ev in events if ev.http is not None and ev.http.status_code < 400]
    assert ok and all(ev.outcome.value == "success" for ev in ok)  # negative-control shape


def test_app_login_failures_and_success() -> None:
    lines = entries("journal/lab_portal.ndjson")
    events = [ev for e in lines for ev in http.parse_lab_portal(e, pctx())]
    failed = [ev for ev in events if ev.event_type == "app.auth.login_failed"]
    assert len(failed) >= 5 and all(ev.actor is not None for ev in failed)
    for ev in failed:
        _valid(ev)
        assert ev.attributes["reason"] and ev.network is not None
    # SYNTHETIC (derived from a real failed line): the success record of the same schema.
    real = next(e for e in lines if '"event":"auth.login_failed"' in e.message)
    obj = json.loads(real.message)
    obj.update(event="auth.login_succeeded", status=303, level="info")
    obj.pop("reason", None)
    (success,) = http.parse_lab_portal(replace(real, message=json.dumps(obj)), pctx())
    _valid(success)
    assert success.event_type == "app.auth.login_succeeded" and success.outcome.value == "success"


# ── sudo (VM-002/003/004 actions run through sudo) ───────────────────────────


def test_sudo_failure_kinds_and_env_field() -> None:
    real = find("journal/sudo.ndjson", "COMMAND=/bin/sh -s -- create extorq-test-")
    # SYNTHETIC variations of the real line in documented sudoers(5) formats.
    wrong = replace(
        real,
        message="extorq-admin : 3 incorrect password attempts ; TTY=pts/0 ; "
        "PWD=/home/extorq-admin ; USER=root ; COMMAND=/usr/bin/true",
    )
    (failure,) = parse_entry(wrong, pctx())
    assert failure.event_type == "auth.sudo.failure" and failure.outcome.value == "failure"
    assert failure.attributes["failure_kind"] == "authentication"
    assert failure.attributes["failed_attempts"] == 3
    env = replace(
        real,
        message="extorq-admin : TTY=pts/0 ; PWD=/home/extorq-admin ; USER=root ; "
        "ENV=LANG=C COMMAND=/usr/sbin/useradd -M extorq-test-x",
    )
    (ran,) = parse_entry(env, pctx())
    assert ran.event_type == "auth.sudo.command" and ran.attributes["env_specified"] is True
    assert ran.process is not None
    assert ran.process.executable == "/usr/sbin/useradd"
    assert ran.process.command_line is None and ran.raw is None
    (policy,) = parse_entry(find("journal/sudo.ndjson", "user NOT in sudoers"), pctx())
    assert policy.outcome.value == "denied" and policy.attributes["failure_kind"] == "policy"


# ── listeners (service exposure shown on every asset) ────────────────────────


def test_listener_events_report_bind_address_and_exposure() -> None:
    doc = load_json("inventory/inventory_baseline.json")
    events = inv.listener_events(_diff("listeners", {"listeners": []}, doc), _dctx())
    by_port = {(ev.attributes["bind_address"], ev.attributes["port"]): ev for ev in events}
    assert by_port[("0.0.0.0", 80)].attributes["exposure"] == "any"  # noqa: S104 - observed
    assert by_port[("127.0.0.1", 8080)].attributes["exposure"] == "loopback"
    assert by_port[("0.0.0.0", 80)].attributes["unit"] == "nginx.service"  # noqa: S104

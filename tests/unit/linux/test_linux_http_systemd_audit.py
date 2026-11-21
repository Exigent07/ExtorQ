"""nginx / lab-portal / apache, systemd and auditd parsing on real (or labelled) inputs."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

from linux_testlib import FIXTURES, entries, find, pctx

from extorq_collectors.linux import auditd, http, systemd
from extorq_collectors.linux.adapters.apache import (
    ApacheAdapter,
    parse_apache_access,
    parse_apache_error,
)
from extorq_collectors.linux.journal import JournalEntry


def _probe_line(path: str) -> JournalEntry:
    for entry in entries("journal/nginx.ndjson"):
        if f'"uri":"{path}"' in entry.message and "extorq-sim-" in entry.message:
            return entry
    raise AssertionError(path)


def test_nginx_access_probe_line() -> None:
    entry = _probe_line("/.git/config")
    (event,) = http.parse_nginx_access(entry, pctx())
    assert event.event_type == "http.request" and event.source.source_type.value == "linux.nginx"
    assert event.http.route == "/.git/config" and event.http.status_code == 404
    assert event.http.method == "GET" and len(event.http.request_id) == 32
    assert event.network.src_ip == "10.0.2.2"  # SLIRP gateway, reported as logged
    assert event.simulation.run_id == "fff5113314b3"
    assert event.outcome.value == "failure"
    assert event.event_time.tzinfo is not None


def test_nginx_access_admin_is_denied_outcome() -> None:
    (event,) = http.parse_nginx_access(_probe_line("/admin"), pctx())
    assert event.http.status_code == 401 and event.outcome.value == "denied"


def test_nginx_error_413_strips_query_string() -> None:
    entry = find("journal/nginx.ndjson", "client intended to send too large body")
    assert "?probe=1" in entry.message  # the real line carried a query string
    (event,) = http.parse_nginx_error(entry, pctx())
    assert event.event_type == "http.server.error"
    assert event.attributes["error_class"] == "request_body_too_large"
    assert event.attributes["log_level"] == "error"
    assert event.http.route == "/login" and event.http.method == "POST"
    assert event.network.src_ip == "10.0.2.2"
    assert "probe=1" not in (event.raw or "") and "probe=1" not in (event.message or "")
    assert event.attributes["query_stripped"] is True


def test_nginx_forged_unit_is_notable() -> None:
    forged = replace(_probe_line("/.env"), unit="session-9.scope")
    (event,) = http.parse_nginx_access(forged, pctx())
    assert event.event_type == "system.log.notable"
    assert event.attributes["forged_identity_suspected"] is True


def test_lab_portal_login_failed_propagated_request_id() -> None:
    entry = find("journal/lab_portal.ndjson", '"event":"auth.login_failed"')
    (event,) = http.parse_lab_portal(entry, pctx())
    assert event.event_type == "app.auth.login_failed" and event.actor.name == "lab-admin"
    assert event.attributes["reason"] == "invalid_password"
    assert event.attributes["request_id_source"] == "propagated"
    assert len(event.http.request_id) == 32 and event.http.route == "/login"
    assert event.simulation is not None  # from the User-Agent
    assert "password" not in (event.raw or "").lower().replace("invalid_password", "")


def test_lab_portal_authz_denied_and_startup_line() -> None:
    (denied,) = http.parse_lab_portal(find("journal/lab_portal.ndjson", '"authz.denied"'), pctx())
    assert (
        denied.event_type == "app.authz.denied" and denied.attributes["reason"] == "missing_session"
    )
    assert http.parse_lab_portal(find("journal/lab_portal.ndjson", "listening on"), pctx()) == []


def test_lab_portal_custom_app_binding() -> None:
    entry = find("journal/lab_portal.ndjson", '"event":"auth.login_failed"')
    # The same line verified against a different configured unit is a forged-origin claim.
    (event,) = http.parse_lab_portal(
        entry, pctx(), expected_unit="shop.service", app_name="lab-portal"
    )
    assert event.event_type == "system.log.notable"


def _apache_examples() -> dict[str, str]:
    lines = (FIXTURES / "apache" / "documented_examples.txt").read_text().splitlines()
    return dict(line.split("\t", 1) for line in lines if line and not line.startswith("#"))


def _apache_entry(message: str, identifier: str) -> JournalEntry:
    # SYNTHETIC journald envelope around a documented Apache log line (see fixture header).
    return JournalEntry(
        cursor="s=00000000000000000000000000000000;i=1;b=00000000000000000000000000000000;"
        "m=1;t=1;x=1",
        time=datetime(2026, 11, 21, 12, 0, tzinfo=UTC),
        boot_id=None,
        hostname="apache-host",
        identifier=identifier,
        unit="apache2.service",
        pid=1234,
        uid=33,
        comm="logger",
        exe="/usr/bin/logger",
        transport="syslog",
        priority=6,
        message=message,
    )


def test_apache_combined_and_common_formats() -> None:
    examples = _apache_examples()
    (combined,) = parse_apache_access(_apache_entry(examples["combined"], "apache_access"), pctx())
    assert combined.source.source_type.value == "linux.apache"
    assert combined.http.method == "GET" and combined.http.route == "/apache_pb.gif"
    assert combined.http.status_code == 200 and combined.http.bytes_sent == 2326
    assert combined.actor.name == "frank" and combined.actor.authenticated is True
    assert combined.http.user_agent == "Mozilla/4.08 [en] (Win98; I ;Nav)"
    assert combined.event_time == datetime(2000, 10, 10, 20, 55, 36, tzinfo=UTC)
    assert "start.html" not in (combined.raw or "")  # Referer is never stored
    (common,) = parse_apache_access(_apache_entry(examples["common"], "apache_access"), pctx())
    assert common.attributes["log_format"] == "common" and common.http.user_agent is None


def test_apache_error_format() -> None:
    (event,) = parse_apache_error(_apache_entry(_apache_examples()["error"], "apache2"), pctx())
    assert event.event_type == "http.server.error"
    assert event.attributes["error_class"] == "file_not_found"
    assert event.attributes["module"] == "core" and event.attributes["log_level"] == "error"
    assert event.network.src_ip == "72.15.99.187"


def test_apache_adapter_is_implemented_but_not_deployed() -> None:
    assert ApacheAdapter.support.value == "implemented" and ApacheAdapter.deployed_in_lab is False


def test_systemd_pid1_lines() -> None:
    started = find("journal/systemd_pid1.ndjson", "Started ssh.service")
    (event,) = systemd.parse_systemd(started, pctx())
    assert event.event_type == "system.service.state_changed"
    assert event.resource.name == "ssh.service" and event.attributes["state"] == "started"
    deact = find("journal/systemd_pid1.ndjson", "lab-portal.service: Deactivated successfully")
    (event,) = systemd.parse_systemd(deact, pctx())
    assert event.attributes["state"] == "deactivated"
    reload_line = find("journal/systemd_pid1.ndjson", "Reloading requested from client PID")
    (event,) = systemd.parse_systemd(reload_line, pctx())
    assert event.event_type == "system.systemd.daemon_reload"
    assert event.attributes["requested_by_comm"] == "systemctl"
    assert event.attributes["requested_by_unit"].startswith("session-")
    assert (
        systemd.parse_systemd(find("journal/systemd_pid1.ndjson", "Starting ssh.service"), pctx())
        == []
    )


def test_systemd_user_manager_ignored_and_session_scope_self() -> None:
    for entry in entries("journal/systemd_user_manager.ndjson"):
        assert systemd.parse_systemd(entry, pctx()) == []
    scope = find("journal/systemd_pid1.ndjson", "Session 77 of User extorq-collector")
    (event,) = systemd.parse_systemd(scope, pctx())
    assert event.labels["extorq.self"] == "true"


def _audit(name: str) -> bytes:
    return (FIXTURES / "audit" / name).read_bytes()


def test_audit_vm002_unit_file_watch_and_root_exec() -> None:
    result = auditd.parse_audit_chunk(_audit("vm002_create.log"), 0, pctx())
    watch = [e for e in result.events if e.event_type == "file.audit.watch"]
    assert len(watch) == 1
    (unit_write,) = watch
    assert unit_write.attributes["audit_key"] == "extorq_systemd"
    assert unit_write.resource.path.startswith("/etc/systemd/system/extorq-sim-")
    assert unit_write.attributes["syscall"] == "openat" and unit_write.actor.name == "extorq-admin"
    assert unit_write.simulation is not None
    execs = [e for e in result.events if e.event_type == "process.audit.exec"]
    commands = [e.process.command_line for e in execs]
    assert any(c and c.startswith("systemctl enable extorq-sim-") for c in commands)
    assert all(e.actor.id == "1000" for e in execs)
    assert result.held_back == 0 and result.malformed_lines == 0


def test_audit_identity_watch_from_useradd() -> None:
    result = auditd.parse_audit_chunk(_audit("useradd.log"), 0, pctx())
    keys = {e.attributes.get("audit_key") for e in result.events}
    assert "extorq_identity" in keys
    paths = {e.resource.path for e in result.events if e.event_type == "file.audit.watch"}
    assert any(p and p.startswith("/etc/passwd") for p in paths)


def test_audit_config_change_records() -> None:
    result = auditd.parse_audit_chunk(_audit("augenrules_load.log"), 0, pctx())
    changes = [e for e in result.events if e.event_type == "audit.config.changed"]
    assert len(changes) >= 20
    removed = [e for e in changes if e.attributes["audit_op"] == "remove_rule"]
    assert removed and all(e.attributes["affects_extorq_rule"] for e in removed)
    assert removed[0].actor.name == "extorq-admin"


def test_audit_incomplete_trailing_group_is_held_back_and_ids_are_stable() -> None:
    data = _audit("vm002_create.log")
    lines = data.splitlines(keepends=True)
    # Cut the chunk inside the LAST syscall event (its PROCTITLE not written yet).
    last_proctitle = max(i for i, line in enumerate(lines) if line.startswith(b"type=PROCTITLE"))
    partial = b"".join(lines[:last_proctitle])
    first = auditd.parse_audit_chunk(partial, 0, pctx())
    assert first.held_back == 1 and first.resume_offset < len(partial)
    second = auditd.parse_audit_chunk(data[first.resume_offset :], first.resume_offset, pctx())
    full = auditd.parse_audit_chunk(data, 0, pctx())
    ids_split = {e.event_id for e in first.events} | {e.event_id for e in second.events}
    assert ids_split == {e.event_id for e in full.events}  # re-reading never changes identity


def test_audit_self_label_by_auid() -> None:
    result = auditd.parse_audit_chunk(_audit("vm002_create.log"), 0, pctx(self_uid=1000))
    assert result.events and all(
        e.labels.get("extorq.self") == "true"
        for e in result.events
        if e.actor and e.actor.id == "1000"
    )

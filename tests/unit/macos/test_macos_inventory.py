"""Listener, process, application and account inventory parsing.

Fixtures are real command output from the reference Mac, trimmed to the lines these tests
need; third-party processes and applications are SYNTHETIC placeholders (README).
"""

from __future__ import annotations

from datetime import UTC, datetime

from macos_helpers import FakeRunner, fixture_bytes, fixture_text, ok

from extorq.contracts import validate_event_semantics
from extorq_collectors.macos.common import SourceContext
from extorq_collectors.macos.inventory import (
    LSOF_TCP_LISTEN_ARGV,
    LSOF_UDP_ARGV,
    NETSTAT_TCP,
    NETSTAT_UDP,
    account_event,
    accounts_from,
    collect_listeners,
    listener_event,
    listeners_from_lsof,
    listeners_from_rows,
    parse_lsof_fields,
    parse_netstat,
    parse_ps,
    parse_system_profiler_apps,
    socket_table_withheld,
    with_verified_paths,
)

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def test_netstat_rows_and_last_pid_attribution() -> None:
    rows = parse_netstat(fixture_text("inventory/netstat_tcp.txt"))
    assert rows
    launchd_held = [r for r in rows if r.process_name == "launchd"]
    assert launchd_held and all(r.pid == 1 for r in launchd_held)
    spaced = [r for r in rows if r.process_name == "Example App (UI)"]
    assert spaced and spaced[0].pid == 42240  # process names may contain spaces
    listeners = listeners_from_rows(rows, include_udp=False)
    proxy = listeners["tcp:127.0.0.1:8021"]
    assert proxy.processes == {"launchd"} and proxy.bind_scope == "loopback"
    dns = listeners["tcp:0.0.0.0:53"]
    assert dns.exposed and dns.processes == {"mDNSResponder"}
    assert all(not k.startswith("udp") for k in listeners)


def test_netstat_udp_unconnected_sockets_only() -> None:
    rows = parse_netstat(fixture_text("inventory/netstat_udp.txt"))
    listeners = listeners_from_rows(rows, include_udp=True)
    assert any(k.startswith("udp:") and k.endswith(":5353") for k in listeners)


def test_lsof_field_output_current_user_only() -> None:
    entries = parse_lsof_fields(fixture_text("inventory/lsof_tcp_listen.txt"))
    assert entries and {e.login for e in entries} == {"testuser"}
    listeners = listeners_from_lsof(entries)
    airplay = listeners["tcp:0.0.0.0:7000"]
    assert airplay.processes == {"ControlCenter"} and airplay.attribution == "lsof"
    assert listeners["tcp:[::]:7000"].family == "ipv6"


def test_lsof_names_with_spaces_and_udp_wildcards() -> None:
    entries = parse_lsof_fields(fixture_text("services/lsof_tcp_services.txt"))
    assert "Example Helper (Plugin)" in {e.command for e in entries}
    udp = listeners_from_lsof(parse_lsof_fields(fixture_text("services/lsof_udp_services.txt")))
    assert all(":*" not in key for key in udp)  # unbound sockets (port '*') are skipped


def test_withheld_socket_table_falls_back_to_lsof() -> None:
    empty = ok(NETSTAT_TCP, b"")
    assert socket_table_withheld(empty)
    assert not socket_table_withheld(ok(NETSTAT_TCP, fixture_bytes("inventory/netstat_tcp.txt")))
    runner = FakeRunner()
    runner.add(NETSTAT_TCP, empty)
    runner.add(
        LSOF_TCP_LISTEN_ARGV,
        ok(LSOF_TCP_LISTEN_ARGV, fixture_bytes("inventory/lsof_tcp_listen.txt")),
    )
    runner.add(LSOF_UDP_ARGV, ok(LSOF_UDP_ARGV, b""))
    snapshot = collect_listeners(runner, include_udp=True, timeout=5)
    assert snapshot.method == "lsof" and not snapshot.full_visibility
    assert "withheld" in snapshot.errors[0]
    full = FakeRunner()
    full.add(NETSTAT_TCP, ok(NETSTAT_TCP, fixture_bytes("inventory/netstat_tcp.txt")))
    full.add(NETSTAT_UDP, ok(NETSTAT_UDP, fixture_bytes("inventory/netstat_udp.txt")))
    assert collect_listeners(full, include_udp=True, timeout=5).method == "netstat"


def test_ps_snapshot_and_verified_paths() -> None:
    rows = parse_ps(fixture_text("services/ps_services.txt"))
    assert len(rows) == 19
    spaced = next(r for r in rows if r.pid == 7310)
    assert spaced.name == "Example Helper (Plugin)"  # paths with spaces stay intact
    launchd = next(r for r in rows if r.pid == 1)
    assert launchd.command == "/sbin/launchd" and launchd.started_at is not None
    qemu = next(r for r in rows if r.command == "qemu-system-aarch64")
    assert not qemu.verified and qemu.executable == "qemu-system-aarch64"
    resolved = with_verified_paths(
        [qemu], lambda pid: "/opt/homebrew/Cellar/qemu/11.1.1/bin/qemu-system-aarch64"
    )[0]
    assert resolved.verified and resolved.executable.startswith("/opt/homebrew/Cellar/")
    assert resolved.attributes()["command"] == "qemu-system-aarch64"
    assert resolved.key == qemu.key  # identity does not depend on path verification


def test_system_profiler_applications() -> None:
    apps = parse_system_profiler_apps(fixture_text("inventory/system_profiler_apps.json"))
    textedit = next(a for a in apps if a.name == "TextEdit")
    assert textedit.obtained_from == "apple" and textedit.signed_by[0] == "macOS Software Signing"
    stub = next(a for a in apps if a.name == "Automator Application Stub")
    assert stub.signed_by == () and stub.attributes()["signed"] is False  # unsigned stays visible
    assert {a.obtained_from for a in apps} == {
        "apple",
        "unknown",
        "identified_developer",
        "mac_app_store",
    }


def test_accounts_inventory_and_events(src: SourceContext) -> None:
    accounts = accounts_from(
        fixture_text("inventory/dscl_users_uid.txt"), fixture_text("inventory/dscl_users_shell.txt")
    )
    user = accounts["testuser"]
    assert user.uid == 501 and not user.system_account and user.can_login
    assert accounts["_www"].system_account and accounts["nobody"].can_login is False
    assert "RealName" not in fixture_text("inventory/dscl_users_uid.txt")
    created = account_event(
        "created", "backdoor", {"uid": 502, "shell": "/bin/zsh"}, src, observed_at=NOW, snapshot="s"
    )
    assert created.event_type == "account.user.created"
    assert (
        created.actor is not None and created.actor.name == "backdoor" and created.actor.id == "502"
    )
    assert (
        validate_event_semantics(created.event_type, created.category.value, "macos.inventory")
        is None
    )


def test_listener_event_fields(src: SourceContext) -> None:
    listeners = listeners_from_lsof(
        parse_lsof_fields(fixture_text("inventory/lsof_tcp_listen.txt"))
    )
    key = "tcp:0.0.0.0:7000"
    opened = listener_event("opened", key, listeners[key], None, src, observed_at=NOW, snapshot="s")
    assert opened.event_type == "network.listener.opened"
    assert opened.network is not None and opened.network.dst_port == 7000
    assert opened.process is not None and opened.process.name == "ControlCenter"
    closed = listener_event(
        "closed", key, None, listeners[key].summary(), src, observed_at=NOW, snapshot="s"
    )
    assert closed.event_type == "network.listener.closed" and closed.network is not None
    assert closed.network.dst_ip == "0.0.0.0"  # noqa: S104 - wildcard bind address observed

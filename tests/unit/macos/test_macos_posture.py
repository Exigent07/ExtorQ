"""Posture parsers, check evaluation and ScanRun/finding records (real command output)."""

from __future__ import annotations

from datetime import UTC, datetime

from macos_helpers import ASSET, FakeRunner, failed, fixture_bytes, fixture_text, ok

from extorq.contracts import ScanStatus, Severity
from extorq.contracts.identity import finding_id
from extorq_collectors.macos.common import SourceContext
from extorq_collectors.macos.inventory import (
    LSOF_TCP_LISTEN_ARGV,
    LSOF_UDP_ARGV,
    NETSTAT_TCP,
    NETSTAT_UDP,
)
from extorq_collectors.macos.posture import (
    COMMANDS,
    SCANNER,
    PostureOptions,
    build_scan_records,
    offered_os_updates,
    parse_authenticated_root,
    parse_csrutil,
    parse_dscl_members,
    parse_fdesetup,
    parse_firewall_allowsigned,
    parse_firewall_global,
    parse_firewall_stealth,
    parse_plist_export,
    parse_spctl,
    parse_sw_vers,
    run_posture,
    setting_change_event,
    settings_changes,
)

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def posture_runner(*, netstat_withheld: bool = True) -> FakeRunner:
    runner = FakeRunner()
    files = {
        "fdesetup": "posture/fdesetup_status.txt",
        "csrutil": "posture/csrutil_status.txt",
        "csrutil_authroot": "posture/csrutil_authenticated_root.txt",
        "fw_global": "posture/socketfilterfw_globalstate.txt",
        "fw_stealth": "posture/socketfilterfw_stealthmode.txt",
        "fw_allowsigned": "posture/socketfilterfw_allowsigned.txt",
        "spctl": "posture/spctl_status.txt",
        "guest": "posture/loginwindow_guestenabled.txt",
        "admins": "posture/dscl_admin.txt",
        "sw_vers": "posture/sw_vers.txt",
        "hw_model": "posture/sysctl_hw_model.txt",
    }
    for name, path in files.items():
        runner.add(COMMANDS[name], ok(COMMANDS[name], fixture_bytes(path)))
    runner.add(
        COMMANDS["su_prefs"],
        ok(COMMANDS["su_prefs"], fixture_bytes("posture/softwareupdate_export.plist")),
    )
    runner.add(
        COMMANDS["commerce_prefs"],
        ok(COMMANDS["commerce_prefs"], fixture_bytes("posture/commerce_export.plist")),
    )
    if netstat_withheld:
        runner.add(NETSTAT_TCP, ok(NETSTAT_TCP, b""))  # observed under the uv runtime
    else:
        runner.add(NETSTAT_TCP, ok(NETSTAT_TCP, fixture_bytes("inventory/netstat_tcp.txt")))
        runner.add(NETSTAT_UDP, ok(NETSTAT_UDP, fixture_bytes("inventory/netstat_udp.txt")))
    runner.add(
        LSOF_TCP_LISTEN_ARGV,
        ok(LSOF_TCP_LISTEN_ARGV, fixture_bytes("inventory/lsof_tcp_listen.txt")),
    )
    runner.add(LSOF_UDP_ARGV, ok(LSOF_UDP_ARGV, b""))
    return runner


def test_parsers_on_real_output() -> None:
    assert parse_fdesetup(fixture_text("posture/fdesetup_status.txt")) == "on"
    assert parse_fdesetup("FileVault is Off.") == "off"
    assert parse_csrutil(fixture_text("posture/csrutil_status.txt")) == "enabled"
    assert parse_csrutil("System Integrity Protection status: disabled.") == "disabled"
    assert (
        parse_authenticated_root(fixture_text("posture/csrutil_authenticated_root.txt"))
        == "enabled"
    )
    assert (
        parse_firewall_global(fixture_text("posture/socketfilterfw_globalstate.txt")) == "disabled"
    )
    assert parse_firewall_global("Firewall is enabled. (State = 1)") == "enabled"
    assert parse_firewall_stealth(fixture_text("posture/socketfilterfw_stealthmode.txt")) == "off"
    assert parse_firewall_allowsigned(fixture_text("posture/socketfilterfw_allowsigned.txt")) == (
        True,
        True,
    )
    assert parse_spctl(fixture_text("posture/spctl_status.txt")) == "enabled"
    assert parse_dscl_members(fixture_text("posture/dscl_admin.txt")) == [
        "_mbsetupuser",
        "root",
        "testuser",
    ]
    assert parse_sw_vers(fixture_text("posture/sw_vers.txt"))["ProductVersion"] == "27.0.1"
    assert parse_fdesetup("garbage") is None and parse_spctl("") is None


def test_offered_os_updates_from_softwareupdate_preferences() -> None:
    prefs = parse_plist_export(fixture_bytes("posture/softwareupdate_export.plist"))
    pending = offered_os_updates(prefs, "27.0.1", NOW)
    assert pending and pending[0]["version"] == "27.2.1"
    assert offered_os_updates(prefs, "99.0", NOW) == []


def test_firewall_disabled_is_a_genuine_finding_and_exposure_scan_is_partial(
    src: SourceContext,
) -> None:
    run = run_posture(posture_runner(), PostureOptions(), lambda: NOW)
    by_check = {r.check_id: r for r in run.results if r.qualifier == ""}
    assert by_check["macos.firewall.enabled"].status == "fail"
    assert by_check["macos.firewall.enabled"].value == "disabled"
    assert by_check["macos.filevault.enabled"].status == "pass"
    assert by_check["macos.sip.enabled"].status == "pass"
    assert by_check["macos.gatekeeper.enabled"].status == "pass"
    assert by_check["macos.accounts.admin_count"].status == "pass"  # one human admin
    # lsof fallback: root-owned listeners invisible -> unknown (error), never "pass"
    assert by_check["macos.sharing.remote_login"].status == "error"
    assert run.listener_method == "lsof"
    scans, findings = build_scan_records(run, src, producer_id="macos-workstation-01")
    status = {s.attributes["scope_name"]: s.status for s in scans}
    assert status == {"configuration": ScanStatus.SUCCEEDED, "exposure": ScanStatus.PARTIAL}
    firewall = next(f for f in findings if f.check_id == "macos.firewall.enabled")
    assert firewall.severity is Severity.MEDIUM and firewall.scanner == SCANNER
    assert firewall.finding_id == finding_id(ASSET, SCANNER, "macos.firewall.enabled", "host", "")
    assert firewall.evidence == "Firewall is disabled. (State = 0)"
    assert {f.scan_run_id for f in findings} <= {s.scan_run_id for s in scans}
    airplay = [f for f in findings if f.check_id == "macos.sharing.airplay_receiver"]
    assert airplay and "ControlCenter" in (airplay[0].evidence or "")


def test_full_socket_table_resolves_sharing_checks(src: SourceContext) -> None:
    run = run_posture(posture_runner(netstat_withheld=False), PostureOptions(), lambda: NOW)
    assert run.listener_method == "netstat"
    remote_login = next(r for r in run.results if r.check_id == "macos.sharing.remote_login")
    assert remote_login.status == "pass"  # nothing on :22 in the captured table
    scans, _ = build_scan_records(run, src, producer_id="macos-workstation-01")
    assert {s.status for s in scans} == {ScanStatus.SUCCEEDED}


def test_command_failure_makes_check_unknown_not_passing(src: SourceContext) -> None:
    runner = posture_runner()
    runner.add(COMMANDS["fdesetup"], ok(COMMANDS["fdesetup"], b"unexpected"))
    run = run_posture(runner, PostureOptions(), lambda: NOW)
    filevault = next(r for r in run.results if r.check_id == "macos.filevault.enabled")
    assert filevault.status == "error"  # unrecognised output is unknown, never a pass
    spawn = posture_runner()
    spawn.add(COMMANDS["spctl"], failed(COMMANDS["spctl"], 1, b"boom"))
    gatekeeper = next(
        r
        for r in run_posture(spawn, PostureOptions(), lambda: NOW).results
        if r.check_id == "macos.gatekeeper.enabled"
    )
    assert gatekeeper.status == "error"
    scans, findings = build_scan_records(run, src, producer_id="macos-workstation-01")
    config = next(s for s in scans if s.attributes["scope_name"] == "configuration")
    assert config.status is ScanStatus.PARTIAL
    assert not any(f.check_id == "macos.filevault.enabled" for f in findings)


def test_setting_changes_become_events(src: SourceContext) -> None:
    changes = settings_changes(
        {"application_firewall": "enabled", "filevault": "on", "x": None},
        {"application_firewall": "disabled", "filevault": "on", "x": "y"},
    )
    assert changes == [("application_firewall", "enabled", "disabled")]
    event = setting_change_event(
        "application_firewall", "enabled", "disabled", src, observed_at=NOW, scan_run_id="r" * 32
    )
    assert event.event_type == "config.security_setting.changed"
    assert event.attributes["previous_value"] == "enabled"
    assert event.attributes["current_value"] == "disabled"

"""sshd / PAM / su / sudo / account-tool / dispatch-denial parsing on REAL lab-vm-01 lines."""

from __future__ import annotations

from dataclasses import replace

from linux_testlib import SELF_UID, entries, find, pctx

from extorq.contracts import ServiceRef
from extorq_collectors.linux import auth
from extorq_collectors.linux.journal import parse_entry

SSH_REF = ServiceRef(service_id="0" * 32, name="ssh", adapter_id="ssh")


def _one(events: list) -> object:
    assert len(events) == 1, events
    return events[0]


def test_invalid_user_vm001_line() -> None:
    entry = find("journal/sshd.ndjson", "Invalid user extorq-test-c7cbc976ecaf")
    event = _one(auth.parse_sshd(entry, pctx(service=SSH_REF)))
    assert event.event_type == "auth.ssh.invalid_user"
    assert event.actor.name == "extorq-test-c7cbc976ecaf"
    assert event.network.src_ip == "10.0.2.2" and event.network.src_port is not None
    assert event.labels == {}  # a detection-test login is ordinary telemetry
    assert event.service == SSH_REF
    assert event.attributes["invalid_user"] is True
    assert event.source.source_native_id == entry.cursor
    assert "source_verified" not in event.attributes  # uid 0 + /usr/sbin/sshd


def test_preauth_close_and_reset() -> None:
    closed = _one(
        auth.parse_sshd(
            find("journal/sshd.ndjson", "Connection closed by invalid user extorq-test-"), pctx()
        )
    )
    assert closed.event_type == "auth.ssh.preauth_closed"
    assert closed.attributes["invalid_user"] is True
    assert closed.attributes["close_kind"] == "connection_closed"
    reset = _one(
        auth.parse_sshd(find("journal/sshd.ndjson", "Connection reset by 10.0.2.2"), pctx())
    )
    assert reset.event_type == "auth.ssh.preauth_closed"
    assert reset.attributes["close_kind"] == "connection_reset"
    assert reset.actor is None  # no user was offered before the reset
    auth_user = _one(
        auth.parse_sshd(
            find("journal/sshd.ndjson", "Connection closed by authenticating user extorq-admin"),
            pctx(),
        )
    )
    assert auth_user.actor.name == "extorq-admin"
    assert auth_user.attributes["authenticating_user"] is True


def test_max_auth_exceeded_both_forms() -> None:
    first = _one(
        auth.parse_sshd(
            find("journal/sshd.ndjson", "maximum authentication attempts exceeded"), pctx()
        )
    )
    second = _one(
        auth.parse_sshd(find("journal/sshd.ndjson", "Too many authentication failures"), pctx())
    )
    for event in (first, second):
        assert event.event_type == "auth.ssh.max_auth_exceeded"
        assert event.attributes["invalid_user"] is True
        assert event.network is not None and event.network.src_ip == "10.0.2.2"
    assert first.attributes["signal"] == "max_attempts_exceeded"
    assert second.attributes["signal"] == "too_many_authentication_failures"


def test_failed_publickey_existing_user_has_fingerprint() -> None:
    event = _one(
        auth.parse_sshd(find("journal/sshd.ndjson", "Failed publickey for extorq-admin"), pctx())
    )
    assert event.event_type == "auth.ssh.login_failed"
    assert event.attributes["auth_method"] == "publickey"
    assert event.attributes["invalid_user"] is False
    assert event.attributes["key_type"] == "ED25519"
    assert event.attributes["key_fingerprint"].startswith("SHA256:")


def test_accepted_publickey_and_self_label() -> None:
    admin = _one(
        auth.parse_sshd(find("journal/sshd.ndjson", "Accepted publickey for extorq-admin"), pctx())
    )
    assert admin.event_type == "auth.ssh.login_succeeded"
    assert admin.outcome.value == "success" and "extorq.self" not in admin.labels
    own = _one(
        auth.parse_sshd(
            find("journal/sshd.ndjson", "Accepted publickey for extorq-collector"), pctx()
        )
    )
    assert own.labels["extorq.self"] == "true"  # the collector's own login is recorded, labelled


def test_session_activity() -> None:
    opened = _one(
        auth.parse_sshd(find("journal/sshd.ndjson", "session opened for user extorq-admin"), pctx())
    )
    assert opened.event_type == "system.log.notable"
    assert opened.action == "ssh.session_opened"
    assert opened.actor.name == "extorq-admin" and opened.attributes["session_uid"] == 1000
    closed = _one(
        auth.parse_sshd(
            find("journal/sshd.ndjson", "session closed for user extorq-collector"), pctx()
        )
    )
    assert closed.action == "ssh.session_closed" and closed.labels["extorq.self"] == "true"


def test_uninteresting_sshd_lines_produce_nothing() -> None:
    for needle in (
        "Connection from 10.0.2.2",
        "Postponed publickey",
        "User child is on pid",
        "Starting session:",
        "Received disconnect from",
        "Server listening on",
    ):
        assert auth.parse_sshd(find("journal/sshd.ndjson", needle), pctx()) == []


def test_forged_sshd_line_becomes_notable_without_service() -> None:
    real = find("journal/sshd.ndjson", "Invalid user extorq-test-c7cbc976ecaf")
    # A local user writing "sshd" lines with logger: kernel-attested uid/exe differ.
    forged = replace(real, uid=1000, exe="/usr/bin/logger", comm="logger")
    event = _one(auth.parse_sshd(forged, pctx(service=SSH_REF)))
    assert event.event_type == "system.log.notable"
    assert event.attributes["forged_identity_suspected"] is True
    assert event.service is None


def test_hostile_user_name_cannot_spoof_source_address() -> None:
    real = find("journal/sshd.ndjson", "Invalid user extorq-test-c7cbc976ecaf")
    # SYNTHETIC (derived from a real line): user name containing a fake "from ... port" part.
    hostile = replace(real, message="Invalid user a from 6.6.6.6 port 1 from 10.0.2.2 port 4242")
    event = _one(auth.parse_sshd(hostile, pctx()))
    assert event.network.src_ip == "10.0.2.2" and event.network.src_port == 4242
    assert event.actor.name == "a from 6.6.6.6 port 1"


def test_pam_su_failure_and_failed_su() -> None:
    pam = find("journal/su_pam.ndjson", "pam_unix(su:auth): authentication failure")
    events = parse_entry(pam, pctx())
    event = _one(events)
    assert event.event_type == "auth.pam.failure"
    assert event.actor.name == "extorq-collector"
    assert event.attributes["pam_service"] == "su" and event.attributes["ruser"] == "extorq-admin"
    failed = _one(parse_entry(find("journal/su_pam.ndjson", "FAILED SU"), pctx()))
    assert failed.event_type == "system.log.notable" and failed.action == "su.failed"
    assert failed.actor.name == "extorq-admin" and failed.attributes["run_as"] == "extorq-collector"


def test_sudo_command_from_vm002() -> None:
    entry = find("journal/sudo.ndjson", "COMMAND=/bin/sh -s -- create extorq-test-")
    event = _one(parse_entry(entry, pctx()))
    assert event.event_type == "auth.sudo.command"
    assert event.actor.name == "extorq-admin"
    assert event.attributes["run_as"] == "root" and event.attributes["cwd"] == "/home/extorq-admin"
    assert event.process.executable == "/bin/sh"
    assert event.process.command_line is None and event.raw is None


def test_sudo_not_in_sudoers_with_leading_spaces() -> None:
    entry = find("journal/sudo.ndjson", "user NOT in sudoers")
    assert entry.message.startswith("  nobody")  # real sudo output
    event = _one(parse_entry(entry, pctx()))
    assert event.event_type == "auth.sudo.failure"
    assert event.outcome.value == "denied"
    assert event.actor.name == "nobody" and event.attributes["reason"] == "user NOT in sudoers"


def test_sudo_session_lines_are_context_only() -> None:
    assert (
        parse_entry(find("journal/sudo.ndjson", "pam_unix(sudo:session): session opened"), pctx())
        == []
    )


def test_account_tools_and_dispatch_denials() -> None:
    created = _one(
        parse_entry(find("journal/accounts.ndjson", "new user: name=extorq-test-"), pctx())
    )
    assert created.event_type == "system.log.notable" and created.action == "account.useradd"
    assert created.attributes["account"].startswith("extorq-test-")
    deleted = _one(parse_entry(find("journal/accounts.ndjson", "delete user"), pctx()))
    assert deleted.action == "account.userdel"
    denial = _one(
        parse_entry(find("journal/dispatch_denials.ndjson", "reason=unknown command"), pctx())
    )
    assert denial.action == "dispatch.denied" and denial.outcome.value == "denied"
    assert denial.attributes["boundary_violation"] is True
    assert denial.attributes["first_token"] == "cat"
    assert denial.labels.get("extorq.self") is None or SELF_UID == 1001


def test_every_fixture_line_parses_without_error() -> None:
    for name in (
        "sshd",
        "su_pam",
        "sudo",
        "systemd_pid1",
        "systemd_user_manager",
        "nginx",
        "lab_portal",
        "accounts",
        "dispatch_denials",
        "other",
    ):
        for entry in entries(f"journal/{name}.ndjson"):
            for event in parse_entry(entry, pctx()):
                assert event.asset_id == "linux:lab-vm-01"
                assert event.provenance.raw_sha256 is not None

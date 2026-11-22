"""sshd, PAM and sudo journald lines -> authentication/authorization events.

Formats are those of OpenSSH 9.6 / sudo 1.9 / pam_unix on Ubuntu 24.04 with
``LogLevel VERBOSE`` (fixtures under tests/fixtures/linux/ are real lines
captured from the Ubuntu VM). User names are attacker-controlled and may contain
spaces, so every pattern is anchored at the end and the user group is greedy:
the trailing ``from <ip> port <n>`` written by sshd always wins.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from extorq.contracts import (
    Actor,
    ActorType,
    Network,
    Outcome,
    ProcessInfo,
    SecurityEvent,
    Severity,
    SourceType,
)
from extorq.contracts.identity import sha256_hex
from extorq_collectors.linux.common import (
    SELF_LABEL,
    ParseContext,
    build_event,
    clean,
    severity_from_priority,
)
from extorq_collectors.linux.journal import (
    SUDO_EXES,
    JournalEntry,
    Trust,
    forged_identity_event,
    is_self,
    notable_event,
    process_of,
    trust_by_exe,
    trust_sshd_auth,
)

PARSER_SSHD = "linux-sshd"
PARSER_PAM = "linux-pam"
PARSER_SUDO = "linux-sudo"

_IP = r"(?P<ip>[0-9A-Fa-f:.]{2,45})"
_PORT = r"(?P<port>\d{1,5})"
_KEY = r"(?:: (?P<keytype>[A-Z0-9-]{2,32}) (?P<fp>(?:SHA256|MD5):[A-Za-z0-9+/=:]{8,100}))?"

SSHD_FAILED = re.compile(
    rf"^Failed (?P<method>[a-z0-9-]{{2,40}}(?:/[a-z0-9-]{{1,40}})?) for (?P<invalid>invalid user )?"
    rf"(?P<user>.*) from {_IP} port {_PORT} ssh2{_KEY}$"
)
SSHD_ACCEPTED = re.compile(
    rf"^Accepted (?P<method>[a-z0-9-]{{2,40}}(?:/[a-z0-9-]{{1,40}})?) for (?P<user>.*) "
    rf"from {_IP} port {_PORT} ssh2{_KEY}$"
)
SSHD_INVALID = re.compile(rf"^Invalid user (?P<user>.*) from {_IP} port {_PORT}$")
SSHD_CLOSED = re.compile(
    rf"^Connection (?P<kind>closed|reset) by (?:(?P<who>invalid|authenticating) user "
    rf"(?P<user>.*) )?{_IP} port {_PORT} \[preauth\]$"
)
SSHD_DISCONNECTED = re.compile(
    rf"^Disconnected from (?:(?P<who>invalid|authenticating) user (?P<user>.*) )?"
    rf"{_IP} port {_PORT} \[preauth\]$"
)
SSHD_MAX_EXCEEDED = re.compile(
    rf"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
    rf"(?P<user>.*) from {_IP} port {_PORT} ssh2 \[preauth\]$"
)
SSHD_TOO_MANY = re.compile(
    rf"^Disconnecting (?:(?P<who>invalid|authenticating) user (?P<user>.*) )?{_IP} port {_PORT}: "
    r"Too many authentication failures \[preauth\]$"
)
SSHD_NOT_ALLOWED = re.compile(
    rf"^User (?P<user>.*) from {_IP} not allowed because (?P<reason>.{{1,200}})$"
)

SSHD_SESSION = re.compile(
    r"^pam_unix\(sshd:session\): session (?P<action>opened|closed) for user "
    r"(?P<user>[^\s(]{1,64})(?:\(uid=(?P<uid>\d{1,10})\))?(?: by (?P<by>\S{1,80}))?$"
)

PAM_FAILURE = re.compile(
    r"^pam_unix\((?P<service>[A-Za-z0-9_.-]{1,64}):auth\): authentication failure; (?P<kv>.*)$"
)
_PAM_KV = re.compile(r"(?P<key>logname|uid|euid|tty|ruser|rhost|user)=(?P<value>\S*)")

# sudo 1.9 log line (sudoers(5) "EVENT LOGGING"):
#   "<user> : [<reason> ; ]TTY=.. ; [CHROOT=.. ;] PWD=.. ; USER=.. ; [GROUP=.. ;] [TSID=.. ;]
#    [ENV=<vars> ]COMMAND=<cmd>"   (ENV is separated from COMMAND by one space, not " ; ")
SUDO_LINE = re.compile(r"^\s{0,8}(?P<user>[^\s:]{1,64}) : (?P<rest>.+)$")
_SUDO_KEYS = frozenset({"TTY", "PWD", "USER", "GROUP", "ENV", "CHROOT", "CWD", "TSID"})
#: A wrong password is an authentication failure; a policy refusal is an authorization denial.
_SUDO_PASSWORD_FAILURE = ("incorrect password", "password is required", "authentication failure")
_SUDO_ATTEMPTS = re.compile(r"^(?P<count>\d{1,4}) incorrect password attempts?$")


def _ip_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _port_or_none(value: str | None) -> int | None:
    if value is None or not value.isdigit():
        return None
    port = int(value)
    return port if 0 <= port <= 65535 else None


def _network(ip: str | None, port: str | None) -> Network | None:
    src_ip = _ip_or_none(ip)
    src_port = _port_or_none(port)
    if src_ip is None and src_port is None:
        return None
    return Network(src_ip=src_ip, src_port=src_port, protocol="tcp", direction="inbound")


def _ssh_event(
    entry: JournalEntry,
    ctx: ParseContext,
    *,
    event_type: str,
    action: str,
    outcome: Outcome,
    user: str | None,
    ip: str | None,
    port: str | None,
    attributes: dict[str, Any],
    severity: Severity | None = None,
) -> SecurityEvent:
    user_clean = clean(user) if user is not None else None
    self_activity = is_self(entry, ctx) or (user is not None and user == ctx.self_user)
    return build_event(
        ctx,
        event_type=event_type,
        source_type=SourceType.LINUX_JOURNALD,
        native_key=entry.cursor,
        source_native_id=entry.cursor,
        event_time=entry.time,
        parser=PARSER_SSHD,
        action=action,
        outcome=outcome,
        severity_hint=severity or severity_from_priority(entry.priority),
        actor=Actor(type=ActorType.USER, name=user_clean) if user is not None else None,
        network=_network(ip, port),
        process=ProcessInfo(
            pid=entry.pid, name="sshd", executable=clean(entry.exe, 2048), uid=entry.uid
        ),
        message=entry.message,
        raw=entry.message,
        attributes={**attributes, "boot_id": entry.boot_id},
        is_self=self_activity,
    )


def parse_sshd_session(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    """SSH session activity: ``pam_unix(sshd:session): session opened|closed for user X``.

    Written by the privileged sshd monitor (uid 0). There is no dedicated catalog type for
    session start/end yet (proposal in docs/team/interface-changes/B1.md), so these are
    ``system.log.notable`` with ``action`` ``ssh.session_opened`` / ``ssh.session_closed``.
    """
    match = SSHD_SESSION.match(entry.message)
    if not match:
        return []
    trust = trust_sshd_auth(entry)
    if trust is Trust.MISMATCH:
        return [forged_identity_event(entry, ctx, "sshd")]
    user = match.group("user")
    uid = match.group("uid")
    event = notable_event(
        entry,
        ctx,
        subsystem="sshd",
        action=f"ssh.session_{match.group('action')}",
        trust=trust,
        actor_name=user,
        outcome=Outcome.SUCCESS,
        attributes={"session_uid": int(uid) if uid else None, "pam_service": "sshd"},
    )
    if user == ctx.self_user and SELF_LABEL not in event.labels:
        event = event.model_copy(update={"labels": {**event.labels, SELF_LABEL: "true"}})
    return [event]


def parse_sshd(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    msg = entry.message
    if not msg:
        return []
    if msg.startswith("pam_unix(") and "authentication failure" in msg:
        return parse_pam_failure(entry, ctx)
    if msg.startswith("pam_unix(sshd:session)"):
        return parse_sshd_session(entry, ctx)

    match = SSHD_FAILED.match(msg)
    kind = "failed" if match else None
    if match is None:
        for name, pattern in (
            ("accepted", SSHD_ACCEPTED),
            ("invalid", SSHD_INVALID),
            ("closed", SSHD_CLOSED),
            ("disconnected", SSHD_DISCONNECTED),
            ("max_exceeded", SSHD_MAX_EXCEEDED),
            ("too_many", SSHD_TOO_MANY),
            ("not_allowed", SSHD_NOT_ALLOWED),
        ):
            match = pattern.match(msg)
            if match:
                kind = name
                break
    if match is None or kind is None:
        return []  # session/kex/diagnostic lines: not security events by themselves

    trust = trust_sshd_auth(entry)
    if trust is Trust.MISMATCH:
        return [forged_identity_event(entry, ctx, "sshd")]
    groups = match.groupdict()
    verified: dict[str, Any] = {} if trust is Trust.VERIFIED else {"source_verified": False}
    user = groups.get("user")

    if kind == "failed":
        return [
            _ssh_event(
                entry,
                ctx,
                event_type="auth.ssh.login_failed",
                action="ssh.login",
                outcome=Outcome.FAILURE,
                user=user,
                ip=groups["ip"],
                port=groups["port"],
                attributes={
                    **verified,
                    "auth_method": groups["method"],
                    "invalid_user": groups.get("invalid") is not None,
                    "key_type": groups.get("keytype"),
                    "key_fingerprint": groups.get("fp"),
                },
            )
        ]
    if kind == "accepted":
        return [
            _ssh_event(
                entry,
                ctx,
                event_type="auth.ssh.login_succeeded",
                action="ssh.login",
                outcome=Outcome.SUCCESS,
                user=user,
                ip=groups["ip"],
                port=groups["port"],
                attributes={
                    **verified,
                    "auth_method": groups["method"],
                    "key_type": groups.get("keytype"),
                    "key_fingerprint": groups.get("fp"),
                },
            )
        ]
    if kind == "invalid":
        return [
            _ssh_event(
                entry,
                ctx,
                event_type="auth.ssh.invalid_user",
                action="ssh.login",
                outcome=Outcome.FAILURE,
                user=user,
                ip=groups["ip"],
                port=groups["port"],
                attributes={**verified, "invalid_user": True},
            )
        ]
    if kind in ("closed", "disconnected"):
        who = groups.get("who")
        close_kind = "disconnected" if kind == "disconnected" else f"connection_{groups['kind']}"
        return [
            _ssh_event(
                entry,
                ctx,
                event_type="auth.ssh.preauth_closed",
                action="ssh.preauth_close",
                outcome=Outcome.FAILURE if who == "invalid" else Outcome.UNKNOWN,
                user=user,
                ip=groups["ip"],
                port=groups["port"],
                attributes={
                    **verified,
                    "invalid_user": who == "invalid" if who else None,
                    "authenticating_user": who == "authenticating" if who else None,
                    "close_kind": close_kind,
                },
            )
        ]
    if kind in ("max_exceeded", "too_many"):
        invalid = groups.get("invalid") is not None or groups.get("who") == "invalid"
        return [
            _ssh_event(
                entry,
                ctx,
                event_type="auth.ssh.max_auth_exceeded",
                action="ssh.login",
                outcome=Outcome.FAILURE,
                user=user,
                ip=groups["ip"],
                port=groups["port"],
                attributes={
                    **verified,
                    "invalid_user": invalid,
                    "signal": "max_attempts_exceeded"
                    if kind == "max_exceeded"
                    else "too_many_authentication_failures",
                },
            )
        ]
    # kind == "not_allowed": an existing account (e.g. root) refused by AllowUsers/DenyUsers.
    # sshd then treats the login as an invalid user, so the failures that follow are
    # auth.ssh.preauth_closed / max_auth_exceeded with invalid_user=true. The line itself has
    # no port and no catalog type of its own: it stays notable context, but its peer address
    # goes where correlation looks for it (network.src_ip).
    src_ip = _ip_or_none(groups.get("ip"))
    return [
        notable_event(
            entry,
            ctx,
            subsystem="sshd",
            action="ssh.user_not_allowed",
            trust=trust,
            actor_name=user,
            outcome=Outcome.DENIED,
            attributes={"reason": groups.get("reason"), "invalid_user": True},
            network=Network(src_ip=src_ip, protocol="tcp", direction="inbound") if src_ip else None,
        )
    ]


def parse_pam_failure(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    match = PAM_FAILURE.match(entry.message)
    if not match:
        return []
    service = match.group("service")
    fields = {m.group("key"): m.group("value") for m in _PAM_KV.finditer(match.group("kv"))}
    rhost = fields.get("rhost") or None
    src_ip = _ip_or_none(rhost)
    user = fields.get("user") or None
    verified: dict[str, Any] = {}
    if entry.uid is not None and entry.uid != 0 and service in ("sshd", "login"):
        return [forged_identity_event(entry, ctx, entry.identifier or service)]
    if entry.exe is None:
        verified["source_verified"] = False
    return [
        build_event(
            ctx,
            event_type="auth.pam.failure",
            source_type=SourceType.LINUX_JOURNALD,
            native_key=entry.cursor,
            source_native_id=entry.cursor,
            event_time=entry.time,
            parser=PARSER_PAM,
            action="pam.auth",
            outcome=Outcome.FAILURE,
            severity_hint=severity_from_priority(entry.priority),
            actor=Actor(type=ActorType.USER, name=clean(user)) if user else None,
            network=Network(src_ip=src_ip, direction="inbound") if src_ip else None,
            process=process_of(entry),
            message=entry.message,
            raw=entry.message,
            attributes={
                **verified,
                "pam_service": service,
                "tty": fields.get("tty") or None,
                "ruser": fields.get("ruser") or None,
                "rhost": rhost if src_ip is None else None,
                "logname": fields.get("logname") or None,
                "uid": fields.get("uid") or None,
                "euid": fields.get("euid") or None,
                "boot_id": entry.boot_id,
            },
            is_self=is_self(entry, ctx),
        )
    ]


def _split_sudo(rest: str) -> tuple[str | None, dict[str, str], str | None]:
    """Split ``[reason ; ]KEY=value ; ... ; [ENV=vars ]COMMAND=cmd`` into its parts.

    COMMAND is always the last field and its value may itself contain `` ; `` (shell
    arguments), so the command starts at the first ``COMMAND=`` that sits on a field
    boundary: after `` ; `` or, when environment variables were passed, after ``ENV=...``
    and a single space.
    """
    command = None
    head = rest
    marker = rest.find(" ; COMMAND=")
    if marker >= 0:
        command, head = rest[marker + len(" ; COMMAND=") :], rest[:marker]
    elif rest.startswith("COMMAND="):
        command, head = rest[len("COMMAND=") :], ""
    reason = None
    fields: dict[str, str] = {}
    for part in [p.strip() for p in head.split(" ; ") if p.strip()]:
        key, sep, value = part.partition("=")
        if sep and key in _SUDO_KEYS:
            if key == "ENV" and command is None and " COMMAND=" in value:
                value, _, command = value.partition(" COMMAND=")
            fields[key] = value
        elif reason is None and not sep:
            reason = part
    return reason, fields, command


def parse_sudo(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    msg = entry.message
    if msg.startswith("pam_unix("):
        if "authentication failure" in msg:
            return parse_pam_failure(entry, ctx)
        return []  # session opened/closed: context only
    match = SUDO_LINE.match(msg)
    if not match:
        return []
    reason, fields, command = _split_sudo(match.group("rest"))
    if command is None and reason is None:
        return []
    trust = trust_by_exe(entry, SUDO_EXES)
    if trust is Trust.MISMATCH:
        return [forged_identity_event(entry, ctx, "sudo")]
    user = match.group("user")
    first = command.split(maxsplit=1)[0] if command and command.strip() else ""
    executable = clean(first) if first.startswith("/") else None
    failure = reason is not None
    password_failure = failure and any(h in (reason or "").lower() for h in _SUDO_PASSWORD_FAILURE)
    attempts = _SUDO_ATTEMPTS.match(reason.strip()) if reason else None
    attrs: dict[str, Any] = {
        "run_as": fields.get("USER"),
        "run_as_group": fields.get("GROUP"),
        "tty": fields.get("TTY"),
        "cwd": fields.get("PWD") or fields.get("CWD"),
        "reason": reason,
        "failure_kind": ("authentication" if password_failure else "policy") if failure else None,
        # sudo logs one record per invocation with the number of wrong passwords.
        "failed_attempts": int(attempts.group("count")) if attempts else None,
        # ENV= values can carry secrets: record only that variables were passed.
        "env_specified": True if "ENV" in fields else None,
        "boot_id": entry.boot_id,
    }
    if trust is not Trust.VERIFIED:
        attrs["source_verified"] = False
    return [
        build_event(
            ctx,
            event_type="auth.sudo.failure" if failure else "auth.sudo.command",
            source_type=SourceType.LINUX_JOURNALD,
            native_key=entry.cursor,
            source_native_id=entry.cursor,
            event_time=entry.time,
            parser=PARSER_SUDO,
            action="sudo",
            outcome=(Outcome.FAILURE if password_failure else Outcome.DENIED)
            if failure
            else Outcome.SUCCESS,
            severity_hint=severity_from_priority(entry.priority),
            actor=Actor(type=ActorType.USER, name=clean(user)),
            process=ProcessInfo(
                pid=entry.pid,
                name=clean(executable.rsplit("/", 1)[-1]) if executable else None,
                executable=executable,
                user=clean(fields.get("USER")),
            ),
            message=(
                f"sudo: {user} {'denied' if failure else 'ran'} "
                f"{executable or 'command'} as {fields.get('USER', '?')}"
            ).strip(),
            raw_sha256=sha256_hex(msg),
            attributes=attrs,
            is_self=is_self(entry, ctx),
        )
    ]

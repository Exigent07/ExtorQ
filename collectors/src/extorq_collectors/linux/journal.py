"""journald entries: model, source verification and routing to parsers.

Any local user can write a syslog line with an arbitrary ``SYSLOG_IDENTIFIER``
(``logger -t sshd "Failed password for root ..."``). Fields starting with ``_``
(``_UID``, ``_PID``, ``_EXE``, ``_COMM``, ``_SYSTEMD_UNIT``, ``_TRANSPORT``) are
added by journald from kernel credentials and ``/proc`` and cannot be set by the
sender. Before a line is parsed as security telemetry its claimed identity is
checked against these trusted fields:

* ``verified``: trusted fields match the expected program;
* ``unverified``: the expected fields are missing (journald reads ``/proc``
  after receiving the datagram; very short-lived processes lose that race);
  the event is still produced with ``attributes.source_verified=false``;
* ``mismatch``: trusted fields contradict the claim. The line is NOT parsed as
  the claimed program; it becomes ``system.log.notable`` with
  ``attributes.forged_identity_suspected=true``.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from extorq.contracts import Actor, ActorType, Outcome, ProcessInfo, SecurityEvent, SourceType

from extorq_collectors.linux.common import (
    ParseContext,
    build_event,
    clean,
    from_epoch_us,
    severity_from_priority,
)

PARSER_NOTABLE = "linux-journald-notable"

_CURSOR_RE = re.compile(
    r"^s=[0-9a-f]{32};i=[0-9a-f]{1,16};b=[0-9a-f]{32};m=[0-9a-f]{1,16};"
    r"t=[0-9a-f]{1,16};x=[0-9a-f]{1,16}$"
)
_INT_RE = re.compile(r"^[0-9]{1,10}$")
MAX_MESSAGE_CHARS = 8192


class Trust(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    MISMATCH = "mismatch"


@dataclass(frozen=True, slots=True)
class JournalEntry:
    cursor: str
    time: datetime
    boot_id: str | None
    hostname: str | None
    identifier: str | None
    unit: str | None
    pid: int | None
    uid: int | None
    comm: str | None
    exe: str | None
    transport: str | None
    priority: int | None
    message: str


def _int_field(value: Any) -> int | None:
    if isinstance(value, str) and _INT_RE.match(value):
        return int(value)
    return None


def _str_field(value: Any, limit: int = 512) -> str | None:
    if isinstance(value, str) and value:
        return value[:limit]
    return None


def entry_from_json(obj: dict[str, Any]) -> JournalEntry | None:
    """Validate one dispatched journald entry; None if structurally invalid."""
    cursor = obj.get("__CURSOR")
    realtime = obj.get("__REALTIME_TIMESTAMP")
    if not isinstance(cursor, str) or not _CURSOR_RE.match(cursor):
        return None
    if not isinstance(realtime, str) or not realtime.isdigit() or len(realtime) > 19:
        return None
    message = obj.get("MESSAGE")
    priority = _int_field(obj.get("PRIORITY"))
    return JournalEntry(
        cursor=cursor,
        time=from_epoch_us(int(realtime)),
        boot_id=_str_field(obj.get("_BOOT_ID"), 64),
        hostname=_str_field(obj.get("_HOSTNAME"), 256),
        identifier=_str_field(obj.get("SYSLOG_IDENTIFIER"), 128),
        unit=_str_field(obj.get("_SYSTEMD_UNIT"), 256),
        pid=_int_field(obj.get("_PID")),
        uid=_int_field(obj.get("_UID")),
        comm=_str_field(obj.get("_COMM"), 64),
        exe=_str_field(obj.get("_EXE"), 1024),
        transport=_str_field(obj.get("_TRANSPORT"), 32),
        priority=priority if priority is not None and priority <= 7 else None,
        message=message[:MAX_MESSAGE_CHARS] if isinstance(message, str) else "",
    )


# ── trust checks ──────────────────────────────────────────────────────────────

SSHD_EXES = frozenset({"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session",
                       "/usr/lib/openssh/sshd-auth"})
SUDO_EXES = frozenset({"/usr/bin/sudo"})
SYSTEMD_EXES = frozenset({"/usr/lib/systemd/systemd", "/lib/systemd/systemd"})
PYTHON_EXE_RE = re.compile(r"^/usr/bin/python3(\.[0-9]{1,2})?$")


def trust_by_exe(entry: JournalEntry, allowed: frozenset[str]) -> Trust:
    if entry.exe is None:
        return Trust.UNVERIFIED
    return Trust.VERIFIED if entry.exe in allowed else Trust.MISMATCH


def trust_sshd_auth(entry: JournalEntry) -> Trust:
    """sshd authentication lines are only ever written by the root monitor."""
    if entry.uid is not None and entry.uid != 0:
        return Trust.MISMATCH
    trust = trust_by_exe(entry, SSHD_EXES)
    if trust is Trust.UNVERIFIED and entry.uid == 0:
        return Trust.VERIFIED  # kernel-attested root sender, /proc race lost
    return trust


def trust_unit(entry: JournalEntry, unit: str) -> Trust:
    """Units come from the sender's cgroup; joining one requires root."""
    if entry.unit is None:
        return Trust.UNVERIFIED
    return Trust.VERIFIED if entry.unit == unit else Trust.MISMATCH


def is_self(entry: JournalEntry, ctx: ParseContext) -> bool:
    return ctx.self_uid is not None and entry.uid == ctx.self_uid


def process_of(entry: JournalEntry, name: str | None = None) -> ProcessInfo:
    return ProcessInfo(
        pid=entry.pid,
        name=clean(name or entry.comm, 256),
        executable=clean(entry.exe, 2048),
        uid=entry.uid,
    )


def forged_identity_event(entry: JournalEntry, ctx: ParseContext, claimed: str) -> SecurityEvent:
    """A line whose claimed program contradicts journald's trusted fields."""
    return build_event(
        ctx,
        event_type="system.log.notable",
        source_type=SourceType.LINUX_JOURNALD,
        native_key=entry.cursor,
        source_native_id=entry.cursor,
        event_time=entry.time,
        parser=PARSER_NOTABLE,
        action="forged_identity_suspected",
        outcome=Outcome.UNKNOWN,
        severity_hint=severity_from_priority(entry.priority),
        actor=Actor(type=ActorType.USER if entry.uid else ActorType.UNKNOWN,
                    id=str(entry.uid) if entry.uid is not None else None),
        process=process_of(entry),
        message=entry.message,
        raw=entry.message,
        attributes={
            "subsystem": claimed,
            "claimed_identifier": claimed,
            "forged_identity_suspected": True,
            "sender_uid": entry.uid,
            "sender_pid": entry.pid,
            "sender_exe": entry.exe,
            "sender_comm": entry.comm,
            "sender_unit": entry.unit,
            "transport": entry.transport,
            "boot_id": entry.boot_id,
        },
        is_self=is_self(entry, ctx),
    )


def notable_event(entry: JournalEntry, ctx: ParseContext, *, subsystem: str, action: str,
                  trust: Trust, actor_name: str | None = None,
                  attributes: dict[str, Any] | None = None,
                  outcome: Outcome = Outcome.UNKNOWN) -> SecurityEvent:
    attrs: dict[str, Any] = {"subsystem": subsystem, "boot_id": entry.boot_id,
                             "transport": entry.transport}
    if trust is not Trust.VERIFIED:
        attrs["source_verified"] = False
    attrs.update(attributes or {})
    return build_event(
        ctx,
        event_type="system.log.notable",
        source_type=SourceType.LINUX_JOURNALD,
        native_key=entry.cursor,
        source_native_id=entry.cursor,
        event_time=entry.time,
        parser=PARSER_NOTABLE,
        action=action,
        outcome=outcome,
        severity_hint=severity_from_priority(entry.priority),
        actor=Actor(type=ActorType.USER, name=clean(actor_name)) if actor_name else None,
        process=process_of(entry),
        message=entry.message,
        raw=entry.message,
        attributes=attrs,
        is_self=is_self(entry, ctx),
    )


# ── account-management and boundary lines kept as notable context ─────────────

ACCOUNT_TOOLS = frozenset({"useradd", "userdel", "usermod", "groupadd", "groupdel", "groupmod",
                           "gpasswd", "passwd", "chpasswd", "chage", "chsh", "chfn"})
_ACCOUNT_NAME = re.compile(r"(?:name=|user ')([a-z_][a-z0-9_.-]{0,31})")
_SU_LINE = re.compile(r"^(?:\(to (?P<target>[^)]{1,64})\) (?P<user>\S{1,64}) on (?P<tty>\S{1,64})"
                      r"|FAILED SU \(to (?P<ftarget>[^)]{1,64})\) (?P<fuser>\S{1,64}) on (?P<ftty>\S+))$")
_DENIAL = re.compile(r"^denied command: first_token=(?P<token>\S{1,16}) length=(?P<length>\d{1,6}) "
                     r"sha256=(?P<sha>[0-9a-f]{16}) reason=(?P<reason>.{1,120})$")


def parse_account_tool(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    ident = entry.identifier or ""
    trust = trust_by_exe(entry, frozenset({f"/usr/sbin/{ident}", f"/usr/bin/{ident}"}))
    if trust is Trust.MISMATCH:
        return [forged_identity_event(entry, ctx, ident)]
    match = _ACCOUNT_NAME.search(entry.message)
    return [notable_event(entry, ctx, subsystem=ident, action=f"account.{ident}", trust=trust,
                          attributes={"account": match.group(1) if match else None})]


def parse_su(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    match = _SU_LINE.match(entry.message)
    if not match:
        return []
    trust = trust_by_exe(entry, frozenset({"/usr/bin/su"}))
    if trust is Trust.MISMATCH:
        return [forged_identity_event(entry, ctx, "su")]
    failed = match.group("fuser") is not None
    return [notable_event(
        entry, ctx, subsystem="su", action="su.failed" if failed else "su.session", trust=trust,
        actor_name=match.group("fuser") or match.group("user"),
        outcome=Outcome.FAILURE if failed else Outcome.SUCCESS,
        attributes={"run_as": match.group("ftarget") or match.group("target"),
                    "tty": match.group("ftty") or match.group("tty")},
    )]


def parse_dispatch_denial(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    """The VM-side dispatcher refused a command sent with the collector key."""
    match = _DENIAL.match(entry.message)
    if not match:
        return []
    if entry.exe is not None and not PYTHON_EXE_RE.match(entry.exe):
        return [forged_identity_event(entry, ctx, "extorq-collect-dispatch")]
    trust = Trust.VERIFIED if entry.exe else Trust.UNVERIFIED
    return [notable_event(
        entry, ctx, subsystem="extorq-collect-dispatch", action="dispatch.denied", trust=trust,
        outcome=Outcome.DENIED,
        attributes={"boundary_violation": True, "first_token": match.group("token"),
                    "command_length": int(match.group("length")),
                    "command_sha256_prefix": match.group("sha"),
                    "reason": match.group("reason")},
    )]


# ── routing ───────────────────────────────────────────────────────────────────

ParserFn = Callable[[JournalEntry, ParseContext], list[SecurityEvent]]


def _routes() -> dict[str, ParserFn]:
    from extorq_collectors.linux import auth, http, systemd  # local import: avoid cycles

    routes: dict[str, ParserFn] = {
        "sshd": auth.parse_sshd,
        "sshd-session": auth.parse_sshd,
        "sudo": auth.parse_sudo,
        "systemd": systemd.parse_systemd,
        "nginx_access": http.parse_nginx_access,
        "lab-portal": http.parse_lab_portal,
        "su": parse_su,
        "extorq-collect-dispatch": parse_dispatch_denial,
    }
    for tool in ACCOUNT_TOOLS:
        routes[tool] = parse_account_tool
    return routes


_ROUTES: dict[str, ParserFn] | None = None


def parse_entry(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    """Route one journald entry to its parser. Unrecognised lines yield []."""
    global _ROUTES
    if _ROUTES is None:
        _ROUTES = _routes()
    parser = _ROUTES.get(entry.identifier or "")
    if parser is not None:
        return parser(entry, ctx)
    from extorq_collectors.linux import auth

    if "pam_unix(" in entry.message and "authentication failure" in entry.message:
        return auth.parse_pam_failure(entry, ctx)
    return []

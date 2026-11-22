"""macOS Unified Logging: bounded incremental collection of security-relevant producers.

Collection: ``/usr/bin/log show --style ndjson --start @<s> --end @<e> --predicate P``
over a short window. The predicate is assembled from a fixed table of named
*producers* (:data:`PRODUCERS`); configuration can only enable/disable names, it
cannot inject predicate text. Each producer was validated on macOS 27.0.1
(see docs/telemetry/macos.md for which ones produced data on the reference host).

Limits that apply regardless of this code (documented as collection gaps):

* Unified logging replaces dynamic message arguments with ``<private>`` unless
  the producer marked them public (e.g. the user name in opendirectoryd
  authentication failures). Recovering them requires a configuration profile
  or root; ExtorQ does neither.
* Unified logging is not an audit trail: retention is size-bounded, messages can
  be rate limited, and process-execution telemetry is not available here at all
  (that requires an Endpoint Security entitlement).
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
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
from extorq.contracts.identity import canonical_json, content_key
from extorq_collectors.macos.common import (
    SourceContext,
    clean_text,
    make_event,
)

LOG_BINARY = "/usr/bin/log"
PARSER = "macos-unified-log"
SOURCE = SourceType.MACOS_UNIFIED_LOG

# ── Producers (predicate fragments are constants; config selects names only) ──


@dataclass(frozen=True, slots=True)
class Producer:
    name: str
    predicate: str
    description: str


PRODUCERS: dict[str, Producer] = {
    p.name: p
    for p in (
        Producer(
            "sudo",
            'process == "sudo"',
            "sudo command and denial records (syslog-format, public).",
        ),
        Producer(
            "sshd",
            'process == "sshd" OR process == "sshd-session" OR process == "sshd-auth"',
            "OpenSSH server records (only when Remote Login is enabled).",
        ),
        Producer(
            "screensharing",
            'process == "screensharingd"',
            "Screen Sharing / VNC authentication records (only when enabled).",
        ),
        Producer(
            "opendirectory_auth",
            'subsystem == "com.apple.opendirectoryd" AND category == "auth" '
            'AND eventMessage BEGINSWITH "Authentication failed for"',
            "Local account password verification failures (one per failed attempt).",
        ),
        Producer(
            "authorization",
            'subsystem == "com.apple.Authorization" '
            'AND eventMessage BEGINSWITH "Failed to authorize"',
            "authd authorization-right denials (e.g. wrong admin password in a prompt).",
        ),
        Producer(
            "screen_lock",
            'subsystem == "com.apple.loginwindow.logging" '
            'AND eventMessage CONTAINS "authFailWithMessage:numFailedAttempts:] | enter."',
            "Failed screen-lock unlock attempts reported by loginwindow.",
        ),
        Producer(
            "xprotect",
            '(subsystem == "com.apple.XProtectFramework.PluginAPI" '
            'AND category == "XPEvent.structured") '
            'OR (subsystem == "com.apple.XProtectFramework" AND category == "Runner" '
            'AND (eventMessage BEGINSWITH "Starting system scan" '
            'OR eventMessage BEGINSWITH "Finished system scan")) '
            'OR (subsystem == "com.apple.xprotect" '
            'AND eventMessage BEGINSWITH "Forwarding detection")',
            "XProtect Remediator results, XProtect scan lifecycle, behaviour-detection forwarding.",
        ),
        Producer(
            "gatekeeper",
            'subsystem == "com.apple.syspolicy.exec" AND (eventMessage BEGINSWITH "GK " '
            'OR eventMessage BEGINSWITH "Prompt shown" '
            'OR eventMessage BEGINSWITH "Allowing code due to" '
            'OR eventMessage BEGINSWITH "Marked application as user approved")',
            "Gatekeeper (syspolicyd) assessments, first-launch prompts and user approvals.",
        ),
    )
}

DEFAULT_PRODUCERS: tuple[str, ...] = tuple(PRODUCERS)

#: Process names of Apple's OpenSSH server. macOS 27.0.1 ships OpenSSH 10.3p1, which splits
#: the server into ``sshd`` (listener), ``sshd-session`` (privileged monitor, writes the
#: authentication results) and ``sshd-auth`` (pre-authentication).
SSHD_PROCESSES: frozenset[str] = frozenset({"sshd", "sshd-session", "sshd-auth"})
#: Image paths of those binaries on the sealed system volume. Unified logging records the
#: kernel-attested image path of the process that wrote a record, and nothing but Apple can
#: write below /usr on the sealed volume, so only these paths are Remote Login. A process
#: merely *named* sshd elsewhere (a copied binary, a third-party OpenSSH build) is reported
#: as an unverified sender (``system.log.notable``) and never as ``auth.ssh.*`` evidence.
SSHD_TRUSTED_PATHS: frozenset[str] = frozenset(
    {"/usr/sbin/sshd", "/usr/libexec/sshd-session", "/usr/libexec/sshd-auth"}
)
SCREENSHARINGD_PATH = (
    "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/"
    "screensharingd"
)
SCREENSHARING_TRUSTED_PATHS: frozenset[str] = frozenset({SCREENSHARINGD_PATH})


def build_predicate(names: Iterable[str]) -> str:
    """OR-combine the predicate fragments of the named producers (order preserved)."""
    selected: list[str] = []
    for name in names:
        producer = PRODUCERS.get(name)
        if producer is None:
            raise ValueError(f"unknown unified-log producer {name!r}")
        fragment = f"({producer.predicate})"
        if fragment not in selected:
            selected.append(fragment)
    if not selected:
        raise ValueError("at least one unified-log producer must be enabled")
    return " OR ".join(selected)


def build_log_show_argv(start_epoch: int, end_epoch: int, predicate: str) -> list[str]:
    """``log show`` arguments for the closed window [start, end] (integer epoch seconds)."""
    if end_epoch < start_epoch:
        raise ValueError("window end precedes start")
    return [
        LOG_BINARY,
        "show",
        "--style",
        "ndjson",
        "--no-pager",
        "--color",
        "none",
        "--timezone",
        "UTC",
        "--start",
        f"@{int(start_epoch)}",
        "--end",
        f"@{int(end_epoch)}",
        "--predicate",
        predicate,
    ]


# ── Records ──────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class LogRecord:
    """The subset of a unified-log ndjson record ExtorQ uses (all values untrusted)."""

    timestamp: datetime
    event_message: str
    process_path: str | None
    process_id: int | None
    sender_path: str | None
    subsystem: str | None
    category: str | None
    message_type: str | None
    user_id: int | None
    boot_uuid: str | None
    mach_timestamp: int | None
    thread_id: int | None
    trace_id: int | None
    raw_line: bytes = field(repr=False, default=b"")

    @property
    def process_name(self) -> str | None:
        return os.path.basename(self.process_path) if self.process_path else None


@dataclass(slots=True)
class ParseStats:
    lines: int = 0
    records: int = 0
    invalid_json: int = 0
    invalid_record: int = 0
    trailer_count: int | None = None
    finished: bool = False


_TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z")


def parse_timestamp(value: str) -> datetime | None:
    """Parse ``2026-11-21 10:10:55.053142+0000`` into an aware UTC datetime."""
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(value, fmt).astimezone(UTC)
        except ValueError:
            continue
    return None


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _str_or_none(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def parse_record(obj: dict[str, Any], raw_line: bytes = b"") -> LogRecord | None:
    """Validate the fields we rely on; return ``None`` for records we cannot use."""
    ts_value = obj.get("timestamp")
    message = obj.get("eventMessage")
    if not isinstance(ts_value, str) or not isinstance(message, str):
        return None
    timestamp = parse_timestamp(ts_value)
    if timestamp is None:
        return None
    pid = _int_or_none(obj.get("processID"))
    return LogRecord(
        timestamp=timestamp,
        event_message=message,
        process_path=_str_or_none(obj.get("processImagePath")),
        process_id=pid if pid is not None and pid >= 0 else None,
        sender_path=_str_or_none(obj.get("senderImagePath")),
        subsystem=_str_or_none(obj.get("subsystem")),
        category=_str_or_none(obj.get("category")),
        message_type=_str_or_none(obj.get("messageType")),
        user_id=_int_or_none(obj.get("userID")),
        boot_uuid=_str_or_none(obj.get("bootUUID")),
        mach_timestamp=_int_or_none(obj.get("machTimestamp")),
        thread_id=_int_or_none(obj.get("threadID")),
        trace_id=_int_or_none(obj.get("traceID")),
        raw_line=raw_line,
    )


def parse_ndjson(data: bytes, *, max_records: int) -> tuple[list[LogRecord], ParseStats]:
    """Parse ``log show --style ndjson`` output.

    The final ``{"count":N,"finished":1}`` trailer is recognised and not treated
    as a record. A trailing partial line (output cut at the byte limit) is
    ignored. Parsing stops after ``max_records`` records.
    """
    stats = ParseStats()
    records: list[LogRecord] = []
    lines = data.split(b"\n")
    if data and not data.endswith(b"\n"):
        lines = lines[:-1]  # incomplete final line (truncated output)
    for line in lines:
        line = line.strip()
        if not line:
            continue
        stats.lines += 1
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            stats.invalid_json += 1
            continue
        if not isinstance(obj, dict):
            stats.invalid_json += 1
            continue
        if "finished" in obj and "eventMessage" not in obj:
            stats.finished = bool(obj.get("finished"))
            count = obj.get("count")
            stats.trailer_count = count if isinstance(count, int) else None
            continue
        record = parse_record(obj, raw_line=line)
        if record is None:
            stats.invalid_record += 1
            continue
        records.append(record)
        stats.records += 1
        if len(records) >= max_records:
            break
    return records, stats


def native_key(record: LogRecord) -> str:
    """Source-native identity: boot UUID + mach timestamp + thread + trace id.

    Falls back to a content key when the identifying fields are missing.
    """
    if record.mach_timestamp is not None and record.thread_id is not None:
        return (
            f"{record.boot_uuid or '-'}:{record.mach_timestamp}:{record.thread_id}:"
            f"{record.trace_id if record.trace_id is not None else '-'}"
        )
    return "content:" + content_key(
        record.timestamp.isoformat(),
        record.process_path,
        record.process_id,
        record.subsystem,
        record.category,
        record.event_message,
    )


# ── Classification ───────────────────────────────────────────────────


@dataclass(slots=True)
class Classified:
    event_type: str
    producer: str
    action: str | None = None
    outcome: Outcome = Outcome.UNKNOWN
    severity_hint: Severity | None = None
    actor: Actor | None = None
    network: Network | None = None
    command_line: str | None = None
    executable_override: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


_MESSAGE_TYPE_SEVERITY = {
    "Fault": Severity.HIGH,
    "Error": Severity.MEDIUM,
    "Default": Severity.INFO,
    "Info": Severity.INFO,
    "Debug": Severity.INFO,
}

# sudo records (sudoers(5) "EVENT LOGGING", sudo 1.9.17p2 as installed on macOS 27):
#   accepted: "<user> : TTY=<tty> ; [CHROOT=..] ; PWD=<cwd> ; USER=<runas> ; [GROUP=..] ;
#              [TSID=..] ; [ENV=<vars> ]COMMAND=<cmd>"
#   denied:   "<user> : <reason> ; TTY=<tty> ; PWD=<cwd> ; USER=<runas> ; COMMAND=<cmd>"
# Note ENV is followed by a single space, not " ; ", before COMMAND. Reasons documented there:
# "user NOT in sudoers", "user NOT authorized on host", "command not allowed",
# "<N> incorrect password attempt(s)", "a password is required" (sudo -n). `sudo -v` logs
# COMMAND=validate and `sudo -l` COMMAND=list. Two kinds of failure are kept apart because
# rules weigh them differently: a wrong password is an authentication FAILURE (MAC-004
# counts attempts), a policy refusal is an authorization DENIAL.
SUDO_TRUSTED_PATHS: frozenset[str] = frozenset({"/usr/bin/sudo"})
_SUDO_PASSWORD_FAILURE_HINTS = (
    "incorrect password",
    "password is required",
    "authentication failure",
    "conversation failed",
)
_SUDO_POLICY_DENIAL_HINTS = (
    "not in sudoers",
    "not authorized on host",
    "command not allowed",
    "not allowed to execute",
    "not allowed to set the following environment variables",
    "a terminal is required",
)
_SUDO_ATTEMPTS = re.compile(r"^(?P<count>\d{1,4}) incorrect password attempts?$")
_SUDO_FIELD_KEYS = frozenset({"TTY", "CHROOT", "PWD", "USER", "GROUP", "TSID", "ENV", "COMMAND"})

# OpenSSH authentication messages (auth.c auth_log(), sshd-session/monitor). The formats are
# the same as on Linux (extorq_collectors.linux.auth): user names are attacker-controlled and
# may contain spaces, so every pattern is anchored at the end and the user group is greedy;
# the trailing "from <ip> port <n>" written by sshd always wins.
_SSH_IP = r"(?P<ip>[0-9A-Fa-f:.]{2,45})"
_SSH_PORT = r"(?P<port>\d{1,5})"
_SSH_METHOD = r"(?P<method>[a-z0-9-]{2,40}(?:/[a-z0-9-]{1,40})?)"
_SSH_KEY = r"(?:: (?P<keytype>[A-Z0-9-]{2,32}) (?P<fp>(?:SHA256|MD5):[A-Za-z0-9+/=:]{8,100}))?"
_SSH_FAILED = re.compile(
    rf"^Failed {_SSH_METHOD} for (?P<invalid>invalid user )?(?P<user>.*) "
    rf"from {_SSH_IP} port {_SSH_PORT} ssh2{_SSH_KEY}$"
)
_SSH_ACCEPTED = re.compile(
    rf"^Accepted {_SSH_METHOD} for (?P<user>.*) from {_SSH_IP} port {_SSH_PORT} ssh2{_SSH_KEY}$"
)
_SSH_INVALID = re.compile(rf"^Invalid user (?P<user>.*) from {_SSH_IP} port {_SSH_PORT}$")
_SSH_CLOSED = re.compile(
    rf"^Connection (?P<kind>closed|reset) by (?:(?P<who>invalid|authenticating) user "
    rf"(?P<user>.*) )?{_SSH_IP} port {_SSH_PORT} \[preauth\]$"
)
_SSH_DISCONNECTED = re.compile(
    rf"^Disconnected from (?:(?P<who>invalid|authenticating) user (?P<user>.*) )?"
    rf"{_SSH_IP} port {_SSH_PORT} \[preauth\]$"
)
_SSH_MAX_EXCEEDED = re.compile(
    rf"^error: maximum authentication attempts exceeded for (?P<invalid>invalid user )?"
    rf"(?P<user>.*) from {_SSH_IP} port {_SSH_PORT} ssh2 \[preauth\]$"
)
_SSH_TOO_MANY = re.compile(
    rf"^Disconnecting (?:(?P<who>invalid|authenticating) user (?P<user>.*) )?{_SSH_IP} "
    rf"port {_SSH_PORT}: Too many authentication failures \[preauth\]$"
)
_SSH_USER_LIMIT = 256
_SCREEN_SHARING_AUTH = re.compile(
    r"Authentication:\s*(?P<result>FAILED|SUCCEEDED)\s*::\s*User Name:\s*(?P<user>.*?)\s*::"
    r"\s*Viewer Address:\s*(?P<ip>[0-9A-Fa-f:.]+)\s*(?:::\s*Type:\s*(?P<type>\S+))?"
)
_OD_AUTH_FAILED = re.compile(
    r"^Authentication failed for (?P<user>.+?) \((?P<guid>[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\): (?P<reason>\S+)"
)
_AUTHZ_FAILED = re.compile(
    r"^Failed to authorize right '(?P<right>[^']*)' by client '(?P<client>[^']*)' \[(?P<pid>\d+)\] "
    r"for authorization created by '(?P<creator>[^']*)' \[(?P<cpid>\d+)\] "
    r"\((?P<flags>[^)]*)\) \((?P<status>-?\d+)\)"
)
_AUTHZ_STATUS = {
    -60005: "errAuthorizationDenied",
    -60006: "errAuthorizationCanceled",
    -60007: "errAuthorizationInteractionNotAllowed",
    -60008: "errAuthorizationInternal",
}
_SCREEN_LOCK_FAIL = re.compile(
    r"authFailWithMessage:numFailedAttempts:\] \| enter\.\s*(?P<reason>.*)$"
)
_PST = re.compile(
    r"PST: \(path: (?P<path>[^)]*)\), \(team: (?P<team>[^)]*)\), \(id: (?P<id>[^)]*)\), "
    r"\(bundle_id: (?P<bundle>[^)]*)\)"
)
_GK_EVAL = re.compile(r"^GK evaluateScanResult: (?P<result>-?\d+),")
_GK_PROMPT = re.compile(r"^Prompt shown \((?P<a>-?\d+), (?P<b>-?\d+)\)")
_GK_MARKED = re.compile(r"^Marked application as user approved: (?P<value>-?\d+)")
_XP_RUNNER = re.compile(
    r"^(?P<phase>Starting|Finished) system scan, (?:running|ran) as (?P<uid>\d+)"
)
_PRIVATE = "<private>"


def _nullable(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    if not value or value in ("(null)", "NOT_A_BUNDLE"):
        return None
    return value


def _pst_attributes(message: str) -> dict[str, Any]:
    match = _PST.search(message)
    if not match:
        return {}
    bundle_raw = match.group("bundle").strip()
    return {
        # syspolicyd logs a hash of the path, never the path itself.
        "path_hash": _nullable(match.group("path")),
        "team_id": _nullable(match.group("team")),
        "signing_id": _nullable(match.group("id")),
        "bundle_id": _nullable(bundle_raw),
        "not_a_bundle": True if bundle_raw == "NOT_A_BUNDLE" else None,
    }


def _ip_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _split_sudo_fields(rest: str) -> tuple[dict[str, str], list[str]]:
    """Split ``[reason ; ]KEY=value ; ... ; [ENV=vars ]COMMAND=cmd`` into fields and reasons.

    COMMAND is always the last field and its value may itself contain `` ; `` (shell
    arguments), so everything after the first ``COMMAND=`` at a field boundary is the
    command. ENV, when present, is separated from COMMAND by a single space.
    """
    fields: dict[str, str] = {}
    reasons: list[str] = []
    command_at = rest.find(" ; COMMAND=")
    if command_at >= 0:
        fields["COMMAND"] = rest[command_at + len(" ; COMMAND=") :]
        rest = rest[:command_at]
    elif rest.startswith("COMMAND="):
        fields["COMMAND"], rest = rest[len("COMMAND=") :], ""
    for part in rest.split(" ; "):
        key, eq, value = part.partition("=")
        if eq and key in _SUDO_FIELD_KEYS:
            if key == "ENV" and " COMMAND=" in value and "COMMAND" not in fields:
                value, _, fields["COMMAND"] = value.partition(" COMMAND=")
            fields[key] = value
        elif part.strip():
            reasons.append(part.strip())
    return fields, reasons


def _classify_sudo(record: LogRecord) -> Classified:
    """sudo records -> ``auth.sudo.command`` / ``auth.sudo.failure`` (documented formats).

    Only records written by ``/usr/bin/sudo`` (sealed system volume; unified logging records
    the kernel-attested image path) are evidence. Any other process merely *named* sudo is
    reported as ``system.log.notable`` with ``source_verified=false`` and nothing taken from
    its message, so a local user cannot fabricate sudo failures (or hide real ones) by
    logging lines from a copied binary.
    """
    if record.process_path not in SUDO_TRUSTED_PATHS:
        return _unverified_sender(record, "sudo", "sudo_unverified_sender")
    message = record.event_message
    user, sep, rest = message.partition(" : ")
    if not sep:
        # PAM modules run inside sudo and log their own diagnostics: context only.
        return Classified("system.log.notable", "sudo", action="sudo_message")
    fields, reasons = _split_sudo_fields(rest)
    reason = "; ".join(reasons) or None
    actor = Actor(type=ActorType.USER, name=user.strip() or None)
    attrs: dict[str, Any] = {
        "auth_service": "sudo",
        "run_as": fields.get("USER"),
        "run_as_group": fields.get("GROUP"),
        "tty": fields.get("TTY"),
        "cwd": fields.get("PWD"),
        # ENV= values can carry secrets: record only that variables were passed.
        "env_specified": True if "ENV" in fields else None,
    }
    lowered = (reason or "").lower()
    if reason and any(hint in lowered for hint in _SUDO_PASSWORD_FAILURE_HINTS):
        attempts = _SUDO_ATTEMPTS.match(reason.strip())
        attrs.update(
            reason=reason,
            failure_kind="authentication",
            # sudo logs ONE record per invocation with the number of wrong passwords; rules
            # sum this value (unknown stays unknown: "a password is required" has no count).
            failed_attempts=int(attempts.group("count")) if attempts else None,
        )
        return Classified(
            "auth.sudo.failure",
            "sudo",
            action="sudo_auth_failed",
            outcome=Outcome.FAILURE,
            actor=actor,
            command_line=fields.get("COMMAND"),
            attributes=attrs,
        )
    if reason and any(hint in lowered for hint in _SUDO_POLICY_DENIAL_HINTS):
        attrs.update(reason=reason, failure_kind="policy")
        return Classified(
            "auth.sudo.failure",
            "sudo",
            action="sudo_denied",
            outcome=Outcome.DENIED,
            actor=actor,
            command_line=fields.get("COMMAND"),
            attributes=attrs,
        )
    if "COMMAND" in fields and reason is None:
        return Classified(
            "auth.sudo.command",
            "sudo",
            action="sudo_command",
            outcome=Outcome.SUCCESS,
            actor=actor,
            command_line=fields.get("COMMAND"),
            attributes=attrs,
        )
    attrs["reason"] = reason
    return Classified(
        "system.log.notable",
        "sudo",
        action="sudo_message",
        actor=actor,
        command_line=fields.get("COMMAND"),
        attributes=attrs,
    )


def _ssh_network(ip: str | None, port: str | None) -> Network | None:
    src_ip = _ip_or_none(ip)
    src_port = int(port) if port is not None and port.isdigit() else None
    if src_port is not None and not 0 <= src_port <= 65535:
        src_port = None
    if src_ip is None and src_port is None:
        return None
    return Network(src_ip=src_ip, src_port=src_port, protocol="tcp", direction="inbound")


def _ssh_actor(user: str | None) -> Actor | None:
    """sshd writes the user name as received (``%.100s``); an empty name stays unknown."""
    if user is None:
        return None
    name, _ = clean_text(user, _SSH_USER_LIMIT)
    return Actor(type=ActorType.USER, name=name or None)


def _unverified_sender(record: LogRecord, producer: str, action: str) -> Classified:
    """A record from a process *named* like a monitored service but not its system binary."""
    return Classified(
        "system.log.notable",
        producer,
        action=action,
        attributes={"auth_service": producer, "source_verified": False},
    )


def _classify_sshd(record: LogRecord) -> Classified:
    """OpenSSH (Remote Login) records -> ``auth.ssh.*`` (catalog B3-IC-1), as on Linux."""
    if record.process_path not in SSHD_TRUSTED_PATHS:
        return _unverified_sender(record, "sshd", "sshd_unverified_sender")
    message = record.event_message
    base = {"auth_service": "sshd"}
    failed = _SSH_FAILED.match(message)
    if failed:
        return Classified(
            "auth.ssh.login_failed",
            "sshd",
            action="ssh_login_failed",
            outcome=Outcome.FAILURE,
            actor=_ssh_actor(failed.group("user")),
            network=_ssh_network(failed.group("ip"), failed.group("port")),
            attributes={
                **base,
                "auth_method": failed.group("method"),
                "invalid_user": failed.group("invalid") is not None,
                "key_type": failed.group("keytype"),
                "key_fingerprint": failed.group("fp"),
            },
        )
    accepted = _SSH_ACCEPTED.match(message)
    if accepted:
        return Classified(
            "auth.ssh.login_succeeded",
            "sshd",
            action="ssh_login_succeeded",
            outcome=Outcome.SUCCESS,
            actor=_ssh_actor(accepted.group("user")),
            network=_ssh_network(accepted.group("ip"), accepted.group("port")),
            attributes={
                **base,
                "auth_method": accepted.group("method"),
                "key_type": accepted.group("keytype"),
                "key_fingerprint": accepted.group("fp"),
            },
        )
    invalid = _SSH_INVALID.match(message)
    if invalid:
        return Classified(
            "auth.ssh.invalid_user",
            "sshd",
            action="ssh_invalid_user",
            outcome=Outcome.FAILURE,
            actor=_ssh_actor(invalid.group("user")),
            network=_ssh_network(invalid.group("ip"), invalid.group("port")),
            attributes={**base, "invalid_user": True},
        )
    for close_kind, pattern in (("connection", _SSH_CLOSED), ("disconnected", _SSH_DISCONNECTED)):
        closed = pattern.match(message)
        if closed:
            who = closed.group("who")
            return Classified(
                "auth.ssh.preauth_closed",
                "sshd",
                action="ssh_preauth_closed",
                outcome=Outcome.FAILURE if who == "invalid" else Outcome.UNKNOWN,
                actor=_ssh_actor(closed.group("user")),
                network=_ssh_network(closed.group("ip"), closed.group("port")),
                attributes={
                    **base,
                    "invalid_user": (who == "invalid") if who else None,
                    "authenticating_user": (who == "authenticating") if who else None,
                    "close_kind": f"connection_{closed.group('kind')}"
                    if close_kind == "connection"
                    else "disconnected",
                },
            )
    for signal, pattern in (
        ("max_attempts_exceeded", _SSH_MAX_EXCEEDED),
        ("too_many_authentication_failures", _SSH_TOO_MANY),
    ):
        exceeded = pattern.match(message)
        if exceeded:
            groups = exceeded.groupdict()
            return Classified(
                "auth.ssh.max_auth_exceeded",
                "sshd",
                action="ssh_max_auth_exceeded",
                outcome=Outcome.FAILURE,
                actor=_ssh_actor(groups.get("user")),
                network=_ssh_network(groups.get("ip"), groups.get("port")),
                attributes={
                    **base,
                    "invalid_user": groups.get("invalid") is not None
                    or groups.get("who") == "invalid",
                    "signal": signal,
                },
            )
    # Key exchange, session and diagnostic lines: kept as notable, never as auth evidence.
    return Classified("system.log.notable", "sshd", action="sshd_message", attributes=base)


def _classify_screensharing(record: LogRecord) -> Classified:
    if record.process_path not in SCREENSHARING_TRUSTED_PATHS:
        return _unverified_sender(record, "screensharing", "screensharing_unverified_sender")
    match = _SCREEN_SHARING_AUTH.search(record.event_message)
    if not match:
        return Classified("system.log.notable", "screensharing", action="screensharing_message")
    user = match.group("user").strip()
    network = Network(src_ip=_ip_or_none(match.group("ip")), protocol="tcp", direction="inbound")
    attrs = {"auth_service": "screensharing", "auth_type": match.group("type")}
    actor = Actor(type=ActorType.USER, name=user if user and user != _PRIVATE else None)
    if match.group("result") == "FAILED":
        return Classified(
            "auth.local.failure",
            "screensharing",
            action="screensharing_auth_failed",
            outcome=Outcome.FAILURE,
            actor=actor,
            network=network,
            attributes=attrs,
        )
    return Classified(
        "system.log.notable",
        "screensharing",
        action="screensharing_auth_succeeded",
        outcome=Outcome.SUCCESS,
        actor=actor,
        network=network,
        attributes=attrs,
    )


def _classify_opendirectory(record: LogRecord) -> Classified | None:
    match = _OD_AUTH_FAILED.match(record.event_message)
    if not match:
        return None
    user = match.group("user")
    return Classified(
        "auth.local.failure",
        "opendirectory_auth",
        action="password_verification_failed",
        outcome=Outcome.FAILURE,
        actor=Actor(
            type=ActorType.USER,
            # opendirectoryd logs the record name as <private>; the GeneratedUID is public.
            name=None if user == _PRIVATE else user,
            id=match.group("guid").upper(),
        ),
        attributes={"auth_service": "opendirectoryd", "reason": match.group("reason")},
    )


def _classify_authorization(record: LogRecord) -> Classified | None:
    match = _AUTHZ_FAILED.match(record.event_message)
    if not match:
        return None
    status = int(match.group("status"))
    status_name = _AUTHZ_STATUS.get(status, str(status))
    attrs = {
        "auth_service": "authorization",
        "right": match.group("right"),
        "client": match.group("client"),
        "client_pid": int(match.group("pid")),
        "creator": match.group("creator"),
        "status_code": status,
        "reason": status_name,
    }
    if status == -60006:
        # The user dismissed the prompt: not an authentication failure.
        return Classified(
            "system.log.notable",
            "authorization",
            action="authorization_canceled",
            outcome=Outcome.FAILURE,
            executable_override=match.group("client") or None,
            attributes=attrs,
        )
    return Classified(
        "auth.local.failure",
        "authorization",
        action="authorization_denied",
        outcome=Outcome.FAILURE,
        executable_override=match.group("client") or None,
        attributes=attrs,
    )


def _classify_screen_lock(record: LogRecord) -> Classified | None:
    match = _SCREEN_LOCK_FAIL.search(record.event_message)
    if not match:
        return None
    return Classified(
        "auth.local.failure",
        "screen_lock",
        action="screen_unlock_failed",
        outcome=Outcome.FAILURE,
        attributes={"auth_service": "screen_lock", "reason": match.group("reason").strip() or None},
    )


def _classify_xprotect(record: LogRecord) -> Classified | None:
    message = record.event_message
    if record.category == "XPEvent.structured":
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            payload = None
        if not isinstance(payload, dict):
            return Classified("security.xprotect.event", "xprotect", action="remediator_event")
        name = record.process_name or ""
        plugin = (
            name.removeprefix("XProtectRemediator")
            if name.startswith("XProtectRemediator")
            else name
        )
        status_message = payload.get("status_message")
        status_code = payload.get("status_code")
        caused_by = payload.get("caused_by")
        caused_count = len(caused_by) if isinstance(caused_by, list) else None
        threat: bool | None
        if caused_count:
            threat = True
        elif status_message == "NoThreatDetected":
            threat = False
        elif isinstance(status_message, str) and "threat" in status_message.lower():
            threat = True
        else:
            threat = None
        if status_message in ("NoThreatDetected", "Success"):
            outcome = Outcome.SUCCESS
        elif isinstance(status_message, str):
            outcome = Outcome.FAILURE if threat is None else Outcome.SUCCESS
        else:
            outcome = Outcome.UNKNOWN
        duration = payload.get("execution_duration")
        return Classified(
            "security.xprotect.event",
            "xprotect",
            action="remediator_scan_result",
            outcome=outcome,
            severity_hint=Severity.HIGH if threat else None,
            attributes={
                "plugin": plugin or None,
                "status_code": status_code if isinstance(status_code, int) else None,
                "status_message": status_message if isinstance(status_message, str) else None,
                "caused_by_count": caused_count,
                "threat_detected": threat,
                "execution_duration_s": duration if isinstance(duration, int | float) else None,
            },
        )
    runner = _XP_RUNNER.match(message)
    if runner:
        phase = "started" if runner.group("phase") == "Starting" else "finished"
        return Classified(
            "security.xprotect.event",
            "xprotect",
            action=f"system_scan_{phase}",
            outcome=Outcome.SUCCESS if phase == "finished" else Outcome.UNKNOWN,
            attributes={"run_as_uid": int(runner.group("uid"))},
        )
    if message.startswith("Forwarding detection"):
        # XProtect behaviour service forwarded a detection to syspolicyd; details are private.
        return Classified(
            "security.xprotect.event",
            "xprotect",
            action="behavior_detection_forwarded",
            outcome=Outcome.SUCCESS if "succeeded" in message else Outcome.UNKNOWN,
        )
    return None


def _classify_gatekeeper(record: LogRecord) -> Classified | None:
    message = record.event_message
    attrs = _pst_attributes(message)
    if message.startswith("GK performScan"):
        return Classified(
            "security.gatekeeper.event", "gatekeeper", action="gk_perform_scan", attributes=attrs
        )
    evaluated = _GK_EVAL.match(message)
    if evaluated:
        attrs["scan_result"] = int(evaluated.group("result"))
        return Classified(
            "security.gatekeeper.event",
            "gatekeeper",
            action="gk_evaluate_scan_result",
            attributes=attrs,
        )
    prompt = _GK_PROMPT.match(message)
    if prompt:
        attrs["prompt_type"] = int(prompt.group("a"))
        return Classified(
            "security.gatekeeper.event", "gatekeeper", action="gk_prompt_shown", attributes=attrs
        )
    if message.startswith("Allowing code due to"):
        reason = message.removeprefix("Allowing code due to").strip() or None
        return Classified(
            "security.gatekeeper.event",
            "gatekeeper",
            action="gk_code_allowed",
            outcome=Outcome.SUCCESS,
            attributes={"reason": reason},
        )
    marked = _GK_MARKED.match(message)
    if marked:
        attrs["approved"] = marked.group("value") == "1"
        return Classified(
            "security.gatekeeper.event",
            "gatekeeper",
            action="gk_marked_user_approved",
            outcome=Outcome.SUCCESS,
            attributes=attrs,
        )
    return None


def classify(record: LogRecord) -> Classified:
    """Map a record to a catalog event type (``system.log.notable`` as fallback)."""
    name = record.process_name
    subsystem = record.subsystem or ""
    result: Classified | None = None
    if name == "sudo":
        result = _classify_sudo(record)
    elif name in SSHD_PROCESSES:
        result = _classify_sshd(record)
    elif name == "screensharingd":
        result = _classify_screensharing(record)
    elif subsystem == "com.apple.opendirectoryd":
        result = _classify_opendirectory(record)
    elif subsystem == "com.apple.Authorization":
        result = _classify_authorization(record)
    elif subsystem == "com.apple.loginwindow.logging":
        result = _classify_screen_lock(record)
    elif subsystem.lower().startswith(("com.apple.xprotect", "com.apple.xprotectframework")):
        result = _classify_xprotect(record)
    elif subsystem.startswith("com.apple.syspolicy"):
        result = _classify_gatekeeper(record)
    if result is None:
        result = Classified("system.log.notable", "other", action="notable_log_message")
    return result


_RAW_FIELDS = (
    "timestamp",
    "processImagePath",
    "processID",
    "senderImagePath",
    "subsystem",
    "category",
    "messageType",
    "eventMessage",
    "userID",
    "bootUUID",
    "machTimestamp",
    "threadID",
    "traceID",
)


def _raw_excerpt(record: LogRecord, *, include_message: bool = True) -> str | None:
    if not record.raw_line:
        return None
    try:
        obj = json.loads(record.raw_line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(obj, dict):
        return None
    return canonical_json(
        {
            key: obj[key]
            for key in _RAW_FIELDS
            if key in obj and (include_message or key != "eventMessage")
        }
    )


def to_event(
    record: LogRecord,
    classified: Classified,
    ctx: SourceContext,
    *,
    observed_time: datetime,
    resolve_actor: Callable[[str], str | None] | None = None,
) -> SecurityEvent:
    """Build the normalised SecurityEvent for one classified record."""
    attrs: dict[str, Any] = {
        "producer": classified.producer,
        "subsystem": record.subsystem,
        "log_category": record.category,
        "message_type": record.message_type,
        "sender_image": os.path.basename(record.sender_path) if record.sender_path else None,
    }
    attrs.update(classified.attributes)
    if _PRIVATE in record.event_message:
        attrs["private_redaction"] = True
    actor = classified.actor
    if (
        actor is not None
        and actor.name is None
        and actor.id is not None
        and resolve_actor is not None
    ):
        resolved = resolve_actor(actor.id)
        if resolved:
            actor = actor.model_copy(update={"name": resolved})
            attrs["actor_name_source"] = "dscl_generated_uid"
    sudo = classified.producer == "sudo"
    if sudo and classified.command_line:
        parts = classified.command_line.split(maxsplit=1)
        first = parts[0] if parts else ""
        if first.startswith("/"):
            attrs["command_executable"], _ = clean_text(first, 1024)
        elif first == "validate":
            attrs["command_operation"] = "validate"
    executable = classified.executable_override or record.process_path
    process = ProcessInfo(
        pid=record.process_id if classified.executable_override is None else None,
        name=os.path.basename(executable) if executable else None,
        executable=executable,
        uid=record.user_id if record.user_id is not None and record.user_id >= 0 else None,
    )
    severity = classified.severity_hint or _MESSAGE_TYPE_SEVERITY.get(record.message_type or "")
    key = native_key(record)
    return make_event(
        ctx=ctx,
        event_type=classified.event_type,
        source_type=SOURCE,
        native_key=key,
        event_time=record.timestamp,
        observed_time=observed_time,
        parser=PARSER,
        raw_record=record.raw_line or None,
        message=classified.action if sudo else record.event_message,
        raw=_raw_excerpt(record, include_message=not sudo),
        action=classified.action,
        outcome=classified.outcome,
        severity_hint=severity,
        actor=actor,
        network=classified.network,
        process=process,
        attributes=attrs,
    )


# ── Incremental window planning (pure) ───────────────────────────────


@dataclass(frozen=True, slots=True)
class WindowPlan:
    start: int
    end: int
    #: Seconds of history skipped because the checkpoint was older than the backfill limit.
    skipped_seconds: int = 0


def plan_window(
    *,
    now_epoch: float,
    checkpoint_end: int | None,
    overlap_seconds: int,
    settle_seconds: int,
    max_window_seconds: int,
    max_backfill_seconds: int,
    initial_lookback_seconds: int,
) -> WindowPlan | None:
    """Plan the next ``log show`` window; ``None`` when there is nothing new yet."""
    end_limit = int(now_epoch) - settle_seconds
    if checkpoint_end is None:
        start = end_limit - initial_lookback_seconds
    else:
        start = checkpoint_end - overlap_seconds
    skipped = 0
    oldest_allowed = end_limit - max_backfill_seconds
    if start < oldest_allowed:
        if checkpoint_end is not None:
            skipped = max(0, oldest_allowed - checkpoint_end)
        start = oldest_allowed
    if checkpoint_end is not None and end_limit <= checkpoint_end:
        return None
    end = min(end_limit, start + max_window_seconds)
    if end <= start:
        return None
    return WindowPlan(start=start, end=end, skipped_seconds=skipped)


@dataclass
class DedupState:
    """Event ids already emitted inside the overlap region (bounded)."""

    end: int | None = None
    seen: list[str] = field(default_factory=list)

    MAX_SEEN = 5000

    def to_json(self) -> str:
        return json.dumps(
            {"end": self.end, "seen": self.seen[-self.MAX_SEEN :]}, separators=(",", ":")
        )

    @classmethod
    def from_json(cls, text: str | None) -> DedupState:
        if not text:
            return cls()
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            return cls()
        if not isinstance(obj, dict):
            return cls()
        end = obj.get("end")
        seen = obj.get("seen")
        return cls(
            end=end if isinstance(end, int) and not isinstance(end, bool) else None,
            seen=[s for s in seen if isinstance(s, str)][-cls.MAX_SEEN :]
            if isinstance(seen, list)
            else [],
        )


def next_checkpoint(
    *,
    plan: WindowPlan,
    records: Sequence[LogRecord],
    event_ids: Sequence[str],
    truncated: bool,
    overlap_seconds: int,
) -> tuple[int, list[str], bool]:
    """Compute (new_end, ids_to_remember, forced_skip).

    Complete window: advance to ``plan.end``. Truncated window (record or byte
    limit hit): advance only to the last record's second so the remainder is
    re-read next cycle; if that would make no progress, advance to ``plan.end``
    and report ``forced_skip`` so the gap is visible in health.
    """
    forced = False
    if truncated and records:
        last = int(records[-1].timestamp.timestamp())
        new_end = min(last, plan.end)
        if new_end <= plan.start:
            new_end, forced = plan.end, True
    elif truncated:
        new_end, forced = plan.end, True
    else:
        new_end = plan.end
    horizon = new_end - overlap_seconds
    remember = [
        eid
        for rec, eid in zip(records, event_ids, strict=True)
        if int(rec.timestamp.timestamp()) >= horizon
    ]
    return new_end, remember, forced

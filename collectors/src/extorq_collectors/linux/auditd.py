"""auditd records (raw /var/log/audit/audit.log lines) -> file/process events.

Only events produced by the ExtorQ rules (``key`` starting with ``extorq_``)
become SecurityEvents:

* watch keys (``extorq_systemd``, ``extorq_sshd``, ``extorq_sudoers``,
  ``extorq_identity``, ``extorq_cron``) -> ``file.audit.watch``;
* ``extorq_root_exec`` (execve with euid 0 by a logged-in user) ->
  ``process.audit.exec``.

Records of one event share ``msg=audit(<sec>.<ms>:<serial>)`` and are grouped by
that identity (records of different events may interleave). Ubuntu's auditd
does not write ``EOE`` records, so an event is complete once its ``PROCTITLE``
record (always the last record of a syscall event) has been seen. Incomplete
events at the end of a chunk are held back and re-read on the next poll; the
deterministic event id makes re-reading idempotent.

The ENRICHED log format appends interpreted fields after an ASCII 0x1D
separator (``AUID="extorq-admin"``, ``SYSCALL=openat``); both parts are used.
Untrusted strings are hex-encoded by the kernel when they contain special
characters; they are decoded, sanitised and (for command lines) redacted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from extorq.contracts import (
    Actor,
    ActorType,
    Outcome,
    ProcessInfo,
    Resource,
    SecurityEvent,
    SourceType,
)
from extorq.contracts.identity import sha256_hex
from extorq_collectors.linux.common import ParseContext, build_event, clean, to_ms

PARSER_AUDIT = "linux-auditd"
AUID_UNSET = 4294967295
HOLDBACK_SECONDS = 10
MAX_GROUP_RECORDS = 64

RECORD_RE = re.compile(
    r"^(?:node=(?P<node>\S{1,64}) )?type=(?P<type>[A-Z0-9_]{2,32}) "
    r"msg=audit\((?P<sec>\d{1,12})\.(?P<ms>\d{3}):(?P<serial>\d{1,20})\): ?(?P<body>.*)$"
)
_KV_RE = re.compile(r"(?P<key>[A-Za-z0-9_\[\]-]{1,64})=(?P<value>\"[^\"]*\"|'[^']*'|\S*)")
_HEX_RE = re.compile(r"^(?:[0-9A-F]{2})+$")
_ARG_RE = re.compile(r"^a(?P<idx>\d{1,4})(?:\[(?P<part>\d{1,4})\])?$")
_HEX_STRING_FIELDS = frozenset({"name", "exe", "comm", "cwd", "proctitle", "key"})
#: Watch keys deployed by infra/vm/files/audit/extorq.rules (any other extorq_* key is
#: treated as a watch as well).
WATCH_KEYS = frozenset(
    {"extorq_systemd", "extorq_sshd", "extorq_sudoers", "extorq_identity", "extorq_cron"}
)
EXEC_KEY = "extorq_root_exec"


def decode_value(key: str, value: str, *, hex_allowed: bool) -> str | None:
    """Decode one audit field value (quoted, ``(null)`` or kernel hex encoding)."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    if value in ("(null)", "(none)", "?", ""):
        return None
    if hex_allowed and _HEX_RE.match(value):
        decoded = bytes.fromhex(value)
        if key == "proctitle":
            decoded = decoded.replace(b"\x00", b" ").rstrip()
        return decoded.decode("utf-8", "replace")
    return value


@dataclass
class AuditRecord:
    type: str
    sec: int
    ms: int
    serial: int
    node: str | None
    fields: dict[str, str]
    enriched: dict[str, str]
    offset: int
    line: str

    def get(self, key: str) -> str | None:
        raw = self.fields.get(key)
        if raw is None:
            return None
        hex_ok = key in _HEX_STRING_FIELDS or (
            self.type == "EXECVE" and _ARG_RE.match(key) is not None
        )
        return decode_value(key, raw, hex_allowed=hex_ok)

    def enriched_value(self, key: str) -> str | None:
        raw = self.enriched.get(key)
        return decode_value(key, raw, hex_allowed=False) if raw is not None else None


def parse_record(line: str, offset: int = 0) -> AuditRecord | None:
    match = RECORD_RE.match(line)
    if not match:
        return None
    body, _, enriched_text = match.group("body").partition("\x1d")
    fields: dict[str, str] = {}
    for kv in _KV_RE.finditer(body):
        fields.setdefault(kv.group("key"), kv.group("value"))
    enriched = {kv.group("key"): kv.group("value") for kv in _KV_RE.finditer(enriched_text)}
    return AuditRecord(
        type=match.group("type"),
        sec=int(match.group("sec")),
        ms=int(match.group("ms")),
        serial=int(match.group("serial")),
        node=match.group("node"),
        fields=fields,
        enriched=enriched,
        offset=offset,
        line=line,
    )


@dataclass
class AuditGroup:
    node: str | None
    sec: int
    ms: int
    serial: int
    first_offset: int
    records: list[AuditRecord] = field(default_factory=list)

    @property
    def time(self) -> datetime:
        return to_ms(datetime.fromtimestamp(self.sec + self.ms / 1000.0, tz=UTC))

    def first(self, record_type: str) -> AuditRecord | None:
        return next((r for r in self.records if r.type == record_type), None)

    def all(self, record_type: str) -> list[AuditRecord]:
        return [r for r in self.records if r.type == record_type]

    @property
    def is_syscall(self) -> bool:
        return self.first("SYSCALL") is not None

    @property
    def complete(self) -> bool:
        return not self.is_syscall or self.first("PROCTITLE") is not None

    def audit_keys(self) -> list[str]:
        syscall = self.first("SYSCALL")
        if syscall is None:
            return []
        key = syscall.get("key")
        if not key:
            return []
        return [k for k in key.split("\x01") if k]  # multiple keys are \x01-separated


def split_lines(payload: bytes, base_offset: int) -> list[tuple[int, str]]:
    """Split a chunk into (absolute byte offset, decoded line) pairs."""
    lines: list[tuple[int, str]] = []
    position = 0
    for raw in payload.split(b"\n"):
        if raw:
            lines.append((base_offset + position, raw.decode("utf-8", "replace")))
        position += len(raw) + 1
    return lines


def group_records(lines: list[tuple[int, str]]) -> tuple[list[AuditGroup], int]:
    """Group records by event identity (order of first appearance). Returns (groups, bad)."""
    groups: dict[tuple[str | None, int, int, int], AuditGroup] = {}
    malformed = 0
    for offset, line in lines:
        record = parse_record(line, offset)
        if record is None:
            malformed += 1
            continue
        key = (record.node, record.sec, record.ms, record.serial)
        group = groups.get(key)
        if group is None:
            group = AuditGroup(
                node=record.node,
                sec=record.sec,
                ms=record.ms,
                serial=record.serial,
                first_offset=offset,
            )
            groups[key] = group
        if len(group.records) < MAX_GROUP_RECORDS:
            group.records.append(record)
    return list(groups.values()), malformed


def _int(value: str | None) -> int | None:
    if value is None or not value.isdigit() or len(value) > 12:
        return None
    return int(value)


def _abs_path(name: str | None, cwd: str | None) -> str | None:
    if name is None:
        return None
    if name.startswith("/") or not cwd:
        return name
    return cwd.rstrip("/") + "/" + name


def _common(group: AuditGroup, ctx: ParseContext) -> dict[str, Any]:
    """Fields shared by watch and exec events."""
    syscall = group.first("SYSCALL")
    if syscall is None:
        raise ValueError("audit group without SYSCALL record")
    cwd_record = group.first("CWD")
    auid = _int(syscall.get("auid"))
    uid = _int(syscall.get("uid"))
    auid_name = syscall.enriched_value("AUID")
    if auid is None or auid == AUID_UNSET:
        actor = Actor(type=ActorType.SYSTEM)
    else:
        actor = Actor(
            type=ActorType.USER,
            id=str(auid),
            name=clean(auid_name) if auid_name and auid_name != "unset" else None,
        )
    success = syscall.get("success")
    return {
        "syscall": syscall,
        "actor": actor,
        "auid": auid,
        "uid": uid,
        "cwd": cwd_record.get("cwd") if cwd_record else None,
        "outcome": Outcome.SUCCESS
        if success == "yes"
        else Outcome.FAILURE
        if success == "no"
        else Outcome.UNKNOWN,
        "is_self": ctx.self_uid is not None and auid == ctx.self_uid,
        "process": ProcessInfo(
            pid=_int(syscall.get("pid")),
            ppid=_int(syscall.get("ppid")),
            name=clean(syscall.get("comm")),
            executable=clean(syscall.get("exe"), 2048),
            user=clean(syscall.enriched_value("UID")),
            uid=uid,
        ),
        "base_attrs": {
            "audit_serial": group.serial,
            "audit_node": group.node,
            "syscall": syscall.enriched_value("SYSCALL") or syscall.get("syscall"),
            "syscall_number": _int(syscall.get("syscall")),
            "arch": syscall.enriched_value("ARCH"),
            "success": success == "yes" if success in ("yes", "no") else None,
            "exit_code": syscall.get("exit"),
            "auid": "unset" if auid == AUID_UNSET else auid,
            "euid": _int(syscall.get("euid")),
            "tty": syscall.get("tty"),
            "session": syscall.get("ses") if syscall.get("ses") != "4294967295" else None,
            "cwd": cwd_record.get("cwd") if cwd_record else None,
        },
    }


def _native_key(group: AuditGroup) -> str:
    return f"{group.node or '-'}:{group.serial}:{group.sec}.{group.ms:03d}:SYSCALL"


def _raw(group: AuditGroup) -> str:
    return "\n".join(
        r.line.replace("\x1d", " ") for r in group.records if r.type in {"SYSCALL", "PATH", "CWD"}
    )


def _raw_sha256(group: AuditGroup) -> str:
    return sha256_hex("\n".join(r.line.replace("\x1d", " ") for r in group.records))


def watch_event(group: AuditGroup, key: str, ctx: ParseContext, *, complete: bool) -> SecurityEvent:
    common = _common(group, ctx)
    paths = group.all("PATH")
    primary = next((p for p in paths if p.get("nametype") not in ("PARENT",)), None) or (
        paths[0] if paths else None
    )
    path = _abs_path(primary.get("name"), common["cwd"]) if primary else None
    path_list = [
        f"{p.get('nametype') or '?'}:{_abs_path(p.get('name'), common['cwd']) or '?'}"
        for p in paths
    ][:16]
    attrs = dict(common["base_attrs"])
    attrs.update(
        {
            "audit_key": key,
            "nametype": primary.get("nametype") if primary else None,
            "inode": _int(primary.get("inode")) if primary else None,
            "mode": primary.get("mode") if primary else None,
            "paths": path_list,
            "audit_complete": None if complete else False,
        }
    )
    syscall_name = attrs.get("syscall")
    return build_event(
        ctx,
        event_type="file.audit.watch",
        source_type=SourceType.LINUX_AUDITD,
        native_key=_native_key(group),
        source_native_id=f"{group.sec}.{group.ms:03d}:{group.serial}",
        event_time=group.time,
        parser=PARSER_AUDIT,
        action=f"audit.{syscall_name}" if syscall_name else "audit.watch",
        outcome=common["outcome"],
        actor=common["actor"],
        resource=Resource(
            type="file",
            path=clean(path, 2048),
            name=clean(path.rsplit("/", 1)[-1]) if path else None,
        ),
        process=common["process"],
        message=f"auditd {key}: {syscall_name or '?'} {path or '?'} by "
        f"{common['actor'].name or attrs['auid']} via {common['process'].name or '?'}",
        raw=_raw(group),
        raw_sha256=_raw_sha256(group),
        attributes=attrs,
        is_self=common["is_self"],
    )


def exec_event(group: AuditGroup, ctx: ParseContext, *, complete: bool) -> SecurityEvent:
    common = _common(group, ctx)
    execve = group.first("EXECVE")
    process = common["process"]
    attrs = dict(common["base_attrs"])
    attrs.update(
        {
            "audit_key": EXEC_KEY,
            "argc": _int(execve.get("argc")) if execve else None,
            "audit_complete": None if complete else False,
        }
    )
    return build_event(
        ctx,
        event_type="process.audit.exec",
        source_type=SourceType.LINUX_AUDITD,
        native_key=_native_key(group),
        source_native_id=f"{group.sec}.{group.ms:03d}:{group.serial}",
        event_time=group.time,
        parser=PARSER_AUDIT,
        action="audit.execve",
        outcome=common["outcome"],
        actor=common["actor"],
        process=process,
        message=(
            f"auditd exec as euid {attrs.get('euid')}: "
            f"{process.executable or process.name or '?'} "
            f"(auid {common['actor'].name or attrs['auid']})"
        ),
        raw=_raw(group),
        raw_sha256=_raw_sha256(group),
        attributes=attrs,
        is_self=common["is_self"],
    )


#: Audit subsystem configuration records -> ``audit.config.changed`` (defence evasion signal).
CONFIG_RECORD_TYPES = frozenset({"CONFIG_CHANGE", "DAEMON_END", "DAEMON_ABORT", "DAEMON_CONFIG"})
_SETTING_RE = re.compile(r"^(?P<name>audit_[a-z_]{1,40}|enabled|backlog_[a-z_]{1,20})$")


def config_event(group: AuditGroup, record: AuditRecord, ctx: ParseContext) -> SecurityEvent:
    """``CONFIG_CHANGE`` (rule added/removed, setting changed) or audit daemon stop/abort."""
    auid = _int(record.get("auid"))
    auid_name = record.enriched_value("AUID")
    if auid is None or auid == AUID_UNSET:
        actor = Actor(type=ActorType.SYSTEM)
    else:
        actor = Actor(
            type=ActorType.USER,
            id=str(auid),
            name=clean(auid_name) if auid_name and auid_name != "unset" else None,
        )
    op = record.get("op")
    key = record.get("key")
    res = record.get("res")
    setting = old = new = None
    for name, raw in record.fields.items():
        if _SETTING_RE.match(name) and name != "audit_backlog_limit_reached":
            setting, new, old = name, raw, record.get("old")
            break
    success = res in ("1", "success") if res is not None else None
    attrs: dict[str, Any] = {
        "audit_record_type": record.type,
        "audit_op": clean(op, 64),
        "audit_key": clean(key, 128),
        "affects_extorq_rule": True if key and key.startswith("extorq_") else None,
        "rule_list": _int(record.get("list")),
        "setting": setting,
        "previous_value": clean(old, 64) if setting else None,
        "current_value": clean(new, 64) if setting else None,
        "result": clean(res, 16),
        "auid": "unset" if auid == AUID_UNSET else auid,
        "session": record.get("ses") if record.get("ses") != "4294967295" else None,
        "audit_serial": group.serial,
        "audit_node": group.node,
        "daemon_pid": _int(record.get("pid")) if record.type.startswith("DAEMON") else None,
    }
    what = op or record.type.lower()
    target = f" {key}" if key else (f" {setting}={new}" if setting else "")
    return build_event(
        ctx,
        event_type="audit.config.changed",
        source_type=SourceType.LINUX_AUDITD,
        native_key=f"{group.node or '-'}:{group.serial}:{group.sec}.{group.ms:03d}:{record.type}",
        source_native_id=f"{group.sec}.{group.ms:03d}:{group.serial}",
        event_time=group.time,
        parser=PARSER_AUDIT,
        action=f"audit.{what}",
        outcome=Outcome.UNKNOWN
        if success is None
        else (Outcome.SUCCESS if success else Outcome.FAILURE),
        actor=actor,
        message=f"audit {record.type} {what}{target} by {actor.name or attrs['auid']}",
        raw=_raw(group),
        attributes=attrs,
        is_self=ctx.self_uid is not None and auid == ctx.self_uid,
    )


@dataclass
class AuditParseResult:
    events: list[SecurityEvent]
    #: Absolute offset from which the next read must start (held-back events).
    resume_offset: int
    groups: int = 0
    malformed_lines: int = 0
    held_back: int = 0
    incomplete_emitted: int = 0
    newest_time: datetime | None = None


def parse_audit_chunk(payload: bytes, base_offset: int, ctx: ParseContext) -> AuditParseResult:
    """Parse one chunk (complete lines starting at ``base_offset``)."""
    end_offset = base_offset + len(payload)
    groups, malformed = group_records(split_lines(payload, base_offset))
    newest = max((g.sec + g.ms / 1000.0 for g in groups), default=None)
    resume = end_offset
    built: list[tuple[int, SecurityEvent]] = []
    held = incomplete = 0
    for group in groups:
        keys = [k for k in group.audit_keys() if k.startswith("extorq_")]
        if not keys:
            # CONFIG_CHANGE arrives with the auditctl SYSCALL/SOCKADDR/PROCTITLE records of
            # the same event; the CONFIG_CHANGE record alone carries everything needed.
            record = next((r for r in group.records if r.type in CONFIG_RECORD_TYPES), None)
            if record is not None:
                built.append((group.first_offset, config_event(group, record, ctx)))
            continue
        complete = group.complete
        if (
            not complete
            and newest is not None
            and group.first_offset > base_offset
            and newest - (group.sec + group.ms / 1000.0) < HOLDBACK_SECONDS
        ):
            resume = min(resume, group.first_offset)  # re-read next poll when complete
            held += 1
            continue
        if not complete:
            incomplete += 1
        key = keys[0]
        if key == EXEC_KEY:
            built.append((group.first_offset, exec_event(group, ctx, complete=complete)))
        else:
            built.append((group.first_offset, watch_event(group, key, ctx, complete=complete)))
    # Everything at/after the resume point is re-read on the next poll; emitting it
    # now as well would only create duplicates (identical ids, but wasted work).
    events = [event for offset, event in built if offset < resume]
    return AuditParseResult(
        events=events,
        resume_offset=resume,
        groups=len(groups),
        malformed_lines=malformed,
        held_back=held,
        incomplete_emitted=incomplete,
        newest_time=to_ms(datetime.fromtimestamp(newest, tz=UTC)) if newest is not None else None,
    )

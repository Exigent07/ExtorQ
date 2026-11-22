"""systemd (PID 1) journald lines -> service state changes and daemon reloads.

Only the system manager is considered: ``_PID == 1`` is attested by the kernel
and cannot be forged by a local user. Per-user managers (``systemd --user``)
are ignored. Intermediate states (``Starting``/``Stopping``) are skipped to keep
volume low; terminal states are kept: started, stopped, reloaded, finished,
deactivated, failed, restart scheduled.
"""

from __future__ import annotations

import re
from typing import Any

from extorq.contracts import Outcome, ProcessInfo, Resource, SecurityEvent, SourceType
from extorq_collectors.linux.common import ParseContext, build_event, clean, severity_from_priority
from extorq_collectors.linux.journal import SYSTEMD_EXES, JournalEntry, is_self

PARSER_SYSTEMD = "linux-systemd"

_UNIT = (
    r"(?P<unit>[A-Za-z0-9@:._\\-]{1,200}\.(?:service|socket|timer|target|mount|automount|"
    r"path|scope|slice|swap|device))"
)
STATE_LINE = re.compile(
    rf"^(?P<state>Started|Stopped|Reloaded|Finished|Failed to start|Failed to stop|"
    rf"Failed to reload) {_UNIT}(?: - (?P<desc>.{{0,300}}?))?\.?$"
)
UNIT_RESULT = re.compile(
    rf"^{_UNIT}: (?:(?P<deactivated>Deactivated successfully)|"
    rf"Failed with result '(?P<result>[a-z-]{{1,40}})'|"
    rf"Scheduled restart job, restart counter is at (?P<restarts>\d{{1,6}}))\.?$"
)
RELOAD_REQUEST = re.compile(
    r"^Reloading requested from client PID (?P<pid>\d{1,10}) \('(?P<comm>[^']{0,64})'\)"
    r"(?: \(unit (?P<unit>[^)]{1,200})\))?\.\.\.$"
)

_STATE_NAMES = {
    "Started": "started",
    "Stopped": "stopped",
    "Reloaded": "reloaded",
    "Finished": "finished",
    "Failed to start": "start_failed",
    "Failed to stop": "stop_failed",
    "Failed to reload": "reload_failed",
}


def _self_unit(unit: str, desc: str | None, ctx: ParseContext) -> bool:
    """Units created for the collector's own SSH sessions (session scope, user manager)."""
    if desc and f"of User {ctx.self_user}" in desc:
        return True
    if ctx.self_uid is not None:
        uid = str(ctx.self_uid)
        return unit in (
            f"user@{uid}.service",
            f"user-runtime-dir@{uid}.service",
            f"user-{uid}.slice",
        )
    return False


def parse_systemd(entry: JournalEntry, ctx: ParseContext) -> list[SecurityEvent]:
    if entry.pid != 1:
        return []  # only the system manager; per-user managers are ignored
    if entry.exe is not None and entry.exe not in SYSTEMD_EXES:
        return []
    msg = entry.message
    process = ProcessInfo(pid=1, name="systemd", executable=clean(entry.exe, 2048), uid=entry.uid)

    reload_match = RELOAD_REQUEST.match(msg)
    if reload_match:
        return [
            build_event(
                ctx,
                event_type="system.systemd.daemon_reload",
                source_type=SourceType.LINUX_JOURNALD,
                native_key=entry.cursor,
                source_native_id=entry.cursor,
                event_time=entry.time,
                parser=PARSER_SYSTEMD,
                action="daemon_reload",
                outcome=Outcome.SUCCESS,
                severity_hint=severity_from_priority(entry.priority),
                process=process,
                message=msg,
                raw=msg,
                attributes={
                    "requested_by_pid": int(reload_match.group("pid")),
                    "requested_by_comm": reload_match.group("comm") or None,
                    "requested_by_unit": reload_match.group("unit"),
                    "boot_id": entry.boot_id,
                },
            )
        ]

    state: str | None = None
    unit: str | None = None
    desc: str | None = None
    extra: dict[str, Any] = {}
    outcome = Outcome.SUCCESS
    match = STATE_LINE.match(msg)
    if match:
        state = _STATE_NAMES[match.group("state")]
        unit = match.group("unit")
        desc = match.group("desc")
        if state.endswith("_failed"):
            outcome = Outcome.FAILURE
    else:
        result = UNIT_RESULT.match(msg)
        if result:
            unit = result.group("unit")
            if result.group("deactivated"):
                state = "deactivated"
            elif result.group("result"):
                state = "failed"
                extra["result"] = result.group("result")
                outcome = Outcome.FAILURE
            else:
                state = "restart_scheduled"
                extra["restart_counter"] = int(result.group("restarts"))
    if state is None or unit is None:
        return []
    return [
        build_event(
            ctx,
            event_type="system.service.state_changed",
            source_type=SourceType.LINUX_JOURNALD,
            native_key=entry.cursor,
            source_native_id=entry.cursor,
            event_time=entry.time,
            parser=PARSER_SYSTEMD,
            action=f"unit.{state}",
            outcome=outcome,
            severity_hint=severity_from_priority(entry.priority),
            resource=Resource(type="systemd_unit", name=clean(unit)),
            process=process,
            message=msg,
            raw=msg,
            attributes={
                "state": state,
                "unit_description": desc,
                "boot_id": entry.boot_id,
                **extra,
            },
            is_self=_self_unit(unit, desc, ctx) or is_self(entry, ctx),
        )
    ]

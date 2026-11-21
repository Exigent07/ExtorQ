"""LaunchAgent / LaunchDaemon persistence monitoring (snapshot diff).

Scanned locations (plain directory reads, no privileges):

* ``~/Library/LaunchAgents``  -> scope ``user``, kind ``agent``
* ``/Library/LaunchAgents``   -> scope ``system``, kind ``agent``
* ``/Library/LaunchDaemons``  -> scope ``system``, kind ``daemon``

``/System/Library/Launch{Agents,Daemons}`` live on the sealed, SIP-protected
system volume; they are only *counted* (reported in health details).

Each ``*.plist`` is read with a size cap, hashed (SHA-256 of the file bytes) and
parsed with :mod:`plistlib` (XML or binary). Only security-relevant keys are
kept; ``EnvironmentVariables`` contributes key *names* only and program
arguments are redacted. Symlinks are recorded as such (their target is hashed
when it is a regular file). What launchd has actually *loaded* is not visible
without root (``launchctl print system`` / the Background Task Management
database), so items are reported as files on disk, not as running jobs.

Diff semantics: the first scan is a baseline (inventory only, no events). Later
scans emit ``persistence.launchd.item_created|item_modified|item_deleted``. The
event time is the observation time (file mtimes are attacker-controllable and
are reported only as ``attributes.file_mtime``). An allow-list match sets
``attributes.allowlisted=true`` and never suppresses an event.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import plistlib
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from extorq.contracts import (
    InventoryItem,
    InventoryItemType,
    Outcome,
    Resource,
    SecurityEvent,
    SourceType,
)
from extorq_collectors.macos.common import (
    SourceContext,
    bounded_attributes,
    make_event,
    redact_list,
    simulation_tag,
    to_ms,
)

PARSER = "macos-launchd"
SOURCE = SourceType.MACOS_LAUNCHD
MAX_PLIST_BYTES = 1024 * 1024
MAX_ENTRIES_PER_DIR = 2000
MAX_PROGRAM_ARGS = 32
SYSTEM_COUNT_DIRS = ("/System/Library/LaunchAgents", "/System/Library/LaunchDaemons")


@dataclass(frozen=True, slots=True)
class Location:
    path: Path
    scope: str  # user | system
    kind: str  # agent | daemon


def default_locations(home: Path | None = None) -> list[Location]:
    home = home if home is not None else Path.home()
    return [
        Location(home / "Library" / "LaunchAgents", "user", "agent"),
        Location(Path("/Library/LaunchAgents"), "system", "agent"),
        Location(Path("/Library/LaunchDaemons"), "system", "daemon"),
    ]


@dataclass(slots=True)
class LaunchItem:
    path: str
    scope: str
    kind: str
    sha256: str | None = None
    size: int | None = None
    mtime: datetime | None = None
    mode: str | None = None
    owner_uid: int | None = None
    world_writable: bool | None = None
    is_symlink: bool = False
    symlink_target: str | None = None
    label: str | None = None
    program: str | None = None
    program_arguments: list[str] = field(default_factory=list)
    run_at_load: bool | None = None
    keep_alive: str | None = None  # "true" | "false" | "conditional"
    start_interval: int | None = None
    start_calendar_interval: bool | None = None
    watch_paths: int | None = None
    disabled: bool | None = None
    user_name: str | None = None
    session_types: list[str] = field(default_factory=list)
    env_var_names: list[str] = field(default_factory=list)
    sockets: bool | None = None
    mach_services: int | None = None
    bundle_ids: list[str] = field(default_factory=list)
    parse_error: str | None = None
    read_error: str | None = None
    allowlisted: bool = False
    redactions: int = 0

    @property
    def fingerprint(self) -> str:
        """Change-detection fingerprint (content hash, or the reason it is unknown)."""
        if self.sha256:
            return self.sha256
        return f"unreadable:{self.read_error or self.parse_error or 'unknown'}"

    def summary(self) -> dict[str, Any]:
        """Compact state kept between scans (needed to describe deletions)."""
        return {
            "fp": self.fingerprint,
            "label": self.label,
            "scope": self.scope,
            "kind": self.kind,
            "program": self.program,
        }

    def attributes(self) -> dict[str, Any]:
        return bounded_attributes(
            {
                "label": self.label,
                "program": self.program,
                "program_arguments": self.program_arguments or None,
                "run_at_load": self.run_at_load,
                "keep_alive": self.keep_alive,
                "start_interval": self.start_interval,
                "start_calendar_interval": self.start_calendar_interval,
                "watch_paths": self.watch_paths,
                "disabled": self.disabled,
                "user_name": self.user_name,
                "session_types": self.session_types or None,
                "env_var_names": self.env_var_names or None,
                "sockets": self.sockets,
                "mach_services": self.mach_services,
                "bundle_ids": self.bundle_ids or None,
                "sha256": self.sha256,
                "size": self.size,
                "file_mtime": self.mtime.isoformat().replace("+00:00", "Z") if self.mtime else None,
                "mode": self.mode,
                "owner_uid": self.owner_uid,
                "world_writable": self.world_writable,
                "is_symlink": self.is_symlink,
                "symlink_target": self.symlink_target,
                "scope": self.scope,
                "kind": self.kind,
                "allowlisted": self.allowlisted,
                "parse_error": self.parse_error,
                "read_error": self.read_error,
            }
        )


class LabelAllowlist:
    """Exact labels or shell-style patterns (``fnmatch``, case-sensitive)."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self._patterns = tuple(p for p in patterns if isinstance(p, str) and p)

    def matches(self, label: str | None) -> bool:
        if not label:
            return False
        return any(fnmatch.fnmatchcase(label, pattern) for pattern in self._patterns)


def _bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _str_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def apply_plist(item: LaunchItem, data: Mapping[str, Any]) -> None:
    """Extract the security-relevant keys from a parsed launchd plist."""
    item.label = _str_or_none(data.get("Label"))
    args_raw = data.get("ProgramArguments")
    args = [a for a in args_raw if isinstance(a, str)] if isinstance(args_raw, list) else []
    program = _str_or_none(data.get("Program")) or (args[0] if args else None)
    redacted_args, count = redact_list(args[:MAX_PROGRAM_ARGS])
    item.program_arguments = redacted_args
    item.redactions += count
    if program:
        redacted_program, count = redact_list([program], 2048)
        item.program = redacted_program[0] or None
        item.redactions += count
    item.run_at_load = _bool_or_none(data.get("RunAtLoad"))
    keep_alive = data.get("KeepAlive")
    if isinstance(keep_alive, bool):
        item.keep_alive = "true" if keep_alive else "false"
    elif isinstance(keep_alive, dict):
        item.keep_alive = "conditional"
    interval = data.get("StartInterval")
    item.start_interval = (
        interval if isinstance(interval, int) and not isinstance(interval, bool) else None
    )
    item.start_calendar_interval = True if "StartCalendarInterval" in data else None
    watch = data.get("WatchPaths")
    item.watch_paths = len(watch) if isinstance(watch, list) else None
    item.disabled = _bool_or_none(data.get("Disabled"))
    item.user_name = _str_or_none(data.get("UserName"))
    sessions = data.get("LimitLoadToSessionType")
    if isinstance(sessions, str):
        item.session_types = [sessions]
    elif isinstance(sessions, list):
        item.session_types = [s for s in sessions if isinstance(s, str)][:16]
    env = data.get("EnvironmentVariables")
    if isinstance(env, dict):
        # Names only: values frequently carry credentials.
        item.env_var_names = sorted(k for k in env if isinstance(k, str))[:32]
    item.sockets = True if isinstance(data.get("Sockets"), dict) else None
    mach = data.get("MachServices")
    item.mach_services = len(mach) if isinstance(mach, dict) else None
    bundles = data.get("AssociatedBundleIdentifiers")
    if isinstance(bundles, str):
        item.bundle_ids = [bundles]
    elif isinstance(bundles, list):
        item.bundle_ids = [b for b in bundles if isinstance(b, str)][:16]


def parse_plist_bytes(item: LaunchItem, data: bytes) -> None:
    """Parse plist bytes into ``item`` (records ``parse_error`` instead of raising)."""
    try:
        parsed = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError) as exc:
        item.parse_error = f"invalid plist: {type(exc).__name__}"
        return
    except Exception as exc:  # noqa: BLE001 - expat/plistlib raise varied errors on hostile input
        item.parse_error = f"invalid plist: {type(exc).__name__}"
        return
    if not isinstance(parsed, dict):
        item.parse_error = "plist root is not a dictionary"
        return
    apply_plist(item, parsed)


def _read_regular_file(
    path: str, follow: bool
) -> tuple[bytes | None, os.stat_result | None, str | None]:
    """Read a regular file up to MAX_PLIST_BYTES; never blocks on FIFOs/devices."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    if not follow:
        flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except PermissionError:
        return None, None, "permission denied"
    except FileNotFoundError:
        return None, None, "vanished"
    except OSError as exc:
        return None, None, f"open failed: {exc.strerror}"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, st, "not a regular file"
        if st.st_size > MAX_PLIST_BYTES:
            digest = hashlib.sha256()
            remaining = 64 * 1024 * 1024
            while remaining > 0:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
            return None, st, f"oversize:{digest.hexdigest()}"
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_PLIST_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks), st, None
    except OSError as exc:
        return None, None, f"read failed: {exc.strerror}"
    finally:
        os.close(fd)


def read_launch_item(path: Path, location: Location, allowlist: LabelAllowlist) -> LaunchItem:
    """Inspect one plist path (symlink-aware, size-bounded, never raises)."""
    item = LaunchItem(path=str(path), scope=location.scope, kind=location.kind)
    try:
        lst = os.lstat(path)
    except OSError as exc:
        item.read_error = f"lstat failed: {exc.strerror}"
        return item
    follow = False
    if stat.S_ISLNK(lst.st_mode):
        item.is_symlink = True
        try:
            item.symlink_target = os.readlink(path)[:1024]
        except OSError:
            item.symlink_target = None
        follow = True
    data, st, error = _read_regular_file(str(path), follow=follow)
    meta = st or (None if item.is_symlink else lst)
    if meta is not None:
        item.size = meta.st_size
        item.mtime = datetime.fromtimestamp(meta.st_mtime, tz=UTC).replace(microsecond=0)
        item.mode = oct(stat.S_IMODE(meta.st_mode))
        item.owner_uid = meta.st_uid
        item.world_writable = bool(meta.st_mode & stat.S_IWOTH)
    if error is not None:
        if error.startswith("oversize:"):
            item.sha256 = error.split(":", 1)[1]
            item.parse_error = "oversize plist not parsed"
        else:
            item.read_error = error
        return item
    if data is None:  # pragma: no cover - defensive
        item.read_error = "no data"
        return item
    item.sha256 = hashlib.sha256(data).hexdigest()
    parse_plist_bytes(item, data)
    item.allowlisted = allowlist.matches(item.label)
    return item


@dataclass(slots=True)
class ScanResult:
    items: dict[str, LaunchItem] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    truncated_dirs: list[str] = field(default_factory=list)


def scan_locations(locations: Sequence[Location], allowlist: LabelAllowlist) -> ScanResult:
    result = ScanResult()
    for location in locations:
        try:
            with os.scandir(location.path) as entries:
                names = []
                for count, entry in enumerate(entries):
                    if count >= MAX_ENTRIES_PER_DIR:
                        result.truncated_dirs.append(str(location.path))
                        break
                    if entry.name.endswith(".plist"):
                        names.append(entry.name)
        except FileNotFoundError:
            continue  # absent directory: nothing installed there
        except PermissionError:
            result.errors.append(f"{location.path}: permission denied")
            continue
        except OSError as exc:
            result.errors.append(f"{location.path}: {exc.strerror}")
            continue
        for name in sorted(names):
            path = location.path / name
            result.items[str(path)] = read_launch_item(path, location, allowlist)
    return result


def count_system_plists(dirs: Sequence[str] = SYSTEM_COUNT_DIRS) -> dict[str, int | None]:
    """Counts of plists in the SIP-protected system directories (no parsing)."""
    counts: dict[str, int | None] = {}
    for directory in dirs:
        key = "system_" + Path(directory).name.lower()  # system_launchagents / system_launchdaemons
        try:
            with os.scandir(directory) as entries:
                counts[key] = sum(1 for e in entries if e.name.endswith(".plist"))
        except OSError:
            counts[key] = None
    return counts


# ── Diff ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Change:
    kind: str  # created | modified | deleted
    path: str
    item: LaunchItem | None
    previous: Mapping[str, Any] | None


def diff(
    previous: Mapping[str, Mapping[str, Any]], current: Mapping[str, LaunchItem]
) -> list[Change]:
    """Compare the stored summaries with the current scan (sorted, deterministic)."""
    changes: list[Change] = []
    for path in sorted(set(previous) | set(current)):
        before = previous.get(path)
        after = current.get(path)
        if before is None and after is not None:
            changes.append(Change("created", path, after, None))
        elif before is not None and after is None:
            changes.append(Change("deleted", path, None, before))
        elif before is not None and after is not None and before.get("fp") != after.fingerprint:
            changes.append(Change("modified", path, after, before))
    return changes


_EVENT_TYPE = {
    "created": "persistence.launchd.item_created",
    "modified": "persistence.launchd.item_modified",
    "deleted": "persistence.launchd.item_deleted",
}


def change_to_event(
    change: Change, ctx: SourceContext, *, observed_at: datetime, snapshot: str
) -> SecurityEvent:
    item = change.item
    previous = change.previous or {}
    if item is not None:
        attrs = item.attributes()
        label = item.label
        scope = item.scope
        fingerprint = item.fingerprint
        redactions = item.redactions
    else:
        label = previous.get("label") if isinstance(previous.get("label"), str) else None
        scope = str(previous.get("scope") or "unknown")
        fingerprint = str(previous.get("fp") or "")
        attrs = bounded_attributes(
            {
                "label": label,
                "scope": scope,
                "kind": previous.get("kind"),
                "program": previous.get("program"),
            }
        )
        redactions = 0
    if change.kind == "modified" or change.kind == "deleted":
        prev_fp = previous.get("fp")
        if isinstance(prev_fp, str) and len(prev_fp) == 64:
            attrs["previous_sha256"] = prev_fp
    name = label or os.path.basename(change.path)
    kind = item.kind if item is not None else str(previous.get("kind") or "item")
    message = f"launchd {kind} plist {change.kind}: {change.path}"
    if label:
        message += f" (label {label})"
    # The snapshot id disambiguates re-creation of identical content; retries are
    # idempotent because the event is persisted in the outbox with its checkpoint.
    native = f"{change.path}:{change.kind}:{fingerprint}:{snapshot}"
    return make_event(
        ctx=ctx,
        event_type=_EVENT_TYPE[change.kind],
        source_type=SOURCE,
        native_key=native,
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=message,
        action=f"launchd_item_{change.kind}",
        outcome=Outcome.SUCCESS,
        resource=Resource(type="launchd_plist", name=name, path=change.path),
        attributes=attrs,
        simulation=simulation_tag(change.path, label),
        redaction_count=redactions,
    )


def to_inventory(
    item: LaunchItem, ctx: SourceContext, *, observed_at: datetime, snapshot: str
) -> InventoryItem:
    return InventoryItem(
        asset_id=ctx.asset_id,
        item_type=InventoryItemType.LAUNCH_ITEM,
        item_key=item.path,
        attributes=item.attributes(),
        snapshot_id=snapshot,
        observed_at=to_ms(observed_at),
        present=True,
        collector_id=ctx.collector_id,
    )


def tombstone(
    path: str,
    previous: Mapping[str, Any],
    ctx: SourceContext,
    *,
    observed_at: datetime,
    snapshot: str,
) -> InventoryItem:
    return InventoryItem(
        asset_id=ctx.asset_id,
        item_type=InventoryItemType.LAUNCH_ITEM,
        item_key=path,
        attributes=bounded_attributes(
            {
                "label": previous.get("label"),
                "scope": previous.get("scope"),
                "kind": previous.get("kind"),
            }
        ),
        snapshot_id=snapshot,
        observed_at=to_ms(observed_at),
        present=False,
        collector_id=ctx.collector_id,
    )

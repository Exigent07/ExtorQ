"""MacOSCollector: the native macOS endpoint collector (SDK adapter).

Configured in ``config/collectors/macos.yaml`` with
``module: extorq_collectors.macos.collector:MacOSCollector``. The runner calls
:meth:`MacOSCollector.collect` every ``interval_seconds`` (60 s); each *source*
has its own interval and runs when due:

==================  ========  ====================================================
source              default   records
==================  ========  ====================================================
``unified_log``     60 s      auth/sudo/XProtect/Gatekeeper events, gap events
``launchd``         60 s      persistence.launchd.* events + launch_item inventory
``inventory``       300 s     listeners (+ network.listener.* events), processes,
                              local accounts (+ account.user.* events), services
                              (Service / ServiceInstance + service.* events)
``posture``         300 s     ScanRun x2 + PostureFindings + setting-change events
``applications``    3600 s    installed applications inventory
``asset``           300 s     Asset record (when changed or refresh due)
==================  ========  ====================================================

Each source commits its records, checkpoints and snapshots in its own
``ctx.emit`` transaction. A failing source drops whatever it staged
(``ctx.discard_staged``) so it can never advance a snapshot without the records
describing it, is reported in health, and does not stop the other sources. The
cycle fails (CollectorHealth ``failed``) only when every due source failed.

Runs as the logged-in user with supported, read-only interfaces: no sudo, no
Full Disk Access, no configuration profile, no launchctl load/bootstrap.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from extorq.contracts import (
    InventoryItem,
    InventoryItemType,
    PostureFinding,
    SecurityEvent,
    SourceType,
)
from extorq.contracts.identity import event_id, iso_utc
from extorq.contracts.service import ServiceRef
from extorq_collectors.macos import launchd as launchd_mod
from extorq_collectors.macos import services as services_mod
from extorq_collectors.macos.adapters import MACOS_ADAPTERS
from extorq_collectors.macos.commands import CommandRunner, SubprocessRunner
from extorq_collectors.macos.common import (
    COLLECTOR_TYPE,
    COLLECTOR_VERSION,
    SourceContext,
    clean_text,
    make_event,
    snapshot_id,
    to_ms,
)
from extorq_collectors.macos.inventory import (
    DSCL_USERS_SHELL,
    DSCL_USERS_UID,
    PS_ARGS_ARGV,
    PS_ARGV,
    SYSTEM_PROFILER_APPS,
    ListenerSnapshot,
    ProcessRow,
    account_event,
    accounts_from,
    collect_listeners,
    inventory_item,
    listener_event,
    parse_ps,
    parse_ps_args,
    parse_system_profiler_apps,
    with_verified_paths,
)
from extorq_collectors.macos.launchctl import collect_domain
from extorq_collectors.macos.posture import (
    PostureOptions,
    build_scan_records,
    parse_sw_vers,
    run_posture,
    setting_change_event,
)
from extorq_collectors.macos.procinfo import no_paths, pid_path
from extorq_collectors.macos.settings import MacOSSettings
from extorq_collectors.macos.unified_log import (
    DedupState,
    LogRecord,
    build_log_show_argv,
    build_predicate,
    classify,
    native_key,
    next_checkpoint,
    parse_ndjson,
    plan_window,
    to_event,
)
from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert
from extorq_collectors.services import AdapterContext

UNIFIED_LOG_CHECKPOINT = "unified_log.window"
KV_SOURCES = "macos.sources"
KV_ADAPTER_LAST_EVENT = "macos.adapter_last_event"
KV_FULL_INVENTORY = "macos.full_inventory"
SOURCES = ("unified_log", "launchd", "inventory", "posture", "applications", "asset")

#: Telemetry this collector cannot provide with supported, unprivileged interfaces.
STATIC_GAPS: tuple[str, ...] = (
    "process execution telemetry (exec/fork/exit) requires an Endpoint Security "
    "entitlement: not collected; processes are periodic ps snapshots only",
    "file creation/modification telemetry requires Endpoint Security or Full Disk Access: "
    "not collected (launchd plists are polled every launchd interval instead)",
    "network flow telemetry requires a Network Extension: not collected",
    "Background Task Management database (login/background item approvals) requires root: "
    "not collected; loaded jobs are visible through launchctl print only",
    "unified logging redacts dynamic message arguments as <private> unless the producer "
    "marks them public; private values are not recoverable without a profile or root",
    "unified logging is not an audit trail: retention is size-bounded and messages may "
    "be rate-limited",
    "/System/Library launchd plists (sealed system volume) are counted, not diffed",
    "TCC privacy database requires Full Disk Access: not collected",
)
#: Posture checks that are, by definition, about one host service (launchd label).
SHARING_CHECK_LABEL: dict[str, str] = {
    "macos.sharing.remote_login": "com.openssh.sshd",
    "macos.sharing.screen_sharing": "com.apple.screensharing",
    "macos.sharing.remote_management": "com.apple.RemoteDesktop.agent",
    "macos.sharing.file_sharing_smb": "com.apple.smbd",
    "macos.sharing.airplay_receiver": "com.apple.controlcenter",
}
_GUID = re.compile(r"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$")
_MAX_GUID_CACHE = 256


class SourceFailure(RuntimeError):
    """A source could not run this cycle (message is sanitised and secret-free)."""


class MacOSCollectorError(RuntimeError):
    """Every due source failed in this cycle."""


def _iso(value: datetime | None) -> str | None:
    return iso_utc(value) if value is not None else None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _error_text(exc: BaseException) -> str:
    text, _ = clean_text(f"{type(exc).__name__}: {exc}", 500)
    return text or type(exc).__name__


class MacOSCollector(Collector):
    collector_type: ClassVar[str] = COLLECTOR_TYPE
    source_types: ClassVar[tuple[str, ...]] = (
        SourceType.MACOS_UNIFIED_LOG.value,
        SourceType.MACOS_LAUNCHD.value,
        SourceType.MACOS_INVENTORY.value,
        SourceType.MACOS_POSTURE.value,
    )
    collector_version: ClassVar[str] = COLLECTOR_VERSION

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        path_resolver: Callable[[int], str | None] | None = None,
        home: Path | None = None,
        uid: int | None = None,
        launch_locations: list[launchd_mod.Location] | None = None,
        apple_definitions_root: Path | None = None,
        system_count_dirs: tuple[str, ...] | None = None,
        require_macos: bool = True,
    ) -> None:
        self.runner: CommandRunner = runner or SubprocessRunner()
        self.resolve_path = path_resolver or pid_path
        self.home = home
        self.uid = os.getuid() if uid is None else uid
        self.launch_locations = launch_locations
        self.apple_root = apple_definitions_root
        self.system_count_dirs = system_count_dirs
        self.require_macos = require_macos
        self._launch_items: dict[str, launchd_mod.LaunchItem] | None = None
        self._listeners: ListenerSnapshot | None = None
        self._listeners_at: datetime | None = None
        self._listener_services: dict[str, str] = {}
        self._service_names: dict[str, str] = {}
        self._guid_cache: dict[str, str | None] = {}
        self._stats: dict[str, dict[str, Any]] = {}
        self._lock_fd: int | None = None

    # ── lifecycle ─────────────────────────────────────────────────────

    def setup(self, ctx: CollectorContext) -> None:
        if self.require_macos and sys.platform != "darwin":
            raise MacOSCollectorError("the macOS collector only runs on macOS")
        MacOSSettings.from_mapping(ctx.config)  # fail fast on invalid settings
        self._acquire_instance_lock(Path(ctx.store.path).with_name("macos-collector.lock"))

    def _acquire_instance_lock(self, path: Path) -> None:
        """One collector instance per state directory.

        Two processes diffing against the same stored snapshots would both report the
        same change (with different snapshot ids, so different event ids). The lock is
        released automatically when the process exits.
        """
        if self._lock_fd is not None:
            return
        fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise MacOSCollectorError(
                "another macOS collector instance is running with the same state directory"
            ) from None
        self._lock_fd = fd

    def close(self) -> None:
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None

    def collect(self, ctx: CollectorContext) -> None:
        settings = MacOSSettings.from_mapping(ctx.config)
        now = ctx.now()
        state: dict[str, dict[str, Any]] = dict(ctx.state.get(KV_SOURCES, {}) or {})
        ran: list[str] = []
        failed: list[str] = []
        for name in SOURCES:
            config = getattr(settings, name)
            entry = dict(state.get(name) or {})
            if not config.enabled:
                entry.update(status="disabled")
                state[name] = entry
                continue
            last = _parse_iso(entry.get("last_attempt"))
            if last is not None and now - last < timedelta(seconds=config.interval_seconds - 1):
                continue
            entry["last_attempt"] = iso_utc(now)
            try:
                runner: Callable[[CollectorContext, MacOSSettings, datetime], None] = getattr(
                    self, f"_run_{name}"
                )
                runner(ctx, settings, now)
            except Exception as exc:  # noqa: BLE001 - isolate sources; reported in health
                dropped = ctx.discard_staged()
                entry.update(status="error", error=_error_text(exc), dropped_snapshots=dropped)
                failed.append(name)
                ctx.log.warning("macos_source_failed", source=name, error=entry["error"])
            else:
                entry.update(status="ok", last_success=iso_utc(now), error=None)
                ran.append(name)
            state[name] = entry
            ctx.state.set(KV_SOURCES, state)
        ctx.state.set(KV_SOURCES, state)
        ctx.health_details = self._health_details(settings, state)
        ctx.checkpoint_summary = self._checkpoint_summary(ctx)
        if failed and not ran:
            errors = "; ".join(f"{n}: {state[n].get('error')}" for n in failed)
            raise MacOSCollectorError(f"all due sources failed: {errors}"[:1000])

    # ── helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _src(ctx: CollectorContext) -> SourceContext:
        return SourceContext(
            collector_id=ctx.collector_id,
            asset_id=ctx.asset_id,
            collector_version=ctx.collector_version,
        )

    @staticmethod
    def _full_due(ctx: CollectorContext, name: str, every: int, now: datetime) -> bool:
        marks = ctx.state.get(KV_FULL_INVENTORY, {}) or {}
        last = _parse_iso(marks.get(name)) if isinstance(marks, dict) else None
        return last is None or now - last >= timedelta(seconds=every)

    @staticmethod
    def _mark_full(ctx: CollectorContext, name: str, now: datetime) -> None:
        marks = dict(ctx.state.get(KV_FULL_INVENTORY, {}) or {})
        marks[name] = iso_utc(now)
        ctx.state.set(KV_FULL_INVENTORY, marks)

    def _set_stats(self, name: str, **values: Any) -> None:
        self._stats[name] = values

    # ── unified log ───────────────────────────────────────────────────

    def _resolve_guid(self, guid: str) -> str | None:
        guid = guid.upper()
        if not _GUID.match(guid):
            return None
        if guid in self._guid_cache:
            return self._guid_cache[guid]
        result = self.runner.run(
            ["/usr/bin/dscl", ".", "-search", "/Users", "GeneratedUID", guid],
            timeout=10.0,
            max_stdout=64 * 1024,
        )
        name: str | None = None
        if result.ok:
            first = result.text().split(None, 1)
            if first and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.@-]{0,254}", first[0]):
                name = first[0]
        if len(self._guid_cache) >= _MAX_GUID_CACHE:
            self._guid_cache.clear()
        self._guid_cache[guid] = name
        return name

    def _run_unified_log(
        self, ctx: CollectorContext, settings: MacOSSettings, now: datetime
    ) -> None:
        cfg = settings.unified_log
        src = self._src(ctx)
        dedup = DedupState.from_json(ctx.checkpoints.get(UNIFIED_LOG_CHECKPOINT))
        plan = plan_window(
            now_epoch=now.timestamp(),
            checkpoint_end=dedup.end,
            overlap_seconds=cfg.overlap_seconds,
            settle_seconds=cfg.settle_seconds,
            max_window_seconds=cfg.max_window_seconds,
            max_backfill_seconds=cfg.max_backfill_seconds,
            initial_lookback_seconds=cfg.initial_lookback_seconds,
        )
        if plan is None:
            self._set_stats("unified_log", note="no new window yet")
            return
        argv = build_log_show_argv(plan.start, plan.end, build_predicate(cfg.producers))
        result = self.runner.run(
            argv, timeout=cfg.command_timeout_seconds, max_stdout=cfg.max_output_bytes
        )
        if result.error is not None:
            raise SourceFailure(f"log show: {result.summary()}")
        if (
            result.returncode not in (0, None)
            and not result.timed_out
            and not result.stdout_truncated
        ):
            raise SourceFailure(f"log show: {result.summary()}")
        records, stats = parse_ndjson(result.stdout, max_records=cfg.max_records_per_cycle)
        if result.timed_out and not records:
            raise SourceFailure(f"log show timed out after {cfg.command_timeout_seconds:.0f}s")
        truncated = (
            result.timed_out
            or result.stdout_truncated
            or not stats.finished
            or len(records) >= cfg.max_records_per_cycle
        )
        observed = to_ms(ctx.now())
        resolver = self._resolve_guid if cfg.resolve_generated_uid else None
        seen = set(dedup.seen)
        ids: list[str] = []
        events: list[SecurityEvent] = []
        duplicates = build_errors = private = 0
        adapter_last: dict[str, datetime] = {}
        for record in records:
            eid = event_id(SourceType.MACOS_UNIFIED_LOG.value, ctx.asset_id, native_key(record))
            ids.append(eid)
            if eid in seen:
                duplicates += 1
                continue
            seen.add(eid)
            try:
                event = self._log_event(record, src, observed, resolver)
            except Exception:  # noqa: BLE001 - one odd record must not block the source
                build_errors += 1
                continue
            if event.attributes.get("private_redaction"):
                private += 1
            if event.service is not None and event.service.adapter_id:
                current = adapter_last.get(event.service.adapter_id)
                if current is None or event.event_time > current:
                    adapter_last[event.service.adapter_id] = event.event_time
            events.append(event)
        new_end, remember, forced = next_checkpoint(
            plan=plan,
            records=records,
            event_ids=ids,
            truncated=truncated,
            overlap_seconds=cfg.overlap_seconds,
        )
        gaps: list[SecurityEvent] = []
        if plan.skipped_seconds > 0 and dedup.end is not None:
            gaps.append(
                self._gap_event(
                    src,
                    observed,
                    reason="checkpoint older than max_backfill_seconds; history skipped",
                    start=datetime.fromtimestamp(dedup.end, UTC),
                    end=datetime.fromtimestamp(plan.start, UTC),
                )
            )
        if forced:
            gaps.append(
                self._gap_event(
                    src,
                    observed,
                    reason="record or output limit reached without progress; rest of window "
                    "skipped",
                    start=datetime.fromtimestamp(plan.start, UTC),
                    end=datetime.fromtimestamp(plan.end, UTC),
                )
            )
        checkpoint = DedupState(end=new_end, seen=remember).to_json()
        ctx.emit([*events, *gaps], {UNIFIED_LOG_CHECKPOINT: checkpoint})
        window_end = datetime.fromtimestamp(new_end, UTC)
        ctx.report_lag(window_end)
        if adapter_last:
            stored = dict(ctx.state.get(KV_ADAPTER_LAST_EVENT, {}) or {})
            for adapter_id, when in adapter_last.items():
                previous = _parse_iso(stored.get(adapter_id))
                if previous is None or when > previous:
                    stored[adapter_id] = iso_utc(when)
            ctx.state.set(KV_ADAPTER_LAST_EVENT, stored)
        self._set_stats(
            "unified_log",
            window=f"{iso_utc(datetime.fromtimestamp(plan.start, UTC))}..{iso_utc(window_end)}",
            records=len(records),
            events=len(events),
            duplicates=duplicates,
            build_errors=build_errors,
            private_fields=private,
            truncated=truncated,
            duration_s=result.duration_seconds,
        )

    def _log_event(
        self,
        record: LogRecord,
        src: SourceContext,
        observed: datetime,
        resolver: Callable[[str], str | None] | None,
    ) -> SecurityEvent:
        for adapter_id, adapter in MACOS_ADAPTERS.items():
            if adapter.accepts_record(record):
                ref = services_mod.adapter_service_ref(src.asset_id, adapter_id)
                return adapter.event_for(
                    record,
                    AdapterContext(
                        asset_id=src.asset_id,
                        asset_type="macos_host",
                        collector_id=src.collector_id,
                        collector_version=src.collector_version,
                        service=ref,
                        observed_time=observed,
                    ),
                    resolve_actor=resolver,
                )
        return to_event(
            record, classify(record), src, observed_time=observed, resolve_actor=resolver
        )

    @staticmethod
    def _gap_event(
        src: SourceContext, observed: datetime, *, reason: str, start: datetime, end: datetime
    ) -> SecurityEvent:
        return make_event(
            ctx=src,
            event_type="extorq.collector.gap_detected",
            source_type=SourceType.MACOS_UNIFIED_LOG,
            native_key=f"gap:unified_log:{int(start.timestamp())}:{int(end.timestamp())}:{reason}",
            event_time=observed,
            observed_time=observed,
            parser="macos-unified-log",
            message=f"unified log collection gap {iso_utc(start)} .. {iso_utc(end)}: {reason}",
            action="collection_gap",
            attributes={
                "collector_id": src.collector_id,
                "source_type": SourceType.MACOS_UNIFIED_LOG.value,
                "gap_reason": reason,
                "gap_start": iso_utc(start),
                "gap_end": iso_utc(end),
                "gap_seconds": max(0, int((end - start).total_seconds())),
            },
        )

    # ── launchd ───────────────────────────────────────────────────────

    def _run_launchd(self, ctx: CollectorContext, settings: MacOSSettings, now: datetime) -> None:
        cfg = settings.launchd
        src = self._src(ctx)
        allowlist = launchd_mod.LabelAllowlist(cfg.allowlist)
        locations = self.launch_locations or launchd_mod.default_locations(self.home)
        scan = launchd_mod.scan_locations(locations, allowlist)
        counts = launchd_mod.count_system_plists(
            self.system_count_dirs or launchd_mod.SYSTEM_COUNT_DIRS
        )
        summaries: dict[str, dict[str, Any]] = {p: i.summary() for p, i in scan.items.items()}
        # A directory that could not be read (or was truncated) keeps its previous items:
        # unreadable must never look like "deleted".
        unreliable = [e.split(":", 1)[0] for e in scan.errors] + scan.truncated_dirs
        if unreliable:
            for path, (text, _digest) in ctx.store.snapshot("launchd.items").items():
                if any(path.startswith(d.rstrip("/") + "/") for d in unreliable):
                    summaries.setdefault(path, json.loads(text))
        diff = ctx.diff_snapshot("launchd.items", summaries)
        snap = snapshot_id(ctx.collector_id, "launchd", now)
        observed = to_ms(now)
        records: list[Any] = []
        if not diff.baseline:
            for path in sorted(diff.added):
                item = scan.items.get(path)
                if item is not None:
                    records.append(
                        self._launch_event(
                            launchd_mod.Change("created", path, item, None), src, observed, snap
                        )
                    )
            for path in sorted(diff.changed):
                item = scan.items.get(path)
                if item is not None:
                    records.append(
                        self._launch_event(
                            launchd_mod.Change("modified", path, item, diff.previous.get(path)),
                            src,
                            observed,
                            snap,
                        )
                    )
            for path in sorted(diff.removed):
                records.append(
                    self._launch_event(
                        launchd_mod.Change("deleted", path, None, diff.removed[path]),
                        src,
                        observed,
                        snap,
                    )
                )
        full = diff.baseline or self._full_due(ctx, "launchd", cfg.full_inventory_seconds, now)
        keys = set(scan.items) if full else set(diff.added) | set(diff.changed)
        for path in sorted(keys):
            item = scan.items.get(path)
            if item is not None:
                records.append(
                    launchd_mod.to_inventory(item, src, observed_at=observed, snapshot=snap)
                )
        for path, previous in sorted(diff.removed.items()):
            records.append(
                launchd_mod.tombstone(path, previous, src, observed_at=observed, snapshot=snap)
            )
        ctx.emit(records)
        if full:
            self._mark_full(ctx, "launchd", now)
        self._launch_items = scan.items
        events = sum(1 for r in records if isinstance(r, SecurityEvent))
        self._set_stats(
            "launchd",
            items=len(scan.items),
            events=events,
            baseline=diff.baseline,
            errors=scan.errors[:8],
            system_launchagents=counts.get("system_launchagents"),
            system_launchdaemons=counts.get("system_launchdaemons"),
        )

    def _launch_event(
        self, change: launchd_mod.Change, src: SourceContext, observed: datetime, snap: str
    ) -> SecurityEvent:
        label: str | None
        if change.item is not None:
            label = change.item.label
        else:
            previous_label = (change.previous or {}).get("label")
            label = previous_label if isinstance(previous_label, str) else None
        # Same natural key as the discovery: the label, or the plist path when it has none.
        ref = services_mod.service_ref_for_label(
            src.asset_id, label or change.path, label or os.path.basename(change.path), None
        )
        return launchd_mod.change_to_event(
            change, src, observed_at=observed, snapshot=snap, service=ref
        )

    # ── inventory (+ services) ────────────────────────────────────────

    def _run_inventory(self, ctx: CollectorContext, settings: MacOSSettings, now: datetime) -> None:
        cfg = settings.inventory
        src = self._src(ctx)
        observed = to_ms(now)
        ps = self.runner.run(PS_ARGV, timeout=cfg.command_timeout_seconds)
        if not ps.ok:
            raise SourceFailure(f"ps: {ps.summary()}")
        rows = parse_ps(ps.text())
        if not rows:
            raise SourceFailure("ps returned no parseable process rows")
        rows = with_verified_paths(
            rows, self.resolve_path if cfg.verify_executable_paths else no_paths
        )
        if cfg.include_process_args:
            args_result = self.runner.run(PS_ARGS_ARGV, timeout=cfg.command_timeout_seconds)
            if args_result.ok:
                args, _redactions = parse_ps_args(args_result.text())
                rows = [replace(r, args=args.get(r.pid)) for r in rows]
        processes: dict[int, ProcessRow] = {r.pid: r for r in rows}
        listeners = collect_listeners(
            self.runner,
            include_udp=cfg.include_udp,
            timeout=cfg.command_timeout_seconds,
            process_index=processes,
        )
        records: list[Any] = []
        notes: dict[str, Any] = {}

        # Services first: listener events reference the services that own the sockets.
        if settings.services.enabled:
            try:
                records.extend(self._services(ctx, settings, now, processes, listeners))
            except Exception as exc:  # noqa: BLE001 - discovery must not block inventory
                ctx.discard_staged()
                self._listener_services = {}
                notes["services_error"] = _error_text(exc)
                self._set_stats("services", error=notes["services_error"])

        snap = snapshot_id(ctx.collector_id, "inventory", now)
        full = self._full_due(ctx, "inventory", cfg.full_inventory_seconds, now)

        # Listening sockets (snapshot name carries the method: switching never fakes diffs).
        if listeners.method != "unavailable":
            current = {k: v.summary() for k, v in listeners.listeners.items()}
            ldiff = ctx.diff_snapshot(f"listeners.{listeners.method}", current)
            if not ldiff.baseline:
                for key in sorted(ldiff.added) + sorted(ldiff.changed):
                    extra: dict[str, Any] = {}
                    if key in ldiff.changed:
                        before = ldiff.previous.get(key, {}).get("processes")
                        extra = {
                            "owner_changed": True,
                            "previous_processes": before if isinstance(before, list) else None,
                        }
                    records.append(
                        listener_event(
                            "opened",
                            key,
                            listeners.listeners[key],
                            None,
                            src,
                            observed_at=observed,
                            snapshot=snap,
                            service=self._listener_ref(key),
                            extra_attributes=extra,
                        )
                    )
                for key, previous in sorted(ldiff.removed.items()):
                    records.append(
                        listener_event(
                            "closed", key, None, previous, src, observed_at=observed, snapshot=snap
                        )
                    )
            keys = (
                set(listeners.listeners)
                if (full or ldiff.baseline)
                else (set(ldiff.added) | set(ldiff.changed))
            )
            for key in sorted(keys):
                records.append(
                    inventory_item(
                        InventoryItemType.LISTENER,
                        key,
                        listeners.listeners[key].attributes(),
                        src,
                        observed_at=observed,
                        snapshot=snap,
                    )
                )
            for key, previous in sorted(ldiff.removed.items()):
                records.append(
                    inventory_item(
                        InventoryItemType.LISTENER,
                        key,
                        {"protocol": previous.get("protocol"), "port": previous.get("port")},
                        src,
                        observed_at=observed,
                        snapshot=snap,
                        present=False,
                    )
                )

        # Processes (inventory only: the catalog has no macOS process events).
        pdiff = ctx.diff_snapshot(
            "processes",
            {r.key: {"exe": r.executable, "user": r.user, "ppid": r.ppid} for r in rows},
        )
        pkeys = (
            {r.key for r in rows}
            if (full or pdiff.baseline)
            else set(pdiff.added) | set(pdiff.changed)
        )
        by_key = {r.key: r for r in rows}
        for key in sorted(pkeys):
            records.append(
                inventory_item(
                    InventoryItemType.PROCESS,
                    key,
                    by_key[key].attributes(),
                    src,
                    observed_at=observed,
                    snapshot=snap,
                )
            )
        for key, previous in sorted(pdiff.removed.items()):
            records.append(
                inventory_item(
                    InventoryItemType.PROCESS,
                    key,
                    {"executable": previous.get("exe"), "user": previous.get("user")},
                    src,
                    observed_at=observed,
                    snapshot=snap,
                    present=False,
                )
            )

        # Local accounts (names, UIDs, shells; never RealName).
        accounts_count: int | None = None
        if cfg.accounts:
            uid_result = self.runner.run(DSCL_USERS_UID, timeout=cfg.command_timeout_seconds)
            shell_result = self.runner.run(DSCL_USERS_SHELL, timeout=cfg.command_timeout_seconds)
            if uid_result.ok:
                accounts = accounts_from(
                    uid_result.text(), shell_result.text() if shell_result.ok else None
                )
                accounts_count = len(accounts)
                adiff = ctx.diff_snapshot(
                    "accounts", {name: a.summary() for name, a in accounts.items()}
                )
                if not adiff.baseline:
                    for name in sorted(adiff.added):
                        records.append(
                            account_event(
                                "created",
                                name,
                                accounts[name].summary(),
                                src,
                                observed_at=observed,
                                snapshot=snap,
                            )
                        )
                    for name, previous in sorted(adiff.removed.items()):
                        records.append(
                            account_event(
                                "deleted", name, previous, src, observed_at=observed, snapshot=snap
                            )
                        )
                akeys = (
                    set(accounts)
                    if (full or adiff.baseline)
                    else set(adiff.added) | set(adiff.changed)
                )
                for name in sorted(akeys):
                    records.append(
                        inventory_item(
                            InventoryItemType.USER,
                            name,
                            accounts[name].attributes(),
                            src,
                            observed_at=observed,
                            snapshot=snap,
                        )
                    )
                for name in sorted(adiff.removed):
                    records.append(
                        inventory_item(
                            InventoryItemType.USER,
                            name,
                            {},
                            src,
                            observed_at=observed,
                            snapshot=snap,
                            present=False,
                        )
                    )
            else:
                notes["accounts_error"] = uid_result.summary()

        ctx.emit(records)
        if full:
            self._mark_full(ctx, "inventory", now)
        self._listeners = listeners
        self._listeners_at = now
        self._set_stats(
            "inventory",
            processes=len(rows),
            executable_paths_verified=sum(1 for r in rows if r.verified),
            listener_method=listeners.method,
            listeners=len(listeners.listeners),
            listener_errors=listeners.errors[:4] or None,
            accounts=accounts_count,
            events=sum(1 for r in records if isinstance(r, SecurityEvent)),
            records=len(records),
            **notes,
        )

    def _listener_ref(self, key: str) -> ServiceRef | None:
        service_id = self._listener_services.get(key)
        if service_id is None:
            return None
        return ServiceRef(
            service_id=service_id, name=self._service_names.get(service_id, key)[:256]
        )

    def _apple_definitions(self) -> dict[str, launchd_mod.LaunchItem]:
        allow = launchd_mod.LabelAllowlist()
        out: dict[str, launchd_mod.LaunchItem] = {}
        for apple in services_mod.APPLE_SERVICES:
            path = Path(apple.definition)
            if self.apple_root is not None:
                path = self.apple_root / path.relative_to("/")
            if not path.exists():
                continue
            location = launchd_mod.Location(
                path.parent, "apple", "daemon" if "Daemons" in path.parent.name else "agent"
            )
            out[apple.label] = launchd_mod.read_launch_item(path, location, allow)
        return out

    def _services(
        self,
        ctx: CollectorContext,
        settings: MacOSSettings,
        now: datetime,
        processes: Mapping[int, ProcessRow],
        listeners: ListenerSnapshot,
    ) -> list[Any]:
        src = self._src(ctx)
        observed = to_ms(now)
        domains = [
            collect_domain(
                self.runner, "system", timeout=settings.inventory.command_timeout_seconds
            ),
            collect_domain(
                self.runner, f"gui/{self.uid}", timeout=settings.inventory.command_timeout_seconds
            ),
        ]
        domain_errors = [f"{d.domain}: {d.error}" for d in domains if d.error]
        if self._launch_items is None:
            locations = self.launch_locations or launchd_mod.default_locations(self.home)
            self._launch_items = launchd_mod.scan_locations(
                locations, launchd_mod.LabelAllowlist(settings.launchd.allowlist)
            ).items
        result = services_mod.discover(
            services_mod.DiscoveryInputs(
                asset_id=ctx.asset_id,
                launch_items=self._launch_items,
                apple_definitions=self._apple_definitions(),
                domains=[d for d in domains if d.ok],
                processes=processes,
                listeners=listeners.listeners,
                listener_method=listeners.method,
            )
        )
        sources = ctx.state.get(KV_SOURCES, {}) or {}
        ul_state = sources.get("unified_log", {}) if isinstance(sources, dict) else {}
        last_events = {
            k: v
            for k, v in (
                (k, _parse_iso(v))
                for k, v in (ctx.state.get(KV_ADAPTER_LAST_EVENT, {}) or {}).items()
            )
            if v is not None
        }
        window_end = DedupState.from_json(ctx.checkpoints.get(UNIFIED_LOG_CHECKPOINT)).end
        coverage = services_mod.CoverageInputs(
            enabled_producers=frozenset(settings.unified_log.producers)
            if settings.unified_log.enabled
            else frozenset(),
            unified_log_fresh_until=datetime.fromtimestamp(window_end, UTC)
            if window_end is not None
            else None,
            unified_log_failing=ul_state.get("status") == "error",
            stale_after_seconds=settings.services.stale_after_seconds,
            adapter_last_event=last_events,
        )
        previous_snapshot = {
            key: text for key, (text, _digest) in ctx.store.snapshot("services").items()
        }
        first_seen: dict[str, str] = {}
        for key, text in previous_snapshot.items():
            try:
                value = json.loads(text).get("first_seen")
            except (ValueError, AttributeError):
                value = None
            if isinstance(value, str):
                first_seen[key] = value
        services, instances = services_mod.build_records(
            result,
            ctx=src,
            now=now,
            first_seen=first_seen,
            coverage=coverage,
            processes=processes,
        )
        # Records are complete: only now stage the snapshots that describe them.
        sdiff = ctx.diff_snapshot(
            "services", {s.service_id: services_mod.ServiceSummary.of(s) for s in services}
        )
        idiff = ctx.diff_snapshot(
            "service_instances",
            {i.instance_id: services_mod.instance_summary(i) for i in instances},
        )
        snap = snapshot_id(ctx.collector_id, "services", now)
        by_id = {s.service_id: s for s in services}
        records: list[Any] = [*services, *instances]
        for service_id in sorted(sdiff.added):
            records.append(
                services_mod.discovered_event(
                    by_id[service_id],
                    src,
                    observed_at=observed,
                    snapshot=snap,
                    baseline=sdiff.baseline,
                )
            )
        for service_id in sorted(sdiff.changed):
            exposure = services_mod.exposure_event(
                by_id[service_id],
                sdiff.previous.get(service_id, {}),
                src,
                observed_at=observed,
                snapshot=snap,
            )
            if exposure is not None:
                records.append(exposure)
        for service_id, previous in sorted(sdiff.removed.items()):
            records.append(
                services_mod.removed_event(
                    service_id, previous, src, observed_at=observed, snapshot=snap
                )
            )
            tombstone = services_mod.service_tombstone(service_id, previous, src, now)
            if tombstone is not None:
                records.append(tombstone)
        for _instance_id, previous in sorted(idiff.removed.items()):
            try:
                records.append(services_mod.instance_tombstone(previous, src, observed))
            except (KeyError, ValueError, TypeError):
                continue
        self._listener_services = dict(result.listener_service)
        self._service_names = {s.service_id: s.name for s in services}
        tally = services_mod.counts(services)
        self._set_stats(
            "services",
            services=len(services),
            instances=len(instances),
            monitored=tally.get("monitored", 0),
            degraded=tally.get("degraded", 0),
            unmonitored=tally.get("unmonitored", 0),
            adapters_implemented=tally.get("support_implemented", 0),
            adapters_planned=tally.get("support_planned", 0),
            unattributed_listeners=len(result.unattributed_listeners),
            domain_errors=domain_errors or None,
            truncated=result.truncated,
        )
        return records

    # ── posture ───────────────────────────────────────────────────────

    def _run_posture(self, ctx: CollectorContext, settings: MacOSSettings, now: datetime) -> None:
        cfg = settings.posture
        src = self._src(ctx)
        fresh = (
            self._listeners
            if self._listeners is not None
            and self._listeners_at is not None
            and now - self._listeners_at < timedelta(seconds=120)
            else None
        )
        run = run_posture(
            self.runner,
            PostureOptions(
                max_admin_accounts=cfg.max_admin_accounts,
                command_timeout=cfg.command_timeout_seconds,
                os_update_medium_after_days=cfg.os_update_medium_after_days,
            ),
            ctx.now,
            listeners=fresh,
        )
        scans, findings = build_scan_records(run, src, producer_id=ctx.producer_id)
        findings = [self._attribute_finding(f, src.asset_id) for f in findings]
        records: list[Any] = [*scans, *findings]
        current = {k: {"v": v} for k, v in sorted(run.settings.items())}
        sdiff = ctx.diff_snapshot("posture.settings", current)
        observed = to_ms(run.finished_at)
        config_scan = next(
            (s.scan_run_id for s in scans if s.attributes.get("scope_name") == "configuration"),
            scans[0].scan_run_id if scans else "",
        )
        if not sdiff.baseline:
            for key in sorted(sdiff.changed):
                before = sdiff.previous.get(key, {}).get("v")
                after = current[key]["v"]
                if before is None or after is None:
                    continue
                records.append(
                    setting_change_event(
                        key, before, after, src, observed_at=observed, scan_run_id=config_scan
                    )
                )
        ctx.emit(records)
        self._set_stats(
            "posture",
            scans=[f"{s.attributes.get('scope_name')}={s.status.value}" for s in scans],
            findings=len(findings),
            failed_checks=sorted({f.check_id for f in findings})[:32],
            listener_method=run.listener_method,
            command_errors=run.command_errors[:6] or None,
        )

    def _attribute_finding(self, finding: PostureFinding, asset_id: str) -> PostureFinding:
        service_id: str | None = None
        label = SHARING_CHECK_LABEL.get(finding.check_id)
        if label is not None:
            service_id = services_mod.service_ref_for_label(asset_id, label, label, None).service_id
        elif finding.check_id == "macos.network.exposed_listener" and finding.resource is not None:
            service_id = self._listener_services.get(finding.resource.name or "")
        if service_id is None:
            return finding
        return PostureFinding.model_validate({**finding.model_dump(), "service_id": service_id})

    # ── applications ──────────────────────────────────────────────────

    def _run_applications(
        self, ctx: CollectorContext, settings: MacOSSettings, now: datetime
    ) -> None:
        cfg = settings.applications
        src = self._src(ctx)
        result = self.runner.run(
            SYSTEM_PROFILER_APPS, timeout=cfg.command_timeout_seconds, max_stdout=64 * 1024 * 1024
        )
        if not result.ok:
            raise SourceFailure(f"system_profiler: {result.summary()}")
        apps = parse_system_profiler_apps(result.text())
        current = {a.path: a.attributes() for a in apps}
        diff = ctx.diff_snapshot("applications", current)
        snap = snapshot_id(ctx.collector_id, "applications", now)
        observed = to_ms(now)
        records: list[InventoryItem] = [
            inventory_item(
                InventoryItemType.SOFTWARE, path, attrs, src, observed_at=observed, snapshot=snap
            )
            for path, attrs in sorted(current.items())
        ]
        records.extend(
            inventory_item(
                InventoryItemType.SOFTWARE,
                path,
                {"name": previous.get("name"), "version": previous.get("version")},
                src,
                observed_at=observed,
                snapshot=snap,
                present=False,
            )
            for path, previous in sorted(diff.removed.items())
        )
        ctx.emit(records)
        self._set_stats(
            "applications",
            applications=len(apps),
            added=len(diff.added),
            changed=len(diff.changed),
            removed=len(diff.removed),
            unsigned=sum(1 for a in apps if not a.signed_by),
        )

    # ── asset ─────────────────────────────────────────────────────────

    def _run_asset(self, ctx: CollectorContext, settings: MacOSSettings, now: datetime) -> None:
        cfg = settings.asset
        sw = self.runner.run(["/usr/bin/sw_vers"], timeout=10.0, max_stdout=64 * 1024)
        model = self.runner.run(["/usr/sbin/sysctl", "-n", "hw.model"], timeout=10.0)
        if not sw.ok:
            raise SourceFailure(f"sw_vers: {sw.summary()}")
        info = parse_sw_vers(sw.text())
        attributes: dict[str, Any] = {
            "os_name": info.get("ProductName"),
            "os_version": info.get("ProductVersion"),
            "os_build": info.get("BuildVersion"),
            "model_identifier": model.text().strip() if model.ok else None,
            "architecture": os.uname().machine,
            "collector": COLLECTOR_TYPE,
            "collector_version": COLLECTOR_VERSION,
            "hostname": cfg.hostname,
        }
        asset = asset_upsert(
            ctx,
            asset_type="macos_host",
            name=cfg.name,
            display_name=cfg.hostname,
            environment=cfg.environment,
            criticality=cfg.criticality,
            owner=cfg.owner,
            attributes={k: v for k, v in attributes.items() if v is not None},
            refresh_seconds=cfg.refresh_seconds,
        )
        ctx.emit([asset] if asset is not None else [])
        self._set_stats("asset", sent=asset is not None, os_version=attributes["os_version"])

    # ── health ────────────────────────────────────────────────────────

    def _health_details(
        self, settings: MacOSSettings, state: Mapping[str, Mapping[str, Any]]
    ) -> dict[str, Any]:
        sources = [f"{n}={(state.get(n) or {}).get('status', 'pending')}" for n in SOURCES]
        errors = [
            f"{n}: {(state.get(n) or {}).get('error')}"
            for n in SOURCES
            if (state.get(n) or {}).get("status") == "error"
        ]
        last_success = [
            f"{n}={(state.get(n) or {}).get('last_success')}"
            for n in SOURCES
            if (state.get(n) or {}).get("last_success")
        ]
        gaps = list(STATIC_GAPS)
        inventory = self._stats.get("inventory", {})
        if inventory.get("listener_method") == "lsof":
            gaps.append(
                "socket table withheld from the collector's process tree (ad-hoc signed "
                "runtime): listeners via lsof, current user's processes only; root-owned "
                "listeners (sshd, Screen Sharing, mDNSResponder) are not visible"
            )
        elif inventory.get("listener_method") == "unavailable":
            gaps.append("listening sockets unavailable this cycle (netstat and lsof failed)")
        if not settings.inventory.include_process_args:
            gaps.append("process arguments not collected (privacy default)")
        details: dict[str, Any] = {
            "sources": sources,
            "source_last_success": last_success,
            "source_errors": errors or None,
            "gaps": gaps,
            "unified_log_producers": list(settings.unified_log.producers),
        }
        for name in ("unified_log", "launchd", "inventory", "services", "posture", "applications"):
            stats = self._stats.get(name)
            if stats:
                details[f"{name}_last_run"] = [
                    f"{k}={v}" for k, v in stats.items() if v is not None
                ][:32]
        return details

    @staticmethod
    def _checkpoint_summary(ctx: CollectorContext) -> str | None:
        dedup = DedupState.from_json(ctx.checkpoints.get(UNIFIED_LOG_CHECKPOINT))
        if dedup.end is None:
            return None
        return f"unified_log until {iso_utc(datetime.fromtimestamp(dedup.end, UTC))}"

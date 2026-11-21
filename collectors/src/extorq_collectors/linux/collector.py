"""LinuxSSHCollector: agentless collection from the lab VM through the dispatch boundary.

Configured in ``config/collectors/linux.yaml`` (no secrets there; the SSH key and the
pinned known_hosts file are referenced by path). Every cycle, each step reads one
dispatch channel and commits its records together with its checkpoint in ONE
``ctx.emit`` transaction (SDK outbox):

1. ``inventory`` (every ``inventory.interval_seconds``) -> service discovery, Service /
   ServiceInstance records, ``service.*`` events, inventory diff events, InventoryItems,
   the Asset record; ``packages`` (every ``packages.interval_seconds``) -> package diffs;
2. ``journal <cursor> <n>`` -> journald events routed to the service adapters (ssh,
   nginx, webapp-json, systemd, apache) or to the host parsers (sudo, su, PAM, account
   tools, dispatch denials); checkpoint ``journal.cursor``;
3. ``audit <inode> <offset> <n>`` -> auditd events; checkpoints ``audit.inode`` /
   ``audit.offset``;
4. ``posture`` (every ``posture.interval_seconds``) -> ScanRun + PostureFindings +
   ``config.security_setting.changed``.

A step that fails does not stop the others; the cycle then raises so the runner reports
the collector as failed (per-step results are in the health details). A lost or
rotated journald cursor / audit offset produces ``extorq.collector.gap_detected``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from extorq.common.config import get_settings
from extorq.contracts import (
    Asset,
    AssetType,
    CollectionMethod,
    InventoryItem,
    InventoryItemType,
    Outcome,
    SecurityEvent,
    Service,
    ServiceInstance,
    ServiceRef,
    SourceType,
)
from extorq.contracts.identity import iso_utc
from extorq_collectors.linux import auditd as auditd_parser
from extorq_collectors.linux import inventory as inv
from extorq_collectors.linux import posture as posture_mod
from extorq_collectors.linux import service_records as svc
from extorq_collectors.linux.adapters import (
    LINUX_ADAPTERS,
    LinuxJournalAdapter,
    WebAppBinding,
    WebAppJsonAdapter,
)
from extorq_collectors.linux.common import (
    COLLECTOR_TYPE,
    COLLECTOR_VERSION,
    SELF_USER,
    ParseContext,
    build_event,
    to_ms,
    utc_now_ms,
)
from extorq_collectors.linux.discovery import DiscoveryResult, discover
from extorq_collectors.linux.journal import JournalEntry, entry_from_json, parse_entry
from extorq_collectors.linux.protocol import (
    PROTOCOL_VERSION,
    ProtocolError,
    parse_audit_response,
    parse_journal_response,
    parse_json_document,
)
from extorq_collectors.linux.ssh import (
    HostKeyVerificationError,
    SSHAuthenticationError,
    SSHConnectionError,
    SSHDispatchClient,
    SSHDispatchError,
    SSHTarget,
    SSHTimeoutError,
)
from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert
from extorq_collectors.services.registry import get_adapter

ALL_LINUX_ADAPTERS = tuple(cls.adapter_id for cls in LINUX_ADAPTERS)
#: Transport failures: the VM is unreachable (or not the pinned host), so the remaining
#: SSH steps of this cycle are skipped instead of each retrying its own connection.
TRANSPORT_ERRORS = (
    SSHConnectionError,
    SSHTimeoutError,
    HostKeyVerificationError,
    SSHAuthenticationError,
)
PARSER_GAP = "linux-collector-gap"
_CURSOR_RE = re.compile(
    r"^s=[0-9a-f]{32};i=[0-9a-f]{1,16};b=[0-9a-f]{32};m=[0-9a-f]{1,16};"
    r"t=[0-9a-f]{1,16};x=[0-9a-f]{1,16}$"
)


class CollectionError(RuntimeError):
    """One or more collection steps failed in this cycle (details in health)."""


def _int(cfg: Mapping[str, Any], key: str, default: int, low: int, high: int) -> int:
    value = cfg.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"setting {key} must be an integer in [{low}, {high}]")
    return value


@dataclass(frozen=True)
class LinuxSettings:
    ssh: SSHTarget
    journal_max_entries: int = 2000
    journal_max_rounds: int = 5
    audit_max_bytes: int = 1048576
    audit_max_rounds: int = 8
    inventory_interval: int = 60
    full_snapshot_interval: int = 21600
    packages_interval: int = 3600
    posture_interval: int = 900
    services_enabled: bool = True
    emit_service_records: bool = True
    service_refresh_seconds: int = 900
    stale_after_seconds: int = 180
    enabled_adapters: frozenset[str] = frozenset(ALL_LINUX_ADAPTERS)
    webapps: tuple[WebAppBinding, ...] = field(default_factory=tuple)
    self_user: str = SELF_USER

    @classmethod
    def from_config(cls, config: Mapping[str, Any], base_dir: Path) -> LinuxSettings:
        def section(name: str) -> Mapping[str, Any]:
            value = config.get(name) or {}
            if not isinstance(value, Mapping):
                raise ValueError(f"settings.{name} must be a mapping")
            return value

        journal, audit, inventory = section("journal"), section("audit"), section("inventory")
        packages, posture, services = section("packages"), section("posture"), section("services")
        adapters = section("adapters")
        enabled = adapters.get("enabled", list(ALL_LINUX_ADAPTERS))
        if not isinstance(enabled, list) or not all(isinstance(a, str) for a in enabled):
            raise ValueError("settings.adapters.enabled must be a list of adapter ids")
        webapp_cfg = adapters.get("webapp-json") or {}
        apps_raw = webapp_cfg.get("apps") if isinstance(webapp_cfg, Mapping) else None
        apps = tuple(
            WebAppBinding.from_mapping(a) for a in apps_raw or [] if isinstance(a, Mapping)
        )
        return cls(
            ssh=SSHTarget.from_mapping(section("ssh"), base_dir=base_dir),
            journal_max_entries=_int(journal, "max_entries", 2000, 1, 5000),
            journal_max_rounds=_int(journal, "max_rounds", 5, 1, 50),
            audit_max_bytes=_int(audit, "max_bytes", 1048576, 4096, 1048576),
            audit_max_rounds=_int(audit, "max_rounds", 8, 1, 100),
            inventory_interval=_int(inventory, "interval_seconds", 60, 10, 86400),
            full_snapshot_interval=_int(inventory, "full_snapshot_seconds", 21600, 600, 604800),
            packages_interval=_int(packages, "interval_seconds", 3600, 60, 604800),
            posture_interval=_int(posture, "interval_seconds", 900, 60, 604800),
            services_enabled=bool(services.get("enabled", True)),
            emit_service_records=bool(services.get("emit_records", True)),
            service_refresh_seconds=_int(services, "refresh_seconds", 900, 60, 86400),
            stale_after_seconds=_int(services, "stale_after_seconds", 180, 30, 86400),
            enabled_adapters=frozenset(enabled),
            webapps=apps or (WebAppBinding("lab-portal", "lab-portal.service", "lab-portal"),),
            self_user=str(config.get("self_user", SELF_USER)),
        )


@dataclass
class _Binding:
    adapter: LinuxJournalAdapter
    app: WebAppBinding | None = None


class LinuxSSHCollector(Collector):
    """Agentless Linux collector (SSH -> dispatch boundary -> parsers/adapters -> outbox)."""

    collector_type = COLLECTOR_TYPE
    source_types = (
        SourceType.LINUX_JOURNALD.value,
        SourceType.LINUX_AUDITD.value,
        SourceType.LINUX_NGINX.value,
        SourceType.LINUX_APACHE.value,
        SourceType.LINUX_APP.value,
        SourceType.LINUX_INVENTORY.value,
        SourceType.LINUX_POSTURE.value,
    )
    collector_version = COLLECTOR_VERSION

    def __init__(self, client: SSHDispatchClient | None = None) -> None:
        #: Injected client (tests); the runner instantiates without arguments.
        self._injected_client = client
        self.settings: LinuxSettings | None = None
        self.client: SSHDispatchClient | None = None
        self.dispatcher_version: str | None = None
        self.discovery: DiscoveryResult | None = None
        self.service_records: dict[str, Service] = {}
        self.refs_by_unit: dict[str, ServiceRef] = {}
        self.refs_by_adapter: dict[str, list[ServiceRef]] = {}
        self.configs: Mapping[str, Any] = {}
        self.self_uid: int | None = None
        self.packages: dict[str, str] = {}
        self.channels: dict[str, svc.ChannelStatus] = {}
        self.bindings: dict[str, _Binding] = {}
        self.disabled_identifiers: set[str] = set()
        #: Discovery of this cycle's inventory, turned into records by the services step.
        self._pending: tuple[DiscoveryResult, datetime] | None = None

    # ── lifecycle ──────────────────────────────────────────────────────────

    def setup(self, ctx: CollectorContext) -> None:
        base_dir = get_settings().resolve(Path("."))
        self.settings = LinuxSettings.from_config(ctx.config, base_dir)
        self.client = self._injected_client or SSHDispatchClient(self.settings.ssh)
        self._build_bindings()
        version = parse_json_document(self.client.run_bytes("version", timeout=60), "version")
        self.dispatcher_version = str(version.get("version"))[:32]
        ctx.log.info(
            "linux_dispatch_ready",
            dispatcher=self.dispatcher_version,
            host=str(version.get("hostname"))[:64],
            protocol=PROTOCOL_VERSION,
        )
        state = ctx.state.get("linux.runtime") or {}
        if isinstance(state, Mapping):
            uid = state.get("self_uid")
            self.self_uid = uid if isinstance(uid, int) else None
            pkgs = state.get("packages")
            self.packages = dict(pkgs) if isinstance(pkgs, Mapping) else {}
            channels = state.get("channels")
            if isinstance(channels, Mapping):
                for name, iso in channels.items():
                    self.channels[name] = svc.ChannelStatus(_parse_iso(iso), False)

    def close(self) -> None:
        if self.client is not None:
            self.client.close()

    def _require(self) -> tuple[LinuxSettings, SSHDispatchClient]:
        if self.settings is None or self.client is None:
            raise CollectionError("collector not set up")
        return self.settings, self.client

    def _build_bindings(self) -> None:
        if self.settings is None:
            raise CollectionError("collector not set up")
        self.bindings = {}
        self.disabled_identifiers = set()
        for adapter_id in ALL_LINUX_ADAPTERS:
            adapter = get_adapter(adapter_id)
            if (
                isinstance(adapter, LinuxJournalAdapter)
                and adapter_id not in self.settings.enabled_adapters
            ):
                # A disabled adapter's records are not collected at all (not even unattributed).
                self.disabled_identifiers.update(adapter.syslog_identifiers)
            if (
                not isinstance(adapter, LinuxJournalAdapter)
                or adapter_id not in self.settings.enabled_adapters
            ):
                continue
            for ident in adapter.syslog_identifiers:
                self.bindings[ident] = _Binding(adapter)
        webapp = get_adapter(WebAppJsonAdapter.adapter_id)
        if (
            isinstance(webapp, LinuxJournalAdapter)
            and WebAppJsonAdapter.adapter_id in self.settings.enabled_adapters
        ):
            for app in self.settings.webapps:
                self.bindings[app.syslog_identifier] = _Binding(webapp, app)

    # ── cycle ──────────────────────────────────────────────────────────────

    def collect(self, ctx: CollectorContext) -> None:
        if self.settings is None or self.client is None:
            raise CollectionError("collector not set up")
        now = ctx.now()
        steps: dict[str, str] = {}
        failures: list[str] = []
        plan = [
            ("inventory", self._due(ctx, "inventory", self.settings.inventory_interval, now)),
            ("journal", True),
            ("audit", True),
            # Service records after journal/audit so coverage reflects this cycle's reads.
            ("services", self.settings.services_enabled),
            ("posture", self._due(ctx, "posture", self.settings.posture_interval, now)),
        ]
        transport_down: str | None = None
        for name, due in plan:
            if name == "services" and self._pending is None:
                due = False  # records are rebuilt only from a fresh inventory
            if not due:
                steps[name] = "not_due"
                continue
            if transport_down is not None and name != "services":
                steps[name] = f"skipped ({transport_down})"
                previous = self.channels.get(name)
                self.channels[name] = svc.ChannelStatus(
                    previous.last_success if previous else None, True
                )
                continue
            try:
                steps[name] = getattr(self, f"_step_{name}")(ctx)
                self.channels[name] = svc.ChannelStatus(ctx.now(), False)
                if name in ("inventory", "posture"):
                    ctx.state.set(f"linux.last_run.{name}", iso_utc(now))
            except (SSHDispatchError, ProtocolError, ValueError, OSError) as exc:
                # Snapshots staged by the failed step must not be committed by a later
                # step's emit (that would advance the baseline without its events).
                ctx.discard_staged()
                previous = self.channels.get(name)
                self.channels[name] = svc.ChannelStatus(
                    previous.last_success if previous else None, True
                )
                summary = f"{name}: {type(exc).__name__}: {str(exc)[:240]}"
                steps[name] = f"failed ({type(exc).__name__})"
                if isinstance(exc, TRANSPORT_ERRORS):
                    transport_down = f"transport failed in {name}: {type(exc).__name__}"
                failures.append(summary)
                ctx.log.warning("linux_step_failed", step=name, error=summary)
        self._save_runtime(ctx)
        ctx.health_details.update({f"step.{k}": v for k, v in steps.items()})
        ctx.health_details["dispatcher_version"] = self.dispatcher_version
        ctx.health_details["services"] = len(self.service_records)
        cursor = ctx.checkpoints.get("journal.cursor")
        ctx.checkpoint_summary = (
            f"journal i={_cursor_seq(cursor)} audit inode={ctx.checkpoints.get('audit.inode')} "
            f"offset={ctx.checkpoints.get('audit.offset')}"
        )
        if failures:
            raise CollectionError("; ".join(failures))

    def _due(self, ctx: CollectorContext, name: str, interval: int, now: datetime) -> bool:
        last = _parse_iso(ctx.state.get(f"linux.last_run.{name}"))
        return last is None or (now - last).total_seconds() >= interval - 1

    def _save_runtime(self, ctx: CollectorContext) -> None:
        ctx.state.set(
            "linux.runtime",
            {
                "self_uid": self.self_uid,
                "packages": self.packages,
                "channels": {
                    k: iso_utc(v.last_success)
                    for k, v in self.channels.items()
                    if v.last_success is not None
                },
            },
        )

    def _parse_ctx(self, ctx: CollectorContext, service: ServiceRef | None = None) -> ParseContext:
        return ParseContext(
            asset_id=ctx.asset_id,
            collector_id=ctx.collector_id,
            collector_version=self.collector_version,
            self_user=self.settings.self_user if self.settings else SELF_USER,
            self_uid=self.self_uid,
            observed_time=ctx.now(),
            service=service,
        )

    # ── step: inventory + packages + discovery + services ─────────────────

    def _step_inventory(self, ctx: CollectorContext) -> str:
        settings, client = self._require()
        doc = parse_json_document(client.run_bytes("inventory"), "inventory")
        now = ctx.now()
        collected = _parse_iso(doc.get("collected_at")) or now
        raw_configs = doc.get("configs")
        self.configs = raw_configs if isinstance(raw_configs, Mapping) else {}
        self.self_uid = next(
            (
                u.get("uid")
                for u in doc.get("users") or []
                if isinstance(u, Mapping)
                and u.get("name") == settings.self_user
                and isinstance(u.get("uid"), int)
            ),
            self.self_uid,
        )
        packages_doc: Mapping[str, Any] | None = None
        if self._due(ctx, "packages", settings.packages_interval, now):
            packages_doc = parse_json_document(client.run_bytes("packages"), "packages")
            self.packages = {
                str(p["name"]): str(p.get("version") or "")
                for p in packages_doc.get("packages") or []
                if isinstance(p, Mapping) and isinstance(p.get("name"), str)
            }

        known = ctx.state.get("linux.services.known_units") or []
        result = discover(
            doc,
            ctx.asset_id,
            webapps=settings.webapps,
            known_units=[u for u in known if isinstance(u, str)],
        )
        self.discovery = result
        records: list[Any] = []
        self._refresh_refs(result)
        self._pending = (result, collected) if settings.services_enabled else None
        service_count = len(result.services)

        pctx = self._parse_ctx(ctx)
        dctx = inv.DiffContext(
            parse=pctx,
            event_time=to_ms(collected),
            services_by_unit=dict(self.refs_by_unit),
            systemd_ref=self.refs_by_unit.get("init.scope"),
        )
        last_full = _parse_iso(ctx.state.get("linux.inventory.last_full"))
        full = (
            last_full is None
            or (now - last_full).total_seconds() >= settings.full_snapshot_interval
        )
        snapshot_id = f"linux-inv-{collected.strftime('%Y%m%dT%H%M%S%fZ')}"
        counts: dict[str, int] = {}
        group_changes: dict[str, Any] = {}
        diffs: dict[str, Any] = {}
        for category, (extract, source, _item_type) in inv.CATEGORIES.items():
            document = doc if source == "inventory" else packages_doc
            if document is None:
                continue
            current = extract(document)
            diff = ctx.diff_snapshot(f"inventory.{category}", current)
            diffs[category] = (diff, current)
            if category == "privileged_groups" and not diff.baseline:
                group_changes = inv.privileged_group_changes(diff)
        for category, (diff, current) in diffs.items():
            events: list[SecurityEvent] = []
            if not diff.baseline:
                events = self._diff_events(category, diff, dctx, group_changes)
            items = inv.inventory_records(
                category,
                diff,
                current,
                asset_id=ctx.asset_id,
                collector_id=ctx.collector_id,
                snapshot_id=snapshot_id,
                observed_at=to_ms(collected),
                full=full or diff.baseline,
            )
            records.extend(events)
            records.extend(items)
            counts[category] = len(events)
        if full:
            records.extend(
                InventoryItem(
                    asset_id=ctx.asset_id,
                    item_type=InventoryItemType.PROCESS,
                    item_key=key,
                    attributes=item,
                    snapshot_id=snapshot_id,
                    observed_at=to_ms(collected),
                    collector_id=ctx.collector_id,
                )
                for key, item in sorted(inv.process_items(doc).items())
            )
        asset = self._asset(ctx, doc, result)
        if asset is not None:
            records.append(asset)
        ctx.emit(records)
        if full:
            ctx.state.set("linux.inventory.last_full", iso_utc(now))
        if packages_doc is not None:
            ctx.state.set("linux.last_run.packages", iso_utc(now))
        diff_events = sum(counts.values())
        return (
            f"ok services={service_count} diff_events={diff_events} records={len(records)}"
            f"{' full' if full else ''}{' packages' if packages_doc is not None else ''}"
        )

    def _diff_events(
        self, category: str, diff: Any, dctx: inv.DiffContext, group_changes: Mapping[str, Any]
    ) -> list[SecurityEvent]:
        if category == "units":
            return inv.unit_events(diff, dctx)
        if category == "enablement":
            return inv.enablement_events(diff, dctx)
        if category == "listeners":
            return inv.listener_events(diff, dctx)
        if category == "users":
            return inv.user_events(diff, dctx)
        if category == "cron":
            return inv.cron_events(diff, dctx)
        if category == "files":
            return inv.file_events(diff, dctx, group_changes)
        if category == "packages":
            return inv.package_events(diff, dctx)
        return []  # privileged_groups: reported through /etc/group changes

    def _step_services(self, ctx: CollectorContext) -> str:
        if self._pending is None:
            return "not_due"
        result, collected = self._pending
        self._pending = None
        records: list[Any] = []
        count = self._services(ctx, result, records, collected)
        ctx.emit(records)
        known = sorted(s.unit for s in result.services if s.unit)[:2000]
        ctx.state.set("linux.services.known_units", known)
        return f"ok services={count} records={len(records)}"

    def _services(
        self,
        ctx: CollectorContext,
        result: DiscoveryResult,
        records: list[Any],
        collected: datetime,
    ) -> int:
        settings, _client = self._require()
        now = ctx.now()
        first_seen_map = ctx.state.get("linux.services.first_seen") or {}
        if not isinstance(first_seen_map, dict):
            first_seen_map = {}
        last_event_map = ctx.state.get("linux.services.last_event") or {}
        if not isinstance(last_event_map, dict):
            last_event_map = {}
        current: dict[str, Service] = {}
        instances: list[ServiceInstance] = []
        for service in result.services:
            sid = service.service_id
            first = _parse_iso(first_seen_map.get(sid)) or to_ms(collected)
            first_seen_map.setdefault(sid, iso_utc(first))
            support, status, note = svc.coverage_for(
                service,
                enabled_adapters=set(settings.enabled_adapters),
                channels=self._channels_for_coverage(ctx),
                configs=self.configs,
                now=now,
                stale_after_seconds=settings.stale_after_seconds,
            )
            current[sid] = svc.service_record(
                service,
                result,
                support=support,
                status=status,
                note=note,
                first_seen=first,
                now=to_ms(collected),
                observed_by=ctx.collector_id,
                packages=self.packages,
                last_telemetry_at=_parse_iso(last_event_map.get(sid)),
            )
            instances.extend(
                svc.instance_records(
                    service, result, observed_by=ctx.collector_id, observed_at=to_ms(collected)
                )
            )
        ctx.state.set("linux.services.first_seen", first_seen_map)

        identity = ctx.diff_snapshot(
            "services.identity", {sid: svc.identity_item(r) for sid, r in current.items()}
        )
        records.extend(
            svc.service_events(identity, current, self._parse_ctx(ctx), to_ms(collected))
        )
        if settings.emit_service_records:
            bucket = int(now.timestamp()) // settings.service_refresh_seconds
            rec_diff = ctx.diff_snapshot(
                "services.records", {sid: svc.record_item(r, bucket) for sid, r in current.items()}
            )
            records.extend(current[sid] for sid in sorted({*rec_diff.added, *rec_diff.changed}))
            for previous in rec_diff.removed.values():
                tomb = svc.tombstone(previous, now=to_ms(collected))
                if tomb is not None:
                    records.append(tomb)
            inst_diff = ctx.diff_snapshot(
                "services.instances", {i.instance_id: svc.instance_item(i) for i in instances}
            )
            by_id = {i.instance_id: i for i in instances}
            records.extend(by_id[iid] for iid in sorted({*inst_diff.added, *inst_diff.changed}))
            for _iid, previous in sorted(inst_diff.removed.items()):
                try:
                    gone = ServiceInstance.model_validate(
                        {**previous, "observed_at": iso_utc(to_ms(collected))}
                    )
                except ValueError:
                    continue
                records.append(gone.model_copy(update={"present": False, "state": "stopped"}))
        self.service_records = current
        return len(current)

    def _channels_for_coverage(self, ctx: CollectorContext) -> dict[str, svc.ChannelStatus]:
        return dict(self.channels)

    def _refresh_refs(self, result: DiscoveryResult) -> None:
        """ServiceRefs used to attribute parsed records (from discovery, before coverage)."""
        self.refs_by_unit = {
            s.unit: ServiceRef(
                service_id=s.service_id,
                name=s.candidate.name[:256],
                adapter_id=s.adapter.adapter_id if s.adapter else None,
            )
            for s in result.services
            if s.unit
        }
        self.refs_by_adapter = {}
        for ref in self.refs_by_unit.values():
            if ref.adapter_id:
                self.refs_by_adapter.setdefault(ref.adapter_id, []).append(ref)

    def _asset(
        self, ctx: CollectorContext, doc: Mapping[str, Any], result: DiscoveryResult
    ) -> Asset | None:
        raw_host = doc.get("host")
        host: Mapping[str, Any] = raw_host if isinstance(raw_host, Mapping) else {}
        raw_osr = host.get("os_release")
        osr: Mapping[str, Any] = raw_osr if isinstance(raw_osr, Mapping) else {}
        hostname = str(host.get("hostname") or ctx.asset_id.split(":", 1)[-1])[:64]
        return asset_upsert(
            ctx,
            asset_type=AssetType.LINUX_HOST,
            name=hostname,
            display_name=f"{osr.get('PRETTY_NAME') or 'Linux'} ({hostname})"[:256],
            attributes={
                k: v
                for k, v in {
                    "os_name": osr.get("NAME"),
                    "os_id": osr.get("ID"),
                    "os_version": osr.get("VERSION_ID"),
                    "os_codename": osr.get("VERSION_CODENAME"),
                    "os_pretty_name": osr.get("PRETTY_NAME"),
                    "kernel": host.get("kernel_release"),
                    "kernel_build": host.get("kernel_version"),
                    "architecture": host.get("machine"),
                    "hostname": hostname,
                    "boot_id": host.get("boot_id"),
                    "collection": "agentless ssh (extorq-collect-dispatch)",
                    "dispatcher_version": self.dispatcher_version,
                    "services_discovered": len(result.services),
                    "unattributed_listeners": len(result.unattributed),
                }.items()
                if v is not None
            },
        )

    # ── step: journal ──────────────────────────────────────────────────────

    def _step_journal(self, ctx: CollectorContext) -> str:
        settings, client = self._require()
        total_entries = total_events = rounds = 0
        newest: datetime | None = None
        gap = False
        while rounds < settings.journal_max_rounds:
            rounds += 1
            cursor = ctx.checkpoints.get("journal.cursor")
            if cursor is not None and not _CURSOR_RE.match(cursor):
                cursor = None  # corrupted checkpoint: restart from the initial window
            batch = parse_journal_response(
                client.run_bytes(f"journal {cursor or '-'} {settings.journal_max_entries}")
            )
            if batch.error and not batch.entries:
                raise ProtocolError(f"journalctl failed: {batch.error}")
            records: list[Any] = []
            if cursor is not None and batch.complete and batch.cursor_exact is False:
                records.append(
                    self._gap_event(
                        ctx, SourceType.LINUX_JOURNALD, "journal_cursor_not_found", cursor
                    )
                )
                gap = True
            last_cursor: str | None = None
            for raw in batch.entries:
                entry = entry_from_json(raw)
                if entry is None:
                    continue
                last_cursor = entry.cursor
                events = self._route(ctx, entry)
                records.extend(events)
                total_events += len(events)
                if newest is None or entry.time > newest:
                    newest = entry.time
            total_entries += len(batch.entries)
            checkpoints = {"journal.cursor": last_cursor} if last_cursor else {}
            if records or checkpoints:
                ctx.emit(records, checkpoints)
                self._note_service_events(ctx, records)
            if not batch.complete or not batch.truncated or not batch.entries:
                break
        ctx.report_lag(newest)
        ctx.health_details["journal_entries"] = total_entries
        return (
            f"ok entries={total_entries} events={total_events} rounds={rounds}"
            f"{' gap' if gap else ''}"
        )

    def _route(self, ctx: CollectorContext, entry: JournalEntry) -> list[SecurityEvent]:
        binding = self.bindings.get(entry.identifier or "")
        if binding is None:
            if entry.identifier in self.disabled_identifiers:
                return []
            return parse_entry(entry, self._parse_ctx(ctx))
        ref = self._ref_for(binding, entry)
        pctx = self._parse_ctx(ctx, ref)
        if binding.app is not None:
            return WebAppJsonAdapter.parse_for(entry, pctx, binding.app)
        events = binding.adapter.parse_entry(entry, pctx)
        return [self._with_subject(event) for event in events]

    def _with_subject(self, event: SecurityEvent) -> SecurityEvent:
        """Lifecycle records name the unit they are about: link it when it is a service."""
        if event.event_type != "system.service.state_changed" or event.resource is None:
            return event
        subject = self.refs_by_unit.get(event.resource.name or "")
        if subject is None:
            return event
        attributes = {**event.attributes, "subject_service_id": subject.service_id}
        return event.model_copy(update={"attributes": attributes})

    def _ref_for(self, binding: _Binding, entry: JournalEntry) -> ServiceRef | None:
        adapter_id = binding.adapter.adapter_id
        ref = None
        if binding.app is not None:
            ref = self.refs_by_unit.get(binding.app.unit)
        if ref is None and entry.unit:
            candidate = self.refs_by_unit.get(entry.unit)
            if candidate is not None and candidate.adapter_id == adapter_id:
                ref = candidate
        if ref is None:
            refs = self.refs_by_adapter.get(adapter_id) or []
            ref = refs[0] if len(refs) == 1 else None
        if ref is None:
            return None
        instance = self._instance_for(entry, ref.service_id)
        return ref.model_copy(update={"instance_id": instance}) if instance else ref

    def _instance_for(self, entry: JournalEntry, service_id: str) -> str | None:
        result = self.discovery
        if result is None or entry.pid is None or entry.boot_id is None:
            return None
        if result.boot_id is None or entry.boot_id.replace("-", "") != result.boot_id.replace(
            "-", ""
        ):
            return None  # different boot: pids are not comparable
        found = result.pid_instances.get(entry.pid)
        return found[1] if found and found[0] == service_id else None

    def _note_service_events(self, ctx: CollectorContext, records: list[Any]) -> None:
        latest: dict[str, datetime] = {}
        for record in records:
            if isinstance(record, SecurityEvent) and record.service is not None:
                sid = record.service.service_id
                if sid not in latest or record.event_time > latest[sid]:
                    latest[sid] = record.event_time
        if not latest:
            return
        stored = ctx.state.get("linux.services.last_event") or {}
        if not isinstance(stored, dict):
            stored = {}
        for sid, when in latest.items():
            previous = _parse_iso(stored.get(sid))
            if previous is None or when > previous:
                stored[sid] = iso_utc(when)
        ctx.state.set("linux.services.last_event", stored)

    # ── step: audit ────────────────────────────────────────────────────────

    def _step_audit(self, ctx: CollectorContext) -> str:
        settings, client = self._require()
        total_events = rounds = 0
        newest: datetime | None = None
        gaps = 0
        auditd_ref = self.refs_by_unit.get("auditd.service")
        if auditd_ref is not None and "auditd" not in settings.enabled_adapters:
            auditd_ref = None
        while rounds < settings.audit_max_rounds:
            rounds += 1
            inode = ctx.checkpoints.get("audit.inode")
            offset = ctx.checkpoints.get("audit.offset") or "0"
            if inode is not None and not inode.isdigit():
                inode, offset = None, "0"
            chunk = parse_audit_response(
                client.run_bytes(
                    f"audit {inode or '-'} {offset if offset.isdigit() else '0'} "
                    f"{settings.audit_max_bytes}"
                )
            )
            records: list[Any] = []
            if chunk.gap:
                gaps += 1
                records.append(
                    self._gap_event(
                        ctx,
                        SourceType.LINUX_AUDITD,
                        chunk.gap_reason or "audit_gap",
                        f"{inode}:{offset}",
                    )
                )
            parsed = auditd_parser.parse_audit_chunk(
                chunk.payload, chunk.start_offset, self._parse_ctx(ctx, auditd_ref)
            )
            records.extend(parsed.events)
            total_events += len(parsed.events)
            if parsed.newest_time and (newest is None or parsed.newest_time > newest):
                newest = parsed.newest_time
            resume = parsed.resume_offset if chunk.payload else chunk.next_offset
            if chunk.header.get("oversized_line_skipped"):
                resume = chunk.next_offset
            checkpoints = {"audit.inode": str(chunk.inode), "audit.offset": str(resume)}
            ctx.emit(records, checkpoints)
            self._note_service_events(ctx, records)
            progressed = resume > chunk.start_offset or chunk.header.get("file") != "audit.log"
            if not chunk.more or not progressed:
                break
        if newest is not None and (ctx.lag_seconds is None):
            ctx.report_lag(newest)
        return f"ok events={total_events} rounds={rounds}{f' gaps={gaps}' if gaps else ''}"

    # ── step: posture ──────────────────────────────────────────────────────

    def _step_posture(self, ctx: CollectorContext) -> str:
        _settings, client = self._require()
        started = ctx.now()
        try:
            doc = parse_json_document(client.run_bytes("posture", timeout=200), "posture")
        except (SSHDispatchError, ProtocolError) as exc:
            scan = posture_mod.failed_scan(
                asset_id=ctx.asset_id,
                producer_id=ctx.producer_id,
                started_at=started,
                finished_at=ctx.now(),
                error=f"{type(exc).__name__}: {exc}",
            )
            ctx.emit([scan])
            raise
        finished = ctx.now()
        service_ids = {unit: ref.service_id for unit, ref in self.refs_by_unit.items()}
        result = posture_mod.evaluate(
            doc,
            asset_id=ctx.asset_id,
            producer_id=ctx.producer_id,
            started_at=started,
            finished_at=finished,
            service_ids=service_ids,
        )
        diff = ctx.diff_snapshot(
            "posture.settings", {k: {"value": v} for k, v in result.settings.items()}
        )
        events = (
            []
            if diff.baseline
            else posture_mod.setting_events(diff, self._parse_ctx(ctx), finished, service_ids)
        )
        ctx.emit([result.scan_run, *result.findings, *events])
        return (
            f"ok status={result.scan_run.status.value} findings={len(result.findings)} "
            f"setting_changes={len(events)}"
        )

    # ── gaps ───────────────────────────────────────────────────────────────

    def _gap_event(
        self, ctx: CollectorContext, source: SourceType, reason: str, previous: str
    ) -> SecurityEvent:
        """``extorq.collector.gap_detected`` under the collector's own source type."""
        return build_event(
            self._parse_ctx(ctx),
            event_type="extorq.collector.gap_detected",
            source_type=source,
            native_key=f"gap:{source.value}:{previous}:{reason}",
            event_time=utc_now_ms(),
            parser=PARSER_GAP,
            collection_method=CollectionMethod.SSH_PULL,
            action="collector.gap",
            outcome=Outcome.FAILURE,
            message=f"telemetry gap in {source.value}: {reason} (checkpoint {previous[:80]})",
            attributes={
                "collector_id": ctx.collector_id,
                "source_type": source.value,
                "gap_reason": reason,
                "previous_checkpoint": previous[:256],
            },
        )


def _cursor_seq(cursor: str | None) -> str:
    if not cursor:
        return "-"
    match = re.search(r";i=([0-9a-f]{1,16});", cursor)
    return match.group(1) if match else "?"


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


__all__ = ["CollectionError", "LinuxSSHCollector", "LinuxSettings"]

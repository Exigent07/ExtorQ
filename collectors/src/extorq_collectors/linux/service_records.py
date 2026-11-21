"""Service / ServiceInstance records, coverage and ``service.*`` events for the Linux host.

Coverage (``adapter_support`` x ``monitoring_status``) is decided by the shared
:func:`~extorq_collectors.services.base.classify_coverage` from:

* the matched adapter (implemented / planned / none) and whether it is enabled in
  ``config/collectors/linux.yaml``;
* the freshness of the adapter's *collection channel* (journal, audit or inventory
  read through the dispatch boundary) - not the event volume: an idle SSH server
  whose journald source is read successfully is monitored, not stale;
* adapter prerequisites visible in configuration (e.g. nginx logs not routed to
  journald) which downgrade ``monitored`` to ``degraded`` with an explicit note.

``Service.last_telemetry_at`` is the time of the newest event genuinely attributed to
the service (kept in collector state), independent of coverage.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts import (
    AdapterSupport,
    InstanceKind,
    MonitoringStatus,
    Outcome,
    Resource,
    SecurityEvent,
    Service,
    ServiceInstance,
    ServiceRef,
    SourceType,
)
from extorq.contracts.identity import canonical_json, sha256_hex
from extorq_collectors.linux.adapters.base import LinuxJournalAdapter
from extorq_collectors.linux.common import ParseContext, build_event, clean
from extorq_collectors.linux.discovery import DiscoveredService, DiscoveryResult
from extorq_collectors.services.base import build_service, classify_coverage

PARSER_SERVICES = "linux-service-discovery"

#: Collection channel that delivers each source type.
CHANNEL_OF_SOURCE = {
    SourceType.LINUX_JOURNALD.value: "journal",
    SourceType.LINUX_NGINX.value: "journal",
    SourceType.LINUX_APACHE.value: "journal",
    SourceType.LINUX_APP.value: "journal",
    SourceType.LINUX_AUDITD.value: "audit",
    SourceType.LINUX_INVENTORY.value: "inventory",
    SourceType.LINUX_POSTURE.value: "posture",
}


@dataclass(frozen=True)
class ChannelStatus:
    """Outcome of the latest read of one dispatch channel."""

    last_success: datetime | None
    failing: bool


def coverage_for(
    service: DiscoveredService,
    *,
    enabled_adapters: set[str],
    channels: Mapping[str, ChannelStatus],
    configs: Mapping[str, Any],
    now: datetime,
    stale_after_seconds: float,
) -> tuple[AdapterSupport, MonitoringStatus, str]:
    adapter = service.adapter
    implemented = adapter is not None and adapter.support is AdapterSupport.IMPLEMENTED
    last_success: datetime | None = None
    failing = False
    if implemented and adapter is not None:
        names = {CHANNEL_OF_SOURCE.get(str(s), "journal") for s in adapter.source_types}
        statuses = [channels.get(name, ChannelStatus(None, False)) for name in sorted(names)]
        failing = any(s.failing for s in statuses)
        times = [s.last_success for s in statuses]
        last_success = None if any(t is None for t in times) else min(t for t in times if t)
    support, status, note = classify_coverage(
        adapter,
        enabled=bool(adapter and adapter.adapter_id in enabled_adapters),
        last_telemetry_at=last_success,
        now=now,
        stale_after_seconds=stale_after_seconds,
        source_failing=failing,
    )
    if status is MonitoringStatus.MONITORED and isinstance(adapter, LinuxJournalAdapter):
        problems = adapter.prerequisite_problems(configs)
        if problems:
            status, note = MonitoringStatus.DEGRADED, "; ".join(problems)
    if not service.running:
        note = f"{note}; not running (no process in the unit)"
    return support, status, note[:2048]


def version_of(
    service: DiscoveredService, packages: Mapping[str, str]
) -> tuple[str | None, str | None]:
    """Installed package version of the service's product (evidence: dpkg), if known."""
    adapter = service.adapter
    if not isinstance(adapter, LinuxJournalAdapter):
        return None, None
    for name in adapter.packages:
        version = packages.get(name)
        if version:
            return version, f"dpkg:{name}"
    return None, None


def service_record(
    service: DiscoveredService,
    result: DiscoveryResult,
    *,
    support: AdapterSupport,
    status: MonitoringStatus,
    note: str,
    first_seen: datetime,
    now: datetime,
    observed_by: str,
    packages: Mapping[str, str],
    last_telemetry_at: datetime | None,
) -> Service:
    version, version_source = version_of(service, packages)
    record = build_service(
        service.candidate,
        service.adapter,
        support=support,
        status=status,
        coverage_note=note,
        observed_by=observed_by,
        first_seen=first_seen,
        now=now,
        instance_count=len(service.main_processes),
        last_telemetry_at=last_telemetry_at,
        version=version,
    )
    attributes = dict(record.attributes)
    attributes["running"] = service.running
    if version_source:
        attributes["version_source"] = version_source
    if service.adapter is not None and isinstance(service.adapter, LinuxJournalAdapter):
        attributes["adapter_deployed_in_lab"] = service.adapter.deployed_in_lab
    return record.model_copy(update={"attributes": _bounded(attributes)})


def instance_records(
    service: DiscoveredService, result: DiscoveryResult, *, observed_by: str, observed_at: datetime
) -> list[ServiceInstance]:
    records: list[ServiceInstance] = []
    for proc in service.main_processes:
        records.append(
            ServiceInstance(
                instance_id=result.instance_id(service, proc),
                service_id=service.service_id,
                asset_id=result.asset_id,
                instance_kind=InstanceKind.PROCESS,
                instance_key=result.instance_key(proc),
                state="running",
                pid=proc.pid,
                process_name=clean(proc.comm),
                user=clean(proc.user),
                started_at=result.started_at(proc),
                observed_at=observed_at,
                present=True,
                observed_by=observed_by,
                attributes=_bounded(
                    {
                        "cgroup": proc.cgroup,
                        "unit": service.unit,
                        "ppid": proc.ppid,
                        "uid": proc.uid,
                        "args": sanitize_untrusted(redact_text(proc.args)[0], 256),
                        "boot_id": result.boot_id,
                    }
                ),
            )
        )
    return records


def _bounded(attributes: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in attributes.items():
        if value is None:
            continue
        if isinstance(value, bool | int | float):
            out[key] = value
        elif isinstance(value, str):
            out[key] = sanitize_untrusted(value, 2048)
        elif isinstance(value, list | tuple):
            out[key] = [
                v if isinstance(v, bool | int | float) else sanitize_untrusted(str(v), 512)
                for v in list(value)[:64]
                if v is not None
            ]
        if len(out) >= 64:
            break
    return out


# ── snapshot items and service.* events ───────────────────────────────────────


def endpoint_strings(record: Service) -> list[str]:
    return sorted(
        f"{e.protocol} {e.address or '*'}:{e.port} ({e.attribution.value})"
        for e in record.endpoints
    )


def identity_item(record: Service) -> dict[str, Any]:
    """What makes a service 'the same' for discovered/removed/exposure diffs."""
    return {
        "name": record.name,
        "service_kind": record.service_kind.value,
        "service_key": record.service_key,
        "category": record.category.value,
        "adapter_id": record.adapter_id,
        "endpoints": endpoint_strings(record),
        "unit_path": record.attributes.get("unit_path"),
    }


def record_item(record: Service, refresh_bucket: int) -> dict[str, Any]:
    """Content that decides whether a Service record is (re)sent (volatile fields excluded)."""
    content = record.model_dump(mode="json", exclude={"last_seen", "last_telemetry_at"})
    content["refresh_bucket"] = refresh_bucket
    return content


def instance_item(record: ServiceInstance) -> dict[str, Any]:
    return record.model_dump(mode="json", exclude={"observed_at"})


def _ref(item: Mapping[str, Any], service_id: str) -> ServiceRef:
    return ServiceRef(
        service_id=service_id,
        name=str(item.get("name") or service_id)[:256],
        adapter_id=item.get("adapter_id"),
    )


def service_events(
    diff: Any, records: Mapping[str, Service], ctx: ParseContext, event_time: datetime
) -> list[SecurityEvent]:
    """service.discovered / service.removed / service.exposure.changed from the identity diff."""
    events: list[SecurityEvent] = []
    baseline = bool(getattr(diff, "baseline", False))
    for sid, item in sorted(diff.added.items()):
        record = records.get(sid)
        if record is None:
            continue
        events.append(
            _service_event(
                ctx,
                "service.discovered",
                sid,
                "discovered",
                item,
                event_time,
                message=(
                    f"service discovered: {record.name} ({record.adapter_support.value} "
                    f"adapter {record.adapter_id or '-'}, {record.monitoring_status.value})"
                ),
                resource=Resource(
                    type="service",
                    name=clean(record.service_key),
                    path=clean(record.attributes.get("unit_path"), 2048),
                ),
                attributes={
                    "service_kind": record.service_kind.value,
                    "category": record.category.value,
                    "discovered_via": [e.value for e in record.discovered_via],
                    "adapter_support": record.adapter_support.value,
                    "monitoring_status": record.monitoring_status.value,
                    "coverage_note": record.coverage_note,
                    "endpoints": endpoint_strings(record),
                    "running": record.attributes.get("running"),
                    "baseline": baseline,
                },
            )
        )
    for sid, item in sorted(diff.removed.items()):
        events.append(
            _service_event(
                ctx,
                "service.removed",
                sid,
                "removed",
                item,
                event_time,
                message=f"service no longer observed: {item.get('name')}",
                resource=Resource(
                    type="service",
                    name=clean(item.get("service_key")),
                    path=clean(item.get("unit_path"), 2048),
                ),
                attributes={
                    "service_kind": item.get("service_kind"),
                    "endpoints": item.get("endpoints"),
                },
            )
        )
    for sid, item in sorted(diff.changed.items()):
        before = set((diff.previous.get(sid) or {}).get("endpoints") or [])
        after = set(item.get("endpoints") or [])
        if before == after:
            continue  # other identity fields changed (e.g. unit path): not an exposure change
        added, removed = sorted(after - before), sorted(before - after)
        attributions = sorted({e.rsplit("(", 1)[-1].rstrip(")") for e in after}) or ["none"]
        events.append(
            _service_event(
                ctx,
                "service.exposure.changed",
                sid,
                "exposure",
                item,
                event_time,
                message=f"service {item.get('name')} exposure changed: +{added} -{removed}",
                resource=Resource(type="service", name=clean(item.get("service_key"))),
                attributes={
                    "endpoints_added": added,
                    "endpoints_removed": removed,
                    "attribution": ",".join(attributions),
                },
            )
        )
    return events


def _service_event(
    ctx: ParseContext,
    event_type: str,
    service_id: str,
    change: str,
    item: Mapping[str, Any],
    event_time: datetime,
    *,
    message: str,
    resource: Resource,
    attributes: Mapping[str, Any],
) -> SecurityEvent:
    pctx = ParseContext(
        asset_id=ctx.asset_id,
        collector_id=ctx.collector_id,
        collector_version=ctx.collector_version,
        self_user=ctx.self_user,
        self_uid=ctx.self_uid,
        observed_time=ctx.observed_time,
        service=_ref(item, service_id),
    )
    return build_event(
        pctx,
        event_type=event_type,
        source_type=SourceType.LINUX_INVENTORY,
        native_key=f"{service_id}:{change}:{sha256_hex(canonical_json(item))}",
        event_time=event_time,
        parser=PARSER_SERVICES,
        action=event_type,
        outcome=Outcome.SUCCESS,
        resource=resource,
        message=message,
        attributes=dict(attributes),
        sim_texts=(str(item.get("service_key") or ""),),
    )


def tombstone(previous: Mapping[str, Any], *, now: datetime) -> Service | None:
    """A Service record marking a service that is no longer observed (present=False).

    ``previous`` is the last committed record item; ``last_seen`` is the time absence
    was observed.
    """
    data = {k: v for k, v in previous.items() if k != "refresh_bucket"}
    data["last_seen"] = now.isoformat()
    try:
        record = Service.model_validate(data)
    except ValueError:
        return None
    return record.model_copy(
        update={
            "present": False,
            "monitoring_status": MonitoringStatus.UNMONITORED,
            "coverage_note": "no longer observed on the host",
            "instance_count": 0,
            "endpoints": [],
        }
    )


def iter_refs(records: Iterable[Service]) -> dict[str, ServiceRef]:
    """unit -> ServiceRef for every present host service."""
    refs: dict[str, ServiceRef] = {}
    for record in records:
        unit = record.attributes.get("unit")
        if isinstance(unit, str) and record.present:
            refs[unit] = ServiceRef(
                service_id=record.service_id, name=record.name, adapter_id=record.adapter_id
            )
    return refs

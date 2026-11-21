"""Common service-model plumbing for host collectors (contract schema 1.1).

Discovery produces evidence-backed :class:`ServiceCandidate` objects (from
systemd units / launchd jobs, processes, listening sockets, known configuration
and adapter configuration). The registry matches each candidate to a
:class:`ServiceAdapter`, which states whether ExtorQ can collect that service's
telemetry (``IMPLEMENTED``) or only knows it as an extension point (``PLANNED``).
:func:`classify_coverage` then decides ``monitored`` / ``degraded`` /
``unmonitored`` from whether the adapter is enabled and its sources are fresh.

Honesty rules enforced here:
* a candidate always carries at least one piece of discovery evidence;
* a process is NOT assumed to be a network service;
* a listening port is attributed to a service only with an explicit
  ``PortAttribution`` (confirmed / inferred / unknown);
* adapters declare what they never collect (credentials, file contents,
  authorization headers, query text) and must not emit such data.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from abc import ABC
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Literal

from extorq.contracts.catalog import SourceType
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import service_id as _service_id
from extorq.contracts.service import (
    AdapterSupport,
    DiscoveryEvidence,
    MonitoringStatus,
    Service,
    ServiceCategory,
    ServiceEndpoint,
    ServiceKind,
    ServiceRef,
)

Exposure = Literal["loopback", "private", "any", "unknown"]


def exposure_of(address: str | None) -> Exposure:
    """Classify a bind address. Unknown/unparseable addresses stay 'unknown'."""
    if not address:
        return "unknown"
    try:
        ip = ipaddress.ip_address(address.strip("[]").split("%", 1)[0])
    except ValueError:
        return "unknown"
    if ip.is_unspecified:
        return "any"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "unknown"


@dataclass(frozen=True)
class ServiceCandidate:
    """A service discovered on an asset, with the evidence that supports it."""

    asset_id: str
    service_kind: ServiceKind
    #: Natural key: systemd unit name, launchd label, configured application name.
    service_key: str
    name: str
    evidence: frozenset[DiscoveryEvidence]
    unit: str | None = None
    executable: str | None = None
    product: str | None = None
    endpoints: tuple[ServiceEndpoint, ...] = ()
    config_refs: tuple[str, ...] = ()
    #: Only True when evidence shows it listens; None = not known (never assumed).
    is_network_service: bool | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.evidence:
            raise ValueError("a service candidate needs at least one piece of discovery evidence")

    @property
    def service_id(self) -> str:
        return _service_id(self.asset_id, self.service_kind.value, self.service_key)


@dataclass(frozen=True)
class AdapterContext:
    """What an adapter needs to build events for one service on one asset."""

    asset_id: str
    asset_type: str
    collector_id: str
    collector_version: str
    service: ServiceRef | None
    observed_time: datetime


class ServiceAdapter(ABC):
    """Base class for service telemetry adapters.

    Subclasses declare matching rules and data-handling statements as class
    attributes. Implemented adapters override :meth:`accepts` and :meth:`parse`;
    planned adapters keep the defaults, which never produce telemetry.
    """

    adapter_id: ClassVar[str]
    support: ClassVar[AdapterSupport] = AdapterSupport.PLANNED
    category: ClassVar[ServiceCategory] = ServiceCategory.UNKNOWN
    #: Evidence-based matching (all optional): products, unit/label fnmatch patterns,
    #: process executable basenames. Well-known ports only ever yield INFERRED attribution.
    products: ClassVar[frozenset[str]] = frozenset()
    unit_patterns: ClassVar[tuple[str, ...]] = ()
    executables: ClassVar[frozenset[str]] = frozenset()
    well_known_ports: ClassVar[frozenset[tuple[str, int]]] = frozenset()
    source_types: ClassVar[tuple[SourceType, ...]] = ()
    description: ClassVar[str] = ""
    #: Human-readable statements surfaced in docs/UI.
    collects: ClassVar[tuple[str, ...]] = ()
    never_collects: ClassVar[tuple[str, ...]] = ()

    def matches(self, candidate: ServiceCandidate) -> bool:
        if candidate.product and candidate.product in self.products:
            return True
        if candidate.unit and any(fnmatch.fnmatch(candidate.unit, p) for p in self.unit_patterns):
            return True
        if candidate.executable:
            base = candidate.executable.rsplit("/", 1)[-1]
            if base in self.executables:
                return True
        return False

    def infer_product(self, candidate: ServiceCandidate) -> str | None:
        """Product name only when the unit or executable name itself names it; else None."""
        if candidate.product:
            return candidate.product
        names: list[str] = []
        if candidate.executable:
            names.append(candidate.executable.rsplit("/", 1)[-1])
        if candidate.unit:
            names.append(candidate.unit.split("@", 1)[0].removesuffix(".service"))
        return next((n for n in names if n in self.products), None)

    def accepts(self, raw: Mapping[str, Any]) -> bool:
        """Whether a raw source record belongs to this adapter's service."""
        return False

    def parse(self, raw: Mapping[str, Any], ctx: AdapterContext) -> list[SecurityEvent]:
        """Turn one raw record into zero or more SecurityEvents carrying ``ctx.service``."""
        raise NotImplementedError(
            f"adapter {self.adapter_id!r} is {self.support.value}: no telemetry"
        )


def classify_coverage(
    adapter: ServiceAdapter | None,
    *,
    enabled: bool,
    last_telemetry_at: datetime | None,
    now: datetime,
    stale_after_seconds: float,
    source_failing: bool = False,
) -> tuple[AdapterSupport, MonitoringStatus, str]:
    """Deterministic coverage state for a discovered service."""
    implemented, monitored = AdapterSupport.IMPLEMENTED, MonitoringStatus.MONITORED
    degraded, unmonitored = MonitoringStatus.DEGRADED, MonitoringStatus.UNMONITORED
    if adapter is None:
        return AdapterSupport.NONE, unmonitored, "no adapter for this service type"
    if adapter.support is not AdapterSupport.IMPLEMENTED:
        return (
            adapter.support,
            unmonitored,
            f"planned adapter '{adapter.adapter_id}': discovered only, no telemetry collected",
        )
    if not enabled:
        return implemented, unmonitored, "adapter available but not enabled"
    if source_failing:
        return implemented, degraded, "telemetry source failing"
    if last_telemetry_at is None:
        return implemented, degraded, "adapter enabled; no telemetry yet"
    if (now - last_telemetry_at).total_seconds() > stale_after_seconds:
        return implemented, degraded, "adapter enabled; telemetry stale"
    return implemented, monitored, "telemetry fresh"


def build_service(
    candidate: ServiceCandidate,
    adapter: ServiceAdapter | None,
    *,
    support: AdapterSupport,
    status: MonitoringStatus,
    coverage_note: str,
    observed_by: str,
    first_seen: datetime,
    now: datetime,
    instance_count: int | None = None,
    last_telemetry_at: datetime | None = None,
    version: str | None = None,
) -> Service:
    """Assemble the contract record for a candidate (no invented fields)."""
    return Service(
        service_id=candidate.service_id,
        asset_id=candidate.asset_id,
        service_kind=candidate.service_kind,
        service_key=candidate.service_key,
        name=candidate.name,
        category=adapter.category if adapter else ServiceCategory.UNKNOWN,
        product=adapter.infer_product(candidate) if adapter else candidate.product,
        version=version,
        discovered_via=sorted(candidate.evidence, key=lambda e: e.value),
        adapter_id=adapter.adapter_id if adapter else None,
        adapter_support=support,
        monitoring_status=status,
        coverage_note=coverage_note,
        telemetry_sources=list(adapter.source_types) if adapter else [],
        endpoints=list(candidate.endpoints),
        config_refs=list(candidate.config_refs),
        instance_count=instance_count,
        last_telemetry_at=last_telemetry_at,
        attributes=dict(candidate.attributes),
        first_seen=first_seen,
        last_seen=now,
        observed_by=observed_by,
    )


def service_ref(
    candidate: ServiceCandidate, adapter: ServiceAdapter | None, instance_id: str | None = None
) -> ServiceRef:
    return ServiceRef(
        service_id=candidate.service_id,
        name=candidate.name,
        instance_id=instance_id,
        adapter_id=adapter.adapter_id if adapter else None,
    )

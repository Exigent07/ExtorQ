"""Service-aware monitoring endpoints (service model since contract schema 1.1, PLAN section 10).

* ``GET /assets/{asset_id}/services``: services of one asset with a coverage summary.
* ``GET /services``: services across assets (filters: asset, kind, category,
  adapter_support, monitoring_status, coverage).
* ``GET /services/{service_id}``: one service with instances, endpoints, telemetry
  coverage per source, authentication activity, recent events, findings and alerts.

Coverage is evaluated at request time (``service.effective_coverage``): an implemented
adapter reported ``monitored`` is shown as ``degraded`` when its discovery record is no
longer refreshed or every collector of one of its declared sources is stale. Planned and
unsupported services are always listed (never hidden).

Every endpoint that reports service coverage (these three, ``GET /assets/{asset_id}``
``services_summary`` and ``GET /overview`` ``service_coverage``) goes through
:func:`evaluate_scope`, which always evaluates against ALL collectors: collectors of an
ancestor asset cover its children (``k8s:<cluster>`` covers ``k8s:<cluster>/node/<name>``),
so the same service has the same coverage state in every view at the same instant.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Query, Request, Response
from fastapi.routing import APIRoute
from pydantic import ValidationError
from starlette.routing import Match
from starlette.types import Scope

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.cache import cached
from extorq.api.errors import ApiError, NotFound
from extorq.api.logs import get_logger
from extorq.api.repository import (
    AlertFilters,
    EventFilters,
    FindingFilters,
    Repository,
    Row,
    ServiceFilters,
    identity_matches,
)
from extorq.api.routes.common import (
    HEX_ID_PATTERN,
    AssetIdPath,
    AssetIdQuery,
    Clock,
    Limit,
    Offset,
    Repo,
    Settings,
    Since,
    Until,
    now_ms,
)
from extorq.api.settings import ApiSettings
from extorq.contracts import AdapterSupport, MonitoringStatus, ServiceCategory, ServiceKind

log = get_logger("extorq.api.services")

#: Upper bound of service records evaluated per request (a single-host deployment has a few
#: hundred at most).
SERVICE_SCAN_CAP = 2000
INSTANCES_LIMIT = 200
RECENT_EVENTS_LIMIT = 50
SERVICE_FINDINGS_LIMIT = 100
SERVICE_ALERTS_LIMIT = 50
AUTH_SOURCES_LIMIT = 20
ALERTS_WINDOW = timedelta(days=30)
#: Instances read for ``hosted`` (Pods/containers on a node) and listed per service.
HOSTED_INSTANCES_LIMIT = 500
HOSTED_INSTANCES_PER_SERVICE = 50

ServiceIdPath = Annotated[str, Path(pattern=HEX_ID_PATTERN, description="32-hex service id.")]
CoverageFilter = Literal["monitored", "degraded", "unmonitored", "planned", "unsupported"]


class AssetSubresourceRoute(APIRoute):
    """``/assets/{asset_id:path}/<sub>`` that only matches a *literal* ``/<sub>`` suffix.

    Asset ids may contain ``/`` (``github:owner/repo``, ``k8s:cluster/node/name``) and are
    sent percent-encoded as one path segment. The decoded path cannot tell an asset whose
    id ends in ``/services`` from the services sub-resource, so the raw (still encoded)
    path decides: ``.../github%3Aowner%2Fservices`` is the asset detail of
    ``github:owner/services``; ``.../linux%3Alab-vm-01/services`` is the sub-resource.
    """

    def matches(self, scope: Scope) -> tuple[Match, Scope]:
        match, child_scope = super().matches(scope)
        if match is Match.NONE:
            return match, child_scope
        raw_path = scope.get("raw_path")
        suffix = "/" + self.path_format.rsplit("/", 1)[-1]
        if isinstance(raw_path, bytes | bytearray) and not bytes(raw_path).endswith(
            suffix.encode("ascii")
        ):
            return Match.NONE, {}
        return match, child_scope


asset_services_router = APIRouter(tags=["services"], route_class=AssetSubresourceRoute)
router = APIRouter(tags=["services"])

_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    404: {"model": s.ErrorResponse, "description": "Not found"},
}


def service_evaluator(
    repo: Repository, settings: ApiSettings, now: datetime
) -> service.ServiceEvaluator:
    """The evaluator of every coverage view: built from ALL collectors, never a subset.

    Restricting it to the asset's own collectors (as ``GET /assets/{id}`` once did) hides the
    cluster collectors that cover a Kubernetes node, so the node's services looked
    ``monitored`` there and ``degraded`` in ``GET /assets/{id}/services`` at the same instant.
    """
    collectors = [service.collector_status(row, now) for row in repo.collectors("")]
    return service.ServiceEvaluator(collectors, now, settings.service_stale_seconds)


@dataclass(frozen=True)
class ServiceScope:
    """Evaluated services of one filter scope (tombstones included)."""

    items: list[s.ServiceListItem]
    truncated: bool
    invalid: int

    def summary(self) -> s.ServicesSummary:
        return service.services_summary(self.items, truncated=self.truncated)


def evaluate_scope(
    repo: Repository, evaluator: service.ServiceEvaluator, filters: ServiceFilters
) -> ServiceScope:
    """All services matching ``filters`` evaluated by ``evaluator`` (the single shared path).

    ``evaluator`` comes from :func:`service_evaluator` (all collectors), built once per
    request. Pagination and the coverage filter run on the evaluated items because the
    effective coverage depends on collector health at request time (bounded by
    SERVICE_SCAN_CAP).
    """
    scan = ServiceFilters(
        asset_id=filters.asset_id,
        service_kind=filters.service_kind,
        category=filters.category,
        adapter_support=filters.adapter_support,
        monitoring_status=filters.monitoring_status,
        include_removed=True,
    )
    rows = repo.list_services(scan, SERVICE_SCAN_CAP + 1)
    scanned = rows[:SERVICE_SCAN_CAP]
    # F-19: a stored row whose id does not match its natural key is never shown as a service.
    genuine = [row for row in scanned if identity_matches(row)]
    if len(genuine) < len(scanned):
        log.warning("service_rows_identity_mismatch", count=len(scanned) - len(genuine))
    items, invalid = evaluator.items(genuine)
    return ServiceScope(
        items=items,
        truncated=len(rows) > SERVICE_SCAN_CAP,
        invalid=invalid + len(scanned) - len(genuine),
    )


def hosted_services(
    repo: Repository, evaluator: service.ServiceEvaluator, asset_id: str
) -> tuple[list[s.HostedService], bool]:
    """Services of ANCESTOR assets with present instances on ``asset_id`` (node -> Pods).

    An instance is listed only under a service whose asset is a strict ancestor of
    ``asset_id`` and whose stored id matches its natural key, so a producer of another asset
    cannot attach instances to a service it does not own (F-19).
    """
    if "/" not in asset_id:
        # Ancestors are "/"-prefixes of an asset id (``is_ancestor_asset``): an id without
        # "/" (a host, a cluster, an account) has none, and every instance on it belongs to
        # one of its own services (listed in ``items``). No query needed.
        return [], False
    rows = repo.instances_on_asset(asset_id, HOSTED_INSTANCES_LIMIT + 1)
    truncated = len(rows) > HOSTED_INSTANCES_LIMIT
    by_service: dict[str, list[Row]] = {}
    for row in rows[:HOSTED_INSTANCES_LIMIT]:
        by_service.setdefault(str(row["service_id"]), []).append(row)
    if not by_service:
        return [], truncated
    owners: dict[str, Row] = {}
    own: set[str] = set()
    for row in repo.services_by_id(sorted(by_service), 4 * len(by_service) + 10):
        sid = str(row["service_id"])
        if sid not in by_service or not identity_matches(row):
            continue
        if str(row["asset_id"]) == asset_id:
            own.add(sid)  # the asset's own service: not hosted, not ownerless
        elif sid not in owners and service.is_ancestor_asset(str(row["asset_id"]), asset_id):
            owners[sid] = row
    skipped = len(set(by_service) - set(owners) - own)
    if skipped:
        log.warning("hosted_instances_without_owner", asset_id=asset_id, services=skipped)
    hosted: list[s.HostedService] = []
    for sid, owner in owners.items():
        try:
            item = evaluator.item(owner)
            instances = [
                evaluator.instance(r) for r in by_service[sid][:HOSTED_INSTANCES_PER_SERVICE]
            ]
        except (ValidationError, KeyError, TypeError, ValueError):
            log.warning("hosted_service_invalid", service_id=sid)
            continue
        hosted.append(
            s.HostedService(
                service=item, instances=instances, instances_on_asset=len(by_service[sid])
            )
        )
    hosted.sort(key=lambda h: (h.service.service_kind, h.service.name, h.service.service_id))
    return hosted, truncated


def _page(
    items: Sequence[s.ServiceListItem],
    *,
    include_removed: bool,
    coverage: CoverageFilter | None,
    limit: int,
    offset: int,
) -> tuple[list[s.ServiceListItem], s.PageInfo]:
    selected = [
        item
        for item in items
        if (include_removed or item.present)
        and (coverage is None or item.coverage_state == coverage)
    ]
    page = selected[offset : offset + limit]
    return page, service.page_info(
        limit=limit, offset=offset, returned=len(page), total=len(selected)
    )


KindQuery = Annotated[
    ServiceKind | None,
    Query(
        alias="kind",
        description="host_service | application | k8s_workload | k8s_service "
        "(a Kubernetes Service is never a host service).",
    ),
]
CategoryQuery = Annotated[ServiceCategory | None, Query()]
SupportQuery = Annotated[AdapterSupport | None, Query(description="implemented | planned | none")]
StatusQuery = Annotated[
    MonitoringStatus | None,
    Query(description="Status as reported by the collector (see coverage for the effective one)."),
]
CoverageQuery = Annotated[
    CoverageFilter | None,
    Query(description="Effective coverage state at request time."),
]
IncludeRemovedQuery = Annotated[
    bool, Query(description="Include services no longer observed (tombstones).")
]


@asset_services_router.get(
    "/assets/{asset_id:path}/services",
    response_model=s.AssetServicesResponse,
    responses=_NOT_FOUND,
    summary="Services, applications and Kubernetes workloads/Services of one asset",
)
def list_asset_services(
    asset_id: AssetIdPath,
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    repo: Repo,
    settings: Settings,
    clock: Clock,
    limit: Limit = 100,
    offset: Offset = 0,
    kind: KindQuery = None,
    category: CategoryQuery = None,
    adapter_support: SupportQuery = None,
    monitoring_status: StatusQuery = None,
    coverage: CoverageQuery = None,
    include_removed: IncludeRemovedQuery = False,
) -> s.AssetServicesResponse:
    filters = ServiceFilters(
        asset_id=asset_id,
        service_kind=kind.value if kind else "",
        category=category.value if category else "",
        adapter_support=adapter_support.value if adapter_support else "",
        monitoring_status=monitoring_status.value if monitoring_status else "",
    )
    return cached(
        request,
        response,
        ("asset_services", filters, limit, offset, coverage, include_removed),
        lambda: _asset_services(
            repo,
            settings,
            now_ms(clock),
            filters,
            limit=limit,
            offset=offset,
            coverage=coverage,
            include_removed=include_removed,
        ),
    )


def _asset_services(
    repo: Repository,
    settings: ApiSettings,
    now: datetime,
    filters: ServiceFilters,
    *,
    limit: int,
    offset: int,
    coverage: CoverageFilter | None,
    include_removed: bool,
) -> s.AssetServicesResponse:
    asset_id = filters.asset_id
    asset_row = repo.get_asset(asset_id)
    evaluator = service_evaluator(repo, settings, now)
    scope = evaluate_scope(repo, evaluator, filters)
    hosted, hosted_truncated = hosted_services(repo, evaluator, asset_id)
    if asset_row is None and not scope.items and not hosted:
        # Neither an asset record nor any service record: unknown asset id.
        raise NotFound("asset not found")
    page, info = _page(
        scope.items, include_removed=include_removed, coverage=coverage, limit=limit, offset=offset
    )
    return s.AssetServicesResponse(
        asset_id=asset_id,
        asset=service.asset_brief(asset_row) if asset_row else None,
        items=page,
        page=info,
        summary=scope.summary(),
        invalid_records=scope.invalid,
        hosted=hosted,
        hosted_truncated=hosted_truncated,
    )


@router.get(
    "/services",
    response_model=s.ServiceListResponse,
    summary="Service inventory across assets with effective monitoring coverage",
)
def list_services(
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    repo: Repo,
    settings: Settings,
    clock: Clock,
    limit: Limit = 100,
    offset: Offset = 0,
    asset_id: AssetIdQuery = None,
    kind: KindQuery = None,
    category: CategoryQuery = None,
    adapter_support: SupportQuery = None,
    monitoring_status: StatusQuery = None,
    coverage: CoverageQuery = None,
    include_removed: IncludeRemovedQuery = False,
) -> s.ServiceListResponse:
    filters = ServiceFilters(
        asset_id=asset_id or "",
        service_kind=kind.value if kind else "",
        category=category.value if category else "",
        adapter_support=adapter_support.value if adapter_support else "",
        monitoring_status=monitoring_status.value if monitoring_status else "",
    )
    return cached(
        request,
        response,
        ("services", filters, limit, offset, coverage, include_removed),
        lambda: _services(
            repo,
            settings,
            now_ms(clock),
            filters,
            limit=limit,
            offset=offset,
            coverage=coverage,
            include_removed=include_removed,
        ),
    )


def _services(
    repo: Repository,
    settings: ApiSettings,
    now: datetime,
    filters: ServiceFilters,
    *,
    limit: int,
    offset: int,
    coverage: CoverageFilter | None,
    include_removed: bool,
) -> s.ServiceListResponse:
    scope = evaluate_scope(repo, service_evaluator(repo, settings, now), filters)
    page, info = _page(
        scope.items, include_removed=include_removed, coverage=coverage, limit=limit, offset=offset
    )
    return s.ServiceListResponse(
        items=page,
        page=info,
        summary=scope.summary(),
        invalid_records=scope.invalid,
    )


@router.get(
    "/services/{service_id}",
    response_model=s.ServiceDetailResponse,
    responses=_NOT_FOUND,
    summary="Service detail: instances, endpoints, telemetry coverage, auth, findings, alerts",
)
def get_service(
    service_id: ServiceIdPath,
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    repo: Repo,
    settings: Settings,
    clock: Clock,
    since: Since = None,
    until: Until = None,
) -> s.ServiceDetailResponse:
    return cached(
        request,
        response,
        ("service", service_id, since, until),
        lambda: _service_detail(repo, settings, now_ms(clock), service_id, since, until),
    )


def _service_detail(
    repo: Repository,
    settings: ApiSettings,
    now: datetime,
    service_id: str,
    since: datetime | None,
    until: datetime | None,
) -> s.ServiceDetailResponse:
    row = repo.get_service(service_id)
    if row is None:
        raise NotFound("service not found")
    evaluator = service_evaluator(repo, settings, now)
    try:
        record = evaluator.record(row)
    except (ValidationError, KeyError, TypeError, ValueError) as exc:
        log.error("stored_service_invalid", service_id=service_id, error_type=type(exc).__name__)
        raise ApiError("stored service failed validation") from exc
    notes: list[str] = []
    if not record.present:
        notes.append("this service is no longer observed by discovery (tombstone)")
    if record.invalid_endpoints:
        notes.append(f"{record.invalid_endpoints} stored endpoint entries failed validation")

    asset_row = repo.get_asset(record.asset_id)
    if asset_row is None:
        notes.append("the parent asset record has not been reported")

    # F-19: instances and events count only on the service's own asset and its descendants
    # (a cluster's nodes): a producer of another asset cannot appear under this service.
    scope = record.asset_id
    instance_rows, instances_total = repo.service_instances(
        service_id, INSTANCES_LIMIT, scope_asset=scope
    )
    instances: list[s.ServiceInstanceItem] = []
    for instance_row in instance_rows:
        try:
            instances.append(evaluator.instance(instance_row))
        except (ValidationError, KeyError, TypeError, ValueError):
            log.warning("stored_instance_invalid", service_id=service_id)
    if len(instances) < len(instance_rows):
        notes.append(f"{len(instance_rows) - len(instances)} instance records failed validation")
    if instances_total > len(instance_rows):
        notes.append(f"showing {len(instance_rows)} of {instances_total} instances")

    time_range = service.resolve_range(
        since,
        until,
        now=now,
        default=timedelta(hours=24),
        maximum=timedelta(days=31),
        future_tolerance=timedelta(days=1),
    )
    telemetry = evaluator.telemetry(
        record,
        repo.service_event_sources(
            service_id, time_range.since, time_range.until, scope_asset=scope
        ),
    )
    if record.telemetry_sources and all(
        t.collection == "no_collector_health" for t in telemetry if t.declared
    ):
        notes.append(
            "no collector health report mentions this service's telemetry sources: "
            "collection freshness cannot be confirmed"
        )
    auth = service.auth_activity(
        time_range,
        repo.service_auth_summary(
            service_id, time_range.since, time_range.until, scope_asset=scope
        ),
        repo.service_auth_sources(
            service_id, time_range.since, time_range.until, AUTH_SOURCES_LIMIT, scope_asset=scope
        ),
    )
    event_rows = repo.list_events(
        EventFilters(
            since=time_range.since,
            until=time_range.until,
            service_id=service_id,
            scope_asset=scope,
        ),
        RECENT_EVENTS_LIMIT,
        0,
    )

    # Same attribution rule as GET /findings?service_id= (latest observation wins).
    finding_rows, findings_total, lifecycle = repo.list_findings(
        FindingFilters(service_id=service_id, scope_asset=scope), SERVICE_FINDINGS_LIMIT, 0
    )

    alerts_range = s.TimeRange(since=now - ALERTS_WINDOW, until=now + timedelta(days=1))
    alert_filters = AlertFilters(
        since=alerts_range.since, until=alerts_range.until, service_id=service_id
    )
    alert_rows = repo.list_alerts(alert_filters, SERVICE_ALERTS_LIMIT, 0)
    return s.ServiceDetailResponse(
        service=record,
        asset=service.asset_brief(asset_row) if asset_row else None,
        instances=instances,
        instances_total=instances_total,
        telemetry_range=time_range,
        telemetry=telemetry,
        auth_activity=auth,
        recent_events=[service.event_item(r) for r in event_rows],
        findings_lifecycle_available=lifecycle,
        findings=[service.finding_item(r, lifecycle) for r in finding_rows],
        findings_total=findings_total,
        alerts=[service.alert_item(r) for r in alert_rows],
        alerts_total=repo.count_alerts(alert_filters),
        alerts_range=alerts_range,
        notes=notes,
    )

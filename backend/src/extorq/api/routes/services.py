"""Service-aware monitoring endpoints (contract schema 1.1, PLAN section 10).

* ``GET /assets/{asset_id}/services``: services of one asset with a coverage summary.
* ``GET /services``: services across assets (filters: asset, kind, category,
  adapter_support, monitoring_status, coverage).
* ``GET /services/{service_id}``: one service with instances, endpoints, telemetry
  coverage per source, authentication activity, recent events, findings and alerts.

Coverage is evaluated at request time (``service.effective_coverage``): an implemented
adapter reported ``monitored`` is shown as ``degraded`` when its discovery record is no
longer refreshed or every collector of one of its declared sources is stale. Planned and
unsupported services are always listed (never hidden).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Path, Query
from fastapi.routing import APIRoute
from pydantic import ValidationError
from starlette.routing import Match
from starlette.types import Scope

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.errors import ApiError, NotFound
from extorq.api.logs import get_logger
from extorq.api.repository import (
    AlertFilters,
    EventFilters,
    FindingFilters,
    Repository,
    ServiceFilters,
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

#: Upper bound of service records evaluated per request (lab scale is far below it).
SERVICE_SCAN_CAP = 2000
INSTANCES_LIMIT = 200
RECENT_EVENTS_LIMIT = 50
SERVICE_FINDINGS_LIMIT = 100
SERVICE_ALERTS_LIMIT = 50
AUTH_SOURCES_LIMIT = 20
ALERTS_WINDOW = timedelta(days=30)

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


def _evaluator(repo: Repository, settings: ApiSettings, now: datetime) -> service.ServiceEvaluator:
    collectors = [service.collector_status(row, now) for row in repo.collectors("")]
    return service.ServiceEvaluator(collectors, now, settings.service_stale_seconds)


def evaluate_services(
    repo: Repository,
    evaluator: service.ServiceEvaluator,
    filters: ServiceFilters,
) -> tuple[list[s.ServiceListItem], bool, int]:
    """All services matching ``filters`` (tombstones included), truncation flag, invalid rows.

    Pagination and the coverage filter run on the evaluated items because the effective
    coverage depends on collector health at request time (bounded by SERVICE_SCAN_CAP).
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
    truncated = len(rows) > SERVICE_SCAN_CAP
    items, invalid = evaluator.items(rows[:SERVICE_SCAN_CAP])
    return items, truncated, invalid


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
    now = now_ms(clock)
    asset_row = repo.get_asset(asset_id)
    filters = ServiceFilters(
        asset_id=asset_id,
        service_kind=kind.value if kind else "",
        category=category.value if category else "",
        adapter_support=adapter_support.value if adapter_support else "",
        monitoring_status=monitoring_status.value if monitoring_status else "",
    )
    items, truncated, invalid = evaluate_services(repo, _evaluator(repo, settings, now), filters)
    if asset_row is None and not items:
        # Neither an asset record nor any service record: unknown asset id.
        raise NotFound("asset not found")
    page, info = _page(
        items, include_removed=include_removed, coverage=coverage, limit=limit, offset=offset
    )
    return s.AssetServicesResponse(
        asset_id=asset_id,
        asset=service.asset_brief(asset_row) if asset_row else None,
        items=page,
        page=info,
        summary=service.services_summary(items, truncated=truncated),
        invalid_records=invalid,
    )


@router.get(
    "/services",
    response_model=s.ServiceListResponse,
    summary="Service inventory across assets with effective monitoring coverage",
)
def list_services(
    principal: CurrentPrincipal,
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
    now = now_ms(clock)
    filters = ServiceFilters(
        asset_id=asset_id or "",
        service_kind=kind.value if kind else "",
        category=category.value if category else "",
        adapter_support=adapter_support.value if adapter_support else "",
        monitoring_status=monitoring_status.value if monitoring_status else "",
    )
    items, truncated, invalid = evaluate_services(repo, _evaluator(repo, settings, now), filters)
    page, info = _page(
        items, include_removed=include_removed, coverage=coverage, limit=limit, offset=offset
    )
    return s.ServiceListResponse(
        items=page,
        page=info,
        summary=service.services_summary(items, truncated=truncated),
        invalid_records=invalid,
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
    repo: Repo,
    settings: Settings,
    clock: Clock,
    since: Since = None,
    until: Until = None,
) -> s.ServiceDetailResponse:
    now = now_ms(clock)
    row = repo.get_service(service_id)
    if row is None:
        raise NotFound("service not found")
    evaluator = _evaluator(repo, settings, now)
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

    instance_rows, instances_total = repo.service_instances(service_id, INSTANCES_LIMIT)
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
        record, repo.service_event_sources(service_id, time_range.since, time_range.until)
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
        repo.service_auth_summary(service_id, time_range.since, time_range.until),
        repo.service_auth_sources(
            service_id, time_range.since, time_range.until, AUTH_SOURCES_LIMIT
        ),
    )
    event_rows = repo.list_events(
        EventFilters(since=time_range.since, until=time_range.until, service_id=service_id),
        RECENT_EVENTS_LIMIT,
        0,
    )

    finding_rows, findings_total, lifecycle = repo.list_findings(
        FindingFilters(service_id=service_id), SERVICE_FINDINGS_LIMIT, 0
    )
    attribution = repo.finding_service_attribution([str(r["finding_id"]) for r in finding_rows])

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
        findings=[service.finding_item(r, lifecycle, attribution) for r in finding_rows],
        findings_total=findings_total,
        alerts=[service.alert_item(r) for r in alert_rows],
        alerts_total=repo.count_alerts(alert_filters),
        alerts_range=alerts_range,
        notes=notes,
    )

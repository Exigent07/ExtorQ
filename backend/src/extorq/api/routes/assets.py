"""GET /assets and GET /assets/{asset_id}."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Query, Request, Response

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.cache import cached
from extorq.api.errors import NotFound
from extorq.api.logs import get_logger
from extorq.api.repository import AlertFilters, FindingFilters, Repository, ServiceFilters
from extorq.api.routes.common import (
    AssetIdPath,
    Clock,
    IncludeRetired,
    Limit,
    Offset,
    Repo,
    Settings,
    Since,
    Until,
    build_estate,
    now_ms,
)
from extorq.api.routes.services import evaluate_scope, service_evaluator
from extorq.api.settings import ApiSettings
from extorq.contracts import AssetType, Environment

log = get_logger("extorq.api.assets")

router = APIRouter(tags=["assets"])

ASSET_FINDINGS_LIMIT = 50
ASSET_RECENT_ALERTS_LIMIT = 20
#: ``Repository.all_assets`` reads at most this many asset records.
ASSETS_SCAN_CAP = 5000


@router.get(
    "/assets",
    response_model=s.AssetListResponse,
    summary="List monitored assets (retired assets only with include_retired=true)",
)
def list_assets(
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    repo: Repo,
    settings: Settings,
    clock: Clock,
    limit: Limit = 50,
    offset: Offset = 0,
    asset_type: Annotated[AssetType | None, Query()] = None,
    environment: Annotated[Environment | None, Query()] = None,
    include_retired: IncludeRetired = False,
) -> s.AssetListResponse:
    key = ("assets", limit, offset, asset_type, environment, include_retired)
    return cached(
        request,
        response,
        key,
        lambda: _list_assets(
            repo,
            settings,
            now_ms(clock),
            limit=limit,
            offset=offset,
            asset_type=asset_type.value if asset_type else "",
            environment=environment.value if environment else "",
            include_retired=include_retired,
        ),
    )


def _list_assets(
    repo: Repository,
    settings: ApiSettings,
    now: datetime,
    *,
    limit: int,
    offset: int,
    asset_type: str,
    environment: str,
    include_retired: bool,
) -> s.AssetListResponse:
    rows = repo.all_assets()
    if len(rows) >= ASSETS_SCAN_CAP:
        log.warning("asset_scan_cap_reached", cap=ASSETS_SCAN_CAP)
    estate = build_estate(repo, settings, now, assets=rows)
    matching = [
        row
        for row in rows
        if (not asset_type or str(row["asset_type"]) == asset_type)
        and (not environment or str(row["environment"]) == environment)
    ]
    visible = (
        matching
        if include_retired
        else [row for row in matching if not estate.is_retired(str(row["asset_id"]))]
    )
    page_rows = visible[offset : offset + limit]
    open_alerts = (
        {str(r["asset_id"]): int(r["open_alerts"]) for r in repo.open_alerts_by_asset()}
        if page_rows
        else {}
    )
    items = [estate.asset_item(row, open_alerts.get(str(row["asset_id"]), 0)) for row in page_rows]
    return s.AssetListResponse(
        items=items,
        page=service.page_info(limit=limit, offset=offset, returned=len(items), total=len(visible)),
        retired_excluded=len(matching) - len(visible),
    )


@router.get(
    "/assets/{asset_id:path}",
    response_model=s.AssetDetailResponse,
    summary="Asset detail: inventory, coverage, lifecycle, event counts, findings, alerts",
)
def get_asset(
    asset_id: AssetIdPath,
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    repo: Repo,
    settings: Settings,
    clock: Clock,
    since: Since = None,
    until: Until = None,
) -> s.AssetDetailResponse:
    return cached(
        request,
        response,
        ("asset", asset_id, since, until),
        lambda: _asset_detail(repo, settings, now_ms(clock), asset_id, since, until),
    )


def _asset_detail(
    repo: Repository,
    settings: ApiSettings,
    now: datetime,
    asset_id: str,
    since: datetime | None,
    until: datetime | None,
) -> s.AssetDetailResponse:
    row = repo.get_asset(asset_id)
    if row is None:
        raise NotFound("asset not found")
    # One evaluator (ALL collectors) for the asset's coverage and its services' coverage:
    # own collectors plus those of ancestor assets (a node is covered by its cluster's).
    # The estate (lifecycle) is built from the same collector reports.
    evaluator = service_evaluator(repo, settings, now)
    estate = build_estate(repo, settings, now, collectors=evaluator.collectors)
    open_counts = service.severity_counts(
        repo.open_alert_severity_counts(asset_id), "severity", "alerts"
    )
    base = estate.asset_item(row, open_counts.total)
    asset = s.AssetRecord(
        **base.model_dump(), attributes=service.parse_json_object(row.get("attributes"))
    )

    event_range = service.resolve_range(
        since,
        until,
        now=now,
        default=timedelta(hours=24),
        maximum=timedelta(days=90),
        future_tolerance=timedelta(days=1),
    )
    event_counts = [
        s.SourceTypeEventCount(
            source_type=str(r["source_type"]),
            events=int(r["events"]),
            last_event_at=r.get("last_event_at"),
            last_ingested_at=r.get("last_ingested_at"),
        )
        for r in repo.event_counts_by_source(asset_id, event_range.since, event_range.until)
    ]
    inventory = [
        s.InventoryTypeSummary(
            item_type=str(r["item_type"]),
            items=int(r["items"]),
            last_observed_at=r.get("last_observed_at"),
        )
        for r in repo.inventory_summary(asset_id)
    ]
    severity_rows, lifecycle = repo.finding_severity_counts(asset_id)
    finding_rows, _, lifecycle_list = repo.list_findings(
        FindingFilters(asset_id=asset_id), ASSET_FINDINGS_LIMIT, 0
    )
    alert_rows = repo.list_alerts(
        AlertFilters(
            since=now - timedelta(days=30), until=now + timedelta(days=1), asset_id=asset_id
        ),
        ASSET_RECENT_ALERTS_LIMIT,
        0,
    )
    # Same function as GET /assets/{asset_id}/services: evaluated against ALL collectors, so
    # a Kubernetes node's services see the cluster collectors that cover them.
    services_scope = evaluate_scope(repo, evaluator, ServiceFilters(asset_id=asset_id))
    return s.AssetDetailResponse(
        asset=asset,
        # Telemetry collectors covering the asset (self-tests left out), with lifecycle.
        collectors=estate.coverage_collectors(asset_id),
        inventory=inventory,
        event_counts=event_counts,
        event_counts_range=event_range,
        findings_summary=service.findings_summary(severity_rows, lifecycle),
        findings=[service.finding_item(r, lifecycle_list) for r in finding_rows],
        recent_alerts=[service.alert_item(r) for r in alert_rows],
        services_summary=services_scope.summary(),
        child_assets=[service.asset_brief(r) for r in repo.asset_children(asset_id)],
    )

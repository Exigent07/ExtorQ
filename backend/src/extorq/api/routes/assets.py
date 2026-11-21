"""GET /assets and GET /assets/{asset_id}."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Query

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.errors import NotFound
from extorq.api.repository import AlertFilters, FindingFilters
from extorq.api.routes.common import (
    AssetIdPath,
    Clock,
    Limit,
    Offset,
    Repo,
    Since,
    Until,
    now_ms,
)
from extorq.contracts import AssetType, Environment

router = APIRouter(tags=["assets"])

ASSET_FINDINGS_LIMIT = 50
ASSET_RECENT_ALERTS_LIMIT = 20


@router.get("/assets", response_model=s.AssetListResponse, summary="List monitored assets")
def list_assets(
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    limit: Limit = 50,
    offset: Offset = 0,
    asset_type: Annotated[AssetType | None, Query()] = None,
    environment: Annotated[Environment | None, Query()] = None,
) -> s.AssetListResponse:
    now = now_ms(clock)
    rows, total = repo.list_assets(
        asset_type.value if asset_type else "",
        environment.value if environment else "",
        limit,
        offset,
    )
    ids = [str(row["asset_id"]) for row in rows]
    by_asset: dict[str, list[s.CollectorStatus]] = defaultdict(list)
    for row in repo.collectors(""):
        status = service.collector_status(row, now)
        by_asset[status.asset_id].append(status)
    last_events = (
        {str(r["asset_id"]): r.get("last_event_at") for r in repo.asset_last_events(ids)}
        if ids
        else {}
    )
    open_alerts = {str(r["asset_id"]): int(r["open_alerts"]) for r in repo.open_alerts_by_asset()}
    items = [
        service.asset_item(
            row,
            by_asset.get(asset_id, []),
            last_events.get(asset_id),
            open_alerts.get(asset_id, 0),
        )
        for row, asset_id in zip(rows, ids, strict=True)
    ]
    return s.AssetListResponse(
        items=items,
        page=service.page_info(limit=limit, offset=offset, returned=len(items), total=total),
    )


@router.get(
    "/assets/{asset_id:path}",
    response_model=s.AssetDetailResponse,
    summary="Asset detail: inventory, telemetry coverage, event counts, findings, alerts",
)
def get_asset(
    asset_id: AssetIdPath,
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    since: Since = None,
    until: Until = None,
) -> s.AssetDetailResponse:
    now = now_ms(clock)
    row = repo.get_asset(asset_id)
    if row is None:
        raise NotFound("asset not found")
    collectors = [service.collector_status(r, now) for r in repo.collectors(asset_id)]
    last_events = repo.asset_last_events([asset_id])
    last_event_at = last_events[0].get("last_event_at") if last_events else None
    open_counts = service.severity_counts(
        repo.open_alert_severity_counts(asset_id), "severity", "alerts"
    )
    base = service.asset_item(row, collectors, last_event_at, open_counts.total)
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
    return s.AssetDetailResponse(
        asset=asset,
        collectors=collectors,
        inventory=inventory,
        event_counts=event_counts,
        event_counts_range=event_range,
        findings_summary=service.findings_summary(severity_rows, lifecycle),
        findings=[service.finding_item(r, lifecycle_list) for r in finding_rows],
        recent_alerts=[service.alert_item(r) for r in alert_rows],
    )

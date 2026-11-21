"""GET /overview."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.repository import AlertFilters, SeriesQuery
from extorq.api.routes.common import Clock, Repo, Settings, now_ms

router = APIRouter(tags=["overview"])

OVERVIEW_SERIES_WINDOW = timedelta(hours=24)
OVERVIEW_SERIES_BUCKET = 3600
RECENT_IMPORTANT_WINDOW = timedelta(days=7)
RECENT_IMPORTANT_LIMIT = 10
SERIES_MAX_ROWS = 20000


@router.get(
    "/overview",
    response_model=s.OverviewResponse,
    summary="Security overview: coverage, open alerts/findings, alert trend, collection health",
)
def get_overview(
    principal: CurrentPrincipal, repo: Repo, settings: Settings, clock: Clock
) -> s.OverviewResponse:
    now = now_ms(clock)

    collectors = [service.collector_status(row, now) for row in repo.collectors("")]
    last_by_type = {
        str(row["asset_type"]): row.get("last_event_at") for row in repo.last_event_by_asset_type()
    }
    coverage = service.asset_class_coverage(repo.all_assets(), collectors, last_by_type)

    open_alerts = service.severity_counts(repo.open_alert_severity_counts(""), "severity", "alerts")
    finding_rows, lifecycle = repo.finding_severity_counts("")
    open_findings = service.findings_summary(finding_rows, lifecycle)

    series_range = s.TimeRange(since=now - OVERVIEW_SERIES_WINDOW, until=now)
    series_rows = repo.alert_series(
        SeriesQuery(
            since=series_range.since,
            until=series_range.until,
            bucket_seconds=OVERVIEW_SERIES_BUCKET,
            group_by="severity",
            max_rows=SERIES_MAX_ROWS,
        )
    )
    alerts_over_time = s.TimeSeriesResponse(
        metric="alerts",
        range=series_range,
        bucket_seconds=OVERVIEW_SERIES_BUCKET,
        group_by="severity",
        points=service.series_points(series_rows, grouped=True),
        truncated=len(series_rows) >= SERIES_MAX_ROWS,
    )

    pipeline = service.pipeline_health(repo.pipeline_latest(), now, settings.pipeline_stale_seconds)
    rules = repo.rules_latest()
    rule_items = service.rule_health(rules, repo.rule_latest_runs(), now)
    collection = service.collection_summary(collectors, pipeline, rule_items, len(rules))

    recent_rows = repo.list_alerts(
        AlertFilters(
            since=now - RECENT_IMPORTANT_WINDOW,
            until=now + timedelta(days=1),
            severities=("high", "critical"),
            sort="last_seen",
        ),
        RECENT_IMPORTANT_LIMIT,
        0,
    )
    return s.OverviewResponse(
        generated_at=now,
        asset_coverage=coverage,
        open_alerts=open_alerts,
        open_findings=open_findings,
        alerts_over_time=alerts_over_time,
        collection_health=collection,
        recent_important_alerts=[service.alert_item(row) for row in recent_rows],
    )

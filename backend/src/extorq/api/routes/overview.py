"""GET /overview."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Response

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.cache import cached
from extorq.api.repository import AlertFilters, Repository, SeriesQuery, ServiceFilters
from extorq.api.routes.common import Clock, IncludeRetired, Repo, Settings, build_estate, now_ms
from extorq.api.routes.services import evaluate_scope, service_evaluator
from extorq.api.settings import ApiSettings

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
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    repo: Repo,
    settings: Settings,
    clock: Clock,
    include_retired: IncludeRetired = False,
) -> s.OverviewResponse:
    return cached(
        request,
        response,
        ("overview", include_retired),
        lambda: _overview(repo, settings, now_ms(clock), include_retired=include_retired),
    )


def _overview(
    repo: Repository, settings: ApiSettings, now: datetime, *, include_retired: bool
) -> s.OverviewResponse:
    evaluator = service_evaluator(repo, settings, now)  # all collectors, read once
    assets = repo.all_assets()
    event_rows = repo.asset_last_events([])
    estate = build_estate(
        repo, settings, now, collectors=evaluator.collectors, assets=assets, event_rows=event_rows
    )
    excluded: frozenset[str] = frozenset() if include_retired else estate.retired_asset_ids
    coverage = estate.class_coverage(assets, event_rows, include_retired=include_retired)

    # Open alerts are never filtered by lifecycle: silencing an asset must not hide them.
    open_alerts = service.severity_counts(repo.open_alert_severity_counts(""), "severity", "alerts")
    finding_rows, lifecycle = repo.finding_severity_counts("", sorted(excluded))
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
    collection = service.collection_summary(
        estate.collectors(include_retired=include_retired),
        pipeline,
        rule_items,
        len(rules),
        retired_collectors=estate.retired_collectors,
    )

    services_scope = evaluate_scope(repo, evaluator, ServiceFilters())
    service_items = [item for item in services_scope.items if item.asset_id not in excluded]

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
        service_coverage=service.services_summary(
            service_items, truncated=services_scope.truncated
        ),
        lifecycle=estate.summary(include_retired=include_retired),
    )

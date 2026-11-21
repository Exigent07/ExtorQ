"""GET /timeseries/alerts and GET /timeseries/events (duplicate-safe counts per bucket)."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Literal

from fastapi import APIRouter, Query

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.repository import SeriesQuery
from extorq.api.routes.common import (
    EVENT_TYPE_PATTERN,
    RULE_ID_PATTERN,
    AssetIdQuery,
    Clock,
    Repo,
    Since,
    Until,
    now_ms,
)
from extorq.contracts import EventCategory, Severity, SourceType

router = APIRouter(tags=["timeseries"])

MAX_SERIES_ROWS = 20000
BucketSeconds = Annotated[
    int | None,
    Query(
        description="Bucket size in seconds: 60, 300, 900, 3600, 21600 or 86400 (auto if omitted)."
    ),
]


@router.get(
    "/timeseries/alerts",
    response_model=s.TimeSeriesResponse,
    summary="Distinct alerts per bucket of first_seen (default last 24h, max 90 days)",
)
def alert_timeseries(
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    since: Since = None,
    until: Until = None,
    bucket_seconds: BucketSeconds = None,
    group_by: Literal["severity", "rule_id", "asset_id"] | None = None,
    asset_id: AssetIdQuery = None,
    rule_id: Annotated[str | None, Query(pattern=RULE_ID_PATTERN)] = None,
    severity: Annotated[list[Severity] | None, Query(max_length=5)] = None,
) -> s.TimeSeriesResponse:
    now = now_ms(clock)
    time_range = service.resolve_range(
        since, until, now=now, default=timedelta(hours=24), maximum=timedelta(days=90)
    )
    bucket = service.choose_bucket(time_range, bucket_seconds)
    rows = repo.alert_series(
        SeriesQuery(
            since=time_range.since,
            until=time_range.until,
            bucket_seconds=bucket,
            group_by=group_by or "",
            asset_id=asset_id or "",
            rule_id=rule_id or "",
            severities=tuple(sev.value for sev in severity or ()),
            max_rows=MAX_SERIES_ROWS,
        )
    )
    return s.TimeSeriesResponse(
        metric="alerts",
        range=time_range,
        bucket_seconds=bucket,
        group_by=group_by,
        points=service.series_points(rows, grouped=group_by is not None),
        truncated=len(rows) >= MAX_SERIES_ROWS,
    )


@router.get(
    "/timeseries/events",
    response_model=s.TimeSeriesResponse,
    summary="Distinct events per bucket of event_time (default last 24h, max 31 days)",
)
def event_timeseries(
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    since: Since = None,
    until: Until = None,
    bucket_seconds: BucketSeconds = None,
    group_by: Literal["source_type", "asset_id", "event_type", "category", "outcome"] | None = None,
    asset_id: AssetIdQuery = None,
    source_type: Annotated[SourceType | None, Query()] = None,
    event_type: Annotated[str | None, Query(pattern=EVENT_TYPE_PATTERN)] = None,
    category: Annotated[EventCategory | None, Query()] = None,
) -> s.TimeSeriesResponse:
    now = now_ms(clock)
    time_range = service.resolve_range(
        since, until, now=now, default=timedelta(hours=24), maximum=timedelta(days=31)
    )
    bucket = service.choose_bucket(time_range, bucket_seconds)
    rows = repo.event_series(
        SeriesQuery(
            since=time_range.since,
            until=time_range.until,
            bucket_seconds=bucket,
            group_by=group_by or "",
            asset_id=asset_id or "",
            source_type=source_type.value if source_type else "",
            event_type=event_type or "",
            category=category.value if category else "",
            max_rows=MAX_SERIES_ROWS,
        )
    )
    return s.TimeSeriesResponse(
        metric="events",
        range=time_range,
        bucket_seconds=bucket,
        group_by=group_by,
        points=service.series_points(rows, grouped=group_by is not None),
        truncated=len(rows) >= MAX_SERIES_ROWS,
    )

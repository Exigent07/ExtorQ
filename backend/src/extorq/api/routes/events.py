"""GET /events (bounded search) and GET /events/{event_id}."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import ValidationError

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.errors import ApiError, NotFound
from extorq.api.logs import get_logger
from extorq.api.repository import EventFilters, Repository
from extorq.api.routes.common import (
    EVENT_TYPE_PATTERN,
    EVENT_TYPE_PREFIX_PATTERN,
    MAX_OFFSET,
    AssetIdQuery,
    Clock,
    EventIdPath,
    Repo,
    ServiceIdQuery,
    Since,
    Until,
    normalise_ip,
    now_ms,
)
from extorq.contracts import EventCategory, Outcome, SecurityEvent, SourceType

log = get_logger("extorq.api.events")

router = APIRouter(tags=["events"])

MAX_EVENT_PAGE = 500
CITING_ALERTS_LIMIT = 100


def _service_scope(repo: Repository, service_id: str | None) -> str:
    """Owning asset of a known service ("" when there is no service filter)."""
    if not service_id:
        return ""
    owner = repo.get_service(service_id)
    if owner is None:
        raise NotFound("service not found")
    return str(owner["asset_id"])


@router.get(
    "/events",
    response_model=s.EventListResponse,
    summary="Bounded event search (default: last 24h, max window 31 days)",
)
def list_events(
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    limit: Annotated[int, Query(ge=1, le=MAX_EVENT_PAGE)] = 100,
    offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
    since: Since = None,
    until: Until = None,
    asset_id: AssetIdQuery = None,
    event_type: Annotated[str | None, Query(pattern=EVENT_TYPE_PATTERN)] = None,
    event_type_prefix: Annotated[
        str | None, Query(pattern=EVENT_TYPE_PREFIX_PATTERN, description="e.g. 'auth.ssh.'")
    ] = None,
    source_type: Annotated[SourceType | None, Query()] = None,
    category: Annotated[EventCategory | None, Query()] = None,
    outcome: Annotated[Outcome | None, Query()] = None,
    actor: Annotated[
        str | None,
        Query(
            min_length=1,
            max_length=256,
            description="Exact match on actor_name, k8s_user or gh_actor_login.",
        ),
    ] = None,
    src_ip: Annotated[
        str | None, Query(max_length=64, description="Exact IP (also matches k8s source IPs).")
    ] = None,
    service_id: ServiceIdQuery = None,
) -> s.EventListResponse:
    now = now_ms(clock)
    time_range = service.resolve_range(
        since,
        until,
        now=now,
        default=timedelta(hours=24),
        maximum=timedelta(days=31),
        future_tolerance=timedelta(days=1),
    )
    filters = EventFilters(
        since=time_range.since,
        until=time_range.until,
        asset_id=asset_id or "",
        event_type=event_type or "",
        event_type_prefix=event_type_prefix or "",
        source_type=source_type.value if source_type else "",
        category=category.value if category else "",
        outcome=outcome.value if outcome else "",
        actor=actor or "",
        src_ip=normalise_ip(src_ip),
        service_id=service_id or "",
        # F-19: events attributed to a known service count only on its own asset subtree.
        scope_asset=_service_scope(repo, service_id),
    )
    rows = repo.list_events(filters, limit + 1, offset)
    has_more = len(rows) > limit
    items = [service.event_item(row) for row in rows[:limit]]
    return s.EventListResponse(
        items=items,
        page=service.page_info(
            limit=limit, offset=offset, returned=len(items), total=None, has_more=has_more
        ),
        range=time_range,
    )


@router.get(
    "/events/{event_id}",
    response_model=s.EventDetailResponse,
    responses={404: {"model": s.ErrorResponse, "description": "Event not found"}},
    summary="One stored SecurityEvent (contract schema 2.0) with ingest metadata",
)
def get_event(
    event_id: EventIdPath, principal: CurrentPrincipal, repo: Repo
) -> s.EventDetailResponse:
    row = repo.get_event(event_id)
    if row is None:
        raise NotFound("event not found")
    try:
        event = SecurityEvent.model_validate_json(str(row["payload"]))
    except ValidationError as exc:
        log.error("stored_event_invalid", event_id=event_id, errors=len(exc.errors()))
        raise ApiError("stored event failed contract validation") from exc
    return s.EventDetailResponse(
        event=event,
        ingest=s.EventIngestInfo(
            ingested_time=row["ingested_time"],
            producer_id=str(row["producer_id"]),
            batch_id=str(row["batch_id"]),
        ),
        alert_ids=repo.alerts_citing_event(event_id, CITING_ALERTS_LIMIT),
    )

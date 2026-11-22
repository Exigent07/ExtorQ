"""GET /findings."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Query

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.errors import BadRequest
from extorq.api.repository import FindingFilters
from extorq.api.routes.common import (
    IDENTIFIER_PATTERN,
    AssetIdQuery,
    Limit,
    Offset,
    Repo,
    ServiceIdQuery,
)
from extorq.contracts import FindingCategory, Severity

router = APIRouter(tags=["findings"])

FindingState = Literal["open", "unverified", "resolved"]


@router.get("/findings", response_model=s.FindingListResponse, summary="List posture findings")
def list_findings(
    principal: CurrentPrincipal,
    repo: Repo,
    limit: Limit = 50,
    offset: Offset = 0,
    asset_id: AssetIdQuery = None,
    severity: Annotated[list[Severity] | None, Query(max_length=5)] = None,
    scanner: Annotated[str | None, Query(pattern=IDENTIFIER_PATTERN)] = None,
    category: Annotated[FindingCategory | None, Query()] = None,
    state: Annotated[
        list[FindingState] | None,
        Query(
            max_length=3,
            description="Lifecycle filter; requires the findings lifecycle view (else 400).",
        ),
    ] = None,
    service_id: ServiceIdQuery = None,
) -> s.FindingListResponse:
    filters = FindingFilters(
        asset_id=asset_id or "",
        severities=tuple(sev.value for sev in severity or ()),
        scanner=scanner or "",
        category=category.value if category else "",
        states=tuple(state or ()),
        service_id=service_id or "",
    )
    if filters.states and not repo.findings_lifecycle_available():
        raise BadRequest(
            "the 'state' filter requires the findings lifecycle view (v_findings_current), "
            "which is not available"
        )
    rows, total, lifecycle = repo.list_findings(filters, limit, offset)
    items = [service.finding_item(row, lifecycle) for row in rows]
    return s.FindingListResponse(
        lifecycle_available=lifecycle,
        source="v_findings_current" if lifecycle else "finding_observations",
        items=items,
        page=service.page_info(limit=limit, offset=offset, returned=len(items), total=total),
        note=None if lifecycle else service.LIFECYCLE_UNAVAILABLE_NOTE,
    )

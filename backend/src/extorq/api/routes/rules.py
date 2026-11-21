"""GET /rules and GET /rules/{rule_id}."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.errors import NotFound
from extorq.api.routes.common import (
    MAX_OFFSET,
    MAX_PAGE,
    Clock,
    Limit,
    Offset,
    Repo,
    RuleIdPath,
    now_ms,
)
from extorq.contracts import RuleRunStatus, RuleStatus, Severity

router = APIRouter(tags=["rules"])


@router.get("/rules", response_model=s.RuleListResponse, summary="List detection rules")
def list_rules(
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    limit: Limit = 50,
    offset: Offset = 0,
    severity: Annotated[list[Severity] | None, Query(max_length=5)] = None,
    status: Annotated[RuleStatus | None, Query()] = None,
    enabled: Annotated[bool | None, Query()] = None,
) -> s.RuleListResponse:
    now = now_ms(clock)
    runs = {str(r["rule_id"]): r for r in repo.rule_latest_runs()}
    counts = {str(r["rule_id"]): r for r in repo.alert_counts_by_rule()}
    wanted = {sev.value for sev in severity or ()}
    items = [
        service.rule_item(row, runs.get(str(row["rule_id"])), counts.get(str(row["rule_id"])), now)
        for row in repo.rules_latest()
    ]
    items = [
        item
        for item in items
        if (not wanted or item.severity.value in wanted)
        and (status is None or item.status == status.value)
        and (enabled is None or item.enabled == enabled)
    ]
    page = items[offset : offset + limit]
    return s.RuleListResponse(
        items=page,
        page=service.page_info(limit=limit, offset=offset, returned=len(page), total=len(items)),
    )


@router.get(
    "/rules/{rule_id}",
    response_model=s.RuleDetailResponse,
    summary="Rule detail with versions, latest runs and alert counts",
)
def get_rule(
    rule_id: RuleIdPath,
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    runs_limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 20,
    runs_offset: Annotated[int, Query(ge=0, le=MAX_OFFSET)] = 0,
    run_status: Annotated[RuleRunStatus | None, Query()] = None,
) -> s.RuleDetailResponse:
    now = now_ms(clock)
    versions = repo.rule_versions(rule_id)
    if not versions:
        raise NotFound("rule not found")
    current = versions[0]
    record = service.rule_record(current)
    latest = next((r for r in repo.rule_latest_runs() if str(r["rule_id"]) == rule_id), None)
    summary = service.run_summary(latest)
    interval = service.interval_from_schedule(current.get("schedule"))
    runs = repo.rule_runs(rule_id, run_status.value if run_status else "", runs_limit, runs_offset)
    by_status = {
        str(r["analyst_status"]): int(r["alerts"])
        for r in repo.alert_status_counts_for_rule(rule_id)
    }
    seen: set[str] = set()
    version_items: list[s.RuleVersionItem] = []
    for row in versions:
        version = str(row["version"])
        if version in seen:
            continue
        seen.add(version)
        version_items.append(
            s.RuleVersionItem(
                version=version,
                loaded_at=row["loaded_at"],
                query_sha256=str(row["query_sha256"]),
                enabled=service.as_bool(row.get("enabled")),
            )
        )
    return s.RuleDetailResponse(
        rule=record,
        versions=version_items,
        last_run=summary,
        interval_seconds=interval,
        run_stale=service.run_stale(summary, interval, record.enabled, now),
        recent_runs=[service.rule_run_item(r) for r in runs],
        alerts_by_status=by_status,
    )

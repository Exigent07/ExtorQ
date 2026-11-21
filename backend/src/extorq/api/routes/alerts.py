"""Alert endpoints: list, detail, context, assessments, AI summary, analyst state."""

from __future__ import annotations

from datetime import timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query
from pydantic import ValidationError

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import AnalystPrincipal, CurrentPrincipal
from extorq.api.errors import ApiError, Conflict, NotFound, ServiceUnavailable
from extorq.api.logs import get_logger
from extorq.api.repository import AlertFilters, Row
from extorq.api.routes.common import (
    RULE_ID_PATTERN,
    SIM_RUN_PATTERN,
    AlertIdPath,
    AssetIdQuery,
    Clock,
    Gate,
    Integr,
    Limit,
    Offset,
    Repo,
    ServiceIdQuery,
    Since,
    Until,
    now_ms,
    write_audit,
)
from extorq.contracts import AIAssessment, AIStatus, AnalystState, AnalystStatus, Severity

log = get_logger("extorq.api.alerts")

router = APIRouter(tags=["alerts"])

EVIDENCE_CAP = 500
EVIDENCE_REF_FETCH = 1000
ACTIONS_LIMIT = 50
ASSESSMENTS_LIMIT = 100

_ERRORS: dict[int | str, dict[str, Any]] = {
    404: {"model": s.ErrorResponse, "description": "Alert not found"},
}


def _require_alert(repo: Any, alert_id: str) -> Row:
    row = repo.get_alert(alert_id)
    if row is None:
        raise NotFound("alert not found")
    row_out: Row = row
    return row_out


@router.get("/alerts", response_model=s.AlertListResponse, summary="List detection alerts")
def list_alerts(
    principal: CurrentPrincipal,
    repo: Repo,
    clock: Clock,
    limit: Limit = 50,
    offset: Offset = 0,
    since: Since = None,
    until: Until = None,
    asset_id: AssetIdQuery = None,
    rule_id: Annotated[str | None, Query(pattern=RULE_ID_PATTERN)] = None,
    severity: Annotated[list[Severity] | None, Query(max_length=5)] = None,
    status: Annotated[list[AnalystStatus] | None, Query(max_length=6)] = None,
    open_only: Annotated[bool, Query(description="Exclude closed_* analyst statuses.")] = False,
    simulation_run_id: Annotated[str | None, Query(pattern=SIM_RUN_PATTERN)] = None,
    sort: Literal["last_seen", "first_seen", "severity"] = "last_seen",
    service_id: ServiceIdQuery = None,
) -> s.AlertListResponse:
    now = now_ms(clock)
    time_range = service.resolve_range(
        since,
        until,
        now=now,
        default=timedelta(days=30),
        maximum=timedelta(days=400),
        future_tolerance=timedelta(days=1),
    )
    filters = AlertFilters(
        since=time_range.since,
        until=time_range.until,
        asset_id=asset_id or "",
        rule_id=rule_id or "",
        severities=tuple(sev.value for sev in severity or ()),
        statuses=tuple(st.value for st in status or ()),
        open_only=open_only,
        simulation_run_id=simulation_run_id or "",
        service_id=service_id or "",
        sort=sort,
    )
    rows = repo.list_alerts(filters, limit, offset)
    total = repo.count_alerts(filters)
    items = [service.alert_item(row) for row in rows]
    return s.AlertListResponse(
        items=items,
        page=service.page_info(limit=limit, offset=offset, returned=len(items), total=total),
        range=time_range,
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=s.AlertDetailResponse,
    responses=_ERRORS,
    summary="Alert detail with analyst state and resolved evidence events",
)
def get_alert(
    alert_id: AlertIdPath, principal: CurrentPrincipal, repo: Repo
) -> s.AlertDetailResponse:
    row = _require_alert(repo, alert_id)
    record = service.alert_record(row)
    state = service.analyst_state_view(repo.get_analyst_state(alert_id))

    refs = repo.evidence_refs(alert_id, EVIDENCE_REF_FETCH)
    ordered, ref_by_id = service.ordered_evidence_ids(refs, record.evidence_event_ids, EVIDENCE_CAP)
    events = {str(e["event_id"]): e for e in repo.events_by_ids(ordered)}
    evidence = [
        service.evidence_event(events[event_id], ref_by_id.get(event_id))
        for event_id in ordered
        if event_id in events
    ]
    unresolved = [event_id for event_id in ordered if event_id not in events]
    total = repo.evidence_total(alert_id, record.evidence_event_ids)

    versions = repo.rule_versions(record.rule_id)
    rule_row = next((v for v in versions if str(v["version"]) == record.rule_version), None)
    rule_row = rule_row or (versions[0] if versions else None)
    asset_row = repo.get_asset(record.asset_id)
    return s.AlertDetailResponse(
        alert=record,
        analyst_state=state,
        rule=service.rule_brief(rule_row) if rule_row else None,
        asset=service.asset_brief(asset_row) if asset_row else None,
        evidence=evidence,
        unresolved_evidence_ids=unresolved,
        evidence_total=max(total, len(ordered)),
        evidence_capped=max(total, len(ordered)) > len(ordered),
        actions=[service.action_item(a) for a in repo.alert_actions(alert_id, ACTIONS_LIMIT)],
    )


@router.get(
    "/alerts/{alert_id}/context",
    response_model=s.ContextResponse,
    responses={**_ERRORS, 503: {"model": s.ErrorResponse, "description": "Correlation absent"}},
    summary="Latest InvestigationContext (built on demand when missing)",
)
def get_alert_context(
    alert_id: AlertIdPath,
    principal: CurrentPrincipal,
    repo: Repo,
    integrations: Integr,
    clock: Clock,
) -> s.ContextResponse:
    _require_alert(repo, alert_id)
    stored = integrations.load_context(repo, alert_id)
    if stored is not None:
        return s.ContextResponse(alert_id=alert_id, source="stored", persisted=True, context=stored)
    try:
        context = integrations.build_context(repo, alert_id)
    except ApiError:
        raise
    except Exception as exc:
        log.error("context_build_failed", alert_id=alert_id, error_type=type(exc).__name__)
        raise ApiError("investigation context could not be built") from exc
    persisted = False
    if principal.is_analyst:
        # Persist only with an audit record; the context is returned either way.
        try:
            write_audit(
                repo,
                principal,
                action="context_built",
                alert_id=alert_id,
                details={"context_id": context.context_id, "input_hash": context.input_hash},
                occurred_at=now_ms(clock),
            )
        except ServiceUnavailable:
            log.warning("context_not_persisted_audit_unavailable", alert_id=alert_id)
        else:
            try:
                integrations.save_context(repo, context)
                persisted = True
            except Exception as exc:  # noqa: BLE001 - caching failure must not fail the read
                log.error("context_save_failed", alert_id=alert_id, error_type=type(exc).__name__)
    return s.ContextResponse(
        alert_id=alert_id, source="built_on_demand", persisted=persisted, context=context
    )


def _assessment_from_row(row: Row) -> AIAssessment:
    output = service.parse_json(row.get("output"))
    if isinstance(output, dict) and "assessment_id" in output:
        return AIAssessment.model_validate(output)
    parts = output if isinstance(output, dict) else {}
    data = {
        key: row.get(key)
        for key in (
            "assessment_id",
            "alert_id",
            "context_id",
            "context_input_hash",
            "provider",
            "model",
            "task",
            "prompt_version",
            "status",
            "latency_ms",
            "input_tokens",
            "output_tokens",
            "provider_request_id",
            "error",
            "created_at",
            "requested_by",
        )
    }
    for key in ("triage", "summary", "validation"):
        data[key] = parts.get(key)
    return AIAssessment.model_validate(data)


@router.get(
    "/alerts/{alert_id}/assessments",
    response_model=s.AssessmentListResponse,
    responses=_ERRORS,
    summary="AI assessments (advisory) recorded for an alert",
)
def list_alert_assessments(
    alert_id: AlertIdPath, principal: CurrentPrincipal, repo: Repo, integrations: Integr
) -> s.AssessmentListResponse:
    _require_alert(repo, alert_id)
    try:
        via_store = integrations.list_assessments(repo, alert_id)
    except ApiError:
        raise
    except Exception as exc:  # noqa: BLE001 - foreign module; direct query fallback
        log.warning("ai_store_failed_using_direct", error_type=type(exc).__name__)
        via_store = None
    if via_store is not None:
        items = sorted(via_store, key=lambda a: a.created_at, reverse=True)[:ASSESSMENTS_LIMIT]
        return s.AssessmentListResponse(
            alert_id=alert_id, items=items, invalid_records=0, source="ai.store"
        )
    items = []
    invalid = 0
    for row in repo.assessments_direct(alert_id, ASSESSMENTS_LIMIT):
        try:
            items.append(_assessment_from_row(row))
        except (ValidationError, ValueError, TypeError):
            invalid += 1
    if invalid:
        log.warning("invalid_assessment_rows", alert_id=alert_id, count=invalid)
    return s.AssessmentListResponse(
        alert_id=alert_id, items=items, invalid_records=invalid, source="direct"
    )


@router.post(
    "/alerts/{alert_id}/summary",
    response_model=s.SummaryResponse,
    responses={
        **_ERRORS,
        403: {"model": s.ErrorResponse, "description": "Viewer role"},
        409: {"model": s.ErrorResponse, "description": "Summary already in progress"},
        429: {"model": s.ErrorResponse, "description": "Per-user rate limit"},
        503: {"model": s.ErrorResponse, "description": "AI unavailable or disabled"},
    },
    summary="Request an evidence-grounded AI summary (analyst only, advisory)",
)
def request_alert_summary(
    alert_id: AlertIdPath,
    principal: AnalystPrincipal,
    repo: Repo,
    integrations: Integr,
    gate: Gate,
    clock: Clock,
) -> s.SummaryResponse:
    _require_alert(repo, alert_id)
    gate.acquire(principal.user, alert_id)
    try:
        write_audit(
            repo,
            principal,
            action="ai_summary_requested",
            alert_id=alert_id,
            details={"task": "summary"},
            occurred_at=now_ms(clock),
        )
        assessment = integrations.request_summary(repo, alert_id, principal.requested_by)
    except ApiError:
        raise
    except Exception as exc:
        log.error("ai_summary_failed", alert_id=alert_id, error_type=type(exc).__name__)
        raise ServiceUnavailable("AI summary request failed") from exc
    finally:
        gate.release(alert_id)
    if assessment.status == AIStatus.DISABLED:
        # E's refusal reason names the flag/variable only (never a value).
        reason = (assessment.error or "provider disabled")[:200]
        raise ServiceUnavailable(f"AI summaries are unavailable: {reason}")
    return s.SummaryResponse(alert_id=alert_id, assessment=assessment)


@router.post(
    "/alerts/{alert_id}/state",
    response_model=s.AlertStateResponse,
    responses={
        **_ERRORS,
        403: {"model": s.ErrorResponse, "description": "Viewer role"},
        409: {"model": s.ErrorResponse, "description": "State changed concurrently"},
        503: {"model": s.ErrorResponse, "description": "Audit log or storage unavailable"},
    },
    summary="Set the analyst workflow state of an alert (analyst only, audited)",
)
def set_alert_state(
    alert_id: AlertIdPath,
    body: s.AlertStateUpdate,
    principal: AnalystPrincipal,
    repo: Repo,
    clock: Clock,
) -> s.AlertStateResponse:
    _require_alert(repo, alert_id)
    current = repo.get_analyst_state(alert_id)
    if body.expected_updated_at is not None:
        current_at = current.get("updated_at") if current else None
        if current_at != body.expected_updated_at:
            raise Conflict("analyst state was changed by someone else; reload and retry")
    now = now_ms(clock)
    state = AnalystState(
        alert_id=alert_id,
        status=body.status,
        assignee=body.assignee,
        note=body.note,
        updated_by=principal.user,
        updated_at=now,
    )
    action_id = write_audit(
        repo,
        principal,
        action="alert_state_changed",
        alert_id=alert_id,
        details={
            "previous_status": (str(current["status"]) if current else None),
            "previous_assignee": (current.get("assignee") if current else None),
            "status": state.status.value,
            "assignee": state.assignee,
            "note": state.note,
        },
        occurred_at=now,
    )
    try:
        repo.insert_analyst_state(
            {
                "alert_id": state.alert_id,
                "status": state.status.value,
                "assignee": state.assignee,
                "note": state.note,
                "updated_by": state.updated_by,
                "updated_at": state.updated_at,
            }
        )
    except Exception as exc:
        log.error("analyst_state_write_failed", alert_id=alert_id, error_type=type(exc).__name__)
        try:
            write_audit(
                repo,
                principal,
                action="alert_state_change_failed",
                alert_id=alert_id,
                details={"intended_action_id": action_id},
                occurred_at=now_ms(clock),
            )
        except ServiceUnavailable:
            log.error("audit_of_failure_failed", alert_id=alert_id)
        raise ServiceUnavailable("analyst state could not be stored") from exc
    return s.AlertStateResponse(
        alert_id=alert_id,
        state=s.AnalystStateView(
            status=state.status,
            assignee=state.assignee,
            note=state.note,
            updated_by=state.updated_by,
            updated_at=state.updated_at,
            recorded=True,
        ),
        action_id=action_id,
    )

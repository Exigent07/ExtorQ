"""Shared dependencies, parameter types and helpers for the API routers."""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, Path, Query, Request

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import Principal
from extorq.api.errors import BadRequest, ServiceUnavailable
from extorq.api.integrations import Integrations
from extorq.api.lifecycle import Estate, last_event_map
from extorq.api.logs import get_logger
from extorq.api.repository import Repository, Row
from extorq.api.service import SummaryGate
from extorq.api.settings import ApiSettings
from extorq.contracts.identity import canonical_json

log = get_logger("extorq.api.routes")

HEX_ID_PATTERN = r"^[0-9a-f]{32}$"
RULE_ID_PATTERN = r"^[A-Z][A-Z0-9]{1,15}-[0-9]{3}$"
ASSET_ID_PATTERN = r"^[a-z0-9][a-z0-9._:/-]{2,199}$"
EVENT_TYPE_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,5}$"
EVENT_TYPE_PREFIX_PATTERN = r"^[a-z][a-z0-9_.]{0,127}$"
IDENTIFIER_PATTERN = r"^[a-z0-9][a-z0-9._-]{1,127}$"
SIM_RUN_PATTERN = r"^[a-z0-9]{8,32}$"

MAX_PAGE = 200
MAX_OFFSET = 10_000


def get_repo(request: Request) -> Repository:
    repo: Repository = request.app.state.repository
    return repo


def get_integrations(request: Request) -> Integrations:
    integrations: Integrations = request.app.state.integrations
    return integrations


def get_settings(request: Request) -> ApiSettings:
    settings: ApiSettings = request.app.state.settings
    return settings


def get_clock(request: Request) -> Callable[[], datetime]:
    clock: Callable[[], datetime] = request.app.state.clock
    return clock


def get_summary_gate(request: Request) -> SummaryGate:
    gate: SummaryGate = request.app.state.summary_gate
    return gate


Repo = Annotated[Repository, Depends(get_repo)]
Integr = Annotated[Integrations, Depends(get_integrations)]
Settings = Annotated[ApiSettings, Depends(get_settings)]
Clock = Annotated[Callable[[], datetime], Depends(get_clock)]
Gate = Annotated[SummaryGate, Depends(get_summary_gate)]

Limit = Annotated[int, Query(ge=1, le=MAX_PAGE, description="Page size (1-200).")]
Offset = Annotated[int, Query(ge=0, le=MAX_OFFSET, description="Rows to skip (0-10000).")]
Since = Annotated[
    datetime | None,
    Query(description="Inclusive lower bound, ISO-8601 with timezone (e.g. 2026-11-21T10:00:00Z)."),
]
Until = Annotated[
    datetime | None, Query(description="Exclusive upper bound, ISO-8601 with timezone.")
]
AlertIdPath = Annotated[str, Path(pattern=HEX_ID_PATTERN, description="32-hex alert id.")]
EventIdPath = Annotated[str, Path(pattern=HEX_ID_PATTERN, description="32-hex event id.")]
RuleIdPath = Annotated[str, Path(pattern=RULE_ID_PATTERN, description="Rule id, e.g. VM-001.")]
AssetIdPath = Annotated[
    str, Path(pattern=ASSET_ID_PATTERN, description="Asset id, e.g. linux:lab-vm-01.")
]
AssetIdQuery = Annotated[
    str | None, Query(pattern=ASSET_ID_PATTERN, description="Filter by asset id.")
]
ServiceIdQuery = Annotated[
    str | None,
    Query(pattern=HEX_ID_PATTERN, description="Filter by service id (32 hex, schema 1.1)."),
]
IncludeRetired = Annotated[
    bool,
    Query(
        description="Include RETIRED assets (no collector reports for them and not observed "
        "within the retirement window, 24 h by default) and their collectors in lists and "
        "rollups. Default: left out (never deleted)."
    ),
]


def build_estate(
    repo: Repository,
    settings: ApiSettings,
    now: datetime,
    *,
    collectors: list[s.CollectorStatus] | None = None,
    assets: list[Row] | None = None,
    event_rows: list[Row] | None = None,
) -> Estate:
    """Lifecycle of every asset and collector for this request (reads what is not given).

    Inputs: every asset row, every collector's latest report (pass the list already read
    for the request) and the newest event per asset id.
    """
    if collectors is None:
        collectors = [service.collector_status(row, now) for row in repo.collectors("")]
    if assets is None:
        assets = repo.all_assets()
    if event_rows is None:
        event_rows = repo.asset_last_events([])
    return Estate(
        assets,
        collectors,
        last_event_map(event_rows),
        now,
        stale_seconds=settings.asset_stale_seconds,
        retire_seconds=settings.asset_retire_seconds,
    )


def now_ms(clock: Callable[[], datetime]) -> datetime:
    """Current time truncated to milliseconds (storage precision), aware UTC."""
    now = clock().astimezone(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def normalise_ip(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise BadRequest("'src_ip' must be a valid IPv4 or IPv6 address") from exc


def write_audit(
    repo: Repository,
    principal: Principal,
    *,
    action: str,
    alert_id: str | None,
    details: dict[str, Any],
    occurred_at: datetime,
) -> str:
    """Append one ``analyst_actions`` row. Raises 503 when the audit log is unwritable.

    Callers write the audit row *before* the mutation it describes, so no mutation can
    happen without an audit record.
    """
    action_id = uuid.uuid4().hex
    row = {
        "action_id": action_id,
        "occurred_at": occurred_at,
        "actor": principal.user,
        "role": principal.role,
        "action": action,
        "alert_id": alert_id,
        "details": canonical_json(details),
    }
    try:
        repo.insert_analyst_action(row)
    except ServiceUnavailable:
        raise
    except Exception as exc:
        log.error("audit_write_failed", action=action, error_type=type(exc).__name__)
        raise ServiceUnavailable("audit log is unavailable; no change was made") from exc
    return action_id

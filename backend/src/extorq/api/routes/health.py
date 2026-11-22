"""GET /health: collectors, pipeline, rules, AI providers, ingestion boundary."""

from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Request, Response

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.cache import cached
from extorq.api.errors import is_quota_error
from extorq.api.integrations import Integrations
from extorq.api.logs import get_logger
from extorq.api.repository import Repository
from extorq.api.routes.common import (
    Clock,
    IncludeRetired,
    Integr,
    Repo,
    Settings,
    build_estate,
    now_ms,
)
from extorq.api.settings import ApiSettings

log = get_logger("extorq.api.health")

router = APIRouter(tags=["health"])

INGEST_WINDOW_HOURS = 24


@router.get(
    "/health",
    response_model=s.HealthResponse,
    summary="Collection, pipeline, rule and AI provider health (stale = 3 x interval)",
)
def get_health(
    principal: CurrentPrincipal,
    request: Request,
    response: Response,
    repo: Repo,
    integrations: Integr,
    settings: Settings,
    clock: Clock,
    include_retired: IncludeRetired = False,
) -> s.HealthResponse:
    return cached(
        request,
        response,
        ("health", include_retired),
        lambda: _health(
            repo, integrations, settings, now_ms(clock), include_retired=include_retired
        ),
    )


def _health(
    repo: Repository,
    integrations: Integrations,
    settings: ApiSettings,
    now: datetime,
    *,
    include_retired: bool,
) -> s.HealthResponse:
    ai_config, ai_source = integrations.ai_configuration()
    try:
        repo.ping()
    except Exception as exc:  # any failure (except quota exhaustion) means storage is unusable
        if is_quota_error(exc):
            # The query quota of the read identity is exhausted: load, not an outage (429).
            raise
        log.error("health_storage_unreachable", error_type=type(exc).__name__)
        return s.HealthResponse(
            generated_at=now,
            storage=s.StorageHealth(reachable=False, error="ClickHouse is unreachable"),
            collectors=[],
            pipeline=[],
            rules=[],
            ai=service.ai_health([], [], ai_config, settings.ai_health_window_hours),
            ai_configuration_source=ai_source,
            ingest=None,
            notes=["storage unreachable: collector, pipeline and rule health are unknown"],
        )

    notes: list[str] = []
    reported = [service.collector_status(row, now) for row in repo.collectors("")]
    estate = build_estate(repo, settings, now, collectors=reported)
    collectors = estate.collectors(include_retired=include_retired)
    retired = estate.retired_collectors
    if not reported:
        notes.append("no collector health has been reported yet")
    elif retired and not include_retired:
        notes.append(
            f"{retired} retired collector(s) not listed: they report for a retired asset or "
            "are self-tests that stopped reporting (include_retired=true lists them)"
        )
    pipeline = service.pipeline_health(repo.pipeline_latest(), now, settings.pipeline_stale_seconds)
    if not pipeline:
        notes.append("no pipeline health has been reported yet")
    rules = service.rule_health(repo.rules_latest(), repo.rule_latest_runs(), now)
    if not rules:
        notes.append("no detection rules are registered and no rule runs are recorded")
    window = settings.ai_health_window_hours
    ai = service.ai_health(
        repo.ai_status_counts(now - timedelta(hours=window)),
        repo.ai_latest(),
        ai_config,
        window,
        runtime=service.ai_runtime(pipeline),
    )
    ingest_since = now - timedelta(hours=INGEST_WINDOW_HOURS)
    ingest = s.IngestSecuritySummary(
        window_hours=INGEST_WINDOW_HOURS,
        quarantined_records=repo.ingest_quarantine_count(ingest_since),
        audit_decisions={
            str(r["decision"]): int(r["events"]) for r in repo.ingest_audit_decisions(ingest_since)
        },
    )
    return s.HealthResponse(
        generated_at=now,
        storage=s.StorageHealth(reachable=True),
        collectors=collectors,
        pipeline=pipeline,
        rules=rules,
        ai=ai,
        ai_configuration_source=ai_source,
        ingest=ingest,
        notes=notes,
        collectors_retired=retired,
    )

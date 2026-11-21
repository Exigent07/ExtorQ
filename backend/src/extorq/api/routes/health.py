"""GET /health: collectors, pipeline, rules, AI providers, ingestion boundary."""

from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.auth import CurrentPrincipal
from extorq.api.logs import get_logger
from extorq.api.routes.common import Clock, Integr, Repo, Settings, now_ms

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
    repo: Repo,
    integrations: Integr,
    settings: Settings,
    clock: Clock,
) -> s.HealthResponse:
    now = now_ms(clock)
    ai_config, ai_source = integrations.ai_configuration()
    try:
        repo.ping()
    except Exception as exc:  # noqa: BLE001 - any failure means storage is unusable
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
    collectors = [service.collector_status(row, now) for row in repo.collectors("")]
    if not collectors:
        notes.append("no collector health has been reported yet")
    pipeline = service.pipeline_health(repo.pipeline_latest(), now, settings.pipeline_stale_seconds)
    if not pipeline:
        notes.append("no pipeline health has been reported yet")
    rules = service.rule_health(repo.rules_latest(), repo.rule_latest_runs(), now)
    if not rules:
        notes.append("no detection rules are registered and no rule runs are recorded")
    window = settings.ai_health_window_hours
    ai = service.ai_health(
        repo.ai_status_counts(now - timedelta(hours=window)), repo.ai_latest(), ai_config, window
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
    )

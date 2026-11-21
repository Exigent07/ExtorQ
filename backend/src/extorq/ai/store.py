"""Persistence of AI assessments (``extorq.ai_assessments``) and ai-worker health.

AI writes ONLY ``ai_assessments`` and ``pipeline_health`` (PLAN §3 invariant 4).
All SQL uses ClickHouse server-side parameters (``{name:Type}``) and
duplicate-safe aggregation (``uniqExact``, ``FINAL``).

Row format: flattened columns from :class:`AIAssessment` plus ``output``, the
canonical JSON of ``{"requested_model", "triage", "summary", "validation"}``
(``requested_model`` is the configured model id; ``model`` is the id the
provider reported). Each provider attempt is one row with a unique
``assessment_id`` (random nonce), so attempts are countable for budgets.

The client arguments are clickhouse-connect clients (``query``/``insert``):
the API passes ``extorq_api_ro`` / ``extorq_api_writer`` clients, the
ai-worker ``extorq_ai`` clients.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError

from extorq.ai._compat import get_logger
from extorq.contracts.ai import (
    AIAssessment,
    AIProvider,
    AIStatus,
    AITask,
    InvestigationSummary,
    JevTriageResult,
    SummaryValidation,
)
from extorq.contracts.health import PipelineHealth
from extorq.contracts.identity import canonical_json

_log = get_logger("extorq.ai.store")

DATABASE = "extorq"
ASSESSMENTS_TABLE = "ai_assessments"
HEALTH_TABLE = "pipeline_health"

#: Statuses that represent an actual provider attempt (counted against budgets).
ATTEMPT_STATUSES: tuple[str, ...] = (
    AIStatus.OK.value,
    AIStatus.INSUFFICIENT_CONTEXT.value,
    AIStatus.INVALID_OUTPUT.value,
    AIStatus.TIMEOUT.value,
    AIStatus.RATE_LIMITED.value,
    AIStatus.ERROR.value,
)
#: Statuses that are a usable result (reused instead of a new paid call).
SUCCESS_STATUSES: tuple[str, ...] = (AIStatus.OK.value, AIStatus.INSUFFICIENT_CONTEXT.value)

ASSESSMENT_COLUMNS: tuple[str, ...] = (
    "assessment_id",
    "alert_id",
    "context_id",
    "context_input_hash",
    "provider",
    "model",
    "task",
    "prompt_version",
    "status",
    "recommendation",
    "uncertain",
    "output",
    "latency_ms",
    "input_tokens",
    "output_tokens",
    "provider_request_id",
    "error",
    "created_at",
    "requested_by",
)
_SELECT_COLUMNS = (
    "assessment_id, alert_id, context_id, context_input_hash, provider, model, task, "
    "prompt_version, status, output, latency_ms, input_tokens, output_tokens, "
    "provider_request_id, error, created_at, requested_by"
)
HEALTH_COLUMNS: tuple[str, ...] = (
    "component",
    "instance",
    "reported_at",
    "status",
    "queue_depth",
    "oldest_queued_age_seconds",
    "accepted_total",
    "duplicate_total",
    "rejected_total",
    "quarantined_total",
    "written_total",
    "write_errors_total",
    "dead_letter_total",
    "last_write_at",
    "details",
)
_UINT32_MAX = 2**32 - 1


def _u32(value: int | None) -> int | None:
    return None if value is None else min(max(value, 0), _UINT32_MAX)


def _epoch_ms(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("aware datetime required")
    return int(value.timestamp() * 1000)


def assessment_to_row(a: AIAssessment, *, requested_model: str | None = None) -> list[Any]:
    output = {
        "requested_model": requested_model or a.model,
        "triage": a.triage.model_dump(mode="json") if a.triage else None,
        "summary": a.summary.model_dump(mode="json") if a.summary else None,
        "validation": a.validation.model_dump(mode="json") if a.validation else None,
    }
    return [
        a.assessment_id,
        a.alert_id,
        a.context_id,
        a.context_input_hash,
        a.provider.value,
        a.model,
        a.task.value,
        a.prompt_version,
        a.status.value,
        a.triage.recommendation.value if a.triage else None,
        (1 if a.triage.uncertain else 0) if a.triage else None,
        canonical_json(output),
        _u32(a.latency_ms),
        _u32(a.input_tokens),
        _u32(a.output_tokens),
        a.provider_request_id,
        a.error,
        a.created_at,
        a.requested_by,
    ]


def save_assessment(
    write_client: Any, a: AIAssessment, *, requested_model: str | None = None
) -> None:
    """Insert one assessment row (raises on storage failure; callers decide)."""
    write_client.insert(
        ASSESSMENTS_TABLE,
        [assessment_to_row(a, requested_model=requested_model)],
        column_names=list(ASSESSMENT_COLUMNS),
        database=DATABASE,
    )


def _aware(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise TypeError("created_at is not a datetime")
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def row_to_assessment(row: Sequence[Any]) -> tuple[AIAssessment, str | None]:
    """Rebuild (assessment, requested_model) from a ``_SELECT_COLUMNS`` row."""
    (
        assessment_id,
        alert_id,
        context_id,
        input_hash,
        provider,
        model,
        task,
        prompt_version,
        status,
        output_text,
        latency_ms,
        input_tokens,
        output_tokens,
        request_id,
        error,
        created_at,
        requested_by,
    ) = row
    output = json.loads(output_text) if output_text else {}
    triage = output.get("triage")
    summary = output.get("summary")
    validation = output.get("validation")
    assessment = AIAssessment(
        assessment_id=assessment_id,
        alert_id=alert_id,
        context_id=context_id,
        context_input_hash=input_hash,
        provider=AIProvider(provider),
        model=model,
        task=AITask(task),
        prompt_version=prompt_version,
        status=AIStatus(status),
        triage=JevTriageResult.model_validate(triage) if triage else None,
        summary=InvestigationSummary.model_validate(summary) if summary else None,
        validation=SummaryValidation.model_validate(validation) if validation else None,
        latency_ms=latency_ms,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        provider_request_id=request_id,
        error=error,
        created_at=_aware(created_at),
        requested_by=requested_by,
    )
    requested = output.get("requested_model")
    return assessment, requested if isinstance(requested, str) else None


def _rows_to_assessments(rows: Iterable[Sequence[Any]]) -> list[tuple[AIAssessment, str | None]]:
    out: list[tuple[AIAssessment, str | None]] = []
    for row in rows:
        try:
            out.append(row_to_assessment(row))
        except (ValidationError, ValueError, TypeError, KeyError) as exc:
            _log.warning("ai_assessment_row_unreadable", error_class=type(exc).__name__)
    return out


def list_assessments(read_client: Any, alert_id: str, *, limit: int = 50) -> list[AIAssessment]:
    """Assessments for an alert, newest first (unreadable rows are skipped and logged)."""
    result = read_client.query(
        f"SELECT {_SELECT_COLUMNS} FROM extorq.ai_assessments FINAL "  # noqa: S608 - constant column list
        "WHERE alert_id = {alert_id:String} "
        "ORDER BY created_at DESC, assessment_id ASC LIMIT {limit:UInt32}",
        parameters={"alert_id": alert_id, "limit": max(1, min(limit, 500))},
    )
    return [a for a, _ in _rows_to_assessments(result.result_rows)]


def find_reusable(
    read_client: Any,
    *,
    alert_id: str,
    provider: AIProvider,
    task: AITask,
    prompt_version: str,
    context_input_hash: str,
    model: str,
) -> AIAssessment | None:
    """Latest successful assessment for the same (context hash, model, prompt version)."""
    result = read_client.query(
        f"SELECT {_SELECT_COLUMNS} FROM extorq.ai_assessments FINAL "  # noqa: S608 - constant column list
        "WHERE alert_id = {alert_id:String} AND provider = {provider:String} "
        "AND task = {task:String} AND prompt_version = {prompt_version:String} "
        "AND context_input_hash = {input_hash:String} "
        "AND has({statuses:Array(String)}, status) "
        "ORDER BY created_at DESC LIMIT 20",
        parameters={
            "alert_id": alert_id,
            "provider": provider.value,
            "task": task.value,
            "prompt_version": prompt_version,
            "input_hash": context_input_hash,
            "statuses": list(SUCCESS_STATUSES),
        },
    )
    for assessment, requested in _rows_to_assessments(result.result_rows):
        if model in (assessment.model, requested):
            return assessment
    return None


def count_attempts_since(read_client: Any, provider: AIProvider, since: datetime) -> int:
    """Provider attempts (all attempt statuses) since ``since`` (duplicate-safe)."""
    result = read_client.query(
        "SELECT uniqExact(assessment_id) FROM extorq.ai_assessments "
        "WHERE provider = {provider:String} "
        "AND created_at >= fromUnixTimestamp64Milli({since_ms:Int64}, 'UTC') "
        "AND has({statuses:Array(String)}, status)",
        parameters={
            "provider": provider.value,
            "since_ms": _epoch_ms(since),
            "statuses": list(ATTEMPT_STATUSES),
        },
    )
    rows = result.result_rows
    return int(rows[0][0]) if rows else 0


def last_attempt_at(
    read_client: Any, *, alert_id: str, provider: AIProvider, task: AITask
) -> datetime | None:
    result = read_client.query(
        "SELECT max(created_at), count() FROM extorq.ai_assessments "
        "WHERE alert_id = {alert_id:String} AND provider = {provider:String} "
        "AND task = {task:String} AND has({statuses:Array(String)}, status)",
        parameters={
            "alert_id": alert_id,
            "provider": provider.value,
            "task": task.value,
            "statuses": list(ATTEMPT_STATUSES),
        },
    )
    rows = result.result_rows
    if not rows or int(rows[0][1]) == 0:
        return None
    return _aware(rows[0][0])


@dataclass(frozen=True)
class PendingContext:
    alert_id: str
    context_id: str
    input_hash: str


_PENDING_FROM = """
FROM
(
    SELECT alert_id,
           argMax(context_id, created_at) AS context_id,
           argMax(input_hash, created_at) AS input_hash,
           max(created_at) AS context_created_at
    FROM extorq.investigation_contexts
    GROUP BY alert_id
    HAVING context_created_at >= now64(3) - toIntervalHour({max_age_hours:UInt32})
) AS l
LEFT JOIN
(
    SELECT alert_id,
           context_input_hash,
           uniqExactIf(assessment_id, status IN ('ok', 'insufficient_context')) AS done,
           uniqExactIf(assessment_id, status NOT IN ('ok', 'insufficient_context')) AS failed,
           max(created_at) AS last_attempt
    FROM extorq.ai_assessments
    WHERE provider = {provider:String} AND task = {task:String}
      AND prompt_version = {prompt_version:String}
    GROUP BY alert_id, context_input_hash
) AS a ON a.alert_id = l.alert_id AND a.context_input_hash = l.input_hash
WHERE ifNull(a.done, 0) = 0
  AND ifNull(a.failed, 0) < {max_failed:UInt32}
  AND ifNull(a.last_attempt, toDateTime64(0, 3, 'UTC'))
      < now64(3) - toIntervalSecond({backoff_seconds:UInt32})
"""


def _pending_parameters(
    prompt_version: str, max_failed: int, backoff_seconds: int, max_age_hours: int
) -> dict[str, Any]:
    return {
        "provider": AIProvider.JEV.value,
        "task": AITask.TRIAGE.value,
        "prompt_version": prompt_version,
        "max_failed": max_failed,
        "backoff_seconds": backoff_seconds,
        "max_age_hours": max_age_hours,
    }


def pending_triage(
    read_client: Any,
    *,
    prompt_version: str,
    limit: int,
    max_failed: int,
    backoff_seconds: int,
    max_age_hours: int,
) -> list[PendingContext]:
    """Latest contexts without a successful Jev triage for that context hash (bounded)."""
    params = _pending_parameters(prompt_version, max_failed, backoff_seconds, max_age_hours)
    params["limit"] = max(1, min(limit, 500))
    result = read_client.query(
        "SELECT l.alert_id, l.context_id, l.input_hash "
        + _PENDING_FROM
        + "ORDER BY l.context_created_at DESC, l.alert_id ASC LIMIT {limit:UInt32}",
        parameters=params,
    )
    return [PendingContext(str(r[0]), str(r[1]), str(r[2])) for r in result.result_rows]


def count_pending_triage(
    read_client: Any,
    *,
    prompt_version: str,
    max_failed: int,
    backoff_seconds: int,
    max_age_hours: int,
) -> int:
    result = read_client.query(
        "SELECT count() " + _PENDING_FROM,
        parameters=_pending_parameters(prompt_version, max_failed, backoff_seconds, max_age_hours),
    )
    rows = result.result_rows
    return int(rows[0][0]) if rows else 0


def save_pipeline_health(write_client: Any, h: PipelineHealth) -> None:
    row = [
        h.component,
        h.instance,
        h.reported_at,
        h.status.value,
        h.queue_depth,
        h.oldest_queued_age_seconds,
        h.accepted_total,
        h.duplicate_total,
        h.rejected_total,
        h.quarantined_total,
        h.written_total,
        h.write_errors_total,
        h.dead_letter_total,
        h.last_write_at,
        canonical_json(h.details),
    ]
    write_client.insert(HEALTH_TABLE, [row], column_names=list(HEALTH_COLUMNS), database=DATABASE)

"""ai-worker: advisory Jev triage of newly built investigation contexts.

Each cycle (every ``ai_worker_interval_seconds``):

1. find the latest context per alert that has no successful Jev triage for its
   ``input_hash`` (bounded: ``ai_worker_batch_size``; failed attempts are
   retried at most ``ai_worker_max_failed_attempts`` times with a backoff;
   contexts older than ``ai_worker_max_context_age_hours`` are ignored);
2. reserve budget (daily cap, persisted + in-process), call Jev, store the
   assessment with the ``extorq_ai`` identity (INSERT on ai_assessments and
   pipeline_health only, no write on alerts);
3. report ``PipelineHealth(component="ai_worker")``.

The worker only reads detection output, so it can never block detection.
When Jev is disabled or has no key it reports ``disabled`` and makes no calls.
"""

from __future__ import annotations

import os
import random
import signal
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.ai import store
from extorq.ai._compat import get_logger, optional_attr
from extorq.ai.budget import BudgetExceeded, BudgetGuard, BudgetUnavailable, shared_guard
from extorq.ai.context_source import ContextLoadError, load_latest_context
from extorq.ai.jev import TRIAGE_PROMPT_VERSION, JevTriageProvider
from extorq.ai.settings import AISettings, get_ai_settings, startup_report
from extorq.contracts.ai import AIProvider, AIStatus
from extorq.contracts.common import HealthStatus, utc_now
from extorq.contracts.context import InvestigationContext
from extorq.contracts.health import PipelineHealth

_log = get_logger("extorq.ai.worker")
COMPONENT = "ai_worker"
REQUESTED_BY = "system:ai-worker"


@dataclass
class CycleStats:
    status: HealthStatus = HealthStatus.OK
    reason: str = ""
    queue_depth: int = 0
    processed: int = 0
    saved: int = 0
    write_errors: int = 0
    budget_denied: int = 0
    skipped: int = 0
    by_status: dict[str, int] = field(default_factory=dict)


@dataclass
class Totals:
    accepted: int = 0
    written: int = 0
    write_errors: int = 0
    rejected: int = 0
    last_write_at: datetime | None = None


ContextLoader = Callable[[Any, str], InvestigationContext | None]


class TriageWorker:
    def __init__(
        self,
        *,
        read_client: Any,
        write_client: Any,
        settings: AISettings | None = None,
        provider: JevTriageProvider | None = None,
        guard: BudgetGuard | None = None,
        context_loader: ContextLoader = load_latest_context,
        clock: Callable[[], datetime] = utc_now,
        instance: str | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.settings = settings or get_ai_settings()
        self.read_client = read_client
        self.write_client = write_client
        self.provider = provider or JevTriageProvider(self.settings, clock=clock)
        self.guard = guard or shared_guard(AIProvider.JEV, self.settings.jev_daily_cap)
        self.context_loader = context_loader
        self.clock = clock
        self.instance = (instance or f"{socket.gethostname()}:{os.getpid()}")[:200]
        self.stop_event = stop_event or threading.Event()
        self.totals = Totals()

    def _count_today(self, day_start: datetime) -> int:
        return store.count_attempts_since(self.read_client, AIProvider.JEV, day_start)

    def run_cycle(self) -> CycleStats:
        stats = CycleStats()
        usable, reason = self.provider.availability()
        if not usable:
            stats.status = HealthStatus.DISABLED
            stats.reason = reason
            return stats
        s = self.settings
        stats.queue_depth = store.count_pending_triage(
            self.read_client,
            prompt_version=TRIAGE_PROMPT_VERSION,
            max_failed=s.ai_worker_max_failed_attempts,
            backoff_seconds=s.ai_worker_retry_backoff_seconds,
            max_age_hours=s.ai_worker_max_context_age_hours,
        )
        candidates = store.pending_triage(
            self.read_client,
            prompt_version=TRIAGE_PROMPT_VERSION,
            limit=s.ai_worker_batch_size,
            max_failed=s.ai_worker_max_failed_attempts,
            backoff_seconds=s.ai_worker_retry_backoff_seconds,
            max_age_hours=s.ai_worker_max_context_age_hours,
        )
        for candidate in candidates:
            if self.stop_event.is_set():
                break
            try:
                ctx = self.context_loader(self.read_client, candidate.alert_id)
            except ContextLoadError as exc:
                _log.warning(
                    "ai_worker_context_invalid", alert_id=candidate.alert_id, reason=str(exc)
                )
                stats.skipped += 1
                continue
            if ctx is None:
                stats.skipped += 1
                continue
            try:
                reservation = self.guard.try_reserve(self._count_today)
            except BudgetExceeded as exc:
                stats.budget_denied += 1
                stats.status = HealthStatus.DEGRADED
                stats.reason = str(exc)
                self.totals.rejected += 1
                break
            except BudgetUnavailable as exc:
                stats.status = HealthStatus.DEGRADED
                stats.reason = str(exc)
                break
            persisted = False
            try:
                assessment = self.provider.assess(ctx, REQUESTED_BY)
                stats.processed += 1
                self.totals.accepted += 1
                stats.by_status[assessment.status.value] = (
                    stats.by_status.get(assessment.status.value, 0) + 1
                )
                try:
                    store.save_assessment(
                        self.write_client, assessment, requested_model=s.jev_model
                    )
                    persisted = True
                    stats.saved += 1
                    self.totals.written += 1
                    self.totals.last_write_at = self.clock()
                except Exception as exc:  # noqa: BLE001 - counted and reported via health
                    stats.write_errors += 1
                    self.totals.write_errors += 1
                    _log.error(
                        "ai_worker_persist_failed",
                        alert_id=ctx.alert_id,
                        error_class=type(exc).__name__,
                    )
            finally:
                reservation.finish(persisted=persisted)
        failures = sum(
            n
            for status, n in stats.by_status.items()
            if status not in (AIStatus.OK.value, AIStatus.INSUFFICIENT_CONTEXT.value)
        )
        if stats.status is HealthStatus.OK and (failures or stats.write_errors):
            stats.status = HealthStatus.DEGRADED
            stats.reason = f"{failures} provider failure(s), {stats.write_errors} write error(s)"
        return stats

    def health(self, stats: CycleStats) -> PipelineHealth:
        details: dict[str, str | int | float | bool | None] = {
            "provider": AIProvider.JEV.value,
            "model": self.settings.jev_model,
            "prompt_version": TRIAGE_PROMPT_VERSION,
            "reason": stats.reason[:500] or None,
            "cycle_processed": stats.processed,
            "cycle_saved": stats.saved,
            "cycle_skipped": stats.skipped,
            "cycle_budget_denied": stats.budget_denied,
            "daily_cap": self.settings.jev_daily_cap,
        }
        for status, n in sorted(stats.by_status.items()):
            details[f"cycle_status_{status}"] = n
        return PipelineHealth(
            component=COMPONENT,
            instance=self.instance,
            reported_at=self.clock(),
            status=stats.status,
            queue_depth=stats.queue_depth,
            accepted_total=self.totals.accepted,
            rejected_total=self.totals.rejected,
            written_total=self.totals.written,
            write_errors_total=self.totals.write_errors,
            last_write_at=self.totals.last_write_at,
            details=details,
        )

    def report(self, stats: CycleStats) -> None:
        try:
            store.save_pipeline_health(self.write_client, self.health(stats))
        except Exception as exc:  # noqa: BLE001 - health reporting is best effort
            _log.warning("ai_worker_health_write_failed", error_class=type(exc).__name__)

    def run_forever(self, *, once: bool = False) -> None:
        failures = 0
        while not self.stop_event.is_set():
            try:
                stats = self.run_cycle()
                failures = 0
            except Exception as exc:  # noqa: BLE001 - keep the service alive; report and back off
                failures += 1
                stats = CycleStats(
                    status=HealthStatus.FAILED, reason=f"cycle_failed ({type(exc).__name__})"
                )
                _log.error(
                    "ai_worker_cycle_failed", error_class=type(exc).__name__, consecutive=failures
                )
            self.report(stats)
            _log.info(
                "ai_worker_cycle",
                status=stats.status.value,
                queue_depth=stats.queue_depth,
                processed=stats.processed,
                saved=stats.saved,
                reason=stats.reason or None,
            )
            if once:
                return
            delay = float(self.settings.ai_worker_interval_seconds)
            if failures:
                delay = min(300.0, delay * (2 ** min(failures, 4)))
            delay *= 1 + random.uniform(0, 0.1)  # noqa: S311 - scheduling jitter only
            self.stop_event.wait(delay)


def _clients() -> tuple[Any, Any]:
    get_client = optional_attr("extorq.storage.clickhouse", "get_client")
    if get_client is None:
        raise RuntimeError("extorq.storage.clickhouse.get_client is not available")
    client = get_client("ai")
    return client, client


def main(once: bool = False) -> None:
    """Entry point for the compose ``ai-worker`` service (``extorq ai-worker``)."""
    configure = optional_attr("extorq.common.logging", "configure_logging")
    if configure is not None:
        configure("ai-worker")
    settings = get_ai_settings()
    _log.info("ai_worker_starting", **startup_report(settings))
    read_client, write_client = _clients()
    stop = threading.Event()

    def _stop(signum: int, _frame: object) -> None:
        _log.info("ai_worker_stopping", signal=signum)
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop)
    worker = TriageWorker(
        read_client=read_client, write_client=write_client, settings=settings, stop_event=stop
    )
    worker.run_forever(once=once)

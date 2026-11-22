"""ai-worker: advisory Jev triage of newly built investigation contexts.

Each cycle (every ``ai_worker_interval_seconds``):

1. **Write retries first.** A result that was paid for but could not be stored (e.g. a
   ClickHouse outage) is kept in memory and only its INSERT is retried, with exponential
   backoff (``ai_worker_write_retry_base_seconds`` doubling up to
   ``ai_worker_write_retry_max_seconds``, jittered). While any result awaits storage no new
   provider call is made, so a write outage never turns into repeated paid calls. After
   ``ai_worker_write_max_attempts`` failed writes the result is dropped (logged, counted)
   and that context is never sent to the provider again by this process.
2. **Queue.** The latest context per alert without a successful Jev triage for its
   ``input_hash`` (newest first; failed attempts are retried at most
   ``ai_worker_max_failed_attempts`` times after ``ai_worker_retry_backoff_seconds``;
   contexts older than ``ai_worker_max_context_age_hours`` are ignored). A context that
   cannot be read or validated (C2's store rejects it) is skipped, counted, reported and
   excluded for the rest of the process, and the queue is paged past it (at most
   ``ai_worker_max_scan_per_cycle`` contexts examined per cycle), so a block of bad contexts
   at the head never stalls the queue.
3. **Calls.** Reserve budget (daily cap, persisted + in-process), call Jev for up to
   ``ai_worker_batch_size`` contexts, store each assessment with the ``extorq_ai`` identity
   (INSERT on ai_assessments and pipeline_health only, no write on alerts).
4. **Health.** ``PipelineHealth(component="ai_worker")`` with queue depth, unreadable
   contexts, results awaiting storage and dropped results.

The worker only reads detection output, so it can never block detection.
When Jev is disabled or has no key it reports ``disabled`` and makes no calls.
"""

from __future__ import annotations

import os
import random
import signal
import socket
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.ai import store
from extorq.ai._compat import get_logger, optional_attr
from extorq.ai.budget import (
    BudgetExceeded,
    BudgetGuard,
    BudgetUnavailable,
    Reservation,
    shared_guard,
)
from extorq.ai.context_source import ContextLoadError, load_latest_context
from extorq.ai.jev import TRIAGE_PROMPT_VERSION, JevTriageProvider
from extorq.ai.settings import AISettings, get_ai_settings, startup_report
from extorq.contracts.ai import AIAssessment, AIProvider, AIStatus, AITask
from extorq.contracts.common import HealthStatus, utc_now
from extorq.contracts.context import InvestigationContext
from extorq.contracts.health import PipelineHealth

_log = get_logger("extorq.ai.worker")
COMPONENT = "ai_worker"
REQUESTED_BY = "system:ai-worker"
#: Bound on remembered unreadable contexts / dropped results (oldest forgotten first).
MAX_REMEMBERED = 5_000

#: (alert_id, context input_hash)
Key = tuple[str, str]


@dataclass
class CycleStats:
    status: HealthStatus = HealthStatus.OK
    reason: str = ""
    queue_depth: int = 0
    #: contexts taken from the queue and examined this cycle
    scanned: int = 0
    processed: int = 0
    #: rows stored this cycle (new results and successful write retries)
    saved: int = 0
    write_errors: int = 0
    write_retries: int = 0
    retried_saved: int = 0
    budget_denied: int = 0
    #: contexts not sent to the provider (unreadable, vanished, or replaced by a newer one)
    skipped: int = 0
    #: subset of ``skipped``: unreadable / invalid contexts (excluded from now on)
    invalid: int = 0
    by_status: dict[str, int] = field(default_factory=dict)


@dataclass
class Totals:
    accepted: int = 0
    written: int = 0
    write_errors: int = 0
    rejected: int = 0
    invalid_contexts: int = 0
    dropped_results: int = 0
    last_write_at: datetime | None = None


@dataclass
class _Unsaved:
    """A paid result that could not be stored yet: only its write is retried."""

    assessment: AIAssessment
    reservation: Reservation
    failed_writes: int
    next_attempt_at: float  # monotonic seconds


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
        monotonic: Callable[[], float] = time.monotonic,
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
        self.monotonic = monotonic
        self.instance = (instance or f"{socket.gethostname()}:{os.getpid()}")[:200]
        self.stop_event = stop_event or threading.Event()
        self.totals = Totals()
        self._unsaved: dict[Key, _Unsaved] = {}
        self._invalid: dict[Key, str] = {}
        self._dropped: dict[Key, None] = {}

    # ── bookkeeping ──────────────────────────────────────────────────
    @property
    def awaiting_storage(self) -> int:
        return len(self._unsaved)

    @staticmethod
    def _remember(table: dict[Key, Any], key: Key, value: Any) -> None:
        table.pop(key, None)
        table[key] = value
        while len(table) > MAX_REMEMBERED:
            del table[next(iter(table))]

    def _blocked(self, key: Key) -> bool:
        return key in self._unsaved or key in self._invalid or key in self._dropped

    def _excluded(self, seen: Iterable[Key]) -> list[str]:
        """Exclusion keys for the queue query, most relevant first."""
        keys = [*seen, *self._unsaved, *reversed(self._dropped), *reversed(self._invalid)]
        return [store.pending_key(alert_id, input_hash) for alert_id, input_hash in keys]

    def _write_backoff(self, failed_writes: int) -> float:
        s = self.settings
        delay = min(
            float(s.ai_worker_write_retry_max_seconds),
            s.ai_worker_write_retry_base_seconds * 2.0 ** max(0, failed_writes - 1),
        )
        return delay * (1 + random.uniform(0, 0.1))  # noqa: S311 - scheduling jitter only

    def next_retry_in(self) -> float | None:
        """Seconds until the next due write retry (None when nothing awaits storage)."""
        if not self._unsaved:
            return None
        soonest = min(entry.next_attempt_at for entry in self._unsaved.values())
        return max(0.0, soonest - self.monotonic())

    def _count_today(self, day_start: datetime) -> int:
        return store.count_attempts_since(self.read_client, AIProvider.JEV, day_start)

    def _save(self, assessment: AIAssessment) -> bool:
        try:
            store.save_assessment(
                self.write_client, assessment, requested_model=self.settings.jev_model
            )
        except Exception as exc:  # noqa: BLE001 - counted and reported via health
            _log.error(
                "ai_worker_persist_failed",
                alert_id=assessment.alert_id,
                error_class=type(exc).__name__,
            )
            return False
        self.totals.written += 1
        self.totals.last_write_at = self.clock()
        return True

    # ── cycle ────────────────────────────────────────────────────────
    def _retry_unsaved(self, stats: CycleStats) -> None:
        """Retry due writes of results already paid for (never calls the provider)."""
        now = self.monotonic()
        due = sorted((e.next_attempt_at, key) for key, e in self._unsaved.items())
        for when, key in due:
            if when > now or self.stop_event.is_set():
                break
            entry = self._unsaved[key]
            stats.write_retries += 1
            if self._save(entry.assessment):
                del self._unsaved[key]
                entry.reservation.persisted_later()
                stats.saved += 1
                stats.retried_saved += 1
                _log.info(
                    "ai_worker_persist_retry_succeeded",
                    alert_id=key[0],
                    failed_writes=entry.failed_writes,
                )
                continue
            entry.failed_writes += 1
            stats.write_errors += 1
            self.totals.write_errors += 1
            if entry.failed_writes >= self.settings.ai_worker_write_max_attempts:
                del self._unsaved[key]
                self._remember(self._dropped, key, None)
                self.totals.dropped_results += 1
                _log.error(
                    "ai_worker_result_dropped",
                    alert_id=key[0],
                    failed_writes=entry.failed_writes,
                    reason="write retries exhausted; context not sent to the provider again",
                )
            else:
                entry.next_attempt_at = now + self._write_backoff(entry.failed_writes)
            break  # storage is failing: leave the other due writes for later cycles

    def _already_triaged(self, ctx: InvestigationContext) -> bool:
        reusable = store.find_reusable(
            self.read_client,
            alert_id=ctx.alert_id,
            provider=AIProvider.JEV,
            task=AITask.TRIAGE,
            prompt_version=TRIAGE_PROMPT_VERSION,
            context_input_hash=ctx.input_hash,
            model=self.settings.jev_model,
        )
        return reusable is not None

    def _triage_one(
        self, candidate: store.PendingContext, seen: dict[Key, None], stats: CycleStats
    ) -> bool:
        """Examine one queued context; False stops the cycle (budget or storage problem)."""
        key: Key = (candidate.alert_id, candidate.input_hash)
        try:
            ctx = self.context_loader(self.read_client, candidate.alert_id)
            if ctx is not None and ctx.alert_id != candidate.alert_id:
                raise ContextLoadError("loaded context belongs to another alert")
        except ContextLoadError as exc:
            stats.skipped += 1
            stats.invalid += 1
            self.totals.invalid_contexts += 1
            self._remember(self._invalid, key, str(exc)[:200])
            _log.warning("ai_worker_context_invalid", alert_id=candidate.alert_id, reason=str(exc))
            return True
        if ctx is None:
            stats.skipped += 1  # vanished since the queue was read
            return True
        if ctx.input_hash != candidate.input_hash:
            # A newer context replaced the queued one: triage it unless that already happened.
            key = (ctx.alert_id, ctx.input_hash)
            if key in seen or self._blocked(key) or self._already_triaged(ctx):
                stats.skipped += 1
                return True
            seen[key] = None
        try:
            reservation = self.guard.try_reserve(self._count_today)
        except BudgetExceeded as exc:
            stats.budget_denied += 1
            stats.status = HealthStatus.DEGRADED
            stats.reason = str(exc)
            self.totals.rejected += 1
            return False
        except BudgetUnavailable as exc:
            stats.status = HealthStatus.DEGRADED
            stats.reason = str(exc)
            return False
        persisted = False
        try:
            assessment = self.provider.assess(ctx, REQUESTED_BY)
            stats.processed += 1
            self.totals.accepted += 1
            status = assessment.status.value
            stats.by_status[status] = stats.by_status.get(status, 0) + 1
            persisted = self._save(assessment)
        finally:
            reservation.finish(persisted=persisted)
        if persisted:
            stats.saved += 1
            return True
        # Keep the paid result; only its write is retried. New calls pause until it is stored.
        stats.write_errors += 1
        self.totals.write_errors += 1
        self._unsaved[key] = _Unsaved(
            assessment=assessment,
            reservation=reservation,
            failed_writes=1,
            next_attempt_at=self.monotonic() + self._write_backoff(1),
        )
        return False

    def _triage_pending(self, stats: CycleStats, pending_args: dict[str, Any]) -> None:
        s = self.settings
        seen: dict[Key, None] = {}
        while (
            not self.stop_event.is_set()
            and stats.processed < s.ai_worker_batch_size
            and stats.scanned < s.ai_worker_max_scan_per_cycle
        ):
            page = store.pending_triage(
                self.read_client,
                limit=min(s.ai_worker_batch_size, s.ai_worker_max_scan_per_cycle - stats.scanned),
                exclude=self._excluded(seen),
                **pending_args,
            )
            fresh = [
                c
                for c in page
                if (c.alert_id, c.input_hash) not in seen
                and not self._blocked((c.alert_id, c.input_hash))
            ]
            if not fresh:
                return
            for candidate in fresh:
                if (
                    self.stop_event.is_set()
                    or stats.processed >= s.ai_worker_batch_size
                    or stats.scanned >= s.ai_worker_max_scan_per_cycle
                ):
                    return
                seen[(candidate.alert_id, candidate.input_hash)] = None
                stats.scanned += 1
                if not self._triage_one(candidate, seen, stats):
                    return

    def run_cycle(self) -> CycleStats:
        stats = CycleStats()
        usable, reason = self.provider.availability()
        if not usable:
            stats.status = HealthStatus.DISABLED
            stats.reason = reason
            return stats
        s = self.settings
        self._retry_unsaved(stats)
        pending_args: dict[str, Any] = {
            "prompt_version": TRIAGE_PROMPT_VERSION,
            "max_failed": s.ai_worker_max_failed_attempts,
            "backoff_seconds": s.ai_worker_retry_backoff_seconds,
            "max_age_hours": s.ai_worker_max_context_age_hours,
        }
        stats.queue_depth = store.count_pending_triage(self.read_client, **pending_args)
        if not self._unsaved:
            self._triage_pending(stats, pending_args)
        return self._finalise(stats)

    def _finalise(self, stats: CycleStats) -> CycleStats:
        failures = sum(
            n
            for status, n in stats.by_status.items()
            if status not in (AIStatus.OK.value, AIStatus.INSUFFICIENT_CONTEXT.value)
        )
        problems: list[str] = []
        if failures:
            problems.append(f"{failures} provider failure(s)")
        if stats.write_errors:
            problems.append(f"{stats.write_errors} write error(s)")
        if self._unsaved:
            problems.append(
                f"{len(self._unsaved)} result(s) awaiting storage, new provider calls paused"
            )
        if stats.invalid:
            problems.append(f"{stats.invalid} unreadable context(s) skipped")
        if problems:
            joined = "; ".join(problems)
            stats.reason = f"{stats.reason}; {joined}" if stats.reason else joined
            if stats.status is HealthStatus.OK:
                stats.status = HealthStatus.DEGRADED
        return stats

    # ── health and loop ──────────────────────────────────────────────
    def health(self, stats: CycleStats) -> PipelineHealth:
        details: dict[str, str | int | float | bool | None] = {
            "provider": AIProvider.JEV.value,
            "model": self.settings.jev_model,
            "prompt_version": TRIAGE_PROMPT_VERSION,
            "reason": stats.reason[:500] or None,
            "cycle_scanned": stats.scanned,
            "cycle_processed": stats.processed,
            "cycle_saved": stats.saved,
            "cycle_skipped": stats.skipped,
            "cycle_invalid_contexts": stats.invalid,
            "cycle_write_retries": stats.write_retries,
            "cycle_retried_saved": stats.retried_saved,
            "cycle_budget_denied": stats.budget_denied,
            "awaiting_storage": len(self._unsaved),
            "invalid_contexts_total": self.totals.invalid_contexts,
            "results_dropped_total": self.totals.dropped_results,
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
                scanned=stats.scanned,
                processed=stats.processed,
                saved=stats.saved,
                skipped=stats.skipped,
                invalid=stats.invalid,
                awaiting_storage=len(self._unsaved),
                reason=stats.reason or None,
            )
            if once:
                return
            delay = float(self.settings.ai_worker_interval_seconds)
            if failures:
                delay = min(300.0, delay * (2 ** min(failures, 4)))
            retry_in = self.next_retry_in()
            if retry_in is not None:
                delay = min(delay, max(1.0, retry_in))
            delay *= 1 + random.uniform(0, 0.1)  # noqa: S311 - scheduling jitter only
            self.stop_event.wait(delay)


def _instance_name() -> str | None:
    """Platform ``EXTORQ_INSTANCE_NAME`` (compose: ``ai-worker``), if the settings load."""
    get_settings = optional_attr("extorq.common.config", "get_settings")
    if get_settings is None:
        return None
    try:
        name = getattr(get_settings(), "instance_name", None)
    except Exception:  # noqa: BLE001 - fall back to hostname:pid
        return None
    return str(name)[:200] if name else None


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
        read_client=read_client,
        write_client=write_client,
        settings=settings,
        stop_event=stop,
        instance=_instance_name(),
    )
    worker.run_forever(once=once)

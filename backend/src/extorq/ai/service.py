"""AIService: on-demand AI requests for the analyst API and CLI.

``request_summary(alert_id, requested_by)`` (used by ``POST /api/v1/alerts/{id}/summary``):

1. validate the alert id; load the latest InvestigationContext (C2's correlation
   store; if none is stored and ``ai_build_missing_context`` is on, ask the
   correlation builder to build and save one);
2. reuse an existing successful summary for the same (context ``input_hash``,
   model, prompt version) instead of a new paid call;
3. refuse without calling when Gemini is disabled / has no key (``disabled``),
   when the per-alert cooldown is active or the daily cap is reached
   (``budget_exceeded``), or when usage cannot be verified (``error``);
4. call Gemini (bounded timeout + retries), persist the assessment with the
   caller's write identity (``extorq_api_writer`` in the API), return it.

Provider failures never raise: they come back as an assessment status.
Refusals (disabled / budget) are returned but not stored: ``ai_assessments``
holds one row per provider attempt. Only precondition failures raise:
:class:`InvalidAlertId` and :class:`ContextNotFound` (API: 400 / 404).

The call blocks for at most roughly ``gemini_max_attempts x
gemini_timeout_seconds`` plus backoff; async callers should run it in a
worker thread (e.g. ``starlette.concurrency.run_in_threadpool``).
"""

from __future__ import annotations

import re
import threading
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from extorq.ai import store
from extorq.ai._compat import get_logger, optional_attr
from extorq.ai.budget import (
    BudgetExceeded,
    BudgetUnavailable,
    CooldownTracker,
    cooldown_remaining,
    shared_cooldowns,
    shared_guard,
)
from extorq.ai.context_source import ContextLoadError, build_and_save_context, load_latest_context
from extorq.ai.gemini import SUMMARY_PROMPT_VERSION, GeminiSummaryProvider
from extorq.ai.jev import TRIAGE_PROMPT_VERSION, JevTriageProvider
from extorq.ai.sanitize import clean_token
from extorq.ai.settings import AISettings, get_ai_settings
from extorq.contracts.ai import AIAssessment, AIProvider, AIStatus, AITask
from extorq.contracts.common import utc_now
from extorq.contracts.context import InvestigationContext
from extorq.contracts.identity import assessment_id

_log = get_logger("extorq.ai.service")
_HEX_ID = re.compile(r"^[0-9a-f]{32}$")


class AIServiceError(Exception):
    """Base class for precondition failures surfaced to the caller."""


class InvalidAlertId(AIServiceError):
    pass


class ContextNotFound(AIServiceError):
    """No InvestigationContext exists (or can be built) for the alert."""


class ContextUnavailable(AIServiceError):
    """Storage could not be read, or the stored context is invalid."""


ClientProvider = Callable[[str], Any]


def _platform_client(role: str) -> Any:
    get_client = optional_attr("extorq.storage.clickhouse", "get_client")
    if get_client is None:
        raise ContextUnavailable("extorq.storage.clickhouse is not available")
    return get_client(role)


class _AlertLocks:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def get(self, alert_id: str) -> threading.Lock:
        with self._lock:
            lock = self._locks.get(alert_id)
            if lock is None:
                if len(self._locks) > 5_000:
                    self._locks = {k: v for k, v in self._locks.items() if v.locked()}
                lock = threading.Lock()
                self._locks[alert_id] = lock
            return lock


_alert_locks = _AlertLocks()


class AIService:
    def __init__(
        self,
        settings: AISettings | None = None,
        *,
        read_client: Any | None = None,
        write_client: Any | None = None,
        read_role: str = "api_ro",
        write_role: str = "api_writer",
        client_provider: ClientProvider | None = None,
        gemini: GeminiSummaryProvider | None = None,
        jev: JevTriageProvider | None = None,
        cooldowns: CooldownTracker | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings or get_ai_settings()
        self._read_client = read_client
        self._write_client = write_client
        self._read_role = read_role
        self._write_role = write_role
        self._client_provider = client_provider or _platform_client
        self._gemini = gemini
        self._jev = jev
        self._cooldowns = cooldowns or shared_cooldowns()
        self._clock = clock

    # ── clients and providers ───────────────────────────────────────
    @property
    def read_client(self) -> Any:
        if self._read_client is None:
            self._read_client = self._client_provider(self._read_role)
        return self._read_client

    @property
    def write_client(self) -> Any:
        if self._write_client is None:
            self._write_client = self._client_provider(self._write_role)
        return self._write_client

    @property
    def gemini(self) -> GeminiSummaryProvider:
        if self._gemini is None:
            self._gemini = GeminiSummaryProvider(self._settings, clock=self._clock)
        return self._gemini

    @property
    def jev(self) -> JevTriageProvider:
        if self._jev is None:
            self._jev = JevTriageProvider(self._settings, clock=self._clock)
        return self._jev

    # ── context ─────────────────────────────────────────────────────
    def load_context(self, alert_id: str) -> InvestigationContext:
        if not isinstance(alert_id, str) or not _HEX_ID.match(alert_id):
            raise InvalidAlertId("alert_id must be 32 lower-case hex characters")
        try:
            ctx = load_latest_context(self.read_client, alert_id)
        except ContextLoadError as exc:
            raise ContextUnavailable(str(exc)) from None
        except AIServiceError:
            raise
        except Exception as exc:  # noqa: BLE001 - storage failure, reported by class name only
            raise ContextUnavailable(f"context store unavailable ({type(exc).__name__})") from None
        if ctx is None and self._settings.ai_build_missing_context:
            try:
                ctx = build_and_save_context(self.read_client, self.write_client, alert_id)
            except AIServiceError:
                raise
            except Exception as exc:  # noqa: BLE001 - builder failure is a precondition failure
                _log.warning(
                    "context_build_failed", alert_id=alert_id, error_class=type(exc).__name__
                )
                ctx = None
        if ctx is None:
            raise ContextNotFound(f"no investigation context for alert {alert_id}")
        if ctx.alert_id != alert_id:
            raise ContextUnavailable("context does not belong to the requested alert")
        return ctx

    # ── helpers ─────────────────────────────────────────────────────
    def _refusal(
        self,
        ctx: InvestigationContext,
        *,
        provider: AIProvider,
        task: AITask,
        model: str,
        prompt_version: str,
        status: AIStatus,
        error: str,
        requested_by: str,
    ) -> AIAssessment:
        """An unsaved assessment describing why no provider call was made."""
        return AIAssessment(
            assessment_id=assessment_id(
                provider.value, model, task.value, prompt_version, ctx.input_hash, uuid.uuid4().hex
            ),
            alert_id=ctx.alert_id,
            context_id=ctx.context_id,
            context_input_hash=ctx.input_hash,
            provider=provider,
            model=model,
            task=task,
            prompt_version=prompt_version,
            status=status,
            error=error,
            created_at=self._clock(),
            requested_by=clean_token(requested_by) or "unknown",
        )

    def _persist(self, assessment: AIAssessment, requested_model: str) -> bool:
        try:
            store.save_assessment(self.write_client, assessment, requested_model=requested_model)
        except Exception as exc:  # noqa: BLE001 - persistence failure must not hide the result
            _log.error(
                "ai_assessment_persist_failed",
                alert_id=assessment.alert_id,
                provider=assessment.provider.value,
                error_class=type(exc).__name__,
            )
            return False
        return True

    def _count_today(self, provider: AIProvider) -> Callable[[datetime], int]:
        def count(day_start: datetime) -> int:
            return store.count_attempts_since(self.read_client, provider, day_start)

        return count

    # ── summary (Gemini) ────────────────────────────────────────────
    def request_summary(self, alert_id: str, requested_by: str) -> AIAssessment:
        ctx = self.load_context(alert_id)
        s = self._settings
        model = s.gemini_model

        def refuse(status: AIStatus, error: str) -> AIAssessment:
            return self._refusal(
                ctx,
                provider=AIProvider.GEMINI,
                task=AITask.SUMMARY,
                model=model,
                prompt_version=SUMMARY_PROMPT_VERSION,
                status=status,
                error=error,
                requested_by=requested_by,
            )

        with _alert_locks.get(f"summary:{alert_id}"):
            try:
                cached = store.find_reusable(
                    self.read_client,
                    alert_id=alert_id,
                    provider=AIProvider.GEMINI,
                    task=AITask.SUMMARY,
                    prompt_version=SUMMARY_PROMPT_VERSION,
                    context_input_hash=ctx.input_hash,
                    model=model,
                )
            except Exception as exc:  # noqa: BLE001 - cannot verify cache/budget: fail closed
                return refuse(AIStatus.ERROR, f"budget_check_unavailable ({type(exc).__name__})")
            if cached is not None:
                _log.info(
                    "ai_summary_reused", alert_id=alert_id, assessment_id=cached.assessment_id
                )
                return cached

            usable, reason = self.gemini.availability()
            if not usable:
                return refuse(AIStatus.DISABLED, reason)

            now = self._clock()
            try:
                persisted_last = store.last_attempt_at(
                    self.read_client,
                    alert_id=alert_id,
                    provider=AIProvider.GEMINI,
                    task=AITask.SUMMARY,
                )
            except Exception as exc:  # noqa: BLE001 - fail closed
                return refuse(AIStatus.ERROR, f"budget_check_unavailable ({type(exc).__name__})")
            local_last = self._cooldowns.last(f"summary:{alert_id}")
            last = max((t for t in (persisted_last, local_last) if t is not None), default=None)
            remaining = cooldown_remaining(last, now, s.gemini_alert_cooldown_seconds)
            if remaining > 0:
                return refuse(
                    AIStatus.BUDGET_EXCEEDED,
                    f"cooldown_active (per-alert summary cooldown; retry in {remaining} s)",
                )

            guard = shared_guard(AIProvider.GEMINI, s.gemini_daily_cap)
            try:
                reservation = guard.try_reserve(self._count_today(AIProvider.GEMINI))
            except BudgetExceeded as exc:
                return refuse(AIStatus.BUDGET_EXCEEDED, str(exc))
            except BudgetUnavailable as exc:
                return refuse(AIStatus.ERROR, str(exc))

            self._cooldowns.note(f"summary:{alert_id}", now)
            persisted = False
            try:
                assessment = self.gemini.summarize(ctx, requested_by)
                persisted = self._persist(assessment, model)
            finally:
                reservation.finish(persisted=persisted)
            return assessment

    # ── triage (Jev), used by the CLI; the ai-worker has its own loop ─
    def request_triage(self, alert_id: str, requested_by: str = "system:cli") -> AIAssessment:
        ctx = self.load_context(alert_id)
        s = self._settings
        model = s.jev_model

        def refuse(status: AIStatus, error: str) -> AIAssessment:
            return self._refusal(
                ctx,
                provider=AIProvider.JEV,
                task=AITask.TRIAGE,
                model=model,
                prompt_version=TRIAGE_PROMPT_VERSION,
                status=status,
                error=error,
                requested_by=requested_by,
            )

        with _alert_locks.get(f"triage:{alert_id}"):
            try:
                cached = store.find_reusable(
                    self.read_client,
                    alert_id=alert_id,
                    provider=AIProvider.JEV,
                    task=AITask.TRIAGE,
                    prompt_version=TRIAGE_PROMPT_VERSION,
                    context_input_hash=ctx.input_hash,
                    model=model,
                )
            except Exception as exc:  # noqa: BLE001 - fail closed
                return refuse(AIStatus.ERROR, f"budget_check_unavailable ({type(exc).__name__})")
            if cached is not None:
                return cached
            usable, reason = self.jev.availability()
            if not usable:
                return refuse(AIStatus.DISABLED, reason)
            guard = shared_guard(AIProvider.JEV, s.jev_daily_cap)
            try:
                reservation = guard.try_reserve(self._count_today(AIProvider.JEV))
            except BudgetExceeded as exc:
                return refuse(AIStatus.BUDGET_EXCEEDED, str(exc))
            except BudgetUnavailable as exc:
                return refuse(AIStatus.ERROR, str(exc))
            persisted = False
            try:
                assessment = self.jev.assess(ctx, requested_by)
                persisted = self._persist(assessment, model)
            finally:
                reservation.finish(persisted=persisted)
            return assessment

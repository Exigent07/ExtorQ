"""AIService: on-demand Jev triage of one alert (``extorq ai triage <alert_id>``).

The ai-worker triages new contexts automatically; this service is the operator's way to
ask for one alert explicitly. ``request_triage(alert_id, requested_by)``:

1. validates the alert id and loads the latest InvestigationContext through C2's
   correlation store (if none is stored and ``ai_build_missing_context`` is on, it asks
   the correlation builder to build and save one);
2. returns an existing successful triage for the same (context ``input_hash``, model,
   question-set version) instead of making a new paid call;
3. refuses without calling when Jev is disabled or has no usable key (``disabled``), when
   the daily cap is reached (``budget_exceeded``) or when usage cannot be verified
   (``error``: fail closed);
4. calls Jev (bounded timeout and retries), persists the assessment with the write
   identity and returns it.

Provider failures never raise: they come back as an assessment status. Refusals are
returned but not stored, so ``ai_assessments`` holds one row per real provider attempt.
Only precondition failures raise: :class:`InvalidAlertId`, :class:`ContextNotFound` and
:class:`ContextUnavailable`.

Identities: reads use ``extorq_api_ro`` and writes ``extorq_api_writer`` by default,
because building a missing context needs SELECT on telemetry and INSERT on
``investigation_contexts``, which the ai-worker's ``extorq_ai`` identity deliberately
lacks. Neither identity can write ``alerts``.
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
from extorq.ai.budget import BudgetExceeded, BudgetUnavailable, shared_guard
from extorq.ai.context_source import ContextLoadError, build_and_save_context, load_latest_context
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
    """The alert id is not 32 lower-case hex characters (checked before any I/O)."""


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
    """One lock per alert, so concurrent requests for one alert make at most one call."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def get(self, alert_id: str) -> threading.Lock:
        with self._lock:
            lock = self._locks.get(alert_id)
            if lock is None:
                if len(self._locks) > 5_000:  # bound memory: keep only locks in use
                    self._locks = {k: v for k, v in self._locks.items() if v.locked()}
                lock = threading.Lock()
                self._locks[alert_id] = lock
            return lock


_alert_locks = _AlertLocks()


class AIService:
    """On-demand Jev triage with reuse, a fail-closed daily cap and per-alert locking."""

    def __init__(
        self,
        settings: AISettings | None = None,
        *,
        read_client: Any | None = None,
        write_client: Any | None = None,
        read_role: str = "api_ro",
        write_role: str = "api_writer",
        client_provider: ClientProvider | None = None,
        jev: JevTriageProvider | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._settings = settings or get_ai_settings()
        self._read_client = read_client
        self._write_client = write_client
        self._read_role = read_role
        self._write_role = write_role
        self._client_provider = client_provider or _platform_client
        self._jev = jev
        self._clock = clock

    # ── clients and provider (created lazily: a disabled CLI call opens nothing) ──
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
    def jev(self) -> JevTriageProvider:
        if self._jev is None:
            self._jev = JevTriageProvider(self._settings, clock=self._clock)
        return self._jev

    # ── context ─────────────────────────────────────────────────────
    def load_context(self, alert_id: str) -> InvestigationContext:
        """Latest stored context for ``alert_id`` (built on demand when allowed)."""
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
        self, ctx: InvestigationContext, *, status: AIStatus, error: str, requested_by: str
    ) -> AIAssessment:
        """An unsaved assessment describing why no provider call was made."""
        model = self._settings.jev_model
        return AIAssessment(
            assessment_id=assessment_id(
                AIProvider.JEV.value,
                model,
                AITask.TRIAGE.value,
                TRIAGE_PROMPT_VERSION,
                ctx.input_hash,
                uuid.uuid4().hex,
            ),
            alert_id=ctx.alert_id,
            context_id=ctx.context_id,
            context_input_hash=ctx.input_hash,
            provider=AIProvider.JEV,
            model=model,
            task=AITask.TRIAGE,
            prompt_version=TRIAGE_PROMPT_VERSION,
            status=status,
            error=error,
            created_at=self._clock(),
            requested_by=clean_token(requested_by) or "unknown",
        )

    def _persist(self, assessment: AIAssessment) -> bool:
        try:
            store.save_assessment(
                self.write_client, assessment, requested_model=self._settings.jev_model
            )
        except Exception as exc:  # noqa: BLE001 - persistence failure must not hide the result
            _log.error(
                "ai_assessment_persist_failed",
                alert_id=assessment.alert_id,
                error_class=type(exc).__name__,
            )
            return False
        return True

    def _count_today(self, day_start: datetime) -> int:
        return store.count_attempts_since(self.read_client, AIProvider.JEV, day_start)

    # ── triage ──────────────────────────────────────────────────────
    def request_triage(self, alert_id: str, requested_by: str = "system:cli") -> AIAssessment:
        """Triage one alert (reused, refused or freshly assessed; see the module docstring)."""
        ctx = self.load_context(alert_id)

        def refuse(status: AIStatus, error: str) -> AIAssessment:
            return self._refusal(ctx, status=status, error=error, requested_by=requested_by)

        with _alert_locks.get(alert_id):
            try:
                cached = store.find_reusable(
                    self.read_client,
                    alert_id=alert_id,
                    provider=AIProvider.JEV,
                    task=AITask.TRIAGE,
                    prompt_version=TRIAGE_PROMPT_VERSION,
                    context_input_hash=ctx.input_hash,
                    model=self._settings.jev_model,
                )
            except Exception as exc:  # noqa: BLE001 - cannot check for reuse: fail closed
                return refuse(AIStatus.ERROR, f"budget_check_unavailable ({type(exc).__name__})")
            if cached is not None:
                _log.info("ai_triage_reused", alert_id=alert_id, assessment_id=cached.assessment_id)
                return cached
            usable, reason = self.jev.availability()
            if not usable:
                return refuse(AIStatus.DISABLED, reason)
            guard = shared_guard(AIProvider.JEV, self._settings.jev_daily_cap)
            try:
                reservation = guard.try_reserve(self._count_today)
            except BudgetExceeded as exc:
                return refuse(AIStatus.BUDGET_EXCEEDED, str(exc))
            except BudgetUnavailable as exc:
                return refuse(AIStatus.ERROR, str(exc))
            persisted = False
            try:
                assessment = self.jev.assess(ctx, requested_by)
                persisted = self._persist(assessment)
            finally:
                reservation.finish(persisted=persisted)
            return assessment

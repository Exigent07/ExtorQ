"""Lazy adapters to other teams' modules (correlation and AI).

The API must keep working when these modules are absent or disabled: every adapter
imports lazily and converts absence/misconfiguration into a 503 with a clear message (or,
for read-only AI data, into a documented fallback). Interfaces (PLAN section 5):

* ``correlation.store.load_latest_context(read_client, alert_id)``
* ``correlation.builder.ContextBuilder(read_client).build(alert_id)``
* ``correlation.store.save_context(write_client, ctx)``
* ``ai.store.list_assessments(read_client, alert_id)``: Jev triage assessments
* ``ai.settings.get_ai_settings()`` / ``ai.settings.resolve_key("JEV_API_KEY", ...)``: the
  Jev flag and credential *state* for GET /health (never the key)

The API never calls an AI provider: Jev triage runs in the ai-worker (schema 2.0 removed
the on-demand summary path).
"""

from __future__ import annotations

import os
from typing import Any, Protocol

from extorq.api.errors import ApiError, ServiceUnavailable
from extorq.api.logs import get_logger
from extorq.api.repository import Repository
from extorq.contracts import AIAssessment, AIProvider, AITask, InvestigationContext

log = get_logger("extorq.api.integrations")

#: ``{(provider, task): {"configured": bool | None, "enabled": bool | None}}``.
AIConfiguration = dict[tuple[str, str], dict[str, bool | None]]

#: The one provider/task pair the API reports configuration for (schema 2.0: Jev only).
JEV_TRIAGE: tuple[str, str] = (AIProvider.JEV.value, AITask.TRIAGE.value)


class Integrations(Protocol):
    def load_context(self, repo: Repository, alert_id: str) -> InvestigationContext | None: ...
    def build_context(self, repo: Repository, alert_id: str) -> InvestigationContext: ...
    def save_context(self, repo: Repository, context: InvestigationContext) -> None: ...
    def list_assessments(self, repo: Repository, alert_id: str) -> list[AIAssessment] | None: ...
    def ai_configuration(self) -> tuple[AIConfiguration, str]: ...


def _coerce_context(value: Any) -> InvestigationContext | None:
    if value is None:
        return None
    if isinstance(value, InvestigationContext):
        return value
    if isinstance(value, dict):
        return InvestigationContext.model_validate(value)
    if isinstance(value, str | bytes):
        return InvestigationContext.model_validate_json(value)
    raise TypeError(f"unexpected context type {type(value).__name__}")


def _coerce_assessment(value: Any) -> AIAssessment:
    if isinstance(value, AIAssessment):
        return value
    if isinstance(value, dict):
        return AIAssessment.model_validate(value)
    raise TypeError(f"unexpected assessment type {type(value).__name__}")


def _env_present(name: str) -> bool:
    """True when the variable or its ``_FILE`` path is set. The value is never read."""
    if os.environ.get(name, "").strip():
        return True
    path = os.environ.get(f"{name}_FILE", "").strip()
    return bool(path) and os.path.isfile(path)


def _env_flag(name: str) -> bool | None:
    """A boolean feature flag from the environment; ``None`` when it is not set at all."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


class PlatformIntegrations:
    """Production adapters (lazy imports of extorq.correlation / extorq.ai)."""

    # -- correlation --

    def load_context(self, repo: Repository, alert_id: str) -> InvestigationContext | None:
        """The newest stored context, or ``None`` when there is none or it cannot be used.

        A stored context that no longer validates (for example one written under contract
        schema 1.x before the 2.0 reset) is treated as absent so the route builds a current
        one; it is logged, never shown. A context whose body does not match its recorded
        input hash is an integrity failure and is reported as an error, never rebuilt over.
        """
        try:
            from extorq.correlation.store import (
                ContextIntegrityError,
                ContextStoreError,
                load_latest_context,
            )
        except ImportError as exc:
            raise ServiceUnavailable(
                "correlation store (extorq.correlation.store) is not installed"
            ) from exc
        try:
            stored = load_latest_context(repo.read_client(), alert_id)
        except ContextIntegrityError as exc:
            log.error("stored_context_integrity_failed", alert_id=alert_id)
            raise ApiError("stored investigation context failed its integrity check") from exc
        except ContextStoreError:
            log.warning("stored_context_unreadable_rebuilding", alert_id=alert_id)
            return None
        return _coerce_context(stored)

    def build_context(self, repo: Repository, alert_id: str) -> InvestigationContext:
        try:
            from extorq.correlation.builder import ContextBuilder
        except ImportError as exc:
            raise ServiceUnavailable(
                "context builder (extorq.correlation.builder) is not installed"
            ) from exc
        context = _coerce_context(ContextBuilder(repo.read_client()).build(alert_id))
        if context is None:
            raise ServiceUnavailable("context builder returned no context")
        return context

    def save_context(self, repo: Repository, context: InvestigationContext) -> None:
        try:
            from extorq.correlation.store import save_context
        except ImportError as exc:
            raise ServiceUnavailable(
                "correlation store (extorq.correlation.store) is not installed"
            ) from exc
        save_context(repo.write_client(), context)

    # -- AI (read-only: Jev assessments and configuration state) --

    def list_assessments(self, repo: Repository, alert_id: str) -> list[AIAssessment] | None:
        """Assessments via the AI module's store, or ``None`` when that module is absent (the
        route then reads ``ai_assessments`` directly)."""
        try:
            from extorq.ai.store import list_assessments
        except ImportError:
            return None
        return [_coerce_assessment(a) for a in list_assessments(repo.read_client(), alert_id)]

    def ai_configuration(self) -> tuple[AIConfiguration, str]:
        """Jev's enabled flag and credential state *as seen by the API process*.

        Jev triage runs in the ai-worker container, which may be configured differently;
        recent ``ai_assessments`` statuses are the ground truth for it, and GET /health
        reports both. Key values are never returned or logged (the AI module's resolver
        exposes the state only), and the dotenv fallback is disabled so the API never loads
        ``.env``.
        """
        try:
            from extorq.ai.settings import KeyState, get_ai_settings, resolve_key
        except ImportError:
            return {
                JEV_TRIAGE: {
                    "configured": _env_present("JEV_API_KEY"),
                    "enabled": _env_flag("EXTORQ_JEV_ENABLED"),
                },
            }, "API process environment (credential presence only; ai-worker may differ)"
        try:
            settings = get_ai_settings()
            jev = resolve_key("JEV_API_KEY", use_dotenv=False)
            configuration: AIConfiguration = {
                JEV_TRIAGE: {
                    "configured": jev.state is KeyState.CONFIGURED,
                    "enabled": bool(settings.jev_enabled),
                },
            }
        except Exception as exc:  # noqa: BLE001 - foreign module; report unknown, never fail health
            log.warning("ai_settings_unavailable", error_type=type(exc).__name__)
            return {}, "unavailable (AI settings could not be read)"
        return configuration, "extorq.ai.settings as seen by the API process (ai-worker may differ)"

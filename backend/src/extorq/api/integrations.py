"""Lazy adapters to other teams' modules (correlation: C2, AI: E).

The API must keep working when these modules are absent or disabled: every adapter
imports lazily and converts absence/misconfiguration into a 503 with a clear message.
Interfaces (PLAN section 5):

* ``correlation.store.load_latest_context(read_client, alert_id)``
* ``correlation.builder.ContextBuilder(read_client).build(alert_id)``
* ``correlation.store.save_context(write_client, ctx)``
* ``ai.store.list_assessments(read_client, alert_id)``
* ``ai.service.AIService.request_summary(alert_id, requested_by)``
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, Protocol

from extorq.api.errors import BadRequest, NotFound, ServiceUnavailable
from extorq.api.logs import get_logger
from extorq.api.repository import Repository
from extorq.contracts import AIAssessment, InvestigationContext

log = get_logger("extorq.api.integrations")

AIConfiguration = dict[tuple[str, str], dict[str, bool | None]]


class Integrations(Protocol):
    def load_context(self, repo: Repository, alert_id: str) -> InvestigationContext | None: ...
    def build_context(self, repo: Repository, alert_id: str) -> InvestigationContext: ...
    def save_context(self, repo: Repository, context: InvestigationContext) -> None: ...
    def list_assessments(self, repo: Repository, alert_id: str) -> list[AIAssessment] | None: ...
    def request_summary(
        self, repo: Repository, alert_id: str, requested_by: str
    ) -> AIAssessment: ...
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
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _default_ai_service_factory(repo: Repository) -> Any:
    """E's AIService using the API's own storage identities (api_ro / api_writer)."""
    try:
        from extorq.ai.service import AIService
    except ImportError as exc:
        raise ServiceUnavailable("AI summary service (extorq.ai.service) is not installed") from exc

    def client_for(role: str) -> Any:
        return repo.write_client() if role == "api_writer" else repo.read_client()

    try:
        return AIService(client_provider=client_for)
    except Exception as exc:
        log.warning("ai_service_unavailable", error_type=type(exc).__name__)
        raise ServiceUnavailable("AI summary service is not configured") from exc


class PlatformIntegrations:
    """Production adapters (lazy imports of extorq.correlation / extorq.ai)."""

    def __init__(self, ai_service_factory: Callable[[Repository], Any] | None = None) -> None:
        self._ai_service_factory = ai_service_factory or _default_ai_service_factory
        self._ai_service: Any = None

    # -- correlation (C2) --

    def load_context(self, repo: Repository, alert_id: str) -> InvestigationContext | None:
        try:
            from extorq.correlation.store import load_latest_context
        except ImportError as exc:
            raise ServiceUnavailable(
                "correlation store (extorq.correlation.store) is not installed"
            ) from exc
        return _coerce_context(load_latest_context(repo.read_client(), alert_id))

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

    # -- AI (E) --

    def list_assessments(self, repo: Repository, alert_id: str) -> list[AIAssessment] | None:
        """Assessments via E's store, or ``None`` when the module is absent (API falls back)."""
        try:
            from extorq.ai.store import list_assessments
        except ImportError:
            return None
        return [_coerce_assessment(a) for a in list_assessments(repo.read_client(), alert_id)]

    def request_summary(self, repo: Repository, alert_id: str, requested_by: str) -> AIAssessment:
        """Delegate to E's AIService and map its precondition errors to HTTP errors.

        Provider failures and refusals (disabled, budget/cooldown) come back as an
        assessment status; only precondition failures raise.
        """
        try:
            from extorq.ai import service as ai_service
        except ImportError as exc:
            raise ServiceUnavailable(
                "AI summary service (extorq.ai.service) is not installed"
            ) from exc
        if self._ai_service is None:
            self._ai_service = self._ai_service_factory(repo)
        try:
            result = self._ai_service.request_summary(alert_id, requested_by)
        except ai_service.InvalidAlertId as exc:
            raise BadRequest("invalid alert id") from exc
        except ai_service.ContextNotFound as exc:
            raise NotFound(
                "no investigation context exists or could be built for this alert"
            ) from exc
        except ai_service.ContextUnavailable as exc:
            raise ServiceUnavailable("investigation context store is unavailable") from exc
        return _coerce_assessment(result)

    def ai_configuration(self) -> tuple[AIConfiguration, str]:
        """Enabled flags and credential state *as seen by the API process*.

        The ai-worker (Jev triage) runs in another container and may be configured
        differently; recent ``ai_assessments`` statuses are the ground truth for it. Key
        values are never returned or logged (E's resolver exposes the state only), and the
        dotenv fallback is disabled so the API never loads ``.env``.
        """
        try:
            from extorq.ai.settings import KeyState, get_ai_settings, resolve_key
        except ImportError:
            return {
                ("typesafe-jev", "triage"): {
                    "configured": _env_present("JEV_API_KEY"),
                    "enabled": _env_flag("EXTORQ_JEV_ENABLED"),
                },
                ("google-gemini", "summary"): {
                    "configured": _env_present("GEMINI_API_KEY"),
                    "enabled": _env_flag("EXTORQ_GEMINI_ENABLED"),
                },
            }, "API process environment (credential presence only; ai-worker may differ)"
        try:
            settings = get_ai_settings()
            jev = resolve_key("JEV_API_KEY", use_dotenv=False)
            gemini = resolve_key("GEMINI_API_KEY", use_dotenv=False)
        except Exception as exc:  # noqa: BLE001 - foreign module; report unknown, never fail health
            log.warning("ai_settings_unavailable", error_type=type(exc).__name__)
            return {}, "unavailable (AI settings could not be read)"
        return {
            ("typesafe-jev", "triage"): {
                "configured": jev.state is KeyState.CONFIGURED,
                "enabled": settings.jev_enabled,
            },
            ("google-gemini", "summary"): {
                "configured": gemini.state is KeyState.CONFIGURED,
                "enabled": settings.gemini_enabled,
            },
        }, "extorq.ai.settings as seen by the API process (ai-worker may differ)"

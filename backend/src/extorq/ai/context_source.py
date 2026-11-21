"""Loading InvestigationContexts for AI (via C2's correlation store when available).

Primary path: ``extorq.correlation.store.load_latest_context(read_client, alert_id)``
and, for on-demand building, ``extorq.correlation.builder.ContextBuilder`` +
``extorq.correlation.store.save_context`` (owned by agent C2).

Fallback while the correlation package is not deployed: read the newest row of
``extorq.investigation_contexts`` for the alert and validate its ``body``
(canonical JSON of the InvestigationContext, per the 0001 schema conventions)
against the contract. Rows that do not validate are reported, never guessed.
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from extorq.ai._compat import get_logger, optional_attr
from extorq.contracts.context import InvestigationContext

_log = get_logger("extorq.ai.context")


class ContextLoadError(RuntimeError):
    """The context exists but could not be read or validated."""


def _fallback_load_latest(read_client: Any, alert_id: str) -> InvestigationContext | None:
    result = read_client.query(
        "SELECT body FROM extorq.investigation_contexts "
        "WHERE alert_id = {alert_id:String} "
        "ORDER BY created_at DESC, context_id DESC LIMIT 1",
        parameters={"alert_id": alert_id},
    )
    rows = result.result_rows
    if not rows:
        return None
    try:
        return InvestigationContext.model_validate_json(rows[0][0])
    except ValidationError as exc:
        raise ContextLoadError(
            f"stored context failed validation ({exc.error_count()} error(s))"
        ) from None


def load_latest_context(read_client: Any, alert_id: str) -> InvestigationContext | None:
    """Newest stored context for ``alert_id`` or ``None`` when none exists."""
    loader = optional_attr("extorq.correlation.store", "load_latest_context")
    if loader is None:
        return _fallback_load_latest(read_client, alert_id)
    store_error = optional_attr("extorq.correlation.store", "ContextStoreError")
    try:
        ctx = loader(read_client, alert_id)
    except Exception as exc:
        # A stored context that fails validation or its input-hash check is a property of
        # that one context: report it as ContextLoadError so callers can skip it (the
        # ai-worker must never be blocked by one bad row). Storage/connectivity errors
        # propagate unchanged.
        if isinstance(store_error, type) and isinstance(exc, store_error):
            raise ContextLoadError(
                f"correlation store rejected the stored context ({type(exc).__name__})"
            ) from None
        raise
    if ctx is None or isinstance(ctx, InvestigationContext):
        return ctx
    try:  # tolerate a loader that returns a dict / JSON text
        if isinstance(ctx, str | bytes):
            return InvestigationContext.model_validate_json(ctx)
        return InvestigationContext.model_validate(ctx)
    except ValidationError as exc:
        raise ContextLoadError(
            f"correlation store returned an invalid context ({exc.error_count()} error(s))"
        ) from None


def build_and_save_context(
    read_client: Any, write_client: Any, alert_id: str
) -> InvestigationContext | None:
    """Ask the correlation builder for a context and persist it (None if unavailable)."""
    builder_cls = optional_attr("extorq.correlation.builder", "ContextBuilder")
    save = optional_attr("extorq.correlation.store", "save_context")
    if builder_cls is None or save is None:
        _log.info("context_builder_unavailable", alert_id=alert_id)
        return None
    ctx = builder_cls(read_client).build(alert_id)
    if ctx is None:
        return None
    if not isinstance(ctx, InvestigationContext):
        ctx = InvestigationContext.model_validate(ctx)
    save(write_client, ctx)
    return ctx

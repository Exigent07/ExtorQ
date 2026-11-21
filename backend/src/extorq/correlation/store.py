"""Persistence of InvestigationContexts (tables ``investigation_contexts`` and
``context_relationships``, migration 0001).

* ``save_context(write_client, ctx)`` is insert-only, so both the detector
  (``extorq_detect``) and the API (``extorq_api_writer``, no SELECT) can use it.
  Relationship rows are written before the context row: a reader that sees the
  context also finds its relationships. Re-saving identical content produces the
  same ``context_id`` and collapses in the ReplacingMergeTree.
* ``load_latest_context(read_client, alert_id)`` returns the newest context
  (``created_at``, then ``context_id``) or ``None``. The stored ``body`` is validated
  against the contract and its ``input_hash`` is recomputed from the stored JSON; a
  mismatch raises :class:`ContextIntegrityError` instead of serving altered evidence.

Both accept a raw clickhouse-connect client or a ``DbClient``.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from extorq.contracts.context import InvestigationContext, RelationshipType
from extorq.contracts.identity import canonical_json
from extorq.correlation.builder import compute_input_hash
from extorq.detection.clients import chunked, wrap

LATEST_CONTEXT_SQL = (
    "SELECT body FROM investigation_contexts WHERE alert_id = {alert_id:String} "
    "ORDER BY created_at DESC, context_id DESC LIMIT 1"
)


class ContextStoreError(RuntimeError):
    """A stored context could not be read or validated."""


class ContextIntegrityError(ContextStoreError):
    """The stored body does not match its recorded input hash."""


def context_to_row(ctx: InvestigationContext) -> dict[str, Any]:
    counts = {t: 0 for t in RelationshipType}
    for rel in ctx.relationships:
        counts[rel.relationship_type] += 1
    return {
        "context_id": ctx.context_id,
        "alert_id": ctx.alert_id,
        "builder_version": ctx.builder_version,
        "input_hash": ctx.input_hash,
        "created_at": ctx.created_at,
        "window_start": ctx.window_start,
        "window_end": ctx.window_end,
        "evidence_count": len(ctx.evidence),
        "related_count": len(ctx.relationships),
        "direct_count": counts[RelationshipType.DIRECT],
        "candidate_count": counts[RelationshipType.CANDIDATE],
        "unestablished_count": counts[RelationshipType.UNESTABLISHED],
        "body": canonical_json(ctx.model_dump(mode="json")),
    }


def relationship_rows(ctx: InvestigationContext) -> list[dict[str, Any]]:
    return [
        {
            "context_id": ctx.context_id,
            "alert_id": ctx.alert_id,
            "event_id": rel.event_id,
            "relationship_type": rel.relationship_type.value,
            "bases": [b.value for b in rel.bases],
            "strength": rel.strength,
            "time_delta_seconds": float(rel.time_delta_seconds),
            "explanation": rel.explanation,
            "created_at": ctx.created_at,
        }
        for rel in ctx.relationships
    ]


def save_context(write_client: Any, ctx: InvestigationContext) -> None:
    """Persist ``ctx`` (relationships first, then the context row)."""
    if compute_input_hash(json.loads(canonical_json(ctx.model_dump(mode="json")))) != (
        ctx.input_hash
    ):
        raise ContextIntegrityError("refusing to save a context whose input_hash does not match")
    db = wrap(write_client)
    for batch in chunked(relationship_rows(ctx), 1000):
        db.insert_rows("context_relationships", batch)
    db.insert_rows("investigation_contexts", [context_to_row(ctx)])


def load_latest_context(read_client: Any, alert_id: str) -> InvestigationContext | None:
    """Newest stored context for ``alert_id`` (validated, hash-checked) or ``None``."""
    db = wrap(read_client)
    rows = db.select(LATEST_CONTEXT_SQL, {"alert_id": alert_id}).rows
    if not rows:
        return None
    body = rows[0][0]
    try:
        data = json.loads(body)
        ctx = InvestigationContext.model_validate(data)
    except (ValueError, ValidationError) as exc:
        count = exc.error_count() if isinstance(exc, ValidationError) else 1
        raise ContextStoreError(f"stored context failed validation ({count} error(s))") from None
    if not isinstance(data, dict) or compute_input_hash(data) != ctx.input_hash:
        raise ContextIntegrityError(
            f"stored context {ctx.context_id} does not match its input_hash"
        )
    return ctx


__all__ = [
    "ContextIntegrityError",
    "ContextStoreError",
    "context_to_row",
    "load_latest_context",
    "relationship_rows",
    "save_context",
]

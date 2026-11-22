"""Wire compatibility for producers that still speak contract schema 1.x.

Contract schema 2.0 removed the simulation category and the Gemini summary models
(see docs/team/PLAN.md section 12). Collectors keep a durable outbox, so a collector
that was started before the 2.0 rollout can hold thousands of already-collected records
stamped ``schema_version`` 1.0 or 1.1, and a still-running pre-2.0 process stamps its
batch envelope the same way. Rejecting those would either stall a collector forever
(the SDK keeps envelope-level 4xx responses buffered) or quarantine evidence whose
source cursor has already advanced and which can therefore never be re-collected.

This module upgrades such documents *before* strict validation:

* only the ``schema_version`` label changes (1.0/1.1 -> 2.0);
* fields that 2.0 retired are dropped (``simulation`` on events);
* nothing else is touched, defaulted or guessed, and the upgraded document is then
  validated exactly like a native 2.0 document (``extra="forbid"``, catalog checks,
  authorization, redaction), so this is not a validation bypass;
* anything unknown (an unrecognised version, a retired record kind such as
  ``simulation_run``) is returned unchanged and is rejected or quarantined by the
  normal path with its usual reason.

The functions are pure and total: they never raise on malformed input.
"""

from __future__ import annotations

from typing import Any

from extorq.contracts.common import SCHEMA_VERSION

#: Wire versions that can be upgraded losslessly to the current schema.
LEGACY_WIRE_VERSIONS = frozenset({"1.0", "1.1"})

#: Event fields that no longer exist in schema 2.0 (the simulation category).
_RETIRED_EVENT_FIELDS = ("simulation",)


def upgrade_batch_document(document: Any) -> tuple[Any, bool]:
    """Upgrade a batch envelope's version label; returns ``(document, upgraded)``."""
    if isinstance(document, dict) and document.get("schema_version") in LEGACY_WIRE_VERSIONS:
        return {**document, "schema_version": SCHEMA_VERSION}, True
    return document, False


def upgrade_record(raw: Any) -> tuple[Any, bool]:
    """Upgrade one raw ``{"kind": ..., "data": {...}}`` record; ``(record, upgraded)``."""
    if not isinstance(raw, dict):
        return raw, False
    data = raw.get("data")
    if not isinstance(data, dict) or data.get("schema_version") not in LEGACY_WIRE_VERSIONS:
        return raw, False
    upgraded = {**data, "schema_version": SCHEMA_VERSION}
    if raw.get("kind") == "event":
        for name in _RETIRED_EVENT_FIELDS:
            upgraded.pop(name, None)
    return {**raw, "data": upgraded}, True

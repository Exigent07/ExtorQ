"""Server-owned event keys and replay fingerprints."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from pydantic import ValidationError

from extorq.contracts.catalog import SourceType
from extorq.contracts.common import SCHEMA_VERSION
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import canonical_json, sha256_hex, stable_id


@dataclass(frozen=True)
class EventIdentity:
    key: str
    fingerprint: str


@dataclass(frozen=True)
class EventReceipt:
    identity: EventIdentity
    stored_id: str
    expires_at: float


def historical_receipt(
    producer_id: str, stored_id: str, data: dict[str, Any], *, horizon: timedelta
) -> EventReceipt | None:
    """Read trusted stored payloads using their original ID and producer provenance."""
    if not producer_id or data.get("event_id") != stored_id:
        return None
    event = stored_event(data)
    if event is None:
        return None
    return EventReceipt(
        identify_event(producer_id, event), stored_id, (event.event_time + horizon).timestamp()
    )


def stored_event(data: dict[str, Any]) -> SecurityEvent | None:
    """Read an event from trusted storage across compatible wire-schema versions."""
    if data.get("schema_version") in {"1.0", "1.1"}:
        # These fields were retired in 2.0. Keep historical controlled-run evidence
        # addressable by its old ID without comparing it with current observations.
        if any(data.get(field) is not None for field in ("simulation_run_id", "scenario_id")):
            return None
        data = {**data, "schema_version": SCHEMA_VERSION}
        data.pop("simulation_run_id", None)
        data.pop("scenario_id", None)
    try:
        return SecurityEvent.model_validate(data)
    except ValidationError:
        return None


def _native_identity(event: SecurityEvent) -> list[Any] | None:
    native = event.source.source_native_id
    # Producers may truncate source references at 256 characters. A clipped
    # path or cursor is insufficient to identify an observation by itself.
    if not native or len(native) >= 256 or "[REDACTED" in native.upper():
        return None
    source = event.source.source_type
    if source == SourceType.K8S_AUDIT:
        stage = event.kubernetes.stage if event.kubernetes else None
        return [native, stage] if stage else None
    if source == SourceType.LINUX_AUDITD:
        # One audit group can yield a syscall observation and control records.
        return [
            native,
            event.attributes.get("audit_node"),
            event.attributes.get("audit_record_type"),
        ]
    return [native]


def identify_event(producer_id: str, event: SecurityEvent) -> EventIdentity:
    """Derive a storage ID without the producer's submitted event ID.

    Event time and the normalized evidence participate in replay comparison.
    The time of collection, reporting software versions and redaction counters
    may vary across deliveries without changing the observation.
    """
    content = event.model_dump(
        mode="json",
        exclude={
            "schema_version": True,
            "event_id": True,
            "observed_time": True,
            "source": {"collector_id", "collector_version", "collection_method"},
            "provenance": {"parser", "parser_version", "redaction_count"},
        },
    )
    fingerprint = sha256_hex(canonical_json(content))
    native = _native_identity(event)
    key = stable_id(
        "accepted-event.v2",
        canonical_json(
            [
                producer_id,
                event.asset_id,
                event.source.source_type.value,
                event.event_type,
                ["native", native] if native is not None else ["content", fingerprint],
            ]
        ),
    )
    return EventIdentity(key, fingerprint)

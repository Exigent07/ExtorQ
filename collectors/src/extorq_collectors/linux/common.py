"""Shared building blocks for the Linux (agentless SSH) collector.

Every parser in this package turns an untrusted observation from the lab VM into
contract records through :func:`build_event`, so the same rules apply everywhere:

* identity comes from :func:`extorq.contracts.identity.event_id` over a
  source-native key (journald ``__CURSOR``, audit ``node:serial:timestamp``,
  snapshot-diff keys), never over collection time;
* the event type is checked against the catalog (category and allowed source)
  before it leaves the collector, so the gateway never has to quarantine it;
* free text is redacted (:func:`extorq.common.redaction.redact_text`) and then
  sanitised/truncated (:func:`sanitize_untrusted`); the number of redactions is
  kept in ``provenance.redaction_count`` and ``provenance.raw_sha256`` hashes the
  original record;
* ``None`` attributes are dropped (absent means unknown), attribute values are
  bounded to the contract limits;
* the ``extorq-sim-<run_id>`` marker sets ``simulation`` (telemetry stays
  genuine) and the collector's own activity is labelled ``extorq.self=true``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts import (
    EVENT_CATALOG,
    Actor,
    AssetType,
    CollectionMethod,
    HttpInfo,
    Network,
    Outcome,
    ProcessInfo,
    Provenance,
    Resource,
    SecurityEvent,
    ServiceRef,
    Severity,
    SimulationTag,
    SourceInfo,
    SourceType,
)
from extorq.contracts.identity import event_id, sha256_hex
from extorq_collectors import __version__ as _package_version

COLLECTOR_TYPE = "linux_ssh"
COLLECTOR_VERSION = _package_version
#: Version of the parsing/normalisation logic (bump when output semantics change).
PARSER_VERSION = "1.0.0"
ASSET_TYPE = AssetType.LINUX_HOST
DEFAULT_ASSET_ID = "linux:lab-vm-01"
DEFAULT_COLLECTOR_ID = "linux-ssh-lab-vm-01"
SELF_USER = "extorq-collector"
SELF_LABEL = "extorq.self"

MAX_MESSAGE = 2048
MAX_RAW = 4096
MAX_ATTR_KEYS = 64
MAX_ATTR_STR = 2048
MAX_ATTR_LIST = 64
MAX_ATTR_LIST_ITEM = 512
MAX_SHORT = 256
MAX_MEDIUM = 2048

_SIM_MARKER = re.compile(r"extorq-sim-([a-z0-9]{8,32})(?![a-z0-9])")
_ATTR_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

#: syslog PRIORITY -> severity hint (source-reported severity, not a verdict).
_PRIORITY_SEVERITY = {
    0: Severity.CRITICAL,
    1: Severity.CRITICAL,
    2: Severity.CRITICAL,
    3: Severity.HIGH,
    4: Severity.MEDIUM,
    5: Severity.LOW,
    6: Severity.INFO,
    7: Severity.INFO,
}


@dataclass(frozen=True, slots=True)
class ParseContext:
    """Identity of the running collector plus facts needed for labelling."""

    asset_id: str = DEFAULT_ASSET_ID
    collector_id: str = DEFAULT_COLLECTOR_ID
    collector_version: str = COLLECTOR_VERSION
    self_user: str = SELF_USER
    #: UID of the collector account on the VM (learned from inventory; None = unknown).
    self_uid: int | None = None
    #: Time the collector read the records (UTC).
    observed_time: datetime | None = None
    #: Service the parsed records belong to (set by the owning service adapter only).
    service: ServiceRef | None = None


def utc_now_ms() -> datetime:
    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def to_ms(value: datetime) -> datetime:
    """Aware UTC datetime truncated to millisecond precision (storage precision)."""
    value = value.astimezone(UTC)
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


def from_epoch_us(value: int) -> datetime:
    return to_ms(datetime.fromtimestamp(value / 1_000_000, tz=UTC))


def from_epoch_s(value: float) -> datetime:
    return to_ms(datetime.fromtimestamp(value, tz=UTC))


def parse_rfc3339(value: str) -> datetime | None:
    """Parse an RFC 3339 timestamp; returns None for naive or malformed values."""
    if not isinstance(value, str) or len(value) > 64:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return to_ms(parsed)


def clean(value: object, limit: int = MAX_SHORT) -> str | None:
    """Sanitise an untrusted scalar into bounded display-safe text (None stays None)."""
    if value is None:
        return None
    text = sanitize_untrusted(str(value), limit)
    return text or None


def redact_clean(value: str | None, limit: int) -> tuple[str | None, int]:
    """Redact secrets, then sanitise/truncate. Returns (text, redaction_count)."""
    if value is None:
        return None, 0
    redacted, count = redact_text(value)
    return (sanitize_untrusted(redacted, limit) or None), count


def severity_from_priority(priority: int | None) -> Severity | None:
    if priority is None:
        return None
    return _PRIORITY_SEVERITY.get(priority)


def find_simulation(texts: Iterable[str | None]) -> SimulationTag | None:
    """Return the simulation tag if any text carries ``extorq-sim-<run_id>``."""
    for text in texts:
        if not text:
            continue
        match = _SIM_MARKER.search(text)
        if match:
            return SimulationTag(run_id=match.group(1))
    return None


def bound_attributes(attributes: Mapping[str, Any]) -> dict[str, Any]:
    """Drop unknown (None) values and bound keys/values to the contract limits."""
    bounded: dict[str, Any] = {}
    for key, value in attributes.items():
        if value is None or not _ATTR_KEY.match(key):
            continue
        if len(bounded) >= MAX_ATTR_KEYS:
            break
        if isinstance(value, bool | int | float):
            bounded[key] = value
        elif isinstance(value, str):
            bounded[key] = sanitize_untrusted(value, MAX_ATTR_STR)
        elif isinstance(value, list | tuple):
            items: list[Any] = []
            for item in list(value)[:MAX_ATTR_LIST]:
                if isinstance(item, bool | int | float):
                    items.append(item)
                elif item is not None:
                    items.append(sanitize_untrusted(str(item), MAX_ATTR_LIST_ITEM))
            bounded[key] = items
        else:
            bounded[key] = sanitize_untrusted(str(value), MAX_ATTR_STR)
    return bounded


def build_event(
    ctx: ParseContext,
    *,
    event_type: str,
    source_type: SourceType,
    native_key: str,
    event_time: datetime,
    parser: str,
    collection_method: CollectionMethod = CollectionMethod.SSH_PULL,
    source_native_id: str | None = None,
    action: str | None = None,
    outcome: Outcome = Outcome.UNKNOWN,
    severity_hint: Severity | None = None,
    actor: Actor | None = None,
    resource: Resource | None = None,
    network: Network | None = None,
    process: ProcessInfo | None = None,
    http: HttpInfo | None = None,
    message: str | None = None,
    raw: str | None = None,
    attributes: Mapping[str, Any] | None = None,
    labels: Mapping[str, str] | None = None,
    sim_texts: Iterable[str | None] = (),
    is_self: bool = False,
    extra_redactions: int = 0,
    attach_service: bool = True,
) -> SecurityEvent:
    """Build a validated :class:`SecurityEvent` (raises ValueError on contract violations).

    ``ctx.service`` is attached unless ``attach_service`` is False (records whose claimed
    origin is contradicted by trusted fields never belong to the claimed service).
    """
    spec = EVENT_CATALOG.get(event_type)
    if spec is None:
        raise ValueError(f"event type {event_type!r} is not in the catalog")
    if source_type not in spec.sources:
        raise ValueError(f"{source_type.value} may not emit {event_type}")
    safe_message, msg_redactions = redact_clean(message, MAX_MESSAGE)
    safe_raw, raw_redactions = redact_clean(raw, MAX_RAW)
    truncated = bool(raw and len(raw) > MAX_RAW) or bool(message and len(message) > MAX_MESSAGE)
    event_labels = dict(labels or {})
    if is_self:
        event_labels[SELF_LABEL] = "true"
    return SecurityEvent(
        event_id=event_id(source_type.value, ctx.asset_id, native_key),
        event_type=event_type,
        category=spec.category,
        asset_id=ctx.asset_id,
        asset_type=ASSET_TYPE,
        source=SourceInfo(
            source_type=source_type,
            collector_id=ctx.collector_id,
            collector_version=ctx.collector_version,
            collection_method=collection_method,
            source_native_id=clean(source_native_id, MAX_SHORT) if source_native_id else None,
        ),
        event_time=to_ms(event_time),
        observed_time=to_ms(ctx.observed_time) if ctx.observed_time else None,
        action=clean(action),
        outcome=outcome,
        severity_hint=severity_hint,
        actor=actor,
        resource=resource,
        network=network,
        process=process,
        http=http,
        service=ctx.service if attach_service else None,
        message=safe_message,
        attributes=bound_attributes(attributes or {}),
        labels=event_labels,
        raw=safe_raw,
        provenance=Provenance(
            parser=parser,
            parser_version=PARSER_VERSION,
            raw_sha256=sha256_hex(raw) if raw else None,
            truncated=truncated,
            redaction_count=msg_redactions + raw_redactions + extra_redactions,
        ),
        simulation=find_simulation([*sim_texts, message, raw]),
    )

"""Shared building blocks for the macOS collector sources.

Everything that turns a parsed observation into a contract record lives here so
that every source applies the same rules:

* event identity comes from :func:`extorq.contracts.identity.event_id` over a
  source-native key (never over collection time alone);
* every event type is checked against the catalog (category and allowed source)
  before it leaves the collector, so the gateway never has to quarantine it;
* free text is redacted (:func:`extorq.common.redaction.redact_text`) and then
  sanitised/truncated (:func:`sanitize_untrusted`); the redaction count is kept
  in ``provenance.redaction_count``;
* attribute maps are bounded to the contract limits before validation;
* the ``extorq-sim-<run_id>`` marker sets ``simulation`` (telemetry stays genuine).
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
from extorq.contracts.identity import event_id, sha256_hex, stable_id
from extorq_collectors import __version__ as _package_version

COLLECTOR_TYPE = "macos"
COLLECTOR_VERSION = _package_version
ASSET_TYPE = AssetType.MACOS_HOST
#: Version of the parsing/normalisation logic (bump when output semantics change).
PARSER_VERSION = "1.0.0"

MAX_ATTR_KEYS = 64
MAX_ATTR_STR = 2048
MAX_ATTR_LIST = 64
MAX_ATTR_LIST_ITEM = 512
MAX_MESSAGE = 2048
MAX_RAW = 4096

_SIM_MARKER = re.compile(r"extorq-sim-([a-z0-9]{8,32})(?![a-z0-9])")
_ATTR_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


@dataclass(frozen=True, slots=True)
class SourceContext:
    """Identity of the running collector instance (from the SDK context)."""

    collector_id: str
    asset_id: str
    collector_version: str = COLLECTOR_VERSION


def utc_now_ms() -> datetime:
    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def to_ms(value: datetime) -> datetime:
    """Aware UTC datetime truncated to millisecond precision (storage precision)."""
    value = value.astimezone(UTC)
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


def clean_text(text: str | None, limit: int) -> tuple[str | None, int]:
    """Redact secrets, strip control characters and truncate. Returns (text, redactions)."""
    if text is None:
        return None, 0
    redacted, count = redact_text(text)
    cleaned = sanitize_untrusted(redacted, limit)
    return (cleaned or None), count


def simulation_tag(*texts: str | None) -> SimulationTag | None:
    """``SimulationTag`` when any text carries an ``extorq-sim-<run_id>`` marker."""
    for text in texts:
        if not text:
            continue
        match = _SIM_MARKER.search(text)
        if match:
            return SimulationTag(run_id=match.group(1))
    return None


#: Reverse-DNS spelling of the marker for launchd labels / plist names (MAC-001):
#: ``com.extorq.sim.<run_id>`` (launchd labels conventionally avoid ``extorq-sim-``).
_SIM_LAUNCHD_LABEL = re.compile(r"com\.extorq\.sim\.([a-z0-9]{8,32})(?:\.plist)?")


def launchd_simulation_tag(path: str | None, label: str | None) -> SimulationTag | None:
    """Simulation tag for a launchd item: the generic marker, or the exact label form."""
    tag = simulation_tag(path, label)
    if tag is not None:
        return tag
    for text in (label, path.rsplit("/", 1)[-1] if path else None):
        match = _SIM_LAUNCHD_LABEL.fullmatch(text or "")
        if match:
            return SimulationTag(run_id=match.group(1))
    return None


def _bound_value(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return value
    if isinstance(value, str):
        return sanitize_untrusted(value, MAX_ATTR_STR)
    if isinstance(value, list | tuple | set | frozenset):
        items: list[Any] = []
        for item in list(value)[:MAX_ATTR_LIST]:
            if isinstance(item, str):
                items.append(sanitize_untrusted(item, MAX_ATTR_LIST_ITEM))
            elif isinstance(item, bool | int | float):
                items.append(item)
            elif item is not None:
                items.append(sanitize_untrusted(str(item), MAX_ATTR_LIST_ITEM))
        return items
    return sanitize_untrusted(str(value), MAX_ATTR_STR)


def bounded_attributes(values: Mapping[str, Any], *, keep_none: bool = False) -> dict[str, Any]:
    """Apply the contract's attribute limits; drop ``None`` unless ``keep_none``."""
    out: dict[str, Any] = {}
    for key, value in values.items():
        if value is None and not keep_none:
            continue
        if not _ATTR_KEY.match(key):
            raise ValueError(f"invalid attribute key {key!r}")
        if len(out) >= MAX_ATTR_KEYS:
            break
        out[key] = _bound_value(value)
    return out


def redact_list(
    values: Iterable[str], item_limit: int = MAX_ATTR_LIST_ITEM
) -> tuple[list[str], int]:
    """Redact and sanitise each item of a list of untrusted strings."""
    total = 0
    out: list[str] = []
    for value in list(values)[:MAX_ATTR_LIST]:
        cleaned, count = clean_text(value, item_limit)
        total += count
        out.append(cleaned or "")
    return out, total


def make_event(
    *,
    ctx: SourceContext,
    event_type: str,
    source_type: SourceType,
    native_key: str,
    event_time: datetime,
    observed_time: datetime | None,
    parser: str,
    raw_record: bytes | str | None = None,
    message: str | None = None,
    raw: str | None = None,
    action: str | None = None,
    outcome: Outcome = Outcome.UNKNOWN,
    severity_hint: Severity | None = None,
    actor: Actor | None = None,
    resource: Resource | None = None,
    network: Network | None = None,
    process: ProcessInfo | None = None,
    attributes: Mapping[str, Any] | None = None,
    labels: Mapping[str, str] | None = None,
    simulation: SimulationTag | None = None,
    redaction_count: int = 0,
    truncated: bool = False,
    source_native_id: str | None = None,
    service: ServiceRef | None = None,
) -> SecurityEvent:
    """Build a validated :class:`SecurityEvent` (raises on catalog violations)."""
    spec = EVENT_CATALOG.get(event_type)
    if spec is None:
        raise ValueError(f"event type not in catalog: {event_type}")
    if source_type not in spec.sources:
        raise ValueError(f"{source_type.value} may not emit {event_type}")
    clean_message, message_redactions = clean_text(message, MAX_MESSAGE)
    clean_raw, raw_redactions = clean_text(raw, MAX_RAW)
    raw_sha = None
    if raw_record is not None:
        raw_sha = sha256_hex(raw_record)
    native = source_native_id if source_native_id is not None else native_key
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
            collection_method=CollectionMethod.NATIVE_COMMAND,
            source_native_id=native[:256] if native else None,
        ),
        event_time=to_ms(event_time),
        observed_time=to_ms(observed_time) if observed_time else None,
        action=action,
        outcome=outcome,
        severity_hint=severity_hint,
        actor=actor,
        resource=resource,
        network=network,
        process=process,
        service=service,
        message=clean_message,
        attributes=bounded_attributes(attributes or {}),
        labels=dict(labels or {}),
        raw=clean_raw,
        provenance=Provenance(
            parser=parser,
            parser_version=PARSER_VERSION,
            raw_sha256=raw_sha,
            truncated=truncated
            or (clean_raw is not None and raw is not None and len(raw) > MAX_RAW),
            redaction_count=redaction_count + message_redactions + raw_redactions,
        ),
        simulation=simulation,
    )


def snapshot_id(collector_id: str, source: str, observed_at: datetime) -> str:
    """Deterministic id of one inventory snapshot (also used in event native keys)."""
    return stable_id("macos.snapshot.v1", collector_id, source, to_ms(observed_at))

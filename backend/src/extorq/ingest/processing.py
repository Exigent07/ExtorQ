"""Per-record ingestion pipeline (pure functions, no I/O).

For every raw record of a batch, in order:

1. size bound (``MAX_RECORD_BYTES`` of canonical JSON)            -> quarantine
2. ``INGEST_RECORD_ADAPTER`` validation (strict contracts)         -> quarantine
3. producer authorization (kind / asset / source type)             -> DENY BATCH (403)
4. event catalog semantics (``validate_event_semantics``)          -> quarantine
5. time sanity: event_time > now+1d or < now-400d; any timestamp
   > now+1d on other kinds                                          -> quarantine
6. secret redaction of free-text fields (count -> provenance)      -> re-validated
7. storage compatibility (``rows.to_row`` must succeed)             -> quarantine
8. identity (``record_identity``) for deduplication in the spool

Authorization failures reject the whole batch: a producer sending records
outside its registration is misconfigured or compromised, and accepting the
rest would let it probe its boundary silently. The batch stays in the
producer's outbox, the gateway answers 403, and an ``ingest_audit`` row is
written (docs/data-flow.md, "Authorization").
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import ValidationError

from extorq.common.redaction import redact_text, sanitize_untrusted, truncate_bytes
from extorq.contracts.catalog import validate_event_semantics
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import canonical_json, sha256_hex, stable_id
from extorq.contracts.ingest import (
    INGEST_RECORD_ADAPTER,
    MAX_RECORD_BYTES,
    IngestRecord,
    RecordKind,
    record_identity,
)
from extorq.ingest.registry import ProducerEntry
from extorq.storage.rows import RowError, to_row

QUARANTINE_EXCERPT_BYTES = 4096
REASON_LIMIT = 512
MAX_DENIALS_REPORTED = 5

_KIND_VALUES = {k.value for k in RecordKind}

# Timestamp fields checked for "in the future" on non-event kinds.
_TIME_FIELDS: dict[str, tuple[str, ...]] = {
    "asset": ("first_seen", "last_seen"),
    "inventory_item": ("observed_at",),
    "finding": ("observed_at",),
    "scan_run": ("started_at", "finished_at"),
    "collector_health": ("reported_at", "last_attempt_at", "last_success_at"),
    "simulation_run": ("started_at", "finished_at"),
}


@dataclass(frozen=True)
class Limits:
    max_future: timedelta = timedelta(days=1)
    max_age: timedelta = timedelta(days=400)


@dataclass
class Candidate:
    index: int
    kind: str
    record_key: str
    payload: str


@dataclass
class QuarantineEntry:
    index: int
    kind: str | None
    reason: str
    excerpt: str
    payload_sha256: str


@dataclass
class PreparedBatch:
    candidates: list[Candidate] = field(default_factory=list)
    quarantined: list[QuarantineEntry] = field(default_factory=list)
    denials: list[str] = field(default_factory=list)
    redactions: int = 0

    @property
    def denied(self) -> bool:
        return bool(self.denials)


# ── helpers ───────────────────────────────────────────────────────────


def clean_reason(text: str, limit: int = REASON_LIMIT) -> str:
    """Secret-free, control-free, bounded reason text."""
    return sanitize_untrusted(redact_text(text)[0], limit)


def summarize_validation_error(exc: ValidationError, max_errors: int = 5) -> str:
    """Compact validation summary WITHOUT input values (they may contain secrets)."""
    errors = exc.errors(include_url=False, include_input=False, include_context=False)
    parts = []
    for err in errors[:max_errors]:
        loc = ".".join(str(p) for p in err.get("loc", ()))
        msg = sanitize_untrusted(str(err.get("msg", "")), 160)
        parts.append(f"{loc}: {err.get('type')}: {msg}")
    if len(errors) > max_errors:
        parts.append(f"(+{len(errors) - max_errors} more)")
    return clean_reason("; ".join(parts))


def make_excerpt(raw: Any) -> tuple[str, str]:
    """Return ``(sanitised redacted excerpt <= 4 KiB, sha256 of the canonical record)``."""
    try:
        text = canonical_json(raw)
    except (TypeError, ValueError):
        text = json.dumps(raw, default=str, ensure_ascii=False, allow_nan=True, sort_keys=True)
    digest = sha256_hex(text.encode("utf-8", "surrogatepass"))
    safe = text.encode("utf-8", "replace").decode("utf-8")
    excerpt = sanitize_untrusted(redact_text(safe)[0], QUARANTINE_EXCERPT_BYTES)
    return truncate_bytes(excerpt, QUARANTINE_EXCERPT_BYTES), digest


def quarantine_id(producer_id: str, batch_id: str, index: int, payload_sha256: str) -> str:
    return stable_id("quarantine.v1", producer_id, batch_id, index, payload_sha256)


def _raw_kind(raw: Any) -> str | None:
    if isinstance(raw, dict):
        kind = raw.get("kind")
        if isinstance(kind, str) and kind in _KIND_VALUES:
            return kind
    return None


# ── redaction of free-text fields (operates on JSON-mode dicts) ───────


class _Redactor:
    def __init__(self) -> None:
        self.count = 0
        self.truncated = False

    def text(self, container: dict[str, Any] | None, key: str, limit: int) -> None:
        if not isinstance(container, dict):
            return
        value = container.get(key)
        if isinstance(value, str) and value:
            container[key] = self._apply(value, limit)

    def _apply(self, value: str, limit: int) -> str:
        redacted, count = redact_text(value)
        if count:
            self.count += count
            if len(redacted) > limit:
                redacted = sanitize_untrusted(redacted, limit, keep_newlines=True)
                self.truncated = True
        return redacted

    def text_list(self, container: dict[str, Any] | None, key: str, limit: int) -> None:
        if not isinstance(container, dict):
            return
        items = container.get(key)
        if isinstance(items, list):
            container[key] = [self._apply(i, limit) if isinstance(i, str) else i for i in items]

    def mapping(self, mapping: Any, str_limit: int, item_limit: int) -> None:
        if not isinstance(mapping, dict):
            return
        for key, value in list(mapping.items()):
            if isinstance(value, str):
                mapping[key] = self._apply(value, str_limit)
            elif isinstance(value, list):
                mapping[key] = [
                    self._apply(v, item_limit) if isinstance(v, str) else v for v in value
                ]


def redact_record_data(kind: str, data: dict[str, Any]) -> int:
    """Redact secrets in-place in the JSON form of a record; return replacement count."""
    r = _Redactor()
    if kind == "event":
        r.text(data, "message", 2048)
        r.text(data, "raw", 16384)
        r.text(data.get("process"), "command_line", 2048)
        r.text(data.get("http"), "user_agent", 2048)
        r.text(data.get("http"), "route", 2048)
        r.text(data.get("kubernetes"), "user_agent", 2048)
        r.mapping(data.get("attributes"), 2048, 512)
        r.mapping(data.get("labels"), 256, 256)
        provenance = data.get("provenance")
        if isinstance(provenance, dict) and (r.count or r.truncated):
            provenance["redaction_count"] = int(provenance.get("redaction_count") or 0) + r.count
            if r.truncated:
                provenance["truncated"] = True
    elif kind == "finding":
        for key, limit in (("title", 256), ("description", 2048), ("evidence", 2048),
                           ("remediation", 2048)):
            r.text(data, key, limit)
        r.mapping(data.get("attributes"), 2048, 512)
    elif kind == "scan_run":
        r.text(data, "error", 2048)
        r.mapping(data.get("attributes"), 2048, 512)
        coverage = data.get("coverage")
        if isinstance(coverage, dict):
            r.text_list(coverage, "notes", 2048)
            for skipped in coverage.get("skipped") or []:
                r.text(skipped, "reason", 2048)
    elif kind == "collector_health":
        r.text(data, "last_error", 2048)
        r.text(data, "checkpoint_summary", 256)
        r.mapping(data.get("details"), 2048, 512)
    elif kind == "simulation_run":
        r.text(data, "description", 2048)
        r.text_list(data, "notes", 2048)
    elif kind in ("asset", "inventory_item"):
        r.mapping(data.get("attributes"), 2048, 512)
        if kind == "asset":
            r.mapping(data.get("labels"), 256, 256)
    return r.count


# ── main entry point ──────────────────────────────────────────────────


def _time_problem(record: IngestRecord, now: datetime, limits: Limits) -> str | None:
    data = record.data
    if isinstance(data, SecurityEvent):
        if data.event_time > now + limits.max_future:
            return "event_time_in_future"
        if data.event_time < now - limits.max_age:
            return "event_time_too_old"
        if data.observed_time is not None and data.observed_time > now + limits.max_future:
            return "observed_time_in_future"
        return None
    for name in _TIME_FIELDS.get(record.kind, ()):
        value = getattr(data, name, None)
        if isinstance(value, datetime) and value > now + limits.max_future:
            return f"{name}_in_future"
    return None


def prepare_batch(
    raw_records: list[Any],
    producer: ProducerEntry,
    *,
    batch_id: str,
    now: datetime,
    limits: Limits | None = None,
) -> PreparedBatch:
    """Validate, authorize, check, redact and key every record of a batch."""
    limits = limits or Limits()
    now = now.astimezone(UTC)
    out = PreparedBatch()
    denied_count = 0

    def quarantine(index: int, raw: Any, reason: str, kind: str | None = None) -> None:
        excerpt, digest = make_excerpt(raw)
        out.quarantined.append(
            QuarantineEntry(index=index, kind=kind if kind is not None else _raw_kind(raw),
                            reason=clean_reason(reason), excerpt=excerpt, payload_sha256=digest)
        )

    for index, raw in enumerate(raw_records):
        # 1. size bound
        try:
            size = len(canonical_json(raw).encode("utf-8", "surrogatepass"))
        except (TypeError, ValueError):
            quarantine(index, raw, "record_not_serialisable")
            continue
        if size > MAX_RECORD_BYTES:
            quarantine(index, raw, f"record_too_large:{size}>{MAX_RECORD_BYTES}")
            continue
        # 2. strict validation
        try:
            record = INGEST_RECORD_ADAPTER.validate_python(raw)
        except ValidationError as exc:
            quarantine(index, raw, f"invalid_record: {summarize_validation_error(exc)}")
            continue
        kind = record.kind
        # 3. authorization (denies the batch)
        denial = producer.authorize(record)
        if denial is not None:
            denied_count += 1
            if denied_count <= MAX_DENIALS_REPORTED:
                out.denials.append(f"record {index}: {clean_reason(denial, 200)}")
            continue
        # 4. catalog semantics
        if isinstance(record.data, SecurityEvent):
            event = record.data
            problem = validate_event_semantics(
                event.event_type, event.category.value, event.source.source_type.value
            )
            if problem is not None:
                quarantine(index, raw, f"semantics: {problem}", kind)
                continue
        # 5. time sanity
        problem = _time_problem(record, now, limits)
        if problem is not None:
            quarantine(index, raw, f"time: {problem}", kind)
            continue
        # 6. redaction (on the JSON form) + re-validation
        data_json = record.data.model_dump(mode="json")
        count = redact_record_data(kind, data_json)
        if count:
            try:
                record = INGEST_RECORD_ADAPTER.validate_python({"kind": kind, "data": data_json})
            except ValidationError as exc:
                quarantine(index, raw, f"redaction_invalidated_record: "
                                       f"{summarize_validation_error(exc)}", kind)
                continue
            data_json = record.data.model_dump(mode="json")
            out.redactions += count
        # 7. storage compatibility
        try:
            to_row(kind, record.data, producer_id=producer.producer_id, batch_id=batch_id,
                   ingested_at=now)
        except RowError as exc:
            quarantine(index, raw, f"storage_constraint: {exc}", kind)
            continue
        # 8. identity
        out.candidates.append(
            Candidate(
                index=index,
                kind=kind,
                record_key=record_identity(record),
                payload=canonical_json({"kind": kind, "data": data_json}),
            )
        )
    if denied_count > MAX_DENIALS_REPORTED:
        out.denials.append(f"(+{denied_count - MAX_DENIALS_REPORTED} more denied records)")
    return out

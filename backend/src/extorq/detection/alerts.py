"""Pure alert logic: validate rule output rows, create alerts, merge late evidence.

Row contract (every rule query returns these columns, see :data:`COMMON_COLUMNS`):
``group_key`` (String), ``asset_id``/``asset_type``, ``first_seen``/``last_seen``
(DateTime64(3, 'UTC')), ``event_count``, ``evidence_event_ids`` (Array(String), earliest
first), ``entities`` (Map(String, String)), ``features`` (JSON object text),
``confidence`` ('high' | 'medium' | 'low') plus ``bucket_start`` (window_bucket rules)
or ``signature`` (event rules). ``supporting_event_ids`` is optional: evidence ids that
corroborate rather than trigger (stored with role ``supporting``). Everything a row
carries is untrusted telemetry and is validated, bounded and sanitised here.

Identity (contracts.identity.alert_id): ``(rule_id, group_key, bucket)`` where
``bucket`` is the row's ``bucket_start`` (window_bucket rules) or ``signature``
(event rules). The rule *version* is deliberately excluded, so a rule upgrade extends
open alerts instead of duplicating them.

Merging a row into an existing alert (late events, overlapping windows):

* evidence is the union of the stored evidence set (``alert_evidence``) and the
  row's ids; only ids not stored before become new ``alert_evidence`` rows
* ``created_at`` is preserved, ``updated_at`` strictly increases
* ``first_seen``/``last_seen`` widen, ``event_count`` never decreases
* confidence is monotone within a rule version; a different rule version reevaluates
  confidence and features from its own result
* numeric features take the max, boolean features OR, lists are unioned (bounded)
* a row that adds nothing (no new evidence, no higher confidence) produces no new
  version: re-running a window is idempotent
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from extorq.contracts.alert import (
    AlertEvidence,
    DedupStrategy,
    DetectionAlert,
    EvidenceConfidence,
    EvidenceRole,
)
from extorq.contracts.common import AssetType
from extorq.contracts.identity import alert_id as make_alert_id
from extorq.detection._compat import sanitize
from extorq.detection.clients import QueryRows
from extorq.detection.templates import render_summary
from extorq.version import __version__

if TYPE_CHECKING:
    from extorq.detection.registry import LoadedRule

DETECTOR_VERSION = f"extorq-detector/{__version__}"
MAX_ALERT_EVIDENCE = 500
MAX_ENTITIES = 16
MAX_SERVICE_IDS = 16
MAX_FEATURE_KEYS = 64
MAX_FEATURE_LIST = 64
COMMON_COLUMNS = (
    "group_key",
    "asset_id",
    "asset_type",
    "first_seen",
    "last_seen",
    "event_count",
    "evidence_event_ids",
    "entities",
    "features",
    "confidence",
)
CONFIDENCE_RANK = {
    EvidenceConfidence.LOW: 0,
    EvidenceConfidence.MEDIUM: 1,
    EvidenceConfidence.HIGH: 2,
}
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_ASSET_ID = re.compile(r"^[a-z0-9][a-z0-9._:/-]{2,199}$")
_ATTR_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_ASSET_TYPES = {a.value for a in AssetType}


class RowError(ValueError):
    """A rule result row violates the row contract (the row, or the run, is rejected)."""


@dataclass
class RuleRow:
    """One validated row returned by a rule query."""

    group_key: str
    asset_id: str
    asset_type: AssetType
    first_seen: datetime
    last_seen: datetime
    event_count: int
    evidence_event_ids: list[str]
    entities: dict[str, str]
    features: dict[str, Any]
    confidence: EvidenceConfidence
    bucket_start: datetime | None = None
    signature: str | None = None
    supporting_event_ids: set[str] = field(default_factory=set)

    @property
    def bucket(self) -> datetime | str:
        if self.bucket_start is not None:
            return self.bucket_start
        assert self.signature is not None  # noqa: S101 - guaranteed by parse_row
        return self.signature


# ── coercion helpers ────────────────────────────────────────────────────


def coerce_attributes(value: dict[str, Any]) -> dict[str, Any]:
    """Force a mapping into the contract's Attributes bounds (truncate, never fail)."""
    out: dict[str, Any] = {}
    for key in sorted(value)[: MAX_FEATURE_KEYS * 2]:
        if len(out) >= MAX_FEATURE_KEYS:
            break
        if not isinstance(key, str) or not _ATTR_KEY.match(key):
            continue
        item = value[key]
        if isinstance(item, bool) or item is None or isinstance(item, int):
            out[key] = item
        elif isinstance(item, float):
            if math.isfinite(item):
                out[key] = item
        elif isinstance(item, str):
            out[key] = sanitize(item, 2048)
        elif isinstance(item, list | tuple):
            items: list[Any] = []
            for element in item:
                if len(items) >= MAX_FEATURE_LIST:
                    break
                if isinstance(element, bool | int) or (
                    isinstance(element, float) and math.isfinite(element)
                ):
                    items.append(element)
                elif isinstance(element, str):
                    items.append(sanitize(element, 512))
            out[key] = items
        elif isinstance(item, dict):
            out[key] = sanitize(json.dumps(item, sort_keys=True, default=str), 2048)
    return out


def _as_datetime(value: Any, column: str) -> datetime:
    if not isinstance(value, datetime):
        raise RowError(f"{column} must be a DateTime64(3, 'UTC'), got {type(value).__name__}")
    if value.tzinfo is None:
        raise RowError(f"{column} is not timezone-aware")
    return value


def parse_row(rule: LoadedRule, record: dict[str, Any]) -> RuleRow:
    """Validate one result row against the rule output contract."""
    group_key = record.get("group_key")
    if not isinstance(group_key, str) or not group_key.strip():
        raise RowError("group_key must be a non-empty String")
    group_key = sanitize(group_key, 2048)
    asset_id = record.get("asset_id")
    if not isinstance(asset_id, str) or not _ASSET_ID.match(asset_id):
        raise RowError(f"asset_id is not a valid asset identifier: {sanitize(str(asset_id), 80)!r}")
    asset_type = record.get("asset_type")
    if asset_type not in _ASSET_TYPES:
        raise RowError(f"asset_type is not a known AssetType: {sanitize(str(asset_type), 40)!r}")
    if rule.metadata.asset_types and AssetType(asset_type) not in rule.metadata.asset_types:
        raise RowError(f"asset_type {asset_type} is not declared in the rule's asset_types")
    first_seen = _as_datetime(record.get("first_seen"), "first_seen")
    last_seen = _as_datetime(record.get("last_seen"), "last_seen")
    if last_seen < first_seen:
        raise RowError("last_seen precedes first_seen")
    event_count = record.get("event_count")
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 0:
        raise RowError("event_count must be a non-negative integer")
    raw_ids = record.get("evidence_event_ids")
    if not isinstance(raw_ids, list):
        raise RowError("evidence_event_ids must be Array(String)")
    evidence: list[str] = []
    seen: set[str] = set()
    for item in raw_ids:
        if isinstance(item, str) and _HEX32.match(item) and item not in seen:
            seen.add(item)
            evidence.append(item)
    if not evidence:
        raise RowError("row has no valid evidence_event_ids")
    raw_entities = record.get("entities")
    if not isinstance(raw_entities, dict):
        raise RowError("entities must be Map(String, String)")
    entities: dict[str, str] = {}
    for key in sorted(raw_entities)[:MAX_ENTITIES]:
        value = raw_entities[key]
        if value is None or value == "":
            continue
        entities[sanitize(str(key), 256)] = sanitize(str(value), 2048)
    raw_features = record.get("features")
    if isinstance(raw_features, str):
        try:
            raw_features = json.loads(raw_features) if raw_features.strip() else {}
        except json.JSONDecodeError as exc:
            raise RowError(f"features is not valid JSON: {exc.msg}") from exc
    if not isinstance(raw_features, dict):
        raise RowError("features must be a JSON object")
    confidence = record.get("confidence")
    if confidence not in {"high", "medium", "low"}:
        raise RowError("confidence must be 'high', 'medium' or 'low'")
    supporting_raw = record.get("supporting_event_ids") or []
    supporting = (
        {s for s in supporting_raw if isinstance(s, str) and s in seen}
        if isinstance(supporting_raw, list)
        else set()
    )
    row = RuleRow(
        group_key=group_key,
        asset_id=asset_id,
        asset_type=AssetType(asset_type),
        first_seen=first_seen,
        last_seen=last_seen,
        event_count=event_count,
        evidence_event_ids=evidence,
        entities=entities,
        features=coerce_attributes(raw_features),
        confidence=EvidenceConfidence(confidence),
        supporting_event_ids=supporting,
    )
    if rule.metadata.dedup.strategy is DedupStrategy.WINDOW_BUCKET:
        row.bucket_start = _as_datetime(record.get("bucket_start"), "bucket_start")
    else:
        signature = record.get("signature")
        if not isinstance(signature, str) or not signature.strip():
            raise RowError("event-dedup rules must return a non-empty signature")
        row.signature = sanitize(signature, 512)
    return row


def required_columns(rule: LoadedRule) -> tuple[str, ...]:
    extra = (
        "bucket_start"
        if rule.metadata.dedup.strategy is DedupStrategy.WINDOW_BUCKET
        else "signature"
    )
    return (*COMMON_COLUMNS, extra)


def parse_rows(rule: LoadedRule, result: QueryRows) -> tuple[list[RuleRow], list[str]]:
    """Validate all rows. Returns ``(valid_rows, problems)``; a missing column is fatal.

    An empty result carries no column metadata over HTTP, so columns are only
    checked when rows exist (the SQL itself is validated statically at load time).
    """
    if not result.rows:
        return [], []
    missing = [c for c in required_columns(rule) if c not in result.columns]
    if missing:
        raise RowError(f"rule query is missing required columns: {', '.join(missing)}")
    rows: list[RuleRow] = []
    problems: list[str] = []
    for record in result.dicts():
        try:
            rows.append(parse_row(rule, record))
        except RowError as exc:
            problems.append(str(exc))
    return rows, problems


# ── alert construction / merge ──────────────────────────────────────────


def alert_identity(rule: LoadedRule, row: RuleRow) -> str:
    return make_alert_id(rule.rule_id, row.group_key, row.bucket)


def max_confidence(a: EvidenceConfidence, b: EvidenceConfidence) -> EvidenceConfidence:
    return a if CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] else b


def merge_features(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    merged = dict(old)
    for key, value in new.items():
        previous = merged.get(key)
        if isinstance(value, bool) and isinstance(previous, bool):
            merged[key] = previous or value
        elif (
            isinstance(value, int | float)
            and isinstance(previous, int | float)
            and not isinstance(value, bool)
            and not isinstance(previous, bool)
        ):
            merged[key] = max(previous, value)
        elif isinstance(value, list) and isinstance(previous, list):
            union = list(previous)
            for item in value:
                if item not in union:
                    union.append(item)
            merged[key] = union[:MAX_FEATURE_LIST]
        else:
            merged[key] = value
    return coerce_attributes(merged)


@dataclass
class AlertDecision:
    alert: DetectionAlert
    new_evidence: list[AlertEvidence]
    created: bool


def summary_values(rule: LoadedRule, alert_fields: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    values.update(alert_fields.get("features", {}))
    values.update(alert_fields.get("entities", {}))
    for name in ("asset_id", "asset_type", "event_count", "first_seen", "last_seen", "group_key"):
        values[name] = alert_fields.get(name)
    values["confidence"] = getattr(
        alert_fields.get("confidence"), "value", alert_fields.get("confidence")
    )
    values["rule_id"] = rule.rule_id
    values["rule_title"] = rule.metadata.title
    values["severity"] = rule.metadata.severity.value
    return values


def decide(
    rule: LoadedRule,
    row: RuleRow,
    alert_id: str,
    *,
    existing: DetectionAlert | None,
    stored_evidence: dict[str, datetime],
    window_start: datetime,
    window_end: datetime,
    now: datetime,
    detector_version: str = DETECTOR_VERSION,
) -> AlertDecision | None:
    """Create a new alert or a new version of ``existing``; ``None`` if nothing changed."""
    known = {
        eid
        for eid, added_at in stored_evidence.items()
        if existing is not None and added_at <= existing.updated_at
    }
    if existing is not None:
        known.update(existing.evidence_event_ids)
    new_ids = [eid for eid in row.evidence_event_ids if eid not in known]
    full_set = known | set(row.evidence_event_ids)

    if existing is not None:
        version_changed = existing.rule_version != rule.version
        confidence = (
            row.confidence
            if version_changed
            else max_confidence(existing.confidence, row.confidence)
        )
        if not new_ids and not version_changed and confidence == existing.confidence:
            return None
        array = list(
            dict.fromkeys(
                row.evidence_event_ids + existing.evidence_event_ids
                if version_changed
                else existing.evidence_event_ids + new_ids
            )
        )[:MAX_ALERT_EVIDENCE]
        fields: dict[str, Any] = {
            "first_seen": min(existing.first_seen, row.first_seen),
            "last_seen": max(existing.last_seen, row.last_seen),
            "event_count": max(existing.event_count, row.event_count, len(full_set)),
            "evidence_truncated": existing.evidence_truncated
            or len(full_set) > len(array)
            or row.event_count > len(row.evidence_event_ids),
            "features": dict(row.features)
            if version_changed
            else merge_features(existing.features, row.features),
            "entities": dict(row.entities)
            if version_changed
            else dict(list({**existing.entities, **row.entities}.items())[:MAX_ENTITIES]),
            "service_ids": list(existing.service_ids),
            "confidence": confidence,
            "created_at": existing.created_at,
            "updated_at": max(now, existing.updated_at + timedelta(milliseconds=1)),
            "window_start": min(existing.window_start, window_start),
            "window_end": max(existing.window_end, window_end),
        }
        created = False
    else:
        ordered = list(row.evidence_event_ids) + sorted(known - set(row.evidence_event_ids))
        array = ordered[:MAX_ALERT_EVIDENCE]
        fields = {
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "event_count": max(row.event_count, len(full_set)),
            "evidence_truncated": len(full_set) > len(array)
            or row.event_count > len(row.evidence_event_ids),
            "features": dict(row.features),
            "entities": dict(row.entities),
            "service_ids": [],
            "confidence": row.confidence,
            "created_at": now,
            "updated_at": now,
            "window_start": window_start,
            "window_end": window_end,
        }
        created = True

    fields.update(
        {"asset_id": row.asset_id, "asset_type": row.asset_type, "group_key": row.group_key}
    )
    summary = render_summary(rule.summary_template, summary_values(rule, fields))
    alert = DetectionAlert(
        alert_id=alert_id,
        rule_id=rule.rule_id,
        rule_version=rule.version,
        rule_title=rule.metadata.title,
        severity=rule.metadata.severity,
        confidence=fields["confidence"],
        asset_id=row.asset_id,
        asset_type=row.asset_type,
        group_key=row.group_key,
        entities=fields["entities"],
        service_ids=fields["service_ids"],
        summary=summary,
        first_seen=fields["first_seen"],
        last_seen=fields["last_seen"],
        window_start=fields["window_start"],
        window_end=fields["window_end"],
        event_count=fields["event_count"],
        evidence_event_ids=array,
        evidence_truncated=fields["evidence_truncated"],
        features=fields["features"],
        mitre_techniques=list(rule.metadata.mitre_techniques),
        created_at=fields["created_at"],
        updated_at=fields["updated_at"],
        detector_version=detector_version,
    )
    # A write interrupted before publishing the alert can leave evidence ahead of its
    # published version. Reuse the association when the same rule result returns.
    new_evidence = [
        AlertEvidence(
            alert_id=alert_id,
            event_id=eid,
            role=EvidenceRole.SUPPORTING
            if eid in row.supporting_event_ids
            else EvidenceRole.TRIGGER,
            added_at=alert.updated_at,
        )
        for eid in new_ids
        if eid not in stored_evidence
    ]
    return AlertDecision(alert=alert, new_evidence=new_evidence, created=created)


def with_service_ids(alert: DetectionAlert, found: Iterable[str]) -> DetectionAlert:
    """Return ``alert`` with the evidence services added to ``service_ids``.

    ``found`` are ``events.service_id`` values of the alert's evidence events (set by the
    producing adapter, never guessed). Ids are validated (32 hex), unioned with the ids
    the alert already carries (service attribution only grows, like evidence), sorted for
    determinism and capped at the contract bound.
    """
    valid = {sid for sid in found if isinstance(sid, str) and _HEX32.match(sid)}
    merged = sorted(set(alert.service_ids) | valid)[:MAX_SERVICE_IDS]
    if merged == list(alert.service_ids):
        return alert
    return DetectionAlert.model_validate({**alert.model_dump(), "service_ids": merged})


def find_continuation(
    candidates: list[DetectionAlert], row: RuleRow, *, gap_seconds: int, max_span_seconds: int
) -> DetectionAlert | None:
    """Existing alert of the same group whose activity is continuous with ``row``.

    Used for window_bucket rules so one burst that crosses a bucket boundary
    extends a single alert instead of opening a second one. Continuous means the
    row overlaps the alert or the gap between them is at most ``gap_seconds``,
    and the combined span stays within ``max_span_seconds``.
    """
    matches: list[DetectionAlert] = []
    for alert in candidates:
        if row.asset_id != alert.asset_id:
            continue
        if (row.first_seen - alert.last_seen).total_seconds() > gap_seconds:
            continue
        if (alert.first_seen - row.last_seen).total_seconds() > gap_seconds:
            continue
        span = (
            max(alert.last_seen, row.last_seen) - min(alert.first_seen, row.first_seen)
        ).total_seconds()
        if span <= max_span_seconds:
            matches.append(alert)
    if not matches:
        return None
    # Deterministic choice: the most recent episode, ties broken by the smaller id.
    return min(matches, key=lambda a: (-a.last_seen.timestamp(), a.alert_id))

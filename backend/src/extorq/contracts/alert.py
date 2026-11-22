"""Detection rule metadata, alerts, rule runs and analyst state (schema 1.0).

Authority model:
* ``DetectionAlert`` is authoritative and written ONLY by the detection engine.
* ``severity`` comes from the versioned rule and is never changed by AI.
* ``confidence`` is a deterministic statement about evidence completeness
  (e.g. audit log + resource-state change => high), not a maliciousness score.
* Analyst workflow state lives in ``AnalystState``; AI output lives in
  ``AIAssessment``. Neither mutates the alert.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from extorq.contracts.catalog import SourceType
from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    AssetType,
    Attributes,
    ContractModel,
    EventTypeStr,
    HexId,
    MediumStr,
    MitreTechnique,
    RuleId,
    SchemaVersion,
    SemVer,
    Severity,
    Sha256Hex,
    ShortStr,
    UtcDatetime,
)


class RuleStatus(StrEnum):
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


class DedupStrategy(StrEnum):
    #: Threshold/behavioural rules: identity = (rule, group_key, bucket_start).
    WINDOW_BUCKET = "window_bucket"
    #: Single-event rules: identity = (rule, group_key, triggering signature).
    EVENT = "event"


class EvidenceConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TelemetryRequirement(ContractModel):
    source_type: SourceType
    event_types: list[EventTypeStr] = Field(min_length=1, max_length=32)
    #: Whether the rule can still fire (with reduced confidence) without this source.
    optional: bool = False


class RuleSchedule(ContractModel):
    interval_seconds: int = Field(ge=10, le=86400)
    #: How far back each evaluation looks (must cover window + late tolerance).
    lookback_seconds: int = Field(ge=60, le=7 * 86400)
    #: Extra overlap so late-arriving events are still evaluated.
    late_tolerance_seconds: int = Field(default=300, ge=0, le=86400)


class RuleDedup(ContractModel):
    strategy: DedupStrategy
    bucket_seconds: int | None = Field(default=None, ge=60, le=86400)


class RuleMetadata(ContractModel):
    rule_id: RuleId
    version: SemVer
    title: ShortStr
    description: MediumStr
    severity: Severity
    status: RuleStatus = RuleStatus.STABLE
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list, max_length=16)
    asset_types: list[AssetType] = Field(min_length=1, max_length=8)
    requires: list[TelemetryRequirement] = Field(min_length=1, max_length=16)
    schedule: RuleSchedule
    dedup: RuleDedup
    group_by: list[ShortStr] = Field(min_length=1, max_length=8)
    params: Attributes = Field(default_factory=dict)
    false_positives: list[MediumStr] = Field(default_factory=list, max_length=16)
    blind_spots: list[MediumStr] = Field(default_factory=list, max_length=16)
    references: list[MediumStr] = Field(default_factory=list, max_length=16)
    #: SHA-256 of the rule's SQL text; identifies exactly what was executed.
    query_sha256: Sha256Hex


class DetectionAlert(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    alert_id: HexId
    rule_id: RuleId
    rule_version: SemVer
    rule_title: ShortStr
    severity: Severity
    confidence: EvidenceConfidence
    asset_id: AssetId
    asset_type: AssetType
    group_key: MediumStr
    #: Grouping entities, e.g. {"src_ip": "10.0.2.2", "unit": "x.service"}.
    entities: dict[ShortStr, MediumStr] = Field(default_factory=dict, max_length=16)
    #: Services whose telemetry is evidence for this alert (1.1); may span several services.
    service_ids: list[HexId] = Field(default_factory=list, max_length=16)
    #: Deterministic, template-rendered summary (no AI).
    summary: MediumStr
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    window_start: UtcDatetime
    window_end: UtcDatetime
    event_count: int = Field(ge=0)
    evidence_event_ids: list[HexId] = Field(min_length=1, max_length=500)
    evidence_truncated: bool = False
    features: Attributes = Field(default_factory=dict)
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list, max_length=16)
    created_at: UtcDatetime
    updated_at: UtcDatetime
    detector_version: ShortStr


class EvidenceRole(StrEnum):
    TRIGGER = "trigger"
    SUPPORTING = "supporting"


class AlertEvidence(ContractModel):
    """Explicit alert→event relationship (the full set; alert arrays may be capped)."""

    alert_id: HexId
    event_id: HexId
    role: EvidenceRole
    added_at: UtcDatetime
    #: Stored source event time verified by the detector. Legacy references may omit it.
    event_time: UtcDatetime | None = None


class RuleRunStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


class RuleRun(ContractModel):
    run_id: HexId
    rule_id: RuleId
    rule_version: SemVer
    started_at: UtcDatetime
    finished_at: UtcDatetime
    window_start: UtcDatetime
    window_end: UtcDatetime
    status: RuleRunStatus
    rows_matched: int = Field(default=0, ge=0)
    alerts_created: int = Field(default=0, ge=0)
    alerts_updated: int = Field(default=0, ge=0)
    duration_ms: int = Field(default=0, ge=0)
    #: Sanitized error summary for failed runs.
    error: MediumStr | None = None
    #: Telemetry requirements that had no data in the window (coverage signal).
    missing_sources: list[ShortStr] = Field(default_factory=list, max_length=16)


class AnalystStatus(StrEnum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CLOSED_TRUE_POSITIVE = "closed_true_positive"
    CLOSED_BENIGN = "closed_benign"
    CLOSED_FALSE_POSITIVE = "closed_false_positive"


class AnalystState(ContractModel):
    alert_id: HexId
    status: AnalystStatus = AnalystStatus.NEW
    assignee: ShortStr | None = None
    note: MediumStr | None = None
    updated_by: ShortStr
    updated_at: UtcDatetime

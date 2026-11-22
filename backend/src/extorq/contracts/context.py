"""InvestigationContext: the deterministic evidence bundle (schema 1.0).

This is the ONLY input AI integrations receive. It is built from stored
telemetry by the correlation layer and is hashed (``input_hash``) so every AI
assessment can be traced to the exact evidence it saw.

Relationship semantics (docs/correlation.md):
* DIRECT        - a verified shared identifier links the event to the alert
                  (request id, pod uid, audit id, commit sha, workflow run).
* CANDIDATE     - plausible but inferred (same asset + time window + a shared
                  non-identifying attribute such as source IP or principal name).
* UNESTABLISHED - considered and shown for completeness, but no supported link
                  (e.g. IP match through a shared NAT/gateway address).
Correlation never asserts causation.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from extorq.contracts.alert import DetectionAlert, RuleMetadata
from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    AssetType,
    Attributes,
    ContractModel,
    Criticality,
    Environment,
    HealthStatus,
    HexId,
    IpAddress,
    MediumStr,
    Outcome,
    SchemaVersion,
    Severity,
    Sha256Hex,
    ShortStr,
    UtcDatetime,
)


class RelationshipType(StrEnum):
    DIRECT = "direct"
    CANDIDATE = "candidate"
    UNESTABLISHED = "unestablished"


class RelationshipBasis(StrEnum):
    EVIDENCE = "evidence"
    SHARED_REQUEST_ID = "shared_request_id"
    SHARED_POD_UID = "shared_pod_uid"
    SHARED_AUDIT_ID = "shared_audit_id"
    SHARED_COMMIT_SHA = "shared_commit_sha"
    SHARED_WORKFLOW_RUN = "shared_workflow_run"
    SHARED_RESOURCE = "shared_resource"
    SHARED_PRINCIPAL = "shared_principal"
    SHARED_SOURCE_IP = "shared_source_ip"
    SHARED_NAT_SOURCE_IP = "shared_nat_source_ip"
    SAME_ASSET_TIME_WINDOW = "same_asset_time_window"
    #: 1.1 service-aware bases
    SAME_SERVICE = "same_service"
    SAME_SERVICE_INSTANCE = "same_service_instance"
    CROSS_SERVICE_SAME_ASSET = "cross_service_same_asset"
    CROSS_ASSET = "cross_asset"


class EventSummary(ContractModel):
    event_id: HexId
    event_time: UtcDatetime
    event_type: ShortStr
    source_type: ShortStr
    asset_id: AssetId
    outcome: Outcome
    actor_name: ShortStr | None = None
    src_ip: IpAddress | None = None
    service_id: HexId | None = None
    service_name: ShortStr | None = None
    #: Deterministic one-line description built from normalized fields (untrusted
    #: substrings are sanitized and truncated).
    summary: MediumStr
    key_fields: Attributes = Field(default_factory=dict)


class Relationship(ContractModel):
    event_id: HexId
    relationship_type: RelationshipType
    bases: list[RelationshipBasis] = Field(min_length=1, max_length=8)
    strength: Literal["strong", "moderate", "weak"]
    #: Seconds from the alert's first_seen (negative = before the alert window).
    time_delta_seconds: float
    explanation: MediumStr


class TimelineEntry(ContractModel):
    event_id: HexId
    time: UtcDatetime
    event_type: ShortStr
    source_type: ShortStr
    summary: MediumStr
    is_evidence: bool
    relationship_type: RelationshipType | None = None


class ServiceSummary(ContractModel):
    service_id: HexId
    asset_id: AssetId
    name: ShortStr
    service_kind: ShortStr
    category: ShortStr
    adapter_support: ShortStr
    monitoring_status: ShortStr
    #: Role of the service in this investigation: evidence source or related activity.
    role: Literal["evidence", "related"]


class AssetSummary(ContractModel):
    asset_id: AssetId
    asset_type: AssetType
    name: ShortStr
    criticality: Criticality
    environment: Environment


class FindingSummary(ContractModel):
    finding_id: HexId
    scanner: ShortStr
    check_id: ShortStr
    severity: Severity
    title: ShortStr
    state: Literal["open", "unverified", "resolved"]
    last_observed_at: UtcDatetime


class SourceCoverage(ContractModel):
    source_type: ShortStr
    collector_id: ShortStr | None = None
    status: HealthStatus
    last_success_at: UtcDatetime | None = None
    lag_seconds: float | None = None
    stale: bool
    #: True when collection was failing or absent for part of the context window.
    gap_during_window: bool
    note: MediumStr | None = None


class InvestigationContext(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    context_id: HexId
    alert_id: HexId
    builder_version: ShortStr
    created_at: UtcDatetime
    #: SHA-256 of the canonical bundle content (excludes context_id/created_at).
    input_hash: Sha256Hex
    window_start: UtcDatetime
    window_end: UtcDatetime
    alert: DetectionAlert
    rule: RuleMetadata
    asset: AssetSummary
    #: Services involved (evidence or related), for service-aware correlation (1.1).
    services: list[ServiceSummary] = Field(default_factory=list, max_length=32)
    #: Other assets with related activity (cross-asset correlation, 1.1).
    related_assets: list[AssetSummary] = Field(default_factory=list, max_length=16)
    evidence: list[EventSummary] = Field(max_length=100)
    timeline: list[TimelineEntry] = Field(max_length=300)
    relationships: list[Relationship] = Field(max_length=300)
    features: Attributes = Field(default_factory=dict)
    findings: list[FindingSummary] = Field(default_factory=list, max_length=50)
    coverage: list[SourceCoverage] = Field(default_factory=list, max_length=32)
    missing_telemetry: list[MediumStr] = Field(default_factory=list, max_length=32)
    limitations: list[MediumStr] = Field(default_factory=list, max_length=32)
    truncated: dict[ShortStr, bool] = Field(default_factory=dict)

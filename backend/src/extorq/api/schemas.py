"""Request and response models of the analyst API (exported to ``docs/api/openapi.json``).

Rules for clients (the security console):

* Every string that originates from telemetry, rules, AI output or analyst input is
  **untrusted**. Render it as text only: never as HTML/Markdown, never inside URLs,
  commands or queries.
* Unknown values are ``null``. Counts are never invented: an empty source yields an
  empty list plus an explicit flag/note, not zeros that look like measurements.
* All timestamps are ISO-8601 UTC.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from extorq.contracts import (
    AdapterSupport,
    AIAssessment,
    AnalystStatus,
    AssetType,
    DiscoveryEvidence,
    HealthStatus,
    InstanceKind,
    InvestigationContext,
    MonitoringStatus,
    PortAttribution,
    SecurityEvent,
    ServiceCategory,
    ServiceKind,
    Severity,
)

JsonObject = dict[str, Any]


class ApiModel(BaseModel):
    """Base for API models: unknown fields are rejected so nothing leaks by accident."""

    model_config = ConfigDict(extra="forbid")


# ── Common ────────────────────────────────────────────────────────────────────────


class ErrorResponse(ApiModel):
    detail: str | list[JsonObject]
    request_id: str | None = None


class PageInfo(ApiModel):
    limit: int
    offset: int
    returned: int
    has_more: bool
    next_offset: int | None = None
    #: Exact number of matching rows when computed; ``null`` when not computed.
    total: int | None = None


class TimeRange(ApiModel):
    since: datetime
    until: datetime


class SeverityCounts(ApiModel):
    info: int = 0
    low: int = 0
    medium: int = 0
    high: int = 0
    critical: int = 0
    total: int = 0


# ── Collectors / coverage ─────────────────────────────────────────────────────────


class CollectorStatus(ApiModel):
    """Latest report of one collector (``v_collector_latest``) plus derived staleness."""

    collector_id: str
    collector_type: str
    asset_id: str
    source_types: list[str]
    status: HealthStatus
    last_reported_at: datetime
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    events_collected: int
    records_buffered: int
    lag_seconds: float | None = None
    checkpoint_summary: str | None = None
    collector_version: str
    interval_seconds: int
    #: ``now - last_success_at > 3 * interval_seconds``, or no success ever reported.
    stale: bool
    stale_reason: str | None = None
    seconds_since_success: float | None = None
    details: JsonObject = Field(default_factory=dict)


CoverageStatus = Literal["ok", "degraded", "stale", "missing"]


class AssetClassCoverage(ApiModel):
    asset_type: str
    #: One of the four monitored classes; listed even when no asset of the class exists.
    expected: bool
    assets_total: int
    assets_ok: int
    assets_degraded: int
    assets_stale: int
    #: Assets known to the inventory without any collector health report.
    assets_without_collector: int
    status: CoverageStatus
    last_event_at: datetime | None = None


# ── Alerts ────────────────────────────────────────────────────────────────────────


class AlertListItem(ApiModel):
    alert_id: str
    rule_id: str
    rule_version: str
    rule_title: str
    severity: Severity
    confidence: str
    asset_id: str
    asset_type: str
    summary: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    entities: dict[str, str]
    mitre_techniques: list[str]
    simulation_run_ids: list[str]
    created_at: datetime
    updated_at: datetime
    #: ``new`` when no analyst has acted on the alert yet (see ``analyst_state_recorded``).
    analyst_status: AnalystStatus
    analyst_state_recorded: bool
    assignee: str | None = None
    #: Services whose telemetry is evidence for the alert (schema 1.1; empty when the
    #: detector could not attribute the evidence to a service).
    service_ids: list[str] = Field(default_factory=list)


class AlertListResponse(ApiModel):
    items: list[AlertListItem]
    page: PageInfo
    range: TimeRange


class AnalystStateView(ApiModel):
    status: AnalystStatus
    assignee: str | None = None
    note: str | None = None
    updated_by: str | None = None
    updated_at: datetime | None = None
    #: False when no analyst state row exists (status is then the default ``new``).
    recorded: bool


class AlertRecord(ApiModel):
    alert_id: str
    schema_version: str
    rule_id: str
    rule_version: str
    rule_title: str
    severity: Severity
    confidence: str
    asset_id: str
    asset_type: str
    group_key: str
    entities: dict[str, str]
    summary: str
    first_seen: datetime
    last_seen: datetime
    window_start: datetime
    window_end: datetime
    event_count: int
    evidence_event_ids: list[str]
    evidence_truncated: bool
    features: JsonObject | None = None
    mitre_techniques: list[str]
    simulation_run_ids: list[str]
    created_at: datetime
    updated_at: datetime
    detector_version: str
    #: Services whose telemetry is evidence for the alert (schema 1.1).
    service_ids: list[str] = Field(default_factory=list)


class EventListItem(ApiModel):
    """Flat projection of a stored event for tables (no ``raw``/``payload``)."""

    event_id: str
    event_type: str
    category: str
    asset_id: str
    asset_type: str
    source_type: str
    collector_id: str
    event_time: datetime
    observed_time: datetime | None = None
    ingested_time: datetime
    action: str | None = None
    outcome: str
    severity_hint: str | None = None
    actor_type: str | None = None
    actor_name: str | None = None
    actor_id: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    resource_namespace: str | None = None
    resource_path: str | None = None
    process_name: str | None = None
    process_pid: int | None = None
    http_method: str | None = None
    http_route: str | None = None
    http_status: int | None = None
    http_request_id: str | None = None
    k8s_cluster: str | None = None
    k8s_namespace: str | None = None
    k8s_node: str | None = None
    k8s_pod_name: str | None = None
    k8s_pod_uid: str | None = None
    k8s_container: str | None = None
    k8s_container_id: str | None = None
    k8s_verb: str | None = None
    k8s_resource: str | None = None
    k8s_object_name: str | None = None
    k8s_response_code: int | None = None
    k8s_user: str | None = None
    k8s_audit_id: str | None = None
    gh_repository: str | None = None
    gh_commit_sha: str | None = None
    gh_workflow_path: str | None = None
    gh_workflow_run_id: int | None = None
    gh_actor_login: str | None = None
    #: Service attribution set by the producing adapter (schema 1.1; ``null`` when the
    #: record could not be attributed to a service).
    service_id: str | None = None
    service_name: str | None = None
    service_instance_id: str | None = None
    adapter_id: str | None = None
    simulation_run_id: str | None = None
    scenario_id: str | None = None
    #: Sanitized one-line message from the source (attacker-controllable text).
    message: str | None = None


class EvidenceEvent(EventListItem):
    #: ``trigger`` / ``supporting`` from ``alert_evidence``; ``null`` when the id is only
    #: listed in the alert's ``evidence_event_ids`` array.
    role: str | None = None
    added_at: datetime | None = None
    attributes: JsonObject | None = None


class AnalystActionItem(ApiModel):
    action_id: str
    occurred_at: datetime
    actor: str
    role: str
    action: str
    alert_id: str | None = None
    details: JsonObject | None = None


class RuleBrief(ApiModel):
    rule_id: str
    version: str
    title: str
    description: str
    false_positives: list[str]
    blind_spots: list[str]
    mitre_techniques: list[str]


class AssetBrief(ApiModel):
    asset_id: str
    asset_type: AssetType
    name: str
    display_name: str | None = None
    environment: str
    criticality: str


class AlertDetailResponse(ApiModel):
    alert: AlertRecord
    analyst_state: AnalystStateView
    rule: RuleBrief | None = None
    asset: AssetBrief | None = None
    #: Evidence events resolved via ``alert_evidence`` (+ the alert's id array), in order:
    #: trigger events first, then by ``added_at``.
    evidence: list[EvidenceEvent]
    #: Evidence ids referenced by the alert that have no stored event (expired by TTL,
    #: not yet written, or lost). Shown explicitly, never silently dropped.
    unresolved_evidence_ids: list[str]
    #: Distinct evidence ids known for the alert (``alert_evidence`` plus the alert array).
    evidence_total: int
    #: True when this response lists fewer evidence ids than ``evidence_total``.
    evidence_capped: bool
    actions: list[AnalystActionItem]


class AlertStateUpdate(ApiModel):
    status: AnalystStatus
    assignee: str | None = Field(
        default=None, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$"
    )
    note: str | None = Field(default=None, max_length=2048)
    #: Optimistic concurrency (best effort): reject with 409 unless the current analyst
    #: state was last updated exactly at this time.
    expected_updated_at: datetime | None = None

    @field_validator("note")
    @classmethod
    def _no_control_chars(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(ch) < 32 and ch not in "\n\t" for ch in value) or "\x7f" in value:
            raise ValueError("note must not contain control characters")
        return value


class AlertStateResponse(ApiModel):
    alert_id: str
    state: AnalystStateView
    action_id: str


class ContextResponse(ApiModel):
    alert_id: str
    #: ``stored``: latest persisted context; ``built_on_demand``: built for this request.
    source: Literal["stored", "built_on_demand"]
    #: Whether an on-demand context was saved (only analyst requests persist; viewers
    #: receive an ephemeral build so read-only users never cause writes).
    persisted: bool
    context: InvestigationContext


class AssessmentListResponse(ApiModel):
    alert_id: str
    items: list[AIAssessment]
    #: Stored assessment rows that failed contract validation (not shown).
    invalid_records: int
    #: ``ai.store`` when E's store module served the data, else ``direct`` (API query).
    source: Literal["ai.store", "direct"]


class SummaryResponse(ApiModel):
    alert_id: str
    assessment: AIAssessment


# ── Events ────────────────────────────────────────────────────────────────────────


class EventListResponse(ApiModel):
    items: list[EventListItem]
    page: PageInfo
    range: TimeRange


class EventIngestInfo(ApiModel):
    ingested_time: datetime
    producer_id: str
    batch_id: str


class EventDetailResponse(ApiModel):
    #: The validated SecurityEvent (contract schema 1.0 or 1.1) exactly as stored.
    event: SecurityEvent
    ingest: EventIngestInfo
    #: Alerts that cite this event as evidence.
    alert_ids: list[str]


# ── Services (schema 1.1: Asset -> Service -> ServiceInstance) ─────────────────────

#: Effective coverage of a service at request time:
#: ``unsupported`` (no adapter exists), ``planned`` (extension point only, no telemetry),
#: ``unmonitored`` (adapter implemented but not enabled/configured), ``degraded`` (enabled
#: but stale/failing/partially unavailable, as reported or as derived by the API), and
#: ``monitored`` (enabled and fresh).
CoverageState = Literal["monitored", "degraded", "unmonitored", "planned", "unsupported"]
Exposure = Literal["any", "unknown", "private", "loopback"]


class ServiceEndpointView(ApiModel):
    """A port of a service. ``attribution`` states how the port was tied to the service:
    ``confirmed`` (socket owner observed), ``inferred`` (configuration / well-known port),
    ``unknown``. ``exposure`` derives from the bind address (``unknown`` also covers
    public addresses)."""

    protocol: Literal["tcp", "udp"]
    address: str | None = None
    port: int
    exposure: Literal["loopback", "private", "any", "unknown"]
    attribution: PortAttribution
    attribution_basis: str | None = None


class ServiceCoverageCounts(ApiModel):
    monitored: int = 0
    degraded: int = 0
    unmonitored: int = 0
    planned: int = 0
    unsupported: int = 0
    total: int = 0


class ServiceKindSummary(ApiModel):
    service_kind: ServiceKind
    coverage: ServiceCoverageCounts


class ServicesSummary(ApiModel):
    """Coverage of the services in scope (present services only; tombstones apart)."""

    #: False when no service record exists in scope (service discovery has not reported).
    reported: bool
    coverage: ServiceCoverageCounts
    #: Host OS services, applications, Kubernetes workloads and Kubernetes Services are
    #: counted separately (a Kubernetes Service is never a host service).
    by_kind: list[ServiceKindSummary]
    #: Services marked as no longer observed (``present=false``), not in ``coverage``.
    removed: int
    #: True when more service records exist than the API evaluated (bounded read).
    truncated: bool
    note: str | None = None


class ServiceListItem(ApiModel):
    service_id: str
    #: Parent asset (host, Kubernetes node or cluster, repository).
    asset_id: str
    service_kind: ServiceKind
    #: Natural key (systemd unit, launchd label, ``<ns>/<kind>/<name>``, ``<ns>/<name>``).
    service_key: str
    name: str
    category: ServiceCategory
    product: str | None = None
    version: str | None = None
    discovered_via: list[DiscoveryEvidence]
    adapter_id: str | None = None
    adapter_support: AdapterSupport
    #: Monitoring status as reported by the collector when it last refreshed the record.
    monitoring_status: MonitoringStatus
    #: Effective state at request time (see docs/api/README.md, "Service coverage").
    coverage_state: CoverageState
    #: Collector's explanation of the reported state.
    coverage_note: str | None = None
    #: API-derived qualifications (stale discovery report, stale telemetry collectors).
    coverage_reasons: list[str]
    #: Source types the adapter collects for this service.
    telemetry_sources: list[str]
    endpoints: list[ServiceEndpointView]
    #: Distinct endpoint exposures, widest first (empty when no endpoint is known).
    exposures: list[Exposure]
    #: Configuration file references (paths only, never contents).
    config_refs: list[str]
    instance_count: int | None = None
    #: Latest telemetry time reported by the collector (``null`` if never reported).
    last_telemetry_at: datetime | None = None
    first_seen: datetime
    last_seen: datetime
    #: Seconds since discovery last refreshed this record.
    report_age_seconds: float
    #: ``report_age_seconds`` exceeds the configured service staleness threshold.
    report_stale: bool
    #: False: the service is no longer observed (tombstone).
    present: bool
    observed_by: str


class ServiceRecord(ServiceListItem):
    attributes: JsonObject | None = None
    #: Stored endpoint entries that failed contract validation (not shown).
    invalid_endpoints: int = 0


class ServiceListResponse(ApiModel):
    items: list[ServiceListItem]
    page: PageInfo
    #: Coverage summary over every service matching the filters (before pagination).
    summary: ServicesSummary
    #: Stored service rows that failed validation (not shown).
    invalid_records: int = 0


class AssetServicesResponse(ApiModel):
    asset_id: str
    #: ``null`` when the asset record itself has not been reported (services exist).
    asset: AssetBrief | None = None
    items: list[ServiceListItem]
    page: PageInfo
    summary: ServicesSummary
    invalid_records: int = 0


class ServiceInstanceItem(ApiModel):
    """A process, container or Pod of a service (``v_service_instances_current``)."""

    instance_id: str
    service_id: str
    #: Host or Kubernetes node asset it runs on (``null`` if not reported).
    asset_id: str | None = None
    instance_kind: InstanceKind
    instance_key: str
    parent_instance_id: str | None = None
    state: Literal["running", "stopped", "pending", "failed", "unknown"]
    pid: int | None = None
    process_name: str | None = None
    user: str | None = None
    namespace: str | None = None
    pod_name: str | None = None
    pod_uid: str | None = None
    container_name: str | None = None
    container_id: str | None = None
    image: str | None = None
    node_name: str | None = None
    workload_kind: str | None = None
    workload_name: str | None = None
    started_at: datetime | None = None
    observed_at: datetime
    observed_by: str
    #: ``observed_at`` is older than the service staleness threshold.
    stale: bool
    attributes: JsonObject | None = None


class ServiceSourceCollector(ApiModel):
    collector_id: str
    asset_id: str
    status: HealthStatus
    last_success_at: datetime | None = None
    interval_seconds: int
    stale: bool
    stale_reason: str | None = None


class ServiceTelemetrySource(ApiModel):
    source_type: str
    #: Listed in the service's ``telemetry_sources`` (declared by its adapter); false for
    #: sources that only appear in attributed events.
    declared: bool
    #: Collectors of the service's asset (or a parent asset) reporting this source type.
    collectors: list[ServiceSourceCollector]
    #: ``fresh``: a reporting collector is fresh; ``stale``: every reporting collector is
    #: stale; ``no_collector_health``: no collector health mentions this source here.
    collection: Literal["fresh", "stale", "no_collector_health"]
    #: Distinct events attributed to this service from this source in ``telemetry_range``.
    events: int
    last_event_at: datetime | None = None
    last_ingested_at: datetime | None = None


class AuthSourceActivity(ApiModel):
    src_ip: str
    events: int
    #: Events with outcome ``failure`` or ``denied``.
    failures: int
    last_seen: datetime


class ServiceAuthActivity(ApiModel):
    """Authentication events attributed to the service (category ``authentication``)."""

    range: TimeRange
    total: int
    #: Distinct events per outcome (success, failure, denied, unknown).
    by_outcome: dict[str, int]
    distinct_actors: int
    distinct_sources: int
    #: Source addresses ordered by failures, then events (bounded).
    top_sources: list[AuthSourceActivity]


# ── Assets ────────────────────────────────────────────────────────────────────────


class AssetListItem(ApiModel):
    asset_id: str
    asset_type: AssetType
    name: str
    display_name: str | None = None
    parent_asset_id: str | None = None
    environment: str
    criticality: str
    owner: str | None = None
    labels: dict[str, str]
    first_seen: datetime
    last_seen: datetime
    observed_by: str
    collectors_total: int
    collectors_stale: int
    coverage_status: CoverageStatus
    last_event_at: datetime | None = None
    open_alerts: int


class AssetListResponse(ApiModel):
    items: list[AssetListItem]
    page: PageInfo


class AssetRecord(AssetListItem):
    attributes: JsonObject | None = None


class InventoryTypeSummary(ApiModel):
    item_type: str
    items: int
    last_observed_at: datetime | None = None


class SourceTypeEventCount(ApiModel):
    source_type: str
    #: Distinct events (``uniqExact(event_id)``) in the requested range.
    events: int
    last_event_at: datetime | None = None
    last_ingested_at: datetime | None = None


class FindingItem(ApiModel):
    finding_id: str
    asset_id: str
    scanner: str
    check_id: str
    category: str
    severity: Severity
    title: str
    #: Lifecycle state from ``v_findings_current``; ``null`` when lifecycle is unavailable.
    state: Literal["open", "unverified", "resolved"] | None = None
    first_observed_at: datetime | None = None
    last_observed_at: datetime
    last_scan_run_id: str | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    resource_namespace: str | None = None
    resource_path: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cvss_score: float | None = None
    remediation: str | None = None
    accepted_risk_reason: str | None = None
    #: Service the finding applies to when the scanner attributed it (schema 1.1): the
    #: latest non-null attribution among the finding's observations; ``null`` otherwise.
    service_id: str | None = None
    #: Scan scope the lifecycle state applies to (lifecycle view only).
    scope_hash: str | None = None
    #: Completion time of the latest succeeded scan of that scope (lifecycle view only).
    last_success_at: datetime | None = None
    #: Effective status of the latest scan attempt of that scope (lifecycle view only).
    latest_scan_status: str | None = None


class FindingsSummary(ApiModel):
    #: True: ``counts`` are findings in state ``open`` (``unverified`` reported apart).
    #: False (``v_findings_current`` absent): ``counts`` are distinct finding fingerprints
    #: observed within retention, without open/resolved semantics.
    lifecycle_available: bool
    source: Literal["v_findings_current", "finding_observations"]
    counts: SeverityCounts
    #: Lifecycle mode only: findings whose current presence cannot be confirmed.
    unverified: SeverityCounts | None = None
    note: str | None = None


class AssetDetailResponse(ApiModel):
    asset: AssetRecord
    collectors: list[CollectorStatus]
    inventory: list[InventoryTypeSummary]
    event_counts: list[SourceTypeEventCount]
    event_counts_range: TimeRange
    findings_summary: FindingsSummary
    findings: list[FindingItem]
    recent_alerts: list[AlertListItem]
    #: Services discovered on this asset by coverage state and kind (schema 1.1). Full
    #: list: ``GET /assets/{asset_id}/services``.
    services_summary: ServicesSummary
    #: Assets whose ``parent_asset_id`` is this asset, e.g. the Kubernetes nodes
    #: (``kubernetes_node``) of a cluster.
    child_assets: list[AssetBrief] = Field(default_factory=list)


# ── Findings ──────────────────────────────────────────────────────────────────────


class FindingListResponse(ApiModel):
    lifecycle_available: bool
    source: Literal["v_findings_current", "finding_observations"]
    items: list[FindingItem]
    page: PageInfo
    note: str | None = None


# ── Service detail ────────────────────────────────────────────────────────────────


class ServiceDetailResponse(ApiModel):
    service: ServiceRecord
    #: Parent asset (``null`` when the asset record has not been reported).
    asset: AssetBrief | None = None
    #: Present instances (processes, containers, Pods), newest observation first.
    instances: list[ServiceInstanceItem]
    instances_total: int
    #: Window of ``telemetry``, ``auth_activity`` and ``recent_events``.
    telemetry_range: TimeRange
    #: Per telemetry source: declared/observed, collector freshness, attributed events.
    telemetry: list[ServiceTelemetrySource]
    auth_activity: ServiceAuthActivity
    #: Latest events attributed to the service (``GET /events?service_id=`` pages them).
    recent_events: list[EventListItem]
    #: Findings attributed to the service (misconfigurations, vulnerabilities, ...).
    findings_lifecycle_available: bool
    findings: list[FindingItem]
    findings_total: int
    #: Alerts whose ``service_ids`` contain this service, within ``alerts_range``.
    alerts: list[AlertListItem]
    alerts_total: int
    alerts_range: TimeRange
    notes: list[str]


# ── Rules ─────────────────────────────────────────────────────────────────────────


class RuleRunSummary(ApiModel):
    rule_version: str
    last_run_at: datetime
    last_status: str
    last_error: str | None = None
    last_duration_ms: int
    missing_sources: list[str]
    runs_24h: int
    failures_24h: int


class RuleListItem(ApiModel):
    rule_id: str
    version: str
    title: str
    severity: Severity
    status: str
    enabled: bool
    mitre_techniques: list[str]
    asset_types: list[str]
    loaded_at: datetime
    interval_seconds: int | None = None
    last_run: RuleRunSummary | None = None
    #: No run within 3 x interval (``null`` when the interval is unknown).
    run_stale: bool | None = None
    alerts_total: int
    alerts_open: int


class RuleListResponse(ApiModel):
    items: list[RuleListItem]
    page: PageInfo


class RuleVersionItem(ApiModel):
    version: str
    loaded_at: datetime
    query_sha256: str
    enabled: bool


class RuleRecord(ApiModel):
    rule_id: str
    version: str
    title: str
    description: str
    severity: Severity
    status: str
    enabled: bool
    mitre_techniques: list[str]
    asset_types: list[str]
    requires: Any = None
    schedule: JsonObject | None = None
    dedup: JsonObject | None = None
    group_by: list[str]
    params: JsonObject | None = None
    false_positives: list[str]
    blind_spots: list[str]
    references: list[str]
    query_sha256: str
    query_text: str
    loaded_at: datetime


class RuleRunItem(ApiModel):
    run_id: str
    rule_version: str
    started_at: datetime
    finished_at: datetime
    window_start: datetime
    window_end: datetime
    status: str
    rows_matched: int
    alerts_created: int
    alerts_updated: int
    duration_ms: int
    error: str | None = None
    missing_sources: list[str]
    detector_instance: str


class RuleDetailResponse(ApiModel):
    rule: RuleRecord
    versions: list[RuleVersionItem]
    last_run: RuleRunSummary | None = None
    interval_seconds: int | None = None
    run_stale: bool | None = None
    recent_runs: list[RuleRunItem]
    alerts_by_status: dict[str, int]


# ── Health ────────────────────────────────────────────────────────────────────────


class StorageHealth(ApiModel):
    reachable: bool
    error: str | None = None


class PipelineComponentHealth(ApiModel):
    component: str
    instance: str
    status: HealthStatus
    last_reported_at: datetime
    report_age_seconds: float
    #: Latest report older than the configured threshold.
    stale: bool
    #: Stale AND a newer instance of the same component is reporting (e.g. a recreated
    #: container); clients may collapse these rows.
    superseded: bool
    queue_depth: int
    oldest_queued_age_seconds: float | None = None
    accepted_total: int
    duplicate_total: int
    rejected_total: int
    quarantined_total: int
    written_total: int
    write_errors_total: int
    dead_letter_total: int
    last_write_at: datetime | None = None
    details: JsonObject = Field(default_factory=dict)


class RuleHealthItem(ApiModel):
    rule_id: str
    title: str | None = None
    enabled: bool | None = None
    interval_seconds: int | None = None
    last_run: RuleRunSummary | None = None
    #: ``true`` when the rule never ran or its last run is older than 3 x interval.
    run_stale: bool | None = None


class AIProviderHealth(ApiModel):
    provider: str
    task: str
    #: Provider credential present (presence only; ``null`` when it cannot be determined).
    configured: bool | None = None
    #: Feature flag state (``null`` when it cannot be determined).
    enabled: bool | None = None
    window_hours: int
    status_counts: dict[str, int]
    last_assessment_at: datetime | None = None
    last_ok_at: datetime | None = None
    last_status: str | None = None
    last_error: str | None = None


class IngestSecuritySummary(ApiModel):
    window_hours: int
    quarantined_records: int
    audit_decisions: dict[str, int]


class HealthResponse(ApiModel):
    generated_at: datetime
    storage: StorageHealth
    collectors: list[CollectorStatus]
    pipeline: list[PipelineComponentHealth]
    rules: list[RuleHealthItem]
    ai: list[AIProviderHealth]
    ai_configuration_source: str
    ingest: IngestSecuritySummary | None = None
    notes: list[str]


# ── Time series / overview ────────────────────────────────────────────────────────


class SeriesPoint(ApiModel):
    bucket_start: datetime
    group: str | None = None
    count: int


class TimeSeriesResponse(ApiModel):
    metric: Literal["alerts", "events"]
    range: TimeRange
    bucket_seconds: int
    group_by: str | None = None
    #: Sparse: buckets without stored rows are omitted. Absence of a bucket means "no rows
    #: stored", which is not proof of zero activity when collection was unhealthy.
    points: list[SeriesPoint]
    truncated: bool


class CollectionHealthSummary(ApiModel):
    collectors_total: int
    collectors_ok: int
    collectors_stale: int
    collectors_failing: int
    pipeline_components: int
    pipeline_unhealthy: int
    rules_total: int
    rules_failing: int
    rule_failures_24h: int
    #: Explicit flags for empty sources (nothing reported yet).
    no_collector_reports: bool
    no_pipeline_reports: bool
    no_rule_runs: bool


class OverviewResponse(ApiModel):
    generated_at: datetime
    asset_coverage: list[AssetClassCoverage]
    open_alerts: SeverityCounts
    open_findings: FindingsSummary
    alerts_over_time: TimeSeriesResponse
    collection_health: CollectionHealthSummary
    recent_important_alerts: list[AlertListItem]
    #: Service coverage across all assets (schema 1.1).
    service_coverage: ServicesSummary


class ServiceHealth(ApiModel):
    status: Literal["ok"]

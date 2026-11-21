/**
 * Runtime validation for every analyst-API response the console renders.
 *
 * Source of truth: D1's response models (backend/src/extorq/api/schemas.py, exported to
 * docs/api/openapi.json) and the lead's contracts (backend/src/extorq/contracts, schema 1.1).
 * `src/lib/api/contract-check.ts` asserts at compile time that these schemas stay
 * assignable to the types generated from the OpenAPI document (`pnpm gen:api`).
 *
 * Rules:
 * - `z.object` strips unknown keys, so nothing unexpected reaches a component.
 * - Unknown values are `null` in the API; optional-nullable fields use `.nullish()`
 *   and are normalised to `null` by the components, never replaced by placeholders.
 * - Every string here may be attacker-controlled telemetry: components render it as
 *   plain text only (see src/lib/security/display.ts).
 */
import { z } from "zod";

// ── Primitives ───────────────────────────────────────────────────────────────────

/** ISO-8601 timestamp with an explicit offset (the API always sends UTC). */
export const zTime = z.iso.datetime({ offset: true });

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const zSeverity = z.enum(SEVERITIES);
export type Severity = z.infer<typeof zSeverity>;

export const ANALYST_STATUSES = [
  "new",
  "acknowledged",
  "investigating",
  "closed_true_positive",
  "closed_benign",
  "closed_false_positive",
] as const;
export const zAnalystStatus = z.enum(ANALYST_STATUSES);
export type AnalystStatus = z.infer<typeof zAnalystStatus>;

export const HEALTH_STATUSES = ["ok", "degraded", "failed", "disabled", "unknown"] as const;
export const zHealthStatus = z.enum(HEALTH_STATUSES);
export type HealthStatus = z.infer<typeof zHealthStatus>;

export const COVERAGE_STATUSES = ["ok", "degraded", "stale", "missing"] as const;
export const zCoverageStatus = z.enum(COVERAGE_STATUSES);
export type CoverageStatus = z.infer<typeof zCoverageStatus>;

export const ASSET_TYPES = [
  "macos_host",
  "linux_host",
  "kubernetes_cluster",
  "kubernetes_node",
  "kubernetes_namespace",
  "kubernetes_workload",
  "github_account",
  "github_repository",
] as const;
export type AssetType = (typeof ASSET_TYPES)[number];
/**
 * Asset types are validated as strings: a type added by a later contract version (1.1 added
 * `kubernetes_node`) must not make a whole page fail. Unknown types render as their raw token.
 */
export const zAssetType = z.string().min(1).max(64);

export const FINDING_STATES = ["open", "unverified", "resolved"] as const;
export const zFindingState = z.enum(FINDING_STATES);
export type FindingState = z.infer<typeof zFindingState>;

const zJsonObject = z.record(z.string(), z.unknown());
const zStringMap = z.record(z.string(), z.string());
const zAttributeValue = z.union([
  z.string(),
  z.number(),
  z.boolean(),
  z.null(),
  z.array(z.union([z.string(), z.number(), z.boolean()])),
]);
export const zAttributes = z.record(z.string(), zAttributeValue);

// ── Common ───────────────────────────────────────────────────────────────────────

export const zErrorResponse = z.object({
  detail: z.union([z.string(), z.array(zJsonObject)]),
  request_id: z.string().nullish(),
});

export const zPageInfo = z.object({
  limit: z.number().int(),
  offset: z.number().int(),
  returned: z.number().int(),
  has_more: z.boolean(),
  next_offset: z.number().int().nullish(),
  total: z.number().int().nullish(),
});
export type PageInfo = z.infer<typeof zPageInfo>;

export const zTimeRange = z.object({ since: zTime, until: zTime });
export type TimeRange = z.infer<typeof zTimeRange>;

export const zSeverityCounts = z.object({
  info: z.number().int().default(0),
  low: z.number().int().default(0),
  medium: z.number().int().default(0),
  high: z.number().int().default(0),
  critical: z.number().int().default(0),
  total: z.number().int().default(0),
});
export type SeverityCounts = z.infer<typeof zSeverityCounts>;

/** Enum-like token validated as a bounded string (new values must not fail a page). */
const zToken = z.string().min(1).max(128);

// Service coverage summary (D1 ServicesSummary, contracts 1.1): used by overview, asset and service views.
const zServiceCoverageCounts = z.object({
  monitored: z.number().int().default(0),
  degraded: z.number().int().default(0),
  unmonitored: z.number().int().default(0),
  planned: z.number().int().default(0),
  unsupported: z.number().int().default(0),
  total: z.number().int().default(0),
});
export type ServiceCoverageCounts = z.infer<typeof zServiceCoverageCounts>;

export const zServicesSummary = z.object({
  /** False when no service record exists in scope (discovery has not reported). */
  reported: z.boolean(),
  coverage: zServiceCoverageCounts,
  by_kind: z.array(z.object({ service_kind: zToken, coverage: zServiceCoverageCounts })),
  removed: z.number().int(),
  truncated: z.boolean(),
  note: z.string().nullish(),
});
export type ServicesSummary = z.infer<typeof zServicesSummary>;

// ── Collectors / coverage ────────────────────────────────────────────────────────

export const zCollectorStatus = z.object({
  collector_id: z.string(),
  collector_type: z.string(),
  asset_id: z.string(),
  source_types: z.array(z.string()),
  status: zHealthStatus,
  last_reported_at: zTime,
  last_attempt_at: zTime.nullish(),
  last_success_at: zTime.nullish(),
  last_error: z.string().nullish(),
  events_collected: z.number().int(),
  records_buffered: z.number().int(),
  lag_seconds: z.number().nullish(),
  checkpoint_summary: z.string().nullish(),
  collector_version: z.string(),
  interval_seconds: z.number().int(),
  stale: z.boolean(),
  stale_reason: z.string().nullish(),
  seconds_since_success: z.number().nullish(),
  details: zJsonObject.optional(),
});
export type CollectorStatus = z.infer<typeof zCollectorStatus>;

export const zAssetClassCoverage = z.object({
  asset_type: z.string(),
  expected: z.boolean(),
  assets_total: z.number().int(),
  assets_ok: z.number().int(),
  assets_degraded: z.number().int(),
  assets_stale: z.number().int(),
  assets_without_collector: z.number().int(),
  status: zCoverageStatus,
  last_event_at: zTime.nullish(),
});
export type AssetClassCoverage = z.infer<typeof zAssetClassCoverage>;

// ── Alerts ───────────────────────────────────────────────────────────────────────

export const zAlertListItem = z.object({
  alert_id: z.string(),
  rule_id: z.string(),
  rule_version: z.string(),
  rule_title: z.string(),
  severity: zSeverity,
  confidence: z.string(),
  asset_id: z.string(),
  asset_type: z.string(),
  summary: z.string(),
  first_seen: zTime,
  last_seen: zTime,
  event_count: z.number().int(),
  entities: zStringMap,
  /** Services whose telemetry is evidence for the alert (contracts 1.1; [] before 1.1). */
  service_ids: z.array(z.string()).default([]),
  mitre_techniques: z.array(z.string()),
  simulation_run_ids: z.array(z.string()),
  created_at: zTime,
  updated_at: zTime,
  analyst_status: zAnalystStatus,
  analyst_state_recorded: z.boolean(),
  assignee: z.string().nullish(),
});
export type AlertListItem = z.infer<typeof zAlertListItem>;

export const zAlertListResponse = z.object({
  items: z.array(zAlertListItem),
  page: zPageInfo,
  range: zTimeRange,
});
export type AlertListResponse = z.infer<typeof zAlertListResponse>;

export const zAnalystStateView = z.object({
  status: zAnalystStatus,
  assignee: z.string().nullish(),
  note: z.string().nullish(),
  updated_by: z.string().nullish(),
  updated_at: zTime.nullish(),
  recorded: z.boolean(),
});
export type AnalystStateView = z.infer<typeof zAnalystStateView>;

export const zAlertRecord = z.object({
  alert_id: z.string(),
  schema_version: z.string(),
  rule_id: z.string(),
  rule_version: z.string(),
  rule_title: z.string(),
  severity: zSeverity,
  confidence: z.string(),
  asset_id: z.string(),
  asset_type: z.string(),
  group_key: z.string(),
  entities: zStringMap,
  service_ids: z.array(z.string()).default([]),
  summary: z.string(),
  first_seen: zTime,
  last_seen: zTime,
  window_start: zTime,
  window_end: zTime,
  event_count: z.number().int(),
  evidence_event_ids: z.array(z.string()),
  evidence_truncated: z.boolean(),
  features: zJsonObject.nullish(),
  mitre_techniques: z.array(z.string()),
  simulation_run_ids: z.array(z.string()),
  created_at: zTime,
  updated_at: zTime,
  detector_version: z.string(),
});
export type AlertRecord = z.infer<typeof zAlertRecord>;

export const zEventListItem = z.object({
  event_id: z.string(),
  event_type: z.string(),
  category: z.string(),
  asset_id: z.string(),
  asset_type: z.string(),
  source_type: z.string(),
  collector_id: z.string(),
  event_time: zTime,
  observed_time: zTime.nullish(),
  ingested_time: zTime,
  action: z.string().nullish(),
  outcome: z.string(),
  severity_hint: z.string().nullish(),
  actor_type: z.string().nullish(),
  actor_name: z.string().nullish(),
  actor_id: z.string().nullish(),
  src_ip: z.string().nullish(),
  src_port: z.number().int().nullish(),
  dst_ip: z.string().nullish(),
  dst_port: z.number().int().nullish(),
  resource_type: z.string().nullish(),
  resource_name: z.string().nullish(),
  resource_namespace: z.string().nullish(),
  resource_path: z.string().nullish(),
  process_name: z.string().nullish(),
  process_pid: z.number().int().nullish(),
  http_method: z.string().nullish(),
  http_route: z.string().nullish(),
  http_status: z.number().int().nullish(),
  http_request_id: z.string().nullish(),
  k8s_namespace: z.string().nullish(),
  k8s_pod_name: z.string().nullish(),
  k8s_verb: z.string().nullish(),
  k8s_resource: z.string().nullish(),
  k8s_object_name: z.string().nullish(),
  k8s_response_code: z.number().int().nullish(),
  k8s_user: z.string().nullish(),
  k8s_audit_id: z.string().nullish(),
  gh_repository: z.string().nullish(),
  gh_commit_sha: z.string().nullish(),
  gh_workflow_path: z.string().nullish(),
  gh_workflow_run_id: z.number().int().nullish(),
  gh_actor_login: z.string().nullish(),
  simulation_run_id: z.string().nullish(),
  scenario_id: z.string().nullish(),
  /** Kubernetes enrichment of container logs / audit events (1.1). */
  k8s_cluster: z.string().nullish(),
  k8s_node: z.string().nullish(),
  k8s_pod_uid: z.string().nullish(),
  k8s_container: z.string().nullish(),
  /** Service attribution (contracts 1.1): set only when the adapter could attribute it. */
  service_id: z.string().nullish(),
  service_name: z.string().nullish(),
  service_instance_id: z.string().nullish(),
  adapter_id: z.string().nullish(),
  k8s_container_id: z.string().nullish(),
  message: z.string().nullish(),
});
export type EventListItem = z.infer<typeof zEventListItem>;

export const zEvidenceEvent = zEventListItem.extend({
  role: z.string().nullish(),
  added_at: zTime.nullish(),
  attributes: zJsonObject.nullish(),
});
export type EvidenceEvent = z.infer<typeof zEvidenceEvent>;

export const zAnalystActionItem = z.object({
  action_id: z.string(),
  occurred_at: zTime,
  actor: z.string(),
  role: z.string(),
  action: z.string(),
  alert_id: z.string().nullish(),
  details: zJsonObject.nullish(),
});
export type AnalystActionItem = z.infer<typeof zAnalystActionItem>;

export const zRuleBrief = z.object({
  rule_id: z.string(),
  version: z.string(),
  title: z.string(),
  description: z.string(),
  false_positives: z.array(z.string()),
  blind_spots: z.array(z.string()),
  mitre_techniques: z.array(z.string()),
});

export const zAssetBrief = z.object({
  asset_id: z.string(),
  asset_type: zAssetType,
  name: z.string(),
  display_name: z.string().nullish(),
  environment: z.string(),
  criticality: z.string(),
});

export const zAlertDetailResponse = z.object({
  alert: zAlertRecord,
  analyst_state: zAnalystStateView,
  rule: zRuleBrief.nullish(),
  asset: zAssetBrief.nullish(),
  evidence: z.array(zEvidenceEvent),
  unresolved_evidence_ids: z.array(z.string()),
  evidence_total: z.number().int(),
  evidence_capped: z.boolean(),
  actions: z.array(zAnalystActionItem),
});
export type AlertDetailResponse = z.infer<typeof zAlertDetailResponse>;

export const zAlertStateResponse = z.object({
  alert_id: z.string(),
  state: zAnalystStateView,
  action_id: z.string(),
});
export type AlertStateResponse = z.infer<typeof zAlertStateResponse>;

// ── Investigation context (contracts/context.py) ─────────────────────────────────

export const RELATIONSHIP_TYPES = ["direct", "candidate", "unestablished"] as const;
export const zRelationshipType = z.enum(RELATIONSHIP_TYPES);
export type RelationshipType = z.infer<typeof zRelationshipType>;

const zDetectionAlert = z.object({
  schema_version: z.string().default("1.0"),
  alert_id: z.string(),
  rule_id: z.string(),
  rule_version: z.string(),
  rule_title: z.string(),
  severity: zSeverity,
  confidence: z.string(),
  asset_id: z.string(),
  asset_type: z.string(),
  group_key: z.string(),
  entities: zStringMap.default({}),
  service_ids: z.array(z.string()).default([]),
  summary: z.string(),
  first_seen: zTime,
  last_seen: zTime,
  window_start: zTime,
  window_end: zTime,
  event_count: z.number().int(),
  evidence_event_ids: z.array(z.string()),
  evidence_truncated: z.boolean().default(false),
  features: zAttributes.default({}),
  mitre_techniques: z.array(z.string()).default([]),
  simulation_run_ids: z.array(z.string()).default([]),
  created_at: zTime,
  updated_at: zTime,
  detector_version: z.string(),
});

const zRuleMetadata = z.object({
  rule_id: z.string(),
  version: z.string(),
  title: z.string(),
  description: z.string(),
  severity: zSeverity,
  status: z.string().default("stable"),
  mitre_techniques: z.array(z.string()).default([]),
  asset_types: z.array(z.string()),
  requires: z.array(
    z.object({
      source_type: z.string(),
      event_types: z.array(z.string()),
      optional: z.boolean().default(false),
    }),
  ),
  schedule: z.object({
    interval_seconds: z.number().int(),
    lookback_seconds: z.number().int(),
    late_tolerance_seconds: z.number().int().default(300),
  }),
  dedup: z.object({ strategy: z.string(), bucket_seconds: z.number().int().nullish() }),
  group_by: z.array(z.string()),
  params: zAttributes.default({}),
  false_positives: z.array(z.string()).default([]),
  blind_spots: z.array(z.string()).default([]),
  references: z.array(z.string()).default([]),
  query_sha256: z.string(),
});

export const zEventSummary = z.object({
  event_id: z.string(),
  event_time: zTime,
  event_type: z.string(),
  source_type: z.string(),
  asset_id: z.string(),
  outcome: z.string(),
  actor_name: z.string().nullish(),
  src_ip: z.string().nullish(),
  service_id: z.string().nullish(),
  service_name: z.string().nullish(),
  summary: z.string(),
  key_fields: zAttributes.default({}),
});
export type EventSummary = z.infer<typeof zEventSummary>;

export const zRelationship = z.object({
  event_id: z.string(),
  relationship_type: zRelationshipType,
  bases: z.array(z.string()),
  strength: z.enum(["strong", "moderate", "weak"]),
  time_delta_seconds: z.number(),
  explanation: z.string(),
});
export type Relationship = z.infer<typeof zRelationship>;

export const zTimelineEntry = z.object({
  event_id: z.string(),
  time: zTime,
  event_type: z.string(),
  source_type: z.string(),
  summary: z.string(),
  is_evidence: z.boolean(),
  relationship_type: zRelationshipType.nullish(),
});
export type TimelineEntry = z.infer<typeof zTimelineEntry>;

export const zFindingSummary = z.object({
  finding_id: z.string(),
  scanner: z.string(),
  check_id: z.string(),
  severity: zSeverity,
  title: z.string(),
  state: zFindingState,
  last_observed_at: zTime,
});
export type FindingSummary = z.infer<typeof zFindingSummary>;

export const zSourceCoverage = z.object({
  source_type: z.string(),
  collector_id: z.string().nullish(),
  status: zHealthStatus,
  last_success_at: zTime.nullish(),
  lag_seconds: z.number().nullish(),
  stale: z.boolean(),
  gap_during_window: z.boolean(),
  note: z.string().nullish(),
});
export type SourceCoverage = z.infer<typeof zSourceCoverage>;

/** Service involved in an investigation (contracts/context.py ServiceSummary, 1.1). */
export const zServiceSummary = z.object({
  service_id: z.string(),
  asset_id: z.string(),
  name: z.string(),
  service_kind: z.string(),
  category: z.string(),
  adapter_support: z.string(),
  monitoring_status: z.string(),
  role: z.string(),
});
export type ServiceSummary = z.infer<typeof zServiceSummary>;

const zContextAsset = z.object({
  asset_id: z.string(),
  asset_type: z.string(),
  name: z.string(),
  criticality: z.string(),
  environment: z.string(),
});

export const zInvestigationContext = z.object({
  schema_version: z.string().default("1.0"),
  context_id: z.string(),
  alert_id: z.string(),
  builder_version: z.string(),
  created_at: zTime,
  input_hash: z.string(),
  window_start: zTime,
  window_end: zTime,
  alert: zDetectionAlert,
  rule: zRuleMetadata,
  asset: zContextAsset,
  services: z.array(zServiceSummary).default([]),
  related_assets: z.array(zContextAsset).default([]),
  evidence: z.array(zEventSummary),
  timeline: z.array(zTimelineEntry),
  relationships: z.array(zRelationship),
  features: zAttributes.default({}),
  findings: z.array(zFindingSummary).default([]),
  coverage: z.array(zSourceCoverage).default([]),
  missing_telemetry: z.array(z.string()).default([]),
  limitations: z.array(z.string()).default([]),
  simulation_run_ids: z.array(z.string()).default([]),
  truncated: z.record(z.string(), z.boolean()).default({}),
});
export type InvestigationContext = z.infer<typeof zInvestigationContext>;

export const zContextResponse = z.object({
  alert_id: z.string(),
  source: z.enum(["stored", "built_on_demand"]),
  persisted: z.boolean(),
  context: zInvestigationContext,
});
export type ContextResponse = z.infer<typeof zContextResponse>;

// ── AI assessments (contracts/ai.py) ─────────────────────────────────────────────

export const AI_STATUSES = [
  "ok",
  "insufficient_context",
  "invalid_output",
  "timeout",
  "rate_limited",
  "error",
  "disabled",
  "budget_exceeded",
] as const;
export const zAIStatus = z.enum(AI_STATUSES);
export type AIStatus = z.infer<typeof zAIStatus>;

export const zJevAnswer = z.object({
  question_id: z.string(),
  type: z.enum(["noul", "choice", "score"]),
  value: z.union([z.number(), z.string()]),
  confidence: z.number().nullish(),
  probabilities: z.record(z.string(), z.number()).default({}),
});
export type JevAnswer = z.infer<typeof zJevAnswer>;

export const zJevTriageResult = z.object({
  recommendation: z.enum([
    "priority_investigation",
    "routine_review",
    "likely_benign_maintenance",
    "insufficient_context",
  ]),
  uncertain: z.boolean(),
  order_consistent: z.boolean(),
  sufficient_context_probability: z.number(),
  answers: z.array(zJevAnswer),
  rationale_codes: z.array(z.string()).default([]),
  question_set_version: z.string(),
});
export type JevTriageResult = z.infer<typeof zJevTriageResult>;

export const zEvidenceStatement = z.object({
  text: z.string(),
  evidence_ids: z.array(z.string()).default([]),
  verified: z.boolean().default(false),
  unverified_ids: z.array(z.string()).default([]),
});
export type EvidenceStatement = z.infer<typeof zEvidenceStatement>;

export const zSummaryTimelineItem = z.object({
  time: z.string(),
  description: z.string(),
  evidence_ids: z.array(z.string()).default([]),
  verified: z.boolean().default(false),
  unverified_ids: z.array(z.string()).default([]),
});
export type SummaryTimelineItem = z.infer<typeof zSummaryTimelineItem>;

export const zInvestigationSummary = z.object({
  what_happened: z.array(zEvidenceStatement),
  timeline: z.array(zSummaryTimelineItem),
  why_rule_fired: zEvidenceStatement,
  related_activity: z.array(zEvidenceStatement).default([]),
  benign_explanations: z.array(z.string()).default([]),
  missing_information: z.array(z.string()).default([]),
  limitations: z.array(z.string()).default([]),
  recommended_next_steps: z.array(z.string()).default([]),
  overall_confidence: z.enum(["low", "medium", "high"]),
});
export type InvestigationSummary = z.infer<typeof zInvestigationSummary>;

export const zSummaryValidation = z.object({
  schema_valid: z.boolean(),
  evidence_ids_cited: z.number().int(),
  evidence_ids_verified: z.number().int(),
  evidence_ids_rejected: z.number().int(),
  statements_without_evidence: z.number().int(),
});

export const zAIAssessment = z.object({
  schema_version: z.string().default("1.0"),
  assessment_id: z.string(),
  alert_id: z.string(),
  context_id: z.string(),
  context_input_hash: z.string(),
  provider: z.string(),
  model: z.string(),
  task: z.enum(["triage", "summary"]),
  prompt_version: z.string(),
  status: zAIStatus,
  triage: zJevTriageResult.nullish(),
  summary: zInvestigationSummary.nullish(),
  validation: zSummaryValidation.nullish(),
  latency_ms: z.number().int().nullish(),
  input_tokens: z.number().int().nullish(),
  output_tokens: z.number().int().nullish(),
  provider_request_id: z.string().nullish(),
  error: z.string().nullish(),
  created_at: zTime,
  requested_by: z.string(),
});
export type AIAssessment = z.infer<typeof zAIAssessment>;

export const zAssessmentListResponse = z.object({
  alert_id: z.string(),
  items: z.array(zAIAssessment),
  invalid_records: z.number().int(),
  source: z.enum(["ai.store", "direct"]),
});
export type AssessmentListResponse = z.infer<typeof zAssessmentListResponse>;

export const zSummaryResponse = z.object({
  alert_id: z.string(),
  assessment: zAIAssessment,
});
export type SummaryResponse = z.infer<typeof zSummaryResponse>;

// ── Events ───────────────────────────────────────────────────────────────────────

export const zEventListResponse = z.object({
  items: z.array(zEventListItem),
  page: zPageInfo,
  range: zTimeRange,
});
export type EventListResponse = z.infer<typeof zEventListResponse>;

/** The subset of contracts/event.py SecurityEvent the console renders. */
export const zSecurityEvent = z.object({
  schema_version: z.string().default("1.0"),
  event_id: z.string(),
  event_type: z.string(),
  category: z.string(),
  asset_id: z.string(),
  asset_type: z.string(),
  source: z.object({
    source_type: z.string(),
    collector_id: z.string(),
    collector_version: z.string(),
    collection_method: z.string(),
    source_native_id: z.string().nullish(),
  }),
  event_time: zTime,
  observed_time: zTime.nullish(),
  action: z.string().nullish(),
  outcome: z.string().default("unknown"),
  severity_hint: z.string().nullish(),
  actor: z
    .object({
      type: z.string().default("unknown"),
      name: z.string().nullish(),
      id: z.string().nullish(),
      groups: z.array(z.string()).default([]),
      authenticated: z.boolean().nullish(),
    })
    .nullish(),
  service: z
    .object({
      service_id: z.string(),
      name: z.string(),
      instance_id: z.string().nullish(),
      adapter_id: z.string().nullish(),
    })
    .nullish(),
  message: z.string().nullish(),
  attributes: zAttributes.default({}),
  labels: zStringMap.default({}),
  raw: z.string().nullish(),
  provenance: z.object({
    parser: z.string(),
    parser_version: z.string(),
    raw_sha256: z.string().nullish(),
    truncated: z.boolean().default(false),
    redaction_count: z.number().int().default(0),
  }),
  simulation: z.object({ run_id: z.string(), scenario_id: z.string().nullish() }).nullish(),
});
export type SecurityEvent = z.infer<typeof zSecurityEvent>;

export const zEventDetailResponse = z.object({
  event: zSecurityEvent,
  ingest: z.object({ ingested_time: zTime, producer_id: z.string(), batch_id: z.string() }),
  alert_ids: z.array(z.string()),
});
export type EventDetailResponse = z.infer<typeof zEventDetailResponse>;

// ── Assets ───────────────────────────────────────────────────────────────────────

export const zAssetListItem = z.object({
  asset_id: z.string(),
  asset_type: zAssetType,
  name: z.string(),
  display_name: z.string().nullish(),
  parent_asset_id: z.string().nullish(),
  environment: z.string(),
  criticality: z.string(),
  owner: z.string().nullish(),
  labels: zStringMap,
  first_seen: zTime,
  last_seen: zTime,
  observed_by: z.string(),
  collectors_total: z.number().int(),
  collectors_stale: z.number().int(),
  coverage_status: zCoverageStatus,
  last_event_at: zTime.nullish(),
  open_alerts: z.number().int(),
});
export type AssetListItem = z.infer<typeof zAssetListItem>;

export const zAssetListResponse = z.object({
  items: z.array(zAssetListItem),
  page: zPageInfo,
});
export type AssetListResponse = z.infer<typeof zAssetListResponse>;

export const zFindingItem = z.object({
  finding_id: z.string(),
  asset_id: z.string(),
  scanner: z.string(),
  check_id: z.string(),
  category: z.string(),
  severity: zSeverity,
  title: z.string(),
  state: zFindingState.nullish(),
  first_observed_at: zTime.nullish(),
  last_observed_at: zTime,
  last_scan_run_id: z.string().nullish(),
  resource_type: z.string().nullish(),
  resource_name: z.string().nullish(),
  resource_namespace: z.string().nullish(),
  resource_path: z.string().nullish(),
  package_name: z.string().nullish(),
  installed_version: z.string().nullish(),
  fixed_version: z.string().nullish(),
  cve_ids: z.array(z.string()).default([]),
  cvss_score: z.number().nullish(),
  remediation: z.string().nullish(),
  accepted_risk_reason: z.string().nullish(),
  /** Service the finding applies to, when attributable (contracts 1.1). */
  service_id: z.string().nullish(),
});
export type FindingItem = z.infer<typeof zFindingItem>;

export const zFindingsSummary = z.object({
  lifecycle_available: z.boolean(),
  source: z.enum(["v_findings_current", "finding_observations"]),
  counts: zSeverityCounts,
  /** Findings whose current state cannot be confirmed (partial/failed latest scan). */
  unverified: zSeverityCounts.nullish(),
  note: z.string().nullish(),
});
export type FindingsSummary = z.infer<typeof zFindingsSummary>;

export const zAssetDetailResponse = z.object({
  asset: zAssetListItem.extend({ attributes: zJsonObject.nullish() }),
  collectors: z.array(zCollectorStatus),
  inventory: z.array(
    z.object({
      item_type: z.string(),
      items: z.number().int(),
      last_observed_at: zTime.nullish(),
    }),
  ),
  event_counts: z.array(
    z.object({
      source_type: z.string(),
      events: z.number().int(),
      last_event_at: zTime.nullish(),
      last_ingested_at: zTime.nullish(),
    }),
  ),
  event_counts_range: zTimeRange,
  findings_summary: zFindingsSummary,
  findings: z.array(zFindingItem),
  recent_alerts: z.array(zAlertListItem),
  /** Service coverage on this asset (1.1); absent from pre-1.1 APIs. */
  services_summary: zServicesSummary.nullish(),
  /** Kubernetes nodes of a cluster (1.1). */
  child_assets: z.array(zAssetBrief).default([]),
});
export type AssetDetailResponse = z.infer<typeof zAssetDetailResponse>;

export const zFindingListResponse = z.object({
  lifecycle_available: z.boolean(),
  source: z.enum(["v_findings_current", "finding_observations"]),
  items: z.array(zFindingItem),
  page: zPageInfo,
  note: z.string().nullish(),
});
export type FindingListResponse = z.infer<typeof zFindingListResponse>;

// ── Rules ────────────────────────────────────────────────────────────────────────

export const zRuleRunSummary = z.object({
  rule_version: z.string(),
  last_run_at: zTime,
  last_status: z.string(),
  last_error: z.string().nullish(),
  last_duration_ms: z.number().int(),
  missing_sources: z.array(z.string()),
  runs_24h: z.number().int(),
  failures_24h: z.number().int(),
});
export type RuleRunSummary = z.infer<typeof zRuleRunSummary>;

export const zRuleListItem = z.object({
  rule_id: z.string(),
  version: z.string(),
  title: z.string(),
  severity: zSeverity,
  status: z.string(),
  enabled: z.boolean(),
  mitre_techniques: z.array(z.string()),
  asset_types: z.array(z.string()),
  loaded_at: zTime,
  interval_seconds: z.number().int().nullish(),
  last_run: zRuleRunSummary.nullish(),
  run_stale: z.boolean().nullish(),
  alerts_total: z.number().int(),
  alerts_open: z.number().int(),
});
export type RuleListItem = z.infer<typeof zRuleListItem>;

export const zRuleListResponse = z.object({
  items: z.array(zRuleListItem),
  page: zPageInfo,
});
export type RuleListResponse = z.infer<typeof zRuleListResponse>;

// ── Health ───────────────────────────────────────────────────────────────────────

export const zPipelineComponentHealth = z.object({
  component: z.string(),
  instance: z.string(),
  status: zHealthStatus,
  last_reported_at: zTime,
  report_age_seconds: z.number(),
  stale: z.boolean(),
  superseded: z.boolean(),
  queue_depth: z.number().int(),
  oldest_queued_age_seconds: z.number().nullish(),
  accepted_total: z.number().int(),
  duplicate_total: z.number().int(),
  rejected_total: z.number().int(),
  quarantined_total: z.number().int(),
  written_total: z.number().int(),
  write_errors_total: z.number().int(),
  dead_letter_total: z.number().int(),
  last_write_at: zTime.nullish(),
  details: zJsonObject.optional(),
});
export type PipelineComponentHealth = z.infer<typeof zPipelineComponentHealth>;

export const zRuleHealthItem = z.object({
  rule_id: z.string(),
  title: z.string().nullish(),
  enabled: z.boolean().nullish(),
  interval_seconds: z.number().int().nullish(),
  last_run: zRuleRunSummary.nullish(),
  run_stale: z.boolean().nullish(),
});
export type RuleHealthItem = z.infer<typeof zRuleHealthItem>;

export const zAIProviderHealth = z.object({
  provider: z.string(),
  task: z.string(),
  configured: z.boolean().nullish(),
  enabled: z.boolean().nullish(),
  window_hours: z.number().int(),
  status_counts: z.record(z.string(), z.number().int()),
  last_assessment_at: zTime.nullish(),
  last_ok_at: zTime.nullish(),
  last_status: z.string().nullish(),
  last_error: z.string().nullish(),
});
export type AIProviderHealth = z.infer<typeof zAIProviderHealth>;

export const zHealthResponse = z.object({
  generated_at: zTime,
  storage: z.object({ reachable: z.boolean(), error: z.string().nullish() }),
  collectors: z.array(zCollectorStatus),
  pipeline: z.array(zPipelineComponentHealth),
  rules: z.array(zRuleHealthItem),
  ai: z.array(zAIProviderHealth),
  ai_configuration_source: z.string(),
  ingest: z
    .object({
      window_hours: z.number().int(),
      quarantined_records: z.number().int(),
      audit_decisions: z.record(z.string(), z.number().int()),
    })
    .nullish(),
  notes: z.array(z.string()),
});
export type HealthResponse = z.infer<typeof zHealthResponse>;

// ── Time series / overview ───────────────────────────────────────────────────────

export const zSeriesPoint = z.object({
  bucket_start: zTime,
  group: z.string().nullish(),
  count: z.number().int(),
});
export type SeriesPoint = z.infer<typeof zSeriesPoint>;

export const zTimeSeriesResponse = z.object({
  metric: z.enum(["alerts", "events"]),
  range: zTimeRange,
  bucket_seconds: z.number().int(),
  group_by: z.string().nullish(),
  points: z.array(zSeriesPoint),
  truncated: z.boolean(),
});
export type TimeSeriesResponse = z.infer<typeof zTimeSeriesResponse>;

export const zCollectionHealthSummary = z.object({
  collectors_total: z.number().int(),
  collectors_ok: z.number().int(),
  collectors_stale: z.number().int(),
  collectors_failing: z.number().int(),
  pipeline_components: z.number().int(),
  pipeline_unhealthy: z.number().int(),
  rules_total: z.number().int(),
  rules_failing: z.number().int(),
  rule_failures_24h: z.number().int(),
  no_collector_reports: z.boolean(),
  no_pipeline_reports: z.boolean(),
  no_rule_runs: z.boolean(),
});
export type CollectionHealthSummary = z.infer<typeof zCollectionHealthSummary>;

export const zOverviewResponse = z.object({
  generated_at: zTime,
  asset_coverage: z.array(zAssetClassCoverage),
  open_alerts: zSeverityCounts,
  open_findings: zFindingsSummary,
  alerts_over_time: zTimeSeriesResponse,
  collection_health: zCollectionHealthSummary,
  recent_important_alerts: z.array(zAlertListItem),
  /** Service coverage across all assets (1.1); absent from pre-1.1 APIs. */
  service_coverage: zServicesSummary.nullish(),
});
export type OverviewResponse = z.infer<typeof zOverviewResponse>;

// ── Services (contracts/service.py 1.1; D1 ServiceListItem / ServiceDetailResponse) ─────
//
// Field names follow D1's published models (docs/api/openapi.json). Enum-like values are
// validated as strings so a new kind, category or state never fails a page; the console
// renders unknown tokens as themselves.

export const SERVICE_KINDS = ["host_service", "application", "k8s_workload", "k8s_service"] as const;
export type ServiceKind = (typeof SERVICE_KINDS)[number];
export const COVERAGE_STATES = ["monitored", "degraded", "unmonitored", "planned", "unsupported"] as const;
export type CoverageState = (typeof COVERAGE_STATES)[number];

export const zServiceEndpoint = z.object({
  protocol: zToken,
  address: z.string().nullish(),
  port: z.number().int(),
  exposure: zToken,
  attribution: zToken,
  attribution_basis: z.string().nullish(),
});
export type ServiceEndpoint = z.infer<typeof zServiceEndpoint>;

export const zServiceItem = z.object({
  service_id: z.string(),
  asset_id: z.string(),
  service_kind: zToken,
  service_key: z.string(),
  name: z.string(),
  category: zToken,
  product: z.string().nullish(),
  version: z.string().nullish(),
  discovered_via: z.array(z.string()),
  adapter_id: z.string().nullish(),
  adapter_support: zToken,
  /** As the collector last reported it. */
  monitoring_status: zToken,
  /** Effective coverage derived by the API at request time (staleness can downgrade it). */
  coverage_state: zToken,
  coverage_note: z.string().nullish(),
  /** API-derived qualifications, e.g. a stale discovery report or stale source collectors. */
  coverage_reasons: z.array(z.string()).default([]),
  telemetry_sources: z.array(z.string()),
  endpoints: z.array(zServiceEndpoint),
  exposures: z.array(z.string()).default([]),
  config_refs: z.array(z.string()),
  instance_count: z.number().int().nullish(),
  last_telemetry_at: zTime.nullish(),
  first_seen: zTime,
  last_seen: zTime,
  report_age_seconds: z.number(),
  report_stale: z.boolean(),
  present: z.boolean(),
  observed_by: z.string(),
});
export type ServiceItem = z.infer<typeof zServiceItem>;

export const zServiceRecord = zServiceItem.extend({
  attributes: zJsonObject.nullish(),
  invalid_endpoints: z.number().int().default(0),
});
export type ServiceRecord = z.infer<typeof zServiceRecord>;

export const zAssetServicesResponse = z.object({
  asset_id: z.string(),
  asset: zAssetBrief.nullish(),
  items: z.array(zServiceItem),
  page: zPageInfo,
  summary: zServicesSummary,
  invalid_records: z.number().int().default(0),
});
export type AssetServicesResponse = z.infer<typeof zAssetServicesResponse>;

export const zServiceInstance = z.object({
  instance_id: z.string(),
  service_id: z.string(),
  asset_id: z.string().nullish(),
  instance_kind: zToken,
  instance_key: z.string(),
  parent_instance_id: z.string().nullish(),
  state: zToken,
  pid: z.number().int().nullish(),
  process_name: z.string().nullish(),
  user: z.string().nullish(),
  namespace: z.string().nullish(),
  pod_name: z.string().nullish(),
  pod_uid: z.string().nullish(),
  container_name: z.string().nullish(),
  container_id: z.string().nullish(),
  image: z.string().nullish(),
  node_name: z.string().nullish(),
  workload_kind: z.string().nullish(),
  workload_name: z.string().nullish(),
  started_at: zTime.nullish(),
  observed_at: zTime,
  observed_by: z.string(),
  /** observed_at is older than the service staleness threshold. */
  stale: z.boolean(),
});
export type ServiceInstance = z.infer<typeof zServiceInstance>;

export const zServiceTelemetrySource = z.object({
  source_type: z.string(),
  /** Declared by the service's adapter (false: only seen in attributed events). */
  declared: z.boolean(),
  collectors: z.array(
    z.object({
      collector_id: z.string(),
      asset_id: z.string(),
      status: zHealthStatus,
      last_success_at: zTime.nullish(),
      interval_seconds: z.number().int(),
      stale: z.boolean(),
      stale_reason: z.string().nullish(),
    }),
  ),
  collection: zToken,
  events: z.number().int(),
  last_event_at: zTime.nullish(),
  last_ingested_at: zTime.nullish(),
});
export type ServiceTelemetrySource = z.infer<typeof zServiceTelemetrySource>;

export const zServiceAuthActivity = z.object({
  range: zTimeRange,
  total: z.number().int(),
  by_outcome: z.record(z.string(), z.number().int()),
  distinct_actors: z.number().int(),
  distinct_sources: z.number().int(),
  top_sources: z.array(
    z.object({
      src_ip: z.string(),
      events: z.number().int(),
      failures: z.number().int(),
      last_seen: zTime,
    }),
  ),
});
export type ServiceAuthActivity = z.infer<typeof zServiceAuthActivity>;

export const zServiceDetailResponse = z.object({
  service: zServiceRecord,
  asset: zAssetBrief.nullish(),
  instances: z.array(zServiceInstance),
  instances_total: z.number().int(),
  telemetry_range: zTimeRange,
  telemetry: z.array(zServiceTelemetrySource),
  auth_activity: zServiceAuthActivity,
  recent_events: z.array(zEventListItem),
  findings_lifecycle_available: z.boolean(),
  findings: z.array(zFindingItem),
  findings_total: z.number().int(),
  alerts: z.array(zAlertListItem),
  alerts_total: z.number().int(),
  alerts_range: zTimeRange,
  notes: z.array(z.string()),
});
export type ServiceDetailResponse = z.infer<typeof zServiceDetailResponse>;

-- ExtorQ core schema, migration 0001 (contract schema 1.0).
-- Applied by `extorq migrate` using the admin identity only. Idempotent.
--
-- Conventions (docs/data-model.md):
--   * Every timestamp is DateTime64(3, 'UTC'). Producers send aware UTC times.
--   * Sorting keys DO NOT enforce uniqueness. Logical entities use
--     ReplacingMergeTree keyed by a deterministic identity (contracts/identity.py).
--     Every analytical query must be duplicate-safe: uniqExact(id), argMax(), or FINAL.
--   * Nullable means "genuinely unknown". Writers never substitute placeholders.
--   * JSON-bearing columns (attributes, features, body, output, ...) hold canonical
--     JSON text produced by extorq.contracts.identity.canonical_json.
--   * argMax over a Nullable column skips NULLs; use argMax(tuple(col), ts).1 when
--     "latest value, even if NULL" is required (see v_collector_latest).

CREATE DATABASE IF NOT EXISTS extorq;

-- ── Assets and inventory ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS extorq.assets
(
    asset_id         String,
    asset_type       LowCardinality(String),
    name             String,
    display_name     Nullable(String),
    parent_asset_id  Nullable(String),
    environment      LowCardinality(String),
    criticality      LowCardinality(String),
    owner            Nullable(String),
    labels           Map(String, String),
    attributes       String,
    first_seen       DateTime64(3, 'UTC'),
    last_seen        DateTime64(3, 'UTC'),
    observed_by      LowCardinality(String),
    producer_id      LowCardinality(String),
    ingested_at      DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY asset_id;

CREATE TABLE IF NOT EXISTS extorq.inventory_items
(
    asset_id      LowCardinality(String),
    item_type     LowCardinality(String),
    item_key      String,
    attributes    String,
    snapshot_id   String,
    observed_at   DateTime64(3, 'UTC'),
    present       UInt8,
    collector_id  LowCardinality(String),
    producer_id   LowCardinality(String),
    ingested_at   DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(observed_at)
ORDER BY (asset_id, item_type, item_key)
TTL toDateTime(observed_at) + INTERVAL 30 DAY;

-- ── Normalised security events ──────────────────────────────────────────────────
-- Column mapping from SecurityEvent (writer: extorq.storage.rows.event_to_row):
--   source.*            -> source_type, collector_id, collector_version,
--                          collection_method, source_native_id
--   actor.*             -> actor_type, actor_name, actor_id
--   resource.*          -> resource_type, resource_name, resource_namespace, resource_path
--   network.*           -> src_ip, src_port, dst_ip, dst_port, net_protocol
--   process.*           -> process_name, process_pid, process_executable, process_command_line
--   http.*              -> http_method, http_route, http_status, http_request_id, http_user_agent
--   kubernetes.*        -> k8s_cluster, k8s_namespace, k8s_pod_name, k8s_pod_uid,
--                          k8s_container, k8s_node, k8s_verb, k8s_resource, k8s_subresource,
--                          k8s_object_name, k8s_audit_id, k8s_response_code, k8s_user,
--                          k8s_user_groups, k8s_source_ips
--   github.*            -> gh_repository, gh_ref, gh_commit_sha, gh_workflow_path,
--                          gh_workflow_run_id, gh_actor_login, gh_event_name, gh_conclusion
--   simulation.*        -> simulation_run_id, scenario_id
--   provenance.*        -> parser, parser_version, raw_sha256, truncated, redaction_count
--   attributes / labels -> attributes (canonical JSON), labels (Map)
--   whole event         -> payload (canonical JSON of the validated SecurityEvent)
CREATE TABLE IF NOT EXISTS extorq.events
(
    event_id              String,
    schema_version        LowCardinality(String),
    event_type            LowCardinality(String),
    category              LowCardinality(String),
    asset_id              LowCardinality(String),
    asset_type            LowCardinality(String),
    source_type           LowCardinality(String),
    collector_id          LowCardinality(String),
    collector_version     LowCardinality(String),
    collection_method     LowCardinality(String),
    source_native_id      Nullable(String),
    event_time            DateTime64(3, 'UTC'),
    observed_time         Nullable(DateTime64(3, 'UTC')),
    ingested_time         DateTime64(3, 'UTC'),
    action                LowCardinality(Nullable(String)),
    outcome               LowCardinality(String),
    severity_hint         LowCardinality(Nullable(String)),
    actor_type            LowCardinality(Nullable(String)),
    actor_name            Nullable(String),
    actor_id              Nullable(String),
    resource_type         LowCardinality(Nullable(String)),
    resource_name         Nullable(String),
    resource_namespace    Nullable(String),
    resource_path         Nullable(String),
    src_ip                Nullable(String),
    src_port              Nullable(UInt16),
    dst_ip                Nullable(String),
    dst_port              Nullable(UInt16),
    net_protocol          LowCardinality(Nullable(String)),
    process_name          Nullable(String),
    process_pid           Nullable(UInt32),
    process_executable    Nullable(String),
    process_command_line  Nullable(String),
    http_method           LowCardinality(Nullable(String)),
    http_route            Nullable(String),
    http_status           Nullable(UInt16),
    http_request_id       Nullable(String),
    http_user_agent       Nullable(String),
    k8s_cluster           LowCardinality(Nullable(String)),
    k8s_namespace         LowCardinality(Nullable(String)),
    k8s_pod_name          Nullable(String),
    k8s_pod_uid           Nullable(String),
    k8s_container         Nullable(String),
    k8s_node              Nullable(String),
    k8s_verb              LowCardinality(Nullable(String)),
    k8s_resource          LowCardinality(Nullable(String)),
    k8s_subresource       LowCardinality(Nullable(String)),
    k8s_object_name       Nullable(String),
    k8s_audit_id          Nullable(String),
    k8s_response_code     Nullable(UInt16),
    k8s_user              Nullable(String),
    k8s_user_groups       Array(String),
    k8s_source_ips        Array(String),
    gh_repository         LowCardinality(Nullable(String)),
    gh_ref                Nullable(String),
    gh_commit_sha         Nullable(String),
    gh_workflow_path      Nullable(String),
    gh_workflow_run_id    Nullable(UInt64),
    gh_actor_login        Nullable(String),
    gh_event_name         LowCardinality(Nullable(String)),
    gh_conclusion         LowCardinality(Nullable(String)),
    simulation_run_id     Nullable(String),
    scenario_id           LowCardinality(Nullable(String)),
    message               Nullable(String),
    attributes            String,
    labels                Map(String, String),
    raw                   Nullable(String),
    parser                LowCardinality(String),
    parser_version        LowCardinality(String),
    raw_sha256            Nullable(String),
    truncated             UInt8,
    redaction_count       UInt32,
    payload               String,
    producer_id           LowCardinality(String),
    batch_id              String,
    INDEX idx_event_id      event_id        TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_src_ip        src_ip          TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_request_id    http_request_id TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_pod_uid       k8s_pod_uid     TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_audit_id      k8s_audit_id    TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_commit_sha    gh_commit_sha   TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_actor_name    actor_name      TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_sim_run       simulation_run_id TYPE bloom_filter(0.01) GRANULARITY 4
)
ENGINE = ReplacingMergeTree(ingested_time)
PARTITION BY toYYYYMM(event_time)
ORDER BY (asset_id, event_type, event_time, event_id)
TTL toDateTime(event_time) + INTERVAL 90 DAY;

-- ── Scans and findings ──────────────────────────────────────────────────────────
-- row_version (writer): epoch_ms(coalesce(finished_at, started_at)) * 10 + status_rank
--   status_rank: running=0, partial=1, failed=1, succeeded=1  (terminal beats running)
CREATE TABLE IF NOT EXISTS extorq.scan_runs
(
    scan_run_id       String,
    scanner           LowCardinality(String),
    scanner_version   LowCardinality(String),
    asset_id          LowCardinality(String),
    scope_targets     Array(String),
    scope_description String,
    scope_hash        String,
    started_at        DateTime64(3, 'UTC'),
    finished_at       Nullable(DateTime64(3, 'UTC')),
    status            LowCardinality(String),
    checks_total      Nullable(UInt32),
    checks_run        Nullable(UInt32),
    coverage          String,
    findings_count    Nullable(UInt32),
    error             Nullable(String),
    producer_id       LowCardinality(String),
    attributes        String,
    row_version       UInt64,
    ingested_at       DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(row_version)
ORDER BY scan_run_id;

CREATE TABLE IF NOT EXISTS extorq.finding_observations
(
    finding_id            String,
    scan_run_id           String,
    asset_id              LowCardinality(String),
    scanner               LowCardinality(String),
    check_id              String,
    category              LowCardinality(String),
    severity              LowCardinality(String),
    title                 String,
    description           Nullable(String),
    resource_type         Nullable(String),
    resource_name         Nullable(String),
    resource_namespace    Nullable(String),
    resource_path         Nullable(String),
    package_name          Nullable(String),
    installed_version     Nullable(String),
    fixed_version         Nullable(String),
    package_ecosystem     Nullable(String),
    cve_ids               Array(String),
    cvss_score            Nullable(Float32),
    evidence              Nullable(String),
    remediation           Nullable(String),
    reference_urls        Array(String),
    observed_at           DateTime64(3, 'UTC'),
    accepted_risk_reason  Nullable(String),
    accepted_risk_source  Nullable(String),
    attributes            String,
    producer_id           LowCardinality(String),
    ingested_at           DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (asset_id, finding_id, scan_run_id)
TTL toDateTime(observed_at) + INTERVAL 180 DAY;

-- ── Detection ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS extorq.detection_rules
(
    rule_id           LowCardinality(String),
    version           String,
    title             String,
    description       String,
    severity          LowCardinality(String),
    status            LowCardinality(String),
    mitre_techniques  Array(String),
    asset_types       Array(String),
    requires          String,
    schedule          String,
    dedup             String,
    group_by          Array(String),
    params            String,
    false_positives   Array(String),
    blind_spots       Array(String),
    reference_urls    Array(String),
    query_sha256      String,
    query_text        String,
    enabled           UInt8,
    loaded_at         DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(loaded_at)
ORDER BY (rule_id, version);

CREATE TABLE IF NOT EXISTS extorq.rule_runs
(
    run_id             String,
    rule_id            LowCardinality(String),
    rule_version       String,
    started_at         DateTime64(3, 'UTC'),
    finished_at        DateTime64(3, 'UTC'),
    window_start       DateTime64(3, 'UTC'),
    window_end         DateTime64(3, 'UTC'),
    status             LowCardinality(String),
    rows_matched       UInt32,
    alerts_created     UInt32,
    alerts_updated     UInt32,
    duration_ms        UInt32,
    error              Nullable(String),
    missing_sources    Array(String),
    detector_instance  LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(started_at)
ORDER BY (rule_id, started_at)
TTL toDateTime(started_at) + INTERVAL 30 DAY;

-- Alerts are versioned rows; the detection engine preserves created_at and bumps
-- updated_at when late evidence extends an alert. Only extorq_detect may INSERT.
CREATE TABLE IF NOT EXISTS extorq.alerts
(
    alert_id            String,
    schema_version      LowCardinality(String),
    rule_id             LowCardinality(String),
    rule_version        String,
    rule_title          String,
    severity            LowCardinality(String),
    confidence          LowCardinality(String),
    asset_id            LowCardinality(String),
    asset_type          LowCardinality(String),
    group_key           String,
    entities            Map(String, String),
    summary             String,
    first_seen          DateTime64(3, 'UTC'),
    last_seen           DateTime64(3, 'UTC'),
    window_start        DateTime64(3, 'UTC'),
    window_end          DateTime64(3, 'UTC'),
    event_count         UInt64,
    evidence_event_ids  Array(String),
    evidence_truncated  UInt8,
    features            String,
    mitre_techniques    Array(String),
    simulation_run_ids  Array(String),
    created_at          DateTime64(3, 'UTC'),
    updated_at          DateTime64(3, 'UTC'),
    detector_version    LowCardinality(String),
    payload             String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (rule_id, alert_id);

CREATE TABLE IF NOT EXISTS extorq.alert_evidence
(
    alert_id   String,
    event_id   String,
    role       LowCardinality(String),
    added_at   DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(added_at)
ORDER BY (alert_id, event_id);

-- ── Correlation / investigation context ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS extorq.investigation_contexts
(
    context_id           String,
    alert_id             String,
    builder_version      LowCardinality(String),
    input_hash           String,
    created_at           DateTime64(3, 'UTC'),
    window_start         DateTime64(3, 'UTC'),
    window_end           DateTime64(3, 'UTC'),
    evidence_count       UInt32,
    related_count        UInt32,
    direct_count         UInt32,
    candidate_count      UInt32,
    unestablished_count  UInt32,
    body                 String
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (alert_id, context_id);

CREATE TABLE IF NOT EXISTS extorq.context_relationships
(
    context_id          String,
    alert_id            String,
    event_id            String,
    relationship_type   LowCardinality(String),
    bases               Array(String),
    strength            LowCardinality(String),
    time_delta_seconds  Float64,
    explanation         String,
    created_at          DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (alert_id, context_id, event_id);

-- ── AI assessments (advisory; never modify alerts) ──────────────────────────────
CREATE TABLE IF NOT EXISTS extorq.ai_assessments
(
    assessment_id        String,
    alert_id             String,
    context_id           String,
    context_input_hash   String,
    provider             LowCardinality(String),
    model                LowCardinality(String),
    task                 LowCardinality(String),
    prompt_version       LowCardinality(String),
    status               LowCardinality(String),
    recommendation       LowCardinality(Nullable(String)),
    uncertain            Nullable(UInt8),
    output               String,
    latency_ms           Nullable(UInt32),
    input_tokens         Nullable(UInt32),
    output_tokens        Nullable(UInt32),
    provider_request_id  Nullable(String),
    error                Nullable(String),
    created_at           DateTime64(3, 'UTC'),
    requested_by         String
)
ENGINE = ReplacingMergeTree(created_at)
ORDER BY (alert_id, assessment_id);

-- ── Analyst state and actions ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS extorq.analyst_state
(
    alert_id    String,
    status      LowCardinality(String),
    assignee    Nullable(String),
    note        Nullable(String),
    updated_by  String,
    updated_at  DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY alert_id;

CREATE TABLE IF NOT EXISTS extorq.analyst_actions
(
    action_id    String,
    occurred_at  DateTime64(3, 'UTC'),
    actor        String,
    role         LowCardinality(String),
    action       LowCardinality(String),
    alert_id     Nullable(String),
    details      String
)
ENGINE = MergeTree
ORDER BY occurred_at
TTL toDateTime(occurred_at) + INTERVAL 365 DAY;

-- ── Health and pipeline audit ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS extorq.collector_health
(
    collector_id        LowCardinality(String),
    collector_type      LowCardinality(String),
    asset_id            LowCardinality(String),
    source_types        Array(String),
    status              LowCardinality(String),
    reported_at         DateTime64(3, 'UTC'),
    last_attempt_at     Nullable(DateTime64(3, 'UTC')),
    last_success_at     Nullable(DateTime64(3, 'UTC')),
    last_error          Nullable(String),
    events_collected    UInt32,
    records_buffered    UInt32,
    lag_seconds         Nullable(Float64),
    checkpoint_summary  Nullable(String),
    collector_version   LowCardinality(String),
    interval_seconds    UInt32,
    details             String,
    producer_id         LowCardinality(String),
    ingested_at         DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(ingested_at)
ORDER BY (collector_id, reported_at)
TTL toDateTime(reported_at) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS extorq.pipeline_health
(
    component                  LowCardinality(String),
    instance                   LowCardinality(String),
    reported_at                DateTime64(3, 'UTC'),
    status                     LowCardinality(String),
    queue_depth                UInt64,
    oldest_queued_age_seconds  Nullable(Float64),
    accepted_total             UInt64,
    duplicate_total            UInt64,
    rejected_total             UInt64,
    quarantined_total          UInt64,
    written_total              UInt64,
    write_errors_total         UInt64,
    dead_letter_total          UInt64,
    last_write_at              Nullable(DateTime64(3, 'UTC')),
    details                    String
)
ENGINE = MergeTree
ORDER BY (component, instance, reported_at)
TTL toDateTime(reported_at) + INTERVAL 14 DAY;

CREATE TABLE IF NOT EXISTS extorq.ingest_quarantine
(
    quarantine_id    String,
    received_at      DateTime64(3, 'UTC'),
    producer_id      LowCardinality(String),
    batch_id         String,
    record_index     UInt32,
    record_kind      LowCardinality(Nullable(String)),
    reason           String,
    payload_excerpt  String,
    payload_sha256   String
)
ENGINE = ReplacingMergeTree(received_at)
ORDER BY (producer_id, quarantine_id)
TTL toDateTime(received_at) + INTERVAL 30 DAY;

-- Security log of the ingestion boundary (forged / unauthorised telemetry attempts).
CREATE TABLE IF NOT EXISTS extorq.ingest_audit
(
    audit_id                String,
    occurred_at             DateTime64(3, 'UTC'),
    remote_addr             Nullable(String),
    claimed_producer        Nullable(String),
    authenticated_producer  Nullable(String),
    decision                LowCardinality(String),
    reason                  String,
    path                    String
)
ENGINE = MergeTree
ORDER BY occurred_at
TTL toDateTime(occurred_at) + INTERVAL 90 DAY;

-- row_version (writer): status_rank * 10^13 + epoch_ms(coalesce(finished_at, started_at))
--   status_rank: started=1, completed=2, failed=2, cleaned_up=3
CREATE TABLE IF NOT EXISTS extorq.simulation_runs
(
    run_id             String,
    scenario_id        LowCardinality(String),
    asset_id           LowCardinality(String),
    status             LowCardinality(String),
    started_at         DateTime64(3, 'UTC'),
    finished_at        Nullable(DateTime64(3, 'UTC')),
    operator           String,
    description        String,
    expected_rule_ids  Array(String),
    notes              Array(String),
    row_version        UInt64,
    producer_id        LowCardinality(String),
    ingested_at        DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(row_version)
ORDER BY run_id;

-- ── Convenience views (duplicate-safe) ──────────────────────────────────────────
CREATE VIEW IF NOT EXISTS extorq.v_assets AS
SELECT * FROM extorq.assets FINAL;

CREATE VIEW IF NOT EXISTS extorq.v_alerts AS
SELECT * FROM extorq.alerts FINAL;

CREATE VIEW IF NOT EXISTS extorq.v_analyst_state AS
SELECT * FROM extorq.analyst_state FINAL;

CREATE VIEW IF NOT EXISTS extorq.v_inventory_current AS
SELECT * FROM extorq.inventory_items FINAL WHERE present = 1;

CREATE VIEW IF NOT EXISTS extorq.v_collector_latest AS
SELECT
    collector_id,
    argMax(collector_type, reported_at)              AS collector_type,
    argMax(asset_id, reported_at)                    AS asset_id,
    argMax(source_types, reported_at)                AS source_types,
    argMax(status, reported_at)                      AS status,
    max(reported_at)                                 AS last_reported_at,
    argMax(tuple(last_attempt_at), reported_at).1    AS last_attempt_at,
    argMax(tuple(last_success_at), reported_at).1    AS last_success_at,
    argMax(tuple(last_error), reported_at).1         AS last_error,
    argMax(events_collected, reported_at)            AS events_collected,
    argMax(records_buffered, reported_at)            AS records_buffered,
    argMax(tuple(lag_seconds), reported_at).1        AS lag_seconds,
    argMax(tuple(checkpoint_summary), reported_at).1 AS checkpoint_summary,
    argMax(collector_version, reported_at)           AS collector_version,
    argMax(interval_seconds, reported_at)            AS interval_seconds,
    argMax(details, reported_at)                     AS details
FROM extorq.collector_health
GROUP BY collector_id;

CREATE VIEW IF NOT EXISTS extorq.v_pipeline_latest AS
SELECT
    component,
    instance,
    argMax(status, reported_at)                                AS status,
    max(reported_at)                                           AS last_reported_at,
    argMax(queue_depth, reported_at)                           AS queue_depth,
    argMax(tuple(oldest_queued_age_seconds), reported_at).1    AS oldest_queued_age_seconds,
    argMax(accepted_total, reported_at)                        AS accepted_total,
    argMax(duplicate_total, reported_at)                       AS duplicate_total,
    argMax(rejected_total, reported_at)                        AS rejected_total,
    argMax(quarantined_total, reported_at)                     AS quarantined_total,
    argMax(written_total, reported_at)                         AS written_total,
    argMax(write_errors_total, reported_at)                    AS write_errors_total,
    argMax(dead_letter_total, reported_at)                     AS dead_letter_total,
    argMax(tuple(last_write_at), reported_at).1                AS last_write_at,
    argMax(details, reported_at)                               AS details
FROM extorq.pipeline_health
GROUP BY component, instance;

CREATE VIEW IF NOT EXISTS extorq.v_rule_latest_run AS
SELECT
    rule_id,
    argMax(rule_version, started_at)                                   AS rule_version,
    max(started_at)                                                    AS last_run_at,
    argMax(status, started_at)                                         AS last_status,
    argMax(tuple(error), started_at).1                                 AS last_error,
    argMax(duration_ms, started_at)                                    AS last_duration_ms,
    argMax(missing_sources, started_at)                                AS missing_sources,
    countIf(started_at > now64(3) - INTERVAL 1 DAY)                    AS runs_24h,
    countIf(status = 'failed' AND started_at > now64(3) - INTERVAL 1 DAY) AS failures_24h
FROM extorq.rule_runs
GROUP BY rule_id;

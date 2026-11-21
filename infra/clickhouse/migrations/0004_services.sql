-- ExtorQ migration 0004: service-aware monitoring (contract schema 1.1, additive).
-- Lead-owned. Applied by `extorq migrate` (admin identity). Idempotent.
--
-- Hierarchy: Asset -> Service -> ServiceInstance -> events / findings / alerts.
-- Row mapping (writer: extorq.storage.rows):
--   Service          -> services          (endpoints = canonical JSON array of ServiceEndpoint)
--   ServiceInstance  -> service_instances (field `user` -> column process_user)
--   SecurityEvent.service.{service_id,name,instance_id,adapter_id}
--                    -> events.service_id, service_name, service_instance_id, adapter_id
--   SecurityEvent.kubernetes.container_id -> events.k8s_container_id
--   PostureFinding.service_id -> finding_observations.service_id
--   DetectionAlert.service_ids -> alerts.service_ids
-- Latest-state tables are ReplacingMergeTree; read them through the v_* views (FINAL).

CREATE TABLE IF NOT EXISTS extorq.services
(
    service_id          String,
    asset_id            LowCardinality(String),
    service_kind        LowCardinality(String),
    service_key         String,
    name                String,
    category            LowCardinality(String),
    product             LowCardinality(Nullable(String)),
    version             Nullable(String),
    discovered_via      Array(String),
    adapter_id          LowCardinality(Nullable(String)),
    adapter_support     LowCardinality(String),
    monitoring_status   LowCardinality(String),
    coverage_note       Nullable(String),
    telemetry_sources   Array(String),
    endpoints           String,
    config_refs         Array(String),
    instance_count      Nullable(UInt32),
    last_telemetry_at   Nullable(DateTime64(3, 'UTC')),
    attributes          String,
    first_seen          DateTime64(3, 'UTC'),
    last_seen           DateTime64(3, 'UTC'),
    present             UInt8,
    observed_by         LowCardinality(String),
    schema_version      LowCardinality(String),
    producer_id         LowCardinality(String),
    ingested_at         DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(last_seen)
ORDER BY (asset_id, service_id)
TTL toDateTime(last_seen) + INTERVAL 30 DAY;

CREATE TABLE IF NOT EXISTS extorq.service_instances
(
    instance_id         String,
    service_id          String,
    asset_id            LowCardinality(Nullable(String)),
    instance_kind       LowCardinality(String),
    instance_key        String,
    parent_instance_id  Nullable(String),
    state               LowCardinality(String),
    pid                 Nullable(UInt32),
    process_name        Nullable(String),
    process_user        Nullable(String),
    namespace           LowCardinality(Nullable(String)),
    pod_name            Nullable(String),
    pod_uid             Nullable(String),
    container_name      Nullable(String),
    container_id        Nullable(String),
    image               Nullable(String),
    node_name           LowCardinality(Nullable(String)),
    workload_kind       LowCardinality(Nullable(String)),
    workload_name       Nullable(String),
    started_at          Nullable(DateTime64(3, 'UTC')),
    observed_at         DateTime64(3, 'UTC'),
    present             UInt8,
    observed_by         LowCardinality(String),
    attributes          String,
    schema_version      LowCardinality(String),
    producer_id         LowCardinality(String),
    ingested_at         DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(observed_at)
ORDER BY (service_id, instance_id)
TTL toDateTime(observed_at) + INTERVAL 30 DAY;

-- Service attribution on existing tables (Nullable/empty = not attributable).
ALTER TABLE extorq.events ADD COLUMN IF NOT EXISTS k8s_container_id Nullable(String) AFTER k8s_container;
ALTER TABLE extorq.events ADD COLUMN IF NOT EXISTS service_id Nullable(String) AFTER gh_conclusion;
ALTER TABLE extorq.events ADD COLUMN IF NOT EXISTS service_name Nullable(String) AFTER service_id;
ALTER TABLE extorq.events ADD COLUMN IF NOT EXISTS service_instance_id Nullable(String) AFTER service_name;
ALTER TABLE extorq.events ADD COLUMN IF NOT EXISTS adapter_id LowCardinality(Nullable(String)) AFTER service_instance_id;
ALTER TABLE extorq.events ADD INDEX IF NOT EXISTS idx_service_id service_id TYPE bloom_filter(0.01) GRANULARITY 4;
ALTER TABLE extorq.finding_observations ADD COLUMN IF NOT EXISTS service_id Nullable(String) AFTER resource_path;
ALTER TABLE extorq.alerts ADD COLUMN IF NOT EXISTS service_ids Array(String) AFTER entities;

CREATE VIEW IF NOT EXISTS extorq.v_services AS
SELECT * FROM extorq.services FINAL;

CREATE VIEW IF NOT EXISTS extorq.v_service_instances_current AS
SELECT * FROM extorq.service_instances FINAL WHERE present = 1;

-- Grants for the new objects (roles created in 0002). Grafana keeps its
-- column-level grant on events: only the new non-sensitive columns are added.
GRANT INSERT ON extorq.services                    TO extorq_role_ingest;
GRANT INSERT ON extorq.service_instances           TO extorq_role_ingest;
GRANT SELECT ON extorq.services                    TO extorq_role_detect;
GRANT SELECT ON extorq.service_instances           TO extorq_role_detect;
GRANT SELECT ON extorq.v_services                  TO extorq_role_detect;
GRANT SELECT ON extorq.v_service_instances_current TO extorq_role_detect;
GRANT SELECT ON extorq.services                    TO extorq_role_rules_ro;
GRANT SELECT ON extorq.service_instances           TO extorq_role_rules_ro;
GRANT SELECT ON extorq.services                    TO extorq_role_api_ro;
GRANT SELECT ON extorq.service_instances           TO extorq_role_api_ro;
GRANT SELECT ON extorq.v_services                  TO extorq_role_api_ro;
GRANT SELECT ON extorq.v_service_instances_current TO extorq_role_api_ro;
GRANT SELECT ON extorq.services                    TO extorq_role_grafana;
GRANT SELECT ON extorq.service_instances           TO extorq_role_grafana;
GRANT SELECT ON extorq.v_services                  TO extorq_role_grafana;
GRANT SELECT ON extorq.v_service_instances_current TO extorq_role_grafana;
GRANT SELECT(service_id, service_name, service_instance_id, adapter_id, k8s_container_id)
    ON extorq.events TO extorq_role_grafana;

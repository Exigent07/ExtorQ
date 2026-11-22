# ExtorQ data model

Owner: platform. Source of truth: the versioned Pydantic contracts in
`backend/src/extorq/contracts/` (schema **2.0**) and the ClickHouse migrations in
`infra/clickhouse/migrations/` (validated on clickhouse-server 26.8.42.13). This
document describes what is implemented; anything not yet built is marked **planned**.

## 1. Principles

* **One contract per concept.** Every record that crosses a component boundary is one
  of the contract models; nobody defines a parallel format. Models forbid unknown
  fields (`extra="forbid"`) and reject `NaN`/`Infinity` (`allow_inf_nan=False`).
* **Unknown stays unknown.** Optional fields default to `None` and map to `NULL`
  (or an empty array/map). No placeholder ever looks like telemetry.
* **Time.** Every timestamp is timezone-aware UTC; naive timestamps are rejected.
  Storage is `DateTime64(3, 'UTC')` (millisecond precision, truncated, never rounded
  up). clickhouse-connect returns these as naive datetimes that are UTC.
* **Bounded.** Strings are length-limited (`ShortStr` 256, `MediumStr` 2048,
  `LongStr` 16384), attribute maps hold at most 64 keys of scalars or short lists,
  a record is at most 64 KiB of canonical JSON, a batch at most 1000 records/4 MiB.
* **Deterministic identities.** Logical entities get ids derived from source-native
  identity or canonical content (section 3), so re-sent records collapse.
* **Sorting keys are not unique.** ClickHouse `ReplacingMergeTree` collapses rows only
  at merge time; every analytical query must be duplicate-safe (`uniqExact(id)`,
  `argMax(..., version)`, `FINAL`, or the `v_*` views).
* **Versioning.** `schema_version` is `2.0`. Schema 2.0 (2026-11-22, PLAN §12) is a
  breaking change: it removed the simulation category (`SimulationRun`, the
  `simulation_run` record kind, `SecurityEvent.simulation`, `simulation_run_ids` on
  alerts and contexts, the `extorq.simulation` source type) and the AI summary
  contracts (Jev triage is the only AI path), and added the catalog event types
  `github.secret.exposed`, `software.installed` and `software.removed`. The service
  model of 1.1 (PLAN §10) is unchanged. A 1.x envelope is refused (422) and a 1.x
  record, or a record of a removed kind, is quarantined as `invalid_record`.
  Detection tests are real activity on the monitored assets, verified by asset, rule
  and time window; nothing in the telemetry marks them.

## 2. Contracts and where they are stored

| Contract (module) | Produced by | Ingest kind | Table |
|---|---|---|---|
| `SecurityEvent` (`event.py`) | collectors, OTLP normaliser | `event` | `events` |
| `Asset` (`asset.py`) | collectors, scanners | `asset` | `assets` |
| `InventoryItem` (`asset.py`) | collectors | `inventory_item` | `inventory_items` |
| `PostureFinding` (`finding.py`) | scanners, posture collectors | `finding` | `finding_observations` |
| `ScanRun` (`scan.py`) | scanners, posture collectors | `scan_run` | `scan_runs` |
| `CollectorHealth` (`health.py`) | collector runner | `collector_health` | `collector_health` |
| `Service` (`service.py`) | host / k8s inventory collectors | `service` | `services` |
| `ServiceInstance` (`service.py`) | host / k8s inventory collectors | `service_instance` | `service_instances` |
| `PipelineHealth` (`health.py`) | gateway, writer, detector, ai-worker | (internal) | `pipeline_health` |
| `DetectionAlert`, `AlertEvidence`, `RuleRun`, `RuleMetadata` (`alert.py`) | detector only | - | `alerts`, `alert_evidence`, `rule_runs`, `detection_rules` |
| `InvestigationContext`, `Relationship` (`context.py`) | correlation (detector/API) | - | `investigation_contexts`, `context_relationships` |
| `AIAssessment` (`ai.py`) | ai-worker (Jev triage, advisory) | - | `ai_assessments` |
| `AnalystState` (`alert.py`) | API | - | `analyst_state` (+ `analyst_actions` audit) |
| quarantine / audit rows | gateway | (internal) | `ingest_quarantine`, `ingest_audit` |

Ingestion wire format (`ingest.py`): `IngestBatch {schema_version, batch_id, producer_id,
sent_at, records[]}` where each record is `{"kind": <RecordKind>, "data": <model>}`;
answer `IngestResult {batch_id, accepted, duplicates, rejected, quarantined[], replayed}`.
The event catalog (`catalog.py`) fixes, per `event_type`, the category and the source
types allowed to emit it; the gateway quarantines catalog violations.

### 2.1 Row mapping (writer: `extorq.storage.rows`)

`to_row(kind, model, producer_id=, batch_id=, ingested_at=)` returns exactly the
table's columns (unit-tested against the schema replayed from every migration file in
order, so 0008's dropped columns are not expected):

* nested objects flatten to prefixed columns (`source.*`, `actor.*`, `network.*`
  -> `src_ip/src_port/dst_ip/dst_port/net_protocol`, `process.*`, `http.*`,
  `kubernetes.*` -> `k8s_*`, `github.*` -> `gh_*`, `service.*`, `provenance.*`);
* JSON-bearing columns (`attributes`, `details`, `coverage`, `features`,
  `endpoints`, `body`, `output`, `payload`) hold `canonical_json` (sorted keys,
  compact, UTF-8, ISO-8601 UTC times);
* `events.payload` / `alerts.payload` hold the canonical JSON of the whole validated
  model, so readers can reconstruct the exact contract object;
* integers are range-checked against their ClickHouse type and every string must be
  valid UTF-8, so a record accepted by the gateway can always be inserted.

Service model columns (migration `0004_services.sql`; views refreshed by 0005/0006):

| Contract field | Column |
|---|---|
| `SecurityEvent.service.{service_id,name,instance_id,adapter_id}` | `events.{service_id,service_name,service_instance_id,adapter_id}` |
| `SecurityEvent.kubernetes.container_id` | `events.k8s_container_id` (bare 64-hex runtime id, PLAN §11) |
| `PostureFinding.service_id` | `finding_observations.service_id` (+ `v_findings_current.service_id`, 0005) |
| `DetectionAlert.service_ids` | `alerts.service_ids` (`rows.alert_to_row`; visible in `v_alerts` since 0006) |
| `Service` (all fields) | `services` (`endpoints` = canonical JSON array of `ServiceEndpoint`) |
| `ServiceInstance` (all fields) | `service_instances` (`user` -> `process_user`) |
| `InvestigationContext.services` / `related_assets` | inside the stored context body (`investigation_contexts`) |

The service model in one paragraph: a host or Kubernetes node (`AssetType.kubernetes_node`,
asset id `k8s:<cluster>/node/<name>`) runs **services** (`ServiceKind` `host_service`,
`application`, `k8s_workload`, `k8s_service`) that exist only with discovery evidence
(`discovered_via`, `DiscoveryEvidence`), carry explicit coverage
(`adapter_support` implemented/planned/none, `monitoring_status`
monitored/degraded/unmonitored, `coverage_note`) and endpoints with a
`PortAttribution` (confirmed/inferred/unknown); **instances** (processes, containers,
Pods) belong to one service and one asset. Events name the PRODUCING service in
`SecurityEvent.service` (`ServiceRef`); alerts list every evidence service in
`service_ids`. Architecture and rules: `docs/architecture.md` section 5, PLAN §10.

## 3. Identities (`contracts/identity.py`)

All ids are the first 32 hex characters of SHA-256 over a namespace plus parts joined
with `\x1f` (`stable_id`). Changing a function is a breaking change: bump the
namespace suffix (`.v1` -> `.v2`) instead of editing in place.

| Identity | Function | Inputs |
|---|---|---|
| event | `event_id(source_type, asset_id, native_key)` | journald `__CURSOR`; audit `<node>:<serial>:<ts>`+type; k8s audit `<auditID>:<stage>`; inventory diff `<kind>/<ns>/<name>:<uid>:<rv>:<change>`; GitHub sha / run attempt; container log `<pod_uid>:<container>:<stream>:<ts_ns>:<sha256(line)>`; snapshot diffs `<key>:<change>:<content sha256>`; else `content_key(...)` over canonical content (never collection time) |
| finding | `finding_id(asset, scanner, check, resource_key, qualifier)` | stable across scans of the same scope |
| alert | `alert_id(rule_id, group_key, bucket)` | rule version deliberately excluded |
| context / assessment | `context_id(alert_id, input_hash)`, `assessment_id(provider, model, task, prompt_version, input_hash, nonce)` | |
| scan scope | `scope_hash(targets, description)` | lifecycle compares equal scopes only |
| service | `service_id(asset_id, service_kind, service_key)` | unit name, launchd label, `<ns>/<kind>/<name>`, `<ns>/<name>` |
| service instance | `instance_id(service_id, instance_kind, instance_key)` | pid+start time, container id, pod uid |
| quarantine row | `stable_id("quarantine.v1", producer, batch_id, index, payload_sha256)` | gateway |
| audit row | random UUID4 (each attempt is a distinct security event) | gateway |

**Identity binding at the gateway.** Service and instance ids are computable from
public facts, so the gateway recomputes them: a `Service` whose `service_id` is not
`service_id(asset_id, service_kind, service_key)`, or a `ServiceInstance` whose
`instance_id` is not `instance_id(service_id, instance_kind, instance_key)`, is
quarantined (`identity_mismatch`). Combined with per-record asset authorization this
binds every service row to an asset the producer is allowed to report.

**Gateway deduplication key** (`record_identity`, per kind, remembered for 7 days in
the spool): events by `event_id`; findings by `(finding_id, scan_run_id)`; scan runs by
`(scan_run_id, status, finished_at)`; collector health by `(collector_id, reported_at)`;
inventory items, assets and services by identity
**plus content** (identical re-sends collapse, genuine changes flow); service instances
by identity, state, presence and content excluding `observed_at`.

## 4. Tables

`extorq` database. Engine `RMT` = `ReplacingMergeTree(version column)`.

| Table | Engine (version) | ORDER BY | Writer identity | TTL |
|---|---|---|---|---|
| `assets` | RMT(`last_seen`) | `asset_id` | ingest | none |
| `inventory_items` | RMT(`observed_at`) | `(asset_id, item_type, item_key)` | ingest | 30 d |
| `events` | RMT(`ingested_time`), partition `toYYYYMM(event_time)` | `(asset_id, event_type, event_time, event_id)` | ingest | 90 d |
| `scan_runs` | RMT(`row_version`) | `scan_run_id` | ingest | none |
| `finding_observations` | RMT(`ingested_at`) | `(asset_id, finding_id, scan_run_id)` | ingest | 180 d |
| `services` | RMT(`last_seen`) | `(asset_id, service_id)` | ingest | 30 d |
| `service_instances` | RMT(`observed_at`) | `(service_id, instance_id)` | ingest | 30 d |
| `collector_health` | RMT(`ingested_at`) | `(collector_id, reported_at)` | ingest | 30 d |
| `pipeline_health` | MergeTree | `(component, instance, reported_at)` | ingest, detect, ai | 14 d |
| `ingest_quarantine` | RMT(`received_at`) | `(producer_id, quarantine_id)` | ingest | 30 d |
| `ingest_audit` | MergeTree | `occurred_at` | ingest | 90 d |
| `detection_rules` | RMT(`loaded_at`) | `(rule_id, version)` | detect | none |
| `rule_runs` | MergeTree, partition by month | `(rule_id, started_at)` | detect | 30 d |
| `alerts` | RMT(`updated_at`) | `(rule_id, alert_id)` | **detect only** | none |
| `alert_evidence` | RMT(`added_at`) | `(alert_id, event_id)` | detect | none |
| `investigation_contexts` | RMT(`created_at`) | `(alert_id, context_id)` | detect, api_writer | none |
| `context_relationships` | RMT(`created_at`) | `(alert_id, context_id, event_id)` | detect, api_writer | none |
| `ai_assessments` | RMT(`created_at`) | `(alert_id, assessment_id)` | ai (api_writer keeps an unused grant, see section 7) | none |
| `analyst_state` | RMT(`updated_at`) | `alert_id` | api_writer | none |
| `analyst_actions` | MergeTree | `occurred_at` | api_writer | 365 d |
| `schema_migrations` | RMT(`applied_at`) | `version` | admin (migrations) | none |

Row version computed by the writer (from the 0001 DDL comment):
`scan_runs.row_version = epoch_ms(coalesce(finished_at, started_at)) * 10 + rank`,
rank running=0, succeeded/partial/failed=1 (a terminal state beats running).

Indexes: bloom filters on `events.event_id`, `src_ip`, `http_request_id`, `k8s_pod_uid`,
`k8s_audit_id`, `gh_commit_sha`, `actor_name`, `service_id`.

### 4.1 Views (duplicate-safe read paths)

| View | Definition |
|---|---|
| `v_assets`, `v_alerts`, `v_analyst_state`, `v_services` | `SELECT * FROM <table> FINAL` |
| `v_inventory_current`, `v_service_instances_current` | `FINAL WHERE present = 1` (tombstones hidden) |
| `v_collector_latest`, `v_pipeline_latest` | latest report per collector / component+instance (`argMax`, NULL-preserving `argMax(tuple(x), t).1`) |
| `v_rule_latest_run` | latest run, 24 h runs and failures per rule |
| `v_scan_runs_current`, `v_findings_current` (C3, 0003/0005) | finding lifecycle per `(asset, scanner, scope_hash)`: open / unverified / resolved; `service_id` of the most recent observation, NULL included (0005, appended as the last column) |

ClickHouse resolves `SELECT *` in a view **at CREATE time**: a view created before a
migration added columns does not show them. Such views are re-created with
`CREATE OR REPLACE VIEW` in a new migration (0006 refreshed `v_alerts` so
`alerts.service_ids` is visible); grants on a view are keyed by name and survive.

## 5. Lifecycle and deduplication semantics

* **Events** are immutable facts; duplicates (same `event_id`) are dropped by the
  gateway within the 7-day dedup window and otherwise collapse in `events` at merge
  time (`ReplacingMergeTree(ingested_time)`); counts must use `uniqExact(event_id)`.
* **Upserts** (assets, services, instances, inventory, health): the newest version
  column wins after merges. Removal is a **tombstone** (`present = false`), never a
  delete, so "it disappeared" is itself evidence.
* **Service coverage** is explicit: `adapter_support` (implemented / planned / none)
  says what ExtorQ *can* collect; `monitoring_status` (monitored / degraded /
  unmonitored) what it *is* collecting, as reported by the collector. A service exists
  only with discovery evidence (`discovered_via`), ports carry a `PortAttribution`
  (confirmed / inferred / unknown) and a Kubernetes Service (`k8s_service`) is never a
  host OS service (`host_service`).
* **Findings** are observations per scan; the lifecycle (open/resolved/unverified) is
  derived by `v_findings_current` from successful scans of the same scope; partial or
  failed scans never resolve a finding.
* **Alerts** are versioned rows written only by the detector; late evidence bumps
  `updated_at` while `created_at` is preserved; analyst workflow lives in
  `analyst_state`, AI output in `ai_assessments`; neither mutates the alert.
* **Detection tests** leave no trace of their own in the data model: they are real
  activity whose genuine telemetry is stored like any other, and the test runner
  verifies alerts by asset, rule and time window (`make test-detections`).

## 6. Retention

TTL is enforced by ClickHouse merges (approximate, never earlier than stated):
events 90 days, findings 180 days, inventory/services/instances/collector health/
quarantine/rule runs 30 days, pipeline health 14 days, ingest audit 90 days, analyst
actions 365 days; assets, scan runs, alerts, evidence, contexts, assessments and
analyst state have no TTL.

The gateway's acceptance window is aligned with the events TTL: an event whose
`event_time` is older than 90 days is quarantined (`older_than_retention`) instead of
being queued for storage (PLAN §11; `EXTORQ_EVENT_RETENTION_DAYS` must equal the TTL,
a unit test parses the DDL). The 90-day evidence retention period is anchored to
the source event time. Delayed ingestion and detection reduce time remaining,
and a pending merge can leave an eligible event readable beyond the cutoff.
Alerts and associations have no TTL. Migration 0009 records the trusted source
event time on new evidence associations so that unresolved IDs beyond the
cutoff can be classified by the API. Historical references with an unknown
event time remain unresolved when their event is missing.

Collector outboxes and the gateway spool retain pending records until
delivery or dead-letter handling. Gateway batch replay expiry is controlled by
`EXTORQ_DEDUP_RETENTION_HOURS` (168 hours by default). See
[evidence retention and recovery](recovery.md).

### 6.1 Clean slate

Prefer a separate checkout and volumes for clean acceptance. `make reset-data`
prints the reset plan and current counts. An explicitly authorized reset requires
a new backup directory, paused external sources and verified backups. It stops
host collectors, ingestion, writer, detector, Jev and analyst API first.

| Store | Reset | Kept |
|---|---|---|
| ClickHouse `extorq` | TRUNCATE of every data table of section 4 (20 tables, all but `schema_migrations`: `extorq.storage.reset.DATA_TABLES`; also `simulation_runs` while 0008 is not applied) as `extorq_admin` in a one-off `migrate` container (`extorq data reset --yes`) | `schema_migrations`, users, roles, quotas, profiles, grants, views; unknown tables are reported, never truncated |
| gateway spool (volume `spool`) | queued records (incl. quarantine/audit/health rows not yet written), batch replay results, dedup keys, dead letters, counters (`extorq spool clear --yes` in a one-off `writer` container) | the database file and its schema |
| collector state (`var/collectors/<id>/state.db`) | outbox and dead letters (pre-reset records), inventory/posture/service/asset snapshots and collection schedules, so the next cycle re-sends everything as a **baseline** (no change events, so no false detections) | source cursors: journald cursor, audit inode/offset, unified-log window, Kubernetes Event versions (`k8s-events` snapshot), GitHub commit heads, workflow-run tracking and activity cursor; first-seen history |
| scanner outbox (`var/state/scanners/outbox.db`) | pending and dead-lettered records | everything else (scan results come back with `make scan`) |
| `var/collectors/simulation-runner` | removed (retired with schema 2.0) | |

The script restarts previously running managed services and collectors after a
successful reset, with the Jev worker stopped until the usage budget is reconciled.
A partial reset leaves writers stopped. Per-collector policies live in
`extorq_collectors.sdk.baseline`. See [backup and restore instructions](recovery.md).

## 7. Access control (migration 0002 + 0004 grants)

Users are created by migration 0002 with password hashes injected by the runner
(`sha256_hash ... SALT`, never plaintext), `HOST IP` limited to loopback and private
ranges, a settings profile each and quotas for `api_ro`/`grafana`. The `default` user
is removed (`infra/clickhouse/users.d/10-extorq-users.xml`); `extorq_admin` is defined
by the bootstrap-generated users.d file and used only by migrations.

| User | Profile | Privileges |
|---|---|---|
| `extorq_ingest` | service | INSERT on every ingest/health/quarantine/audit table + services, service_instances |
| `extorq_detect` | service | SELECT telemetry, findings, health, alerts, contexts, services; INSERT alerts, alert_evidence, rule_runs, detection_rules, contexts, relationships, pipeline_health |
| `extorq_rules_ro` | readonly=1, 60 s, 100k rows | SELECT events, assets, inventory, findings, scan runs, services |
| `extorq_ai` | service | SELECT alerts, contexts, relationships, ai_assessments; INSERT ai_assessments, pipeline_health (**no write on alerts**) |
| `extorq_api_ro` | readonly=2, 30 s, 100k rows, quota 6000 queries/min (0007) | SELECT `extorq.*` |
| `extorq_api_writer` | service | INSERT analyst_state, analyst_actions, contexts, relationships (**no write on alerts**); the 0002 INSERT grant on ai_assessments is unused since schema 2.0 (the API never calls an AI provider; revocation proposed, docs/team/interface-changes/P.md) |
| `extorq_grafana` | readonly=2, quota | SELECT analytics tables; on `events` every column except `raw` and `payload`; on `ingest_quarantine` every column except `payload_excerpt` |

Verified live by `tests/integration/platform/test_platform_live.py` (RBAC matrix).

## 8. Migrations

`extorq migrate` (`extorq.storage.migrate`) applies `NNNN_name.sql` in order as
`extorq_admin`, records `(version, name, checksum, applied_at, duration_ms, applied_by)`
in `extorq.schema_migrations`, **refuses to run** when an applied file's SHA-256 changed,
renders `{{password_sha256:<user>}}` / `{{password_salt:<user>}}` placeholders from the
password files (strict hex validation; rendered SQL is never logged) and re-syncs every
service user's password on each run (rotation = `make rotate` + `make rotate-apply`).
DDL is not transactional, so every statement is idempotent (`IF NOT EXISTS`, additive
GRANTs, `CREATE OR REPLACE VIEW`). Migrations are baked into the backend image, so
`make migrate` rebuilds it first.

| Migration | Owner | Content |
|---|---|---|
| `0001_core_tables` | lead | every table and base view (schema 1.0) |
| `0002_rbac` | platform | roles, users (hashed passwords, `HOST IP`), profiles, quotas, grants |
| `0003_findings_views` | C3 | `v_scan_runs_current`, `v_findings_current` (finding lifecycle) |
| `0004_services` | lead | schema 1.1: `services`, `service_instances`, their views, service columns on events/findings/alerts, grants |
| `0005_findings_services` | C3 | `v_findings_current` + `service_id` (latest observation wins); SELECT on `v_scan_runs_current` for detect/rules_ro/grafana |
| `0006_refresh_views` | lead | re-creates `v_alerts` so it exposes `alerts.service_ids` |
| `0007_api_quota` | platform (API-DATA) | `extorq_api_quota` (extorq_api_ro): 1200 -> 6000 queries per minute; errors, result rows, read rows and execution time restated unchanged (ALTER QUOTA replaces every limit of an interval) |
| `0008_remove_simulation` | lead | schema 2.0: revokes the grants on the simulation objects, drops `simulation_runs`, `events.simulation_run_id`/`scenario_id` (and their bloom index) and `alerts.simulation_run_ids`, re-creates `v_alerts` |

Applied on the live stack: 0001-0007; 0008 is applied by the verification stage once no
running code reads the dropped columns (`make demo-check` compares the applied list with
the files and reports pending ones).

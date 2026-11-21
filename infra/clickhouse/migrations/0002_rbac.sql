-- ExtorQ RBAC, migration 0002 (PLAN §4.4). Applied by `extorq migrate` as extorq_admin.
--
-- * No secrets in this file. `{{password_sha256:<user>}}` / `{{password_salt:<user>}}`
--   placeholders are rendered by extorq.storage.migrate from
--   var/secrets/clickhouse/<user>_password (salted SHA-256; hex-validated before
--   rendering). The checksum recorded in extorq.schema_migrations is computed over
--   this template, so password rotation does not change it. Every run of the
--   migrator re-syncs passwords with ALTER USER (see migrate.py).
-- * Every statement is idempotent (IF NOT EXISTS / GRANT is additive).
-- * Service users may only connect from loopback and RFC 1918 private ranges
--   (Docker networks). The `default` user is removed in users.d/10-extorq-users.xml.
-- * Privileges are granted to roles; each user receives exactly one role.

-- ── Settings profiles ──────────────────────────────────────────────────────────
-- Writers and the detector: bounded runtime/memory, may adjust session settings.
CREATE SETTINGS PROFILE IF NOT EXISTS extorq_service
    SETTINGS max_execution_time = 120, max_memory_usage = 1073741824, max_threads = 4;

-- Rule SQL: strictly read-only (readonly=1 also forbids changing settings).
CREATE SETTINGS PROFILE IF NOT EXISTS extorq_rules_readonly
    SETTINGS readonly = 1, max_execution_time = 60, max_memory_usage = 1073741824,
             max_result_rows = 100000, result_overflow_mode = 'throw', max_threads = 4;

-- Analyst API: read-only queries; settings may be lowered but never raised past the caps.
CREATE SETTINGS PROFILE IF NOT EXISTS extorq_api_readonly
    SETTINGS readonly = 2,
             max_execution_time = 30 MAX 60,
             max_memory_usage = 1073741824 MAX 1073741824,
             max_result_rows = 100000 MAX 1000000,
             result_overflow_mode = 'throw' CONST,
             max_threads = 4 MAX 8;

-- Grafana: read-only dashboards with tighter caps.
CREATE SETTINGS PROFILE IF NOT EXISTS extorq_grafana_readonly
    SETTINGS readonly = 2,
             max_execution_time = 30 MAX 60,
             max_memory_usage = 1073741824 MAX 1073741824,
             max_result_rows = 500000 MAX 1000000,
             result_overflow_mode = 'throw' CONST,
             max_threads = 4 MAX 8;

-- ── Roles and privileges ───────────────────────────────────────────────────────
CREATE ROLE IF NOT EXISTS extorq_role_ingest;
GRANT INSERT ON extorq.events               TO extorq_role_ingest;
GRANT INSERT ON extorq.assets               TO extorq_role_ingest;
GRANT INSERT ON extorq.inventory_items      TO extorq_role_ingest;
GRANT INSERT ON extorq.scan_runs            TO extorq_role_ingest;
GRANT INSERT ON extorq.finding_observations TO extorq_role_ingest;
GRANT INSERT ON extorq.collector_health     TO extorq_role_ingest;
GRANT INSERT ON extorq.pipeline_health      TO extorq_role_ingest;
GRANT INSERT ON extorq.ingest_quarantine    TO extorq_role_ingest;
GRANT INSERT ON extorq.ingest_audit         TO extorq_role_ingest;
GRANT INSERT ON extorq.simulation_runs      TO extorq_role_ingest;

CREATE ROLE IF NOT EXISTS extorq_role_detect;
GRANT SELECT ON extorq.events                 TO extorq_role_detect;
GRANT SELECT ON extorq.assets                 TO extorq_role_detect;
GRANT SELECT ON extorq.inventory_items        TO extorq_role_detect;
GRANT SELECT ON extorq.finding_observations   TO extorq_role_detect;
GRANT SELECT ON extorq.scan_runs              TO extorq_role_detect;
GRANT SELECT ON extorq.simulation_runs        TO extorq_role_detect;
GRANT SELECT ON extorq.collector_health       TO extorq_role_detect;
GRANT SELECT ON extorq.pipeline_health        TO extorq_role_detect;
GRANT SELECT ON extorq.alerts                 TO extorq_role_detect;
GRANT SELECT ON extorq.alert_evidence         TO extorq_role_detect;
GRANT SELECT ON extorq.detection_rules        TO extorq_role_detect;
GRANT SELECT ON extorq.rule_runs              TO extorq_role_detect;
GRANT SELECT ON extorq.investigation_contexts TO extorq_role_detect;
GRANT SELECT ON extorq.context_relationships  TO extorq_role_detect;
GRANT SELECT ON extorq.v_assets               TO extorq_role_detect;
GRANT SELECT ON extorq.v_alerts               TO extorq_role_detect;
GRANT SELECT ON extorq.v_inventory_current    TO extorq_role_detect;
GRANT SELECT ON extorq.v_collector_latest     TO extorq_role_detect;
GRANT SELECT ON extorq.v_pipeline_latest      TO extorq_role_detect;
GRANT SELECT ON extorq.v_rule_latest_run      TO extorq_role_detect;
GRANT SELECT ON extorq.v_findings_current     TO extorq_role_detect;
GRANT INSERT ON extorq.alerts                 TO extorq_role_detect;
GRANT INSERT ON extorq.alert_evidence         TO extorq_role_detect;
GRANT INSERT ON extorq.rule_runs              TO extorq_role_detect;
GRANT INSERT ON extorq.detection_rules        TO extorq_role_detect;
GRANT INSERT ON extorq.investigation_contexts TO extorq_role_detect;
GRANT INSERT ON extorq.context_relationships  TO extorq_role_detect;
GRANT INSERT ON extorq.pipeline_health        TO extorq_role_detect;

CREATE ROLE IF NOT EXISTS extorq_role_rules_ro;
GRANT SELECT ON extorq.events               TO extorq_role_rules_ro;
GRANT SELECT ON extorq.assets               TO extorq_role_rules_ro;
GRANT SELECT ON extorq.inventory_items      TO extorq_role_rules_ro;
GRANT SELECT ON extorq.finding_observations TO extorq_role_rules_ro;
GRANT SELECT ON extorq.scan_runs            TO extorq_role_rules_ro;
GRANT SELECT ON extorq.simulation_runs      TO extorq_role_rules_ro;
GRANT SELECT ON extorq.v_assets             TO extorq_role_rules_ro;
GRANT SELECT ON extorq.v_inventory_current  TO extorq_role_rules_ro;
GRANT SELECT ON extorq.v_findings_current   TO extorq_role_rules_ro;

CREATE ROLE IF NOT EXISTS extorq_role_ai;
GRANT SELECT ON extorq.alerts                 TO extorq_role_ai;
GRANT SELECT ON extorq.v_alerts               TO extorq_role_ai;
GRANT SELECT ON extorq.investigation_contexts TO extorq_role_ai;
GRANT SELECT ON extorq.context_relationships  TO extorq_role_ai;
GRANT SELECT ON extorq.ai_assessments         TO extorq_role_ai;
GRANT INSERT ON extorq.ai_assessments         TO extorq_role_ai;
GRANT INSERT ON extorq.pipeline_health        TO extorq_role_ai;

CREATE ROLE IF NOT EXISTS extorq_role_api_ro;
GRANT SELECT ON extorq.* TO extorq_role_api_ro;

CREATE ROLE IF NOT EXISTS extorq_role_api_writer;
GRANT INSERT ON extorq.analyst_state          TO extorq_role_api_writer;
GRANT INSERT ON extorq.analyst_actions        TO extorq_role_api_writer;
GRANT INSERT ON extorq.ai_assessments         TO extorq_role_api_writer;
GRANT INSERT ON extorq.investigation_contexts TO extorq_role_api_writer;
GRANT INSERT ON extorq.context_relationships  TO extorq_role_api_writer;

-- Grafana: analytics tables; events WITHOUT raw/payload; quarantine WITHOUT payload_excerpt.
CREATE ROLE IF NOT EXISTS extorq_role_grafana;
GRANT SELECT(event_id, schema_version, event_type, category, asset_id, asset_type, source_type,
             collector_id, collector_version, collection_method, source_native_id, event_time,
             observed_time, ingested_time, action, outcome, severity_hint, actor_type,
             actor_name, actor_id, resource_type, resource_name, resource_namespace,
             resource_path, src_ip, src_port, dst_ip, dst_port, net_protocol, process_name,
             process_pid, process_executable, process_command_line, http_method, http_route,
             http_status, http_request_id, http_user_agent, k8s_cluster, k8s_namespace,
             k8s_pod_name, k8s_pod_uid, k8s_container, k8s_node, k8s_verb, k8s_resource,
             k8s_subresource, k8s_object_name, k8s_audit_id, k8s_response_code, k8s_user,
             k8s_user_groups, k8s_source_ips, gh_repository, gh_ref, gh_commit_sha,
             gh_workflow_path, gh_workflow_run_id, gh_actor_login, gh_event_name, gh_conclusion,
             simulation_run_id, scenario_id, message, attributes, labels, parser, parser_version,
             raw_sha256, truncated, redaction_count, producer_id, batch_id)
    ON extorq.events TO extorq_role_grafana;
GRANT SELECT(quarantine_id, received_at, producer_id, batch_id, record_index, record_kind,
             reason, payload_sha256)
    ON extorq.ingest_quarantine TO extorq_role_grafana;
GRANT SELECT ON extorq.assets               TO extorq_role_grafana;
GRANT SELECT ON extorq.inventory_items      TO extorq_role_grafana;
GRANT SELECT ON extorq.scan_runs            TO extorq_role_grafana;
GRANT SELECT ON extorq.finding_observations TO extorq_role_grafana;
GRANT SELECT ON extorq.detection_rules      TO extorq_role_grafana;
GRANT SELECT ON extorq.rule_runs            TO extorq_role_grafana;
GRANT SELECT ON extorq.alerts               TO extorq_role_grafana;
GRANT SELECT ON extorq.alert_evidence       TO extorq_role_grafana;
GRANT SELECT ON extorq.analyst_state        TO extorq_role_grafana;
GRANT SELECT ON extorq.ai_assessments       TO extorq_role_grafana;
GRANT SELECT ON extorq.collector_health     TO extorq_role_grafana;
GRANT SELECT ON extorq.pipeline_health      TO extorq_role_grafana;
GRANT SELECT ON extorq.ingest_audit         TO extorq_role_grafana;
GRANT SELECT ON extorq.simulation_runs      TO extorq_role_grafana;
GRANT SELECT ON extorq.v_assets             TO extorq_role_grafana;
GRANT SELECT ON extorq.v_alerts             TO extorq_role_grafana;
GRANT SELECT ON extorq.v_analyst_state      TO extorq_role_grafana;
GRANT SELECT ON extorq.v_inventory_current  TO extorq_role_grafana;
GRANT SELECT ON extorq.v_collector_latest   TO extorq_role_grafana;
GRANT SELECT ON extorq.v_pipeline_latest    TO extorq_role_grafana;
GRANT SELECT ON extorq.v_rule_latest_run    TO extorq_role_grafana;
GRANT SELECT ON extorq.v_findings_current   TO extorq_role_grafana;

-- ── Users (password hashes rendered by the migrator; private networks only) ────
CREATE USER IF NOT EXISTS extorq_ingest
    IDENTIFIED WITH sha256_hash BY '{{password_sha256:extorq_ingest}}' SALT '{{password_salt:extorq_ingest}}'
    HOST IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', IP '192.168.0.0/16'
    DEFAULT DATABASE extorq
    SETTINGS PROFILE 'extorq_service';
CREATE USER IF NOT EXISTS extorq_detect
    IDENTIFIED WITH sha256_hash BY '{{password_sha256:extorq_detect}}' SALT '{{password_salt:extorq_detect}}'
    HOST IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', IP '192.168.0.0/16'
    DEFAULT DATABASE extorq
    SETTINGS PROFILE 'extorq_service';
CREATE USER IF NOT EXISTS extorq_rules_ro
    IDENTIFIED WITH sha256_hash BY '{{password_sha256:extorq_rules_ro}}' SALT '{{password_salt:extorq_rules_ro}}'
    HOST IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', IP '192.168.0.0/16'
    DEFAULT DATABASE extorq
    SETTINGS PROFILE 'extorq_rules_readonly';
CREATE USER IF NOT EXISTS extorq_ai
    IDENTIFIED WITH sha256_hash BY '{{password_sha256:extorq_ai}}' SALT '{{password_salt:extorq_ai}}'
    HOST IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', IP '192.168.0.0/16'
    DEFAULT DATABASE extorq
    SETTINGS PROFILE 'extorq_service';
CREATE USER IF NOT EXISTS extorq_api_ro
    IDENTIFIED WITH sha256_hash BY '{{password_sha256:extorq_api_ro}}' SALT '{{password_salt:extorq_api_ro}}'
    HOST IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', IP '192.168.0.0/16'
    DEFAULT DATABASE extorq
    SETTINGS PROFILE 'extorq_api_readonly';
CREATE USER IF NOT EXISTS extorq_api_writer
    IDENTIFIED WITH sha256_hash BY '{{password_sha256:extorq_api_writer}}' SALT '{{password_salt:extorq_api_writer}}'
    HOST IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', IP '192.168.0.0/16'
    DEFAULT DATABASE extorq
    SETTINGS PROFILE 'extorq_service';
CREATE USER IF NOT EXISTS extorq_grafana
    IDENTIFIED WITH sha256_hash BY '{{password_sha256:extorq_grafana}}' SALT '{{password_salt:extorq_grafana}}'
    HOST IP '127.0.0.1', IP '::1', IP '10.0.0.0/8', IP '172.16.0.0/12', IP '192.168.0.0/16'
    DEFAULT DATABASE extorq
    SETTINGS PROFILE 'extorq_grafana_readonly';

GRANT extorq_role_ingest     TO extorq_ingest;
GRANT extorq_role_detect     TO extorq_detect;
GRANT extorq_role_rules_ro   TO extorq_rules_ro;
GRANT extorq_role_ai         TO extorq_ai;
GRANT extorq_role_api_ro     TO extorq_api_ro;
GRANT extorq_role_api_writer TO extorq_api_writer;
GRANT extorq_role_grafana    TO extorq_grafana;

-- ── Quotas (per user, per minute) ──────────────────────────────────────────────
CREATE QUOTA IF NOT EXISTS extorq_api_quota
    KEYED BY user_name
    FOR INTERVAL 1 minute MAX queries = 1200, errors = 300, result_rows = 50000000,
                              read_rows = 5000000000, execution_time = 600
    TO extorq_api_ro;
CREATE QUOTA IF NOT EXISTS extorq_grafana_quota
    KEYED BY user_name
    FOR INTERVAL 1 minute MAX queries = 600, errors = 200, result_rows = 20000000,
                              read_rows = 2000000000, execution_time = 300
    TO extorq_grafana;

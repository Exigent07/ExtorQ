-- ExtorQ findings lifecycle view with service attribution, migration 0005
-- (owner: C3, contract schema 1.1). Applied by `extorq migrate` (admin identity)
-- after 0004_services.sql, which adds finding_observations.service_id.
--
-- Recreates extorq.v_findings_current (first defined in 0003, which is immutable
-- once applied) with CREATE OR REPLACE VIEW. View changes versus 0003:
--   * one added column, service_id (Nullable(String)), appended LAST so every
--     existing column keeps its name, type and position (D1 API, Grafana panels).
--     It is the service_id of the MOST RECENT observation of the finding, NULL
--     included (argMax over a tuple): attribution is evidence of that scan, so a
--     later scan without evidence clears it instead of keeping a stale link.
--   * nothing else: lifecycle semantics, grain, NULL handling and the readonly
--     compatibility are identical to 0003 (tests/unit/scanners run the full
--     scenario suite against both definitions).
-- state per (asset_id, scanner, scope_hash), unchanged from 0003:
--   open       observed in the latest SUCCEEDED scan, no newer partial/failed attempt
--   unverified a newer attempt was partial/failed, or only observed in partial/failed
--              scans, or the observation's ScanRun is unknown
--   resolved   a newer SUCCEEDED scan of the same scope did not observe it
-- PARTIAL and FAILED scans never resolve. Running scans older than 6 h count as failed.
-- Grants: privileges granted on v_findings_current in 0002 refer to the view by
-- name and survive CREATE OR REPLACE (verified in the tests). SQL SECURITY INVOKER
-- is kept: readers need SELECT on the view, scan_runs and finding_observations.
-- 0005 also grants SELECT on v_scan_runs_current (0003) to the roles that already
-- read scan_runs and v_findings_current (detect, rules_ro, grafana):
-- with INVOKER security this widens nothing, it only lets them use the view.
-- Validated on clickhouse-server 26.8.42.13.
-- Note: no semicolons inside comments (keeps statement splitting trivial).

CREATE OR REPLACE VIEW extorq.v_findings_current
SQL SECURITY INVOKER
AS
WITH
    scans AS
    (
        SELECT
            sr_id,
            sr_asset_id,
            sr_scanner,
            sr_scope_hash,
            sr_started_at,
            coalesce(sr_finished_at, sr_started_at)                       AS sr_at,
            if(sr_raw_status = 'running' AND sr_started_at < now64(3) - INTERVAL 6 HOUR,
               'failed', sr_raw_status)                                   AS sr_status
        FROM
        (
            SELECT
                scan_run_id                                 AS sr_id,
                argMax(asset_id, row_version)               AS sr_asset_id,
                argMax(scanner, row_version)                AS sr_scanner,
                argMax(scope_hash, row_version)             AS sr_scope_hash,
                argMax(status, row_version)                 AS sr_raw_status,
                argMax(started_at, row_version)             AS sr_started_at,
                argMax(tuple(finished_at), row_version).1   AS sr_finished_at
            FROM extorq.scan_runs
            GROUP BY scan_run_id
        )
    ),
    grp AS
    (
        SELECT
            sr_asset_id                                                            AS g_asset_id,
            sr_scanner                                                             AS g_scanner,
            sr_scope_hash                                                          AS g_scope_hash,
            countIf(sr_status = 'succeeded')                                       AS g_success_n,
            argMaxIf(sr_id, tuple(sr_started_at, sr_id), sr_status = 'succeeded')  AS g_success_id,
            maxIf(sr_started_at, sr_status = 'succeeded')                          AS g_success_started,
            argMaxIf(sr_at, tuple(sr_started_at, sr_id), sr_status = 'succeeded')  AS g_success_at,
            countIf(sr_status IN ('partial', 'failed'))                            AS g_nonsuccess_n,
            maxIf(sr_started_at, sr_status IN ('partial', 'failed'))               AS g_nonsuccess_started,
            argMax(sr_status, tuple(sr_started_at, sr_id))                         AS g_latest_status,
            argMax(sr_at, tuple(sr_started_at, sr_id))                             AS g_latest_at
        FROM scans
        GROUP BY g_asset_id, g_scanner, g_scope_hash
    ),
    obs AS
    (
        SELECT
            o.finding_id                                                   AS o_finding_id,
            o.asset_id                                                     AS o_asset_id,
            o.scanner                                                      AS o_scanner,
            o.scan_run_id                                                  AS o_scan_run_id,
            o.check_id                                                     AS o_check_id,
            o.category                                                     AS o_category,
            o.severity                                                     AS o_severity,
            o.title                                                        AS o_title,
            o.resource_type                                                AS o_resource_type,
            o.resource_name                                                AS o_resource_name,
            o.resource_namespace                                           AS o_resource_namespace,
            o.resource_path                                                AS o_resource_path,
            o.package_name                                                 AS o_package_name,
            o.installed_version                                            AS o_installed_version,
            o.fixed_version                                                AS o_fixed_version,
            o.cve_ids                                                      AS o_cve_ids,
            o.accepted_risk_reason                                         AS o_accepted_risk_reason,
            o.service_id                                                   AS o_service_id,
            o.observed_at                                                  AS o_observed_at,
            ifNull(s.sr_known, 0)                                          AS o_known,
            ifNull(s.sr_scope_hash, '')                                    AS o_scope_hash,
            if(o_known = 1, ifNull(s.sr_started_at, o.observed_at), o.observed_at) AS o_scan_at,
            tuple(o_scan_at, o.observed_at, o.scan_run_id)                 AS o_ord
        FROM extorq.finding_observations AS o
        LEFT JOIN
        (
            SELECT sr_id, sr_asset_id, sr_scanner, sr_scope_hash, sr_started_at, toUInt8(1) AS sr_known
            FROM scans
        ) AS s
            ON o.scan_run_id = s.sr_id AND o.asset_id = s.sr_asset_id AND o.scanner = s.sr_scanner
    ),
    agg AS
    (
        SELECT
            obs.o_finding_id                                                AS a_finding_id,
            obs.o_asset_id                                                  AS a_asset_id,
            obs.o_scanner                                                   AS a_scanner,
            obs.o_scope_hash                                                AS a_scope_hash,
            argMax(obs.o_check_id, obs.o_ord)                               AS a_check_id,
            argMax(obs.o_category, obs.o_ord)                               AS a_category,
            argMax(obs.o_severity, obs.o_ord)                               AS a_severity,
            argMax(obs.o_title, obs.o_ord)                                  AS a_title,
            argMax(tuple(obs.o_resource_type), obs.o_ord).1                 AS a_resource_type,
            argMax(tuple(obs.o_resource_name), obs.o_ord).1                 AS a_resource_name,
            argMax(tuple(obs.o_resource_namespace), obs.o_ord).1            AS a_resource_namespace,
            argMax(tuple(obs.o_resource_path), obs.o_ord).1                 AS a_resource_path,
            argMax(tuple(obs.o_package_name), obs.o_ord).1                  AS a_package_name,
            argMax(tuple(obs.o_installed_version), obs.o_ord).1             AS a_installed_version,
            argMax(tuple(obs.o_fixed_version), obs.o_ord).1                 AS a_fixed_version,
            argMax(obs.o_cve_ids, obs.o_ord)                                AS a_cve_ids,
            argMax(tuple(obs.o_accepted_risk_reason), obs.o_ord).1          AS a_accepted_risk_reason,
            argMax(tuple(obs.o_service_id), obs.o_ord).1                    AS a_service_id,
            min(obs.o_observed_at)                                          AS a_first_observed_at,
            max(obs.o_observed_at)                                          AS a_last_observed_at,
            argMax(obs.o_scan_run_id, obs.o_ord)                            AS a_last_scan_run_id,
            max(obs.o_scan_at)                                              AS a_last_obs_scan_at,
            max(obs.o_known)                                                AS a_known,
            max(obs.o_scan_run_id = ifNull(g.g_success_id, ''))             AS a_in_last_success,
            any(ifNull(g.g_success_n, 0))                                   AS a_g_success_n,
            any(ifNull(g.g_success_started, toDateTime64(0, 3, 'UTC')))     AS a_g_success_started,
            any(ifNull(g.g_success_at, toDateTime64(0, 3, 'UTC')))          AS a_g_success_at,
            any(ifNull(g.g_nonsuccess_n, 0))                                AS a_g_nonsuccess_n,
            any(ifNull(g.g_nonsuccess_started, toDateTime64(0, 3, 'UTC')))  AS a_g_nonsuccess_started,
            any(ifNull(g.g_latest_status, ''))                              AS a_g_latest_status,
            any(ifNull(g.g_latest_at, toDateTime64(0, 3, 'UTC')))           AS a_g_latest_at
        FROM obs
        LEFT JOIN grp AS g
            ON obs.o_asset_id = g.g_asset_id
            AND obs.o_scanner = g.g_scanner
            AND obs.o_scope_hash = g.g_scope_hash
        GROUP BY a_asset_id, a_scanner, a_scope_hash, a_finding_id
    )
SELECT
    a_finding_id                                                         AS finding_id,
    a_asset_id                                                           AS asset_id,
    a_scanner                                                            AS scanner,
    a_scope_hash                                                         AS scope_hash,
    a_check_id                                                           AS check_id,
    a_category                                                           AS category,
    a_severity                                                           AS severity,
    a_title                                                              AS title,
    a_resource_type                                                      AS resource_type,
    a_resource_name                                                      AS resource_name,
    a_resource_namespace                                                 AS resource_namespace,
    a_resource_path                                                      AS resource_path,
    a_package_name                                                       AS package_name,
    a_installed_version                                                  AS installed_version,
    a_fixed_version                                                      AS fixed_version,
    a_cve_ids                                                            AS cve_ids,
    a_accepted_risk_reason                                               AS accepted_risk_reason,
    a_first_observed_at                                                  AS first_observed_at,
    a_last_observed_at                                                   AS last_observed_at,
    a_last_scan_run_id                                                   AS last_scan_run_id,
    if(a_known = 1 AND a_g_success_n > 0, toNullable(a_g_success_at), NULL)  AS last_success_at,
    if(a_known = 1, toNullable(a_g_latest_status), NULL)                 AS latest_scan_status,
    if(a_known = 1, toNullable(a_g_latest_at), NULL)                     AS latest_scan_at,
    multiIf(
        a_known = 0, 'unverified',
        a_in_last_success = 1 AND a_g_nonsuccess_n > 0
            AND a_g_nonsuccess_started > a_g_success_started, 'unverified',
        a_in_last_success = 1, 'open',
        a_g_success_n > 0 AND a_g_success_started > a_last_obs_scan_at, 'resolved',
        'unverified')                                                    AS state,
    a_service_id                                                         AS service_id
FROM agg;

GRANT SELECT ON extorq.v_scan_runs_current TO extorq_role_detect;
GRANT SELECT ON extorq.v_scan_runs_current TO extorq_role_rules_ro;
GRANT SELECT ON extorq.v_scan_runs_current TO extorq_role_grafana;

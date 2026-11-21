-- ExtorQ findings lifecycle views, migration 0003 (owner: C3, contract schema 1.0).
-- Applied by `extorq migrate` with the admin identity after 0001 and 0002.
-- Idempotent: CREATE OR REPLACE, so re-applying updates the definitions in place.
-- Validated on clickhouse-server 26.8.42.13 (tests/unit/scanners/test_lifecycle_view.py).
--
-- Both views use SQL SECURITY INVOKER: a reader needs SELECT on the view AND on
-- extorq.scan_runs and extorq.finding_observations. Views never widen privileges.
--
-- Scan ordering uses scan_runs.started_at, ties broken by scan_run_id.
-- A scan still 'running' 6 hours after it started is treated as 'failed'
-- (abandoned: the runner died before reporting a terminal status). Scanner
-- timeouts are far below 6 hours, so this never fires for a healthy scan.
-- Note: no semicolons inside comments, the migration runner splits on them.
--
-- ClickHouse pitfalls avoided on purpose:
--   * Aliases are query-global. No aggregate is aliased with the name of a column
--     that is referenced inside another aggregate (sr_/g_/o_/a_ prefixes below,
--     public names are assigned only in the outermost, non-aggregating SELECT).
--   * argMax over a Nullable column skips NULLs. argMax(tuple(col), key).1 is used
--     wherever the latest value must win even when it is NULL.
--   * LEFT JOIN fills non-matching rows with defaults (join_use_nulls = 0) or NULLs
--     (join_use_nulls = 1). Every right-side column is wrapped in ifNull() so the
--     result is identical under either setting. No SETTINGS clause is used, so
--     readonly = 1 users can query the views.

-- ── v_scan_runs_current: one row per scan_run_id, latest version wins ───────────
CREATE OR REPLACE VIEW extorq.v_scan_runs_current
SQL SECURITY INVOKER
AS
SELECT
    sr_id                AS scan_run_id,
    sr_scanner           AS scanner,
    sr_scanner_version   AS scanner_version,
    sr_asset_id          AS asset_id,
    sr_scope_targets     AS scope_targets,
    sr_scope_description AS scope_description,
    sr_scope_hash        AS scope_hash,
    sr_started_at        AS started_at,
    sr_finished_at       AS finished_at,
    sr_status            AS status,
    if(sr_status = 'running' AND sr_started_at < now64(3) - INTERVAL 6 HOUR,
       'failed', sr_status)                                   AS effective_status,
    sr_checks_total      AS checks_total,
    sr_checks_run        AS checks_run,
    sr_coverage          AS coverage,
    sr_findings_count    AS findings_count,
    sr_error             AS error,
    sr_producer_id       AS producer_id,
    sr_attributes        AS attributes
FROM
(
    SELECT
        scan_run_id                                     AS sr_id,
        argMax(scanner, row_version)                    AS sr_scanner,
        argMax(scanner_version, row_version)            AS sr_scanner_version,
        argMax(asset_id, row_version)                   AS sr_asset_id,
        argMax(scope_targets, row_version)              AS sr_scope_targets,
        argMax(scope_description, row_version)          AS sr_scope_description,
        argMax(scope_hash, row_version)                 AS sr_scope_hash,
        argMax(started_at, row_version)                 AS sr_started_at,
        argMax(tuple(finished_at), row_version).1       AS sr_finished_at,
        argMax(status, row_version)                     AS sr_status,
        argMax(tuple(checks_total), row_version).1      AS sr_checks_total,
        argMax(tuple(checks_run), row_version).1        AS sr_checks_run,
        argMax(coverage, row_version)                   AS sr_coverage,
        argMax(tuple(findings_count), row_version).1    AS sr_findings_count,
        argMax(tuple(error), row_version).1             AS sr_error,
        argMax(producer_id, row_version)                AS sr_producer_id,
        argMax(attributes, row_version)                 AS sr_attributes
    FROM extorq.scan_runs
    GROUP BY scan_run_id
);

-- ── v_findings_current: lifecycle state per finding and scan scope ──────────────
-- Grain: one row per (asset_id, scanner, scope_hash, finding_id). scope_hash comes
-- from the ScanRun that produced the observation, so a scan with a different scope
-- never changes the state of a finding observed under another scope.
--
-- state, per (asset_id, scanner, scope_hash):
--   open       observed in the latest SUCCEEDED scan and no newer partial/failed attempt
--   unverified observed in the latest succeeded scan but a newer attempt was
--              partial/failed, OR observed only in partial/failed/running scans with
--              no later succeeded scan, OR its ScanRun row is not (yet) known
--              (scope_hash = '' and latest_* columns NULL in that case)
--   resolved   a SUCCEEDED scan of the same scope, newer than the last observation,
--              did not observe it
-- PARTIAL and FAILED scans never resolve a finding. 'running' scans are ignored
-- for state until they finish (or are treated as failed once abandoned, see above).
--
-- Descriptive columns (check_id .. accepted_risk_reason) come from the most recent
-- observation. last_scan_run_id is the scan that most recently observed the finding.
-- last_success_at / latest_scan_at are completion times (start time while running)
-- of the latest succeeded scan / latest attempt of the scope. latest_scan_status is
-- the effective status of the latest attempt.
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
        'unverified')                                                    AS state
FROM agg;

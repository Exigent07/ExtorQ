-- ExtorQ migration 0008 (lead-owned): contract schema 2.0.
--
-- Product decision (2026-11-22): there is no "simulation" category. Detection
-- tests perform real activity on the monitored assets and are verified by asset,
-- rule and time window from the test runner, never by markers in telemetry.
-- This removes the simulation storage introduced in 0001. Idempotent.
--
-- Order matters: revoke grants that name the objects, drop the bloom index
-- before its column, then refresh views whose SELECT * column list was frozen.

REVOKE ALL ON extorq.simulation_runs FROM extorq_role_ingest, extorq_role_detect,
    extorq_role_rules_ro, extorq_role_api_ro, extorq_role_grafana;
REVOKE SELECT(simulation_run_id, scenario_id) ON extorq.events FROM extorq_role_grafana;

DROP TABLE IF EXISTS extorq.simulation_runs SYNC;

ALTER TABLE extorq.events DROP INDEX IF EXISTS idx_sim_run;
ALTER TABLE extorq.events DROP COLUMN IF EXISTS simulation_run_id;
ALTER TABLE extorq.events DROP COLUMN IF EXISTS scenario_id;
ALTER TABLE extorq.alerts DROP COLUMN IF EXISTS simulation_run_ids;

CREATE OR REPLACE VIEW extorq.v_alerts AS
SELECT * FROM extorq.alerts FINAL;

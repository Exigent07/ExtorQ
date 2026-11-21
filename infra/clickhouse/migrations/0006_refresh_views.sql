-- ExtorQ migration 0006 (lead-owned): refresh views whose column lists were frozen
-- before migration 0004 added columns. ClickHouse resolves `SELECT *` in a VIEW at
-- CREATE time, so v_alerts did not expose alerts.service_ids. Grants on the view are
-- keyed by name and survive CREATE OR REPLACE.
CREATE OR REPLACE VIEW extorq.v_alerts AS
SELECT * FROM extorq.alerts FINAL;

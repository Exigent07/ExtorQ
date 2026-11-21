"""Correlation: deterministic InvestigationContext bundles for detection alerts.

Public interface (docs/team/PLAN.md section 5):

* ``correlation.builder.ContextBuilder(read_client).build(alert_id) -> InvestigationContext``
* ``correlation.store.save_context(write_client, ctx)``
* ``correlation.store.load_latest_context(read_client, alert_id)``

Correlation describes co-occurrence and shared attributes. It never asserts
causation (docs/correlation.md).
"""

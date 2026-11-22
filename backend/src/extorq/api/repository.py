"""ClickHouse access for the analyst API.

Security properties (checked by tests/unit/api/test_repository_sql.py):

* Every SQL statement below is a **static literal**. Optional filters use the pattern
  ``(empty({p:String}) OR col = {p:String})`` and selectable sort/grouping use
  ``if``/``multiIf`` over a parameter, so no SQL text is composed at runtime and every
  value travels as a ClickHouse server-side parameter (``{name:Type}``).
* Reads use the ``extorq_api_ro`` identity; writes use ``extorq_api_writer`` and touch
  only ``analyst_state`` and ``analyst_actions`` (context persistence goes through the
  correlation store with the same writer identity).
* Queries are duplicate-safe: ``FINAL`` on ReplacingMergeTree tables, ``uniqExact`` for
  counts, ``argMax`` for latest values and ``LIMIT 1 BY event_id`` for event rows.
* Never ``SELECT *``; ``events.payload`` is read only by the single-event endpoint and
  ``events.raw`` is never read (the payload already contains the sanitized excerpt).

Rows are returned as dicts keyed by SQL alias with every datetime normalised to aware
UTC (the driver returns naive UTC by default).
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from extorq.api.errors import ServiceUnavailable
from extorq.api.logs import get_logger
from extorq.contracts.identity import service_id as compute_service_id

log = get_logger("extorq.api.repository")

Row = dict[str, Any]
ClientFactory = Callable[[str], Any]

CLOSED_STATUSES: tuple[str, ...] = (
    "closed_true_positive",
    "closed_benign",
    "closed_false_positive",
)


# ── Client providers ──────────────────────────────────────────────────────────────


def _platform_client_factory(role: str) -> Any:
    try:
        from extorq.storage.clickhouse import get_client
    except ImportError as exc:
        raise ServiceUnavailable("storage layer (extorq.storage) is not installed") from exc
    return get_client(role)  # type: ignore[arg-type]


class ClientProvider:
    """Lazily creates and caches one ClickHouse client for a storage identity."""

    def __init__(self, role: str, factory: ClientFactory | None = None) -> None:
        self.role = role
        self._factory = factory or _platform_client_factory
        self._client: Any = None
        self._lock = threading.Lock()

    def get(self) -> Any:
        client = self._client
        if client is not None:
            return client
        with self._lock:
            if self._client is None:
                try:
                    self._client = self._factory(self.role)
                except ServiceUnavailable:
                    raise
                except Exception as exc:
                    log.error(
                        "clickhouse_client_unavailable",
                        role=self.role,
                        error_type=type(exc).__name__,
                    )
                    raise ServiceUnavailable(
                        f"storage identity '{self.role}' is unavailable"
                    ) from exc
            return self._client


# ── Filters ───────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AlertFilters:
    since: datetime
    until: datetime
    asset_id: str = ""
    rule_id: str = ""
    severities: tuple[str, ...] = ()
    statuses: tuple[str, ...] = ()
    open_only: bool = False
    simulation_run_id: str = ""
    #: Alerts whose ``service_ids`` contain this service id.
    service_id: str = ""
    #: ``last_seen`` | ``first_seen`` | ``severity``
    sort: str = "last_seen"


@dataclass(frozen=True)
class EventFilters:
    since: datetime
    until: datetime
    asset_id: str = ""
    event_type: str = ""
    event_type_prefix: str = ""
    source_type: str = ""
    category: str = ""
    outcome: str = ""
    actor: str = ""
    src_ip: str = ""
    simulation_run_id: str = ""
    service_id: str = ""
    #: Only events of this asset or its descendants (set with ``service_id``: the service's
    #: owning asset, F-19). Empty = no restriction.
    scope_asset: str = ""


@dataclass(frozen=True)
class FindingFilters:
    asset_id: str = ""
    severities: tuple[str, ...] = ()
    scanner: str = ""
    category: str = ""
    states: tuple[str, ...] = field(default_factory=tuple)
    #: Findings whose LATEST observation is attributed to this service
    #: (``v_findings_current.service_id``; an older attribution does not count).
    service_id: str = ""


@dataclass(frozen=True)
class ServiceFilters:
    asset_id: str = ""
    service_kind: str = ""
    category: str = ""
    adapter_support: str = ""
    monitoring_status: str = ""
    include_removed: bool = False


@dataclass(frozen=True)
class SeriesQuery:
    since: datetime
    until: datetime
    bucket_seconds: int
    group_by: str = ""
    asset_id: str = ""
    rule_id: str = ""
    severities: tuple[str, ...] = ()
    source_type: str = ""
    event_type: str = ""
    category: str = ""
    max_rows: int = 20000


# ── Repository protocol (implemented by ClickHouseRepository and test fakes) ─────────


class Repository(Protocol):
    def ping(self) -> None: ...

    # assets / coverage
    def all_assets(self) -> list[Row]: ...
    def get_asset(self, asset_id: str) -> Row | None: ...
    def asset_last_events(self, asset_ids: Sequence[str]) -> list[Row]: ...
    def collectors(self, asset_id: str) -> list[Row]: ...
    def asset_children(self, asset_id: str) -> list[Row]: ...
    def inventory_summary(self, asset_id: str) -> list[Row]: ...
    def event_counts_by_source(
        self, asset_id: str, since: datetime, until: datetime
    ) -> list[Row]: ...

    # findings
    def findings_lifecycle_available(self) -> bool: ...
    def list_findings(
        self, filters: FindingFilters, limit: int, offset: int
    ) -> tuple[list[Row], int, bool]: ...
    def finding_severity_counts(
        self, asset_id: str, exclude_assets: Sequence[str] = ()
    ) -> tuple[list[Row], bool]: ...

    # services (schema 1.1)
    def list_services(self, filters: ServiceFilters, max_rows: int) -> list[Row]: ...
    def get_service(self, service_id: str) -> Row | None: ...
    def service_instances(
        self, service_id: str, limit: int, scope_asset: str = ""
    ) -> tuple[list[Row], int]: ...
    def instances_on_asset(self, asset_id: str, limit: int) -> list[Row]: ...
    def services_by_id(self, service_ids: Sequence[str], max_rows: int) -> list[Row]: ...
    def service_event_sources(
        self, service_id: str, since: datetime, until: datetime, scope_asset: str = ""
    ) -> list[Row]: ...
    def service_auth_summary(
        self, service_id: str, since: datetime, until: datetime, scope_asset: str = ""
    ) -> Row: ...
    def service_auth_sources(
        self, service_id: str, since: datetime, until: datetime, limit: int, scope_asset: str = ""
    ) -> list[Row]: ...

    # rules
    def rules_latest(self) -> list[Row]: ...
    def rule_latest_runs(self) -> list[Row]: ...
    def rule_versions(self, rule_id: str) -> list[Row]: ...
    def rule_runs(self, rule_id: str, status: str, limit: int, offset: int) -> list[Row]: ...
    def alert_counts_by_rule(self) -> list[Row]: ...
    def alert_status_counts_for_rule(self, rule_id: str) -> list[Row]: ...

    # alerts
    def list_alerts(self, filters: AlertFilters, limit: int, offset: int) -> list[Row]: ...
    def count_alerts(self, filters: AlertFilters) -> int: ...
    def get_alert(self, alert_id: str) -> Row | None: ...
    def get_analyst_state(self, alert_id: str) -> Row | None: ...
    def open_alert_severity_counts(self, asset_id: str) -> list[Row]: ...
    def open_alerts_by_asset(self) -> list[Row]: ...
    def evidence_refs(self, alert_id: str, limit: int) -> list[Row]: ...
    def evidence_total(self, alert_id: str, array_ids: Sequence[str]) -> int: ...
    def events_by_ids(self, event_ids: Sequence[str]) -> list[Row]: ...
    def alert_actions(self, alert_id: str, limit: int) -> list[Row]: ...
    def assessments_direct(self, alert_id: str, limit: int) -> list[Row]: ...

    # events
    def list_events(self, filters: EventFilters, limit: int, offset: int) -> list[Row]: ...
    def get_event(self, event_id: str) -> Row | None: ...
    def alerts_citing_event(self, event_id: str, limit: int) -> list[str]: ...

    # health
    def pipeline_latest(self) -> list[Row]: ...
    def ai_status_counts(self, since: datetime) -> list[Row]: ...
    def ai_latest(self) -> list[Row]: ...
    def ingest_quarantine_count(self, since: datetime) -> int: ...
    def ingest_audit_decisions(self, since: datetime) -> list[Row]: ...

    # series
    def alert_series(self, query: SeriesQuery) -> list[Row]: ...
    def event_series(self, query: SeriesQuery) -> list[Row]: ...

    # writes (extorq_api_writer)
    def insert_analyst_action(self, row: Row) -> None: ...
    def insert_analyst_state(self, row: Row) -> None: ...

    # raw clients for integrations (correlation store, AI store)
    def read_client(self) -> Any: ...
    def write_client(self) -> Any: ...


# ── SQL (static literals only) ─────────────────────────────────────────────────────

PING_SQL = "SELECT 1"

# Every asset (lab scale: a handful). GET /assets filters and pages these rows in Python
# because the default excludes RETIRED assets, a state derived at request time from
# collector health and observation times (``extorq.api.lifecycle``).
ASSETS_ALL_SQL = """
SELECT asset_id, asset_type, name, display_name, parent_asset_id, environment, criticality,
       owner, labels, first_seen, last_seen, observed_by
FROM extorq.assets FINAL
ORDER BY asset_type, asset_id
LIMIT 5000
"""

ASSET_GET_SQL = """
SELECT asset_id, asset_type, name, display_name, parent_asset_id, environment, criticality,
       owner, labels, attributes, first_seen, last_seen, observed_by
FROM extorq.assets FINAL
WHERE asset_id = {asset_id:String}
LIMIT 1
"""

# Newest event per asset id (also ids without an asset record), with the event's asset
# type: lifecycle "last observed" input and the overview's last event per asset class.
ASSET_LAST_EVENTS_SQL = """
SELECT asset_id, any(asset_type) AS asset_type, max(event_time) AS last_event_at,
       max(ingested_time) AS last_ingested_at
FROM extorq.events
WHERE (empty({asset_ids:Array(String)}) OR has({asset_ids:Array(String)}, asset_id))
GROUP BY asset_id
LIMIT 5000
"""

COLLECTORS_SQL = """
SELECT collector_id, collector_type, asset_id, source_types, status, last_reported_at,
       last_attempt_at, last_success_at, last_error, events_collected, records_buffered,
       lag_seconds, checkpoint_summary, collector_version, interval_seconds, details
FROM extorq.v_collector_latest
WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
ORDER BY asset_id, collector_id
LIMIT 1000
"""

ASSET_CHILDREN_SQL = """
SELECT asset_id, asset_type, name, display_name, environment, criticality
FROM extorq.assets FINAL
WHERE parent_asset_id = {asset_id:String}
ORDER BY asset_type, asset_id
LIMIT 500
"""

INVENTORY_SUMMARY_SQL = """
SELECT item_type, count() AS items, max(observed_at) AS last_observed_at
FROM extorq.v_inventory_current
WHERE asset_id = {asset_id:String}
GROUP BY item_type
ORDER BY item_type
LIMIT 100
"""

EVENT_COUNTS_BY_SOURCE_SQL = """
SELECT source_type,
       uniqExact(event_id) AS events,
       max(event_time) AS last_event_at,
       max(ingested_time) AS last_ingested_at
FROM extorq.events
WHERE asset_id = {asset_id:String}
  AND event_time >= {since:DateTime64(3, 'UTC')}
  AND event_time < {until:DateTime64(3, 'UTC')}
GROUP BY source_type
ORDER BY source_type
LIMIT 100
"""

FINDINGS_VIEW_EXISTS_SQL = "EXISTS TABLE extorq.v_findings_current"

# Lifecycle view (0003, owner C3; 0005 adds service_id): one row per
# (asset_id, scanner, scope_hash, finding_id) with state open | unverified | resolved derived
# from scan history. ``service_id`` is the attribution of the finding's MOST RECENT
# observation, NULL included: a later scan without attribution evidence clears an older link
# (it is never carried forward). Every endpoint reads attribution from here (the fallback
# below reproduces the same rule), so the findings list, the service filter, asset detail
# and service detail always agree.
FINDINGS_LC_LIST_SQL = """
SELECT finding_id, asset_id, scanner, scope_hash, check_id, category, severity, title,
       resource_type, resource_name, resource_namespace, resource_path, package_name,
       installed_version, fixed_version, cve_ids, accepted_risk_reason, first_observed_at,
       last_observed_at, last_scan_run_id, last_success_at, latest_scan_status, state,
       service_id
FROM extorq.v_findings_current
WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
  AND (empty({severities:Array(String)}) OR has({severities:Array(String)}, severity))
  AND (empty({scanner:String}) OR scanner = {scanner:String})
  AND (empty({category:String}) OR category = {category:String})
  AND (empty({states:Array(String)}) OR has({states:Array(String)}, state))
  AND (empty({service_id:String}) OR service_id = {service_id:String})
ORDER BY multiIf(state = 'open', 0, state = 'unverified', 1, 2),
         multiIf(severity = 'critical', 4, severity = 'high', 3, severity = 'medium', 2,
                 severity = 'low', 1, 0) DESC,
         last_observed_at DESC,
         finding_id,
         scope_hash
LIMIT {limit:UInt32} OFFSET {offset:UInt32}
"""

FINDINGS_LC_COUNT_SQL = """
SELECT count() AS total
FROM extorq.v_findings_current
WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
  AND (empty({severities:Array(String)}) OR has({severities:Array(String)}, severity))
  AND (empty({scanner:String}) OR scanner = {scanner:String})
  AND (empty({category:String}) OR category = {category:String})
  AND (empty({states:Array(String)}) OR has({states:Array(String)}, state))
  AND (empty({service_id:String}) OR service_id = {service_id:String})
"""

# ``exclude_assets``: retired assets left out of the overview's findings KPI.
FINDINGS_LC_SEVERITY_SQL = """
SELECT severity, state, uniqExact(finding_id) AS findings
FROM extorq.v_findings_current
WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
  AND NOT has({exclude_assets:Array(String)}, asset_id)
GROUP BY severity, state
"""

# Fallback when the lifecycle view (0003, C3) is absent: latest observation per finding
# fingerprint. Aliases are prefixed ``f_`` so aggregates never shadow source columns.
# ``f_service_id`` follows the view's rule: the latest observation's attribution, NULL
# included (``argMax`` over a tuple keeps NULL instead of skipping it).
FINDINGS_OBS_LIST_SQL = """
SELECT
    finding_id,
    any(asset_id) AS f_asset_id,
    argMax(scanner, observed_at) AS f_scanner,
    argMax(check_id, observed_at) AS f_check_id,
    argMax(category, observed_at) AS f_category,
    argMax(severity, observed_at) AS f_severity,
    argMax(title, observed_at) AS f_title,
    min(observed_at) AS first_observed_at,
    max(observed_at) AS last_observed_at,
    argMax(scan_run_id, observed_at) AS last_scan_run_id,
    argMax(tuple(resource_type), observed_at).1 AS f_resource_type,
    argMax(tuple(resource_name), observed_at).1 AS f_resource_name,
    argMax(tuple(resource_namespace), observed_at).1 AS f_resource_namespace,
    argMax(tuple(resource_path), observed_at).1 AS f_resource_path,
    argMax(tuple(package_name), observed_at).1 AS f_package_name,
    argMax(tuple(installed_version), observed_at).1 AS f_installed_version,
    argMax(tuple(fixed_version), observed_at).1 AS f_fixed_version,
    argMax(cve_ids, observed_at) AS f_cve_ids,
    argMax(tuple(cvss_score), observed_at).1 AS f_cvss_score,
    argMax(tuple(remediation), observed_at).1 AS f_remediation,
    argMax(tuple(accepted_risk_reason), observed_at).1 AS f_accepted_risk_reason,
    argMax(tuple(service_id), observed_at).1 AS f_service_id
FROM extorq.finding_observations
WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
GROUP BY finding_id
HAVING (empty({severities:Array(String)}) OR has({severities:Array(String)}, f_severity))
   AND (empty({scanner:String}) OR f_scanner = {scanner:String})
   AND (empty({category:String}) OR f_category = {category:String})
   AND (empty({service_id:String}) OR ifNull(f_service_id = {service_id:String}, 0))
ORDER BY multiIf(f_severity = 'critical', 4, f_severity = 'high', 3, f_severity = 'medium', 2,
                 f_severity = 'low', 1, 0) DESC,
         last_observed_at DESC,
         finding_id
LIMIT {limit:UInt32} OFFSET {offset:UInt32}
"""

FINDINGS_OBS_COUNT_SQL = """
SELECT count() AS total
FROM
(
    SELECT finding_id,
           argMax(scanner, observed_at) AS f_scanner,
           argMax(category, observed_at) AS f_category,
           argMax(severity, observed_at) AS f_severity,
           argMax(tuple(service_id), observed_at).1 AS f_service_id
    FROM extorq.finding_observations
    WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
    GROUP BY finding_id
    HAVING (empty({severities:Array(String)}) OR has({severities:Array(String)}, f_severity))
       AND (empty({scanner:String}) OR f_scanner = {scanner:String})
       AND (empty({category:String}) OR f_category = {category:String})
       AND (empty({service_id:String}) OR ifNull(f_service_id = {service_id:String}, 0))
)
"""

FINDINGS_OBS_SEVERITY_SQL = """
SELECT f_severity AS severity, count() AS findings
FROM
(
    SELECT finding_id, argMax(severity, observed_at) AS f_severity
    FROM extorq.finding_observations
    WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
      AND NOT has({exclude_assets:Array(String)}, asset_id)
    GROUP BY finding_id
)
GROUP BY severity
"""

RULES_LATEST_SQL = """
SELECT rule_id,
       argMax(version, loaded_at) AS r_version,
       argMax(title, loaded_at) AS r_title,
       argMax(severity, loaded_at) AS r_severity,
       argMax(status, loaded_at) AS r_status,
       argMax(enabled, loaded_at) AS r_enabled,
       argMax(mitre_techniques, loaded_at) AS r_mitre_techniques,
       argMax(asset_types, loaded_at) AS r_asset_types,
       argMax(schedule, loaded_at) AS r_schedule,
       max(loaded_at) AS r_loaded_at
FROM extorq.detection_rules
GROUP BY rule_id
ORDER BY rule_id
LIMIT 1000
"""

RULE_LATEST_RUNS_SQL = """
SELECT rule_id, rule_version, last_run_at, last_status, last_error, last_duration_ms,
       missing_sources, runs_24h, failures_24h
FROM extorq.v_rule_latest_run
ORDER BY rule_id
LIMIT 1000
"""

RULE_VERSIONS_SQL = """
SELECT rule_id, version, title, description, severity, status, mitre_techniques, asset_types,
       requires, schedule, dedup, group_by, params, false_positives, blind_spots,
       reference_urls, query_sha256, query_text, enabled, loaded_at
FROM extorq.detection_rules FINAL
WHERE rule_id = {rule_id:String}
ORDER BY loaded_at DESC, version DESC
LIMIT 50
"""

RULE_RUNS_SQL = """
SELECT run_id, rule_version, started_at, finished_at, window_start, window_end, status,
       rows_matched, alerts_created, alerts_updated, duration_ms, error, missing_sources,
       detector_instance
FROM extorq.rule_runs
WHERE rule_id = {rule_id:String}
  AND (empty({status:String}) OR status = {status:String})
ORDER BY started_at DESC, run_id
LIMIT 1 BY run_id
LIMIT {limit:UInt32} OFFSET {offset:UInt32}
"""

ALERT_COUNTS_BY_RULE_SQL = """
SELECT a.rule_id AS rule_id,
       count() AS alerts_total,
       countIf(ifNull(s.status, '') NOT IN ('closed_true_positive', 'closed_benign',
                                            'closed_false_positive')) AS alerts_open
FROM extorq.alerts AS a FINAL
LEFT JOIN
(
    SELECT alert_id, status FROM extorq.analyst_state FINAL
) AS s ON s.alert_id = a.alert_id
GROUP BY rule_id
LIMIT 1000
"""

ALERT_STATUS_COUNTS_FOR_RULE_SQL = """
SELECT if(ifNull(s.alert_id, '') = '', 'new', s.status) AS analyst_status, count() AS alerts
FROM extorq.alerts AS a FINAL
LEFT JOIN
(
    SELECT alert_id, status FROM extorq.analyst_state FINAL
) AS s ON s.alert_id = a.alert_id
WHERE a.rule_id = {rule_id:String}
GROUP BY analyst_status
LIMIT 100
"""

ALERT_LIST_SQL = """
SELECT
    a.alert_id AS alert_id, a.rule_id AS rule_id, a.rule_version AS rule_version,
    a.rule_title AS rule_title, a.severity AS severity, a.confidence AS confidence,
    a.asset_id AS asset_id, a.asset_type AS asset_type, a.summary AS summary,
    a.first_seen AS first_seen, a.last_seen AS last_seen, a.event_count AS event_count,
    a.entities AS entities, a.mitre_techniques AS mitre_techniques,
    a.simulation_run_ids AS simulation_run_ids, a.created_at AS created_at,
    a.updated_at AS updated_at,
    if(ifNull(s.alert_id, '') = '', 'new', s.status) AS analyst_status,
    ifNull(s.alert_id, '') != '' AS analyst_state_recorded,
    s.assignee AS assignee,
    a.service_ids AS service_ids
FROM extorq.alerts AS a FINAL
LEFT JOIN
(
    SELECT alert_id, status, assignee FROM extorq.analyst_state FINAL
) AS s ON s.alert_id = a.alert_id
WHERE a.last_seen >= {since:DateTime64(3, 'UTC')}
  AND a.first_seen < {until:DateTime64(3, 'UTC')}
  AND (empty({asset_id:String}) OR a.asset_id = {asset_id:String})
  AND (empty({rule_id:String}) OR a.rule_id = {rule_id:String})
  AND (empty({severities:Array(String)}) OR has({severities:Array(String)}, a.severity))
  AND (empty({statuses:Array(String)}) OR has({statuses:Array(String)}, analyst_status))
  AND ({open_only:UInt8} = 0 OR analyst_status NOT IN ('closed_true_positive', 'closed_benign',
                                                       'closed_false_positive'))
  AND (empty({simulation_run_id:String}) OR has(a.simulation_run_ids, {simulation_run_id:String}))
  AND (empty({service_id:String}) OR has(a.service_ids, {service_id:String}))
ORDER BY
    if({sort:String} = 'severity',
       multiIf(a.severity = 'critical', 4, a.severity = 'high', 3, a.severity = 'medium', 2,
               a.severity = 'low', 1, 0),
       0) DESC,
    if({sort:String} = 'first_seen', a.first_seen, a.last_seen) DESC,
    a.alert_id
LIMIT {limit:UInt32} OFFSET {offset:UInt32}
"""

ALERT_COUNT_SQL = """
SELECT count() AS total
FROM
(
    SELECT a.alert_id AS alert_id,
           if(ifNull(s.alert_id, '') = '', 'new', s.status) AS analyst_status
    FROM extorq.alerts AS a FINAL
    LEFT JOIN
    (
        SELECT alert_id, status FROM extorq.analyst_state FINAL
    ) AS s ON s.alert_id = a.alert_id
    WHERE a.last_seen >= {since:DateTime64(3, 'UTC')}
      AND a.first_seen < {until:DateTime64(3, 'UTC')}
      AND (empty({asset_id:String}) OR a.asset_id = {asset_id:String})
      AND (empty({rule_id:String}) OR a.rule_id = {rule_id:String})
      AND (empty({severities:Array(String)}) OR has({severities:Array(String)}, a.severity))
      AND (empty({simulation_run_id:String})
           OR has(a.simulation_run_ids, {simulation_run_id:String}))
      AND (empty({service_id:String}) OR has(a.service_ids, {service_id:String}))
)
WHERE (empty({statuses:Array(String)}) OR has({statuses:Array(String)}, analyst_status))
  AND ({open_only:UInt8} = 0 OR analyst_status NOT IN ('closed_true_positive', 'closed_benign',
                                                       'closed_false_positive'))
"""

ALERT_GET_SQL = """
SELECT alert_id, schema_version, rule_id, rule_version, rule_title, severity, confidence,
       asset_id, asset_type, group_key, entities, summary, first_seen, last_seen, window_start,
       window_end, event_count, evidence_event_ids, evidence_truncated, features,
       mitre_techniques, simulation_run_ids, created_at, updated_at, detector_version,
       service_ids
FROM extorq.alerts FINAL
WHERE alert_id = {alert_id:String}
LIMIT 1
"""

ANALYST_STATE_GET_SQL = """
SELECT alert_id, status, assignee, note, updated_by, updated_at
FROM extorq.analyst_state FINAL
WHERE alert_id = {alert_id:String}
LIMIT 1
"""

OPEN_ALERT_SEVERITY_SQL = """
SELECT a.severity AS severity, count() AS alerts
FROM extorq.alerts AS a FINAL
LEFT JOIN
(
    SELECT alert_id, status FROM extorq.analyst_state FINAL
) AS s ON s.alert_id = a.alert_id
WHERE ifNull(s.status, '') NOT IN ('closed_true_positive', 'closed_benign', 'closed_false_positive')
  AND (empty({asset_id:String}) OR a.asset_id = {asset_id:String})
GROUP BY severity
"""

OPEN_ALERTS_BY_ASSET_SQL = """
SELECT a.asset_id AS asset_id, count() AS open_alerts
FROM extorq.alerts AS a FINAL
LEFT JOIN
(
    SELECT alert_id, status FROM extorq.analyst_state FINAL
) AS s ON s.alert_id = a.alert_id
WHERE ifNull(s.status, '') NOT IN ('closed_true_positive', 'closed_benign', 'closed_false_positive')
GROUP BY asset_id
LIMIT 5000
"""

EVIDENCE_REFS_SQL = """
SELECT event_id, role, added_at
FROM extorq.alert_evidence FINAL
WHERE alert_id = {alert_id:String}
ORDER BY role = 'trigger' DESC, added_at, event_id
LIMIT {limit:UInt32}
"""

EVIDENCE_TOTAL_SQL = """
SELECT uniqExact(event_id) AS total
FROM
(
    SELECT event_id FROM extorq.alert_evidence WHERE alert_id = {alert_id:String}
    UNION ALL
    SELECT arrayJoin({array_ids:Array(String)}) AS event_id
)
"""

EVENTS_BY_IDS_SQL = """
SELECT event_id, event_type, category, asset_id, asset_type, source_type, collector_id,
       event_time, observed_time, ingested_time, action, outcome, severity_hint, actor_type,
       actor_name, actor_id, src_ip, src_port, dst_ip, dst_port, resource_type, resource_name,
       resource_namespace, resource_path, process_name, process_pid, http_method, http_route,
       http_status, http_request_id, k8s_cluster, k8s_namespace, k8s_node, k8s_pod_name,
       k8s_pod_uid, k8s_container, k8s_container_id, k8s_verb, k8s_resource, k8s_object_name,
       k8s_response_code, k8s_user, k8s_audit_id, gh_repository, gh_commit_sha,
       gh_workflow_path, gh_workflow_run_id, gh_actor_login, service_id, service_name,
       service_instance_id, adapter_id, simulation_run_id, scenario_id, message, attributes
FROM extorq.events
WHERE event_id IN {event_ids:Array(String)}
ORDER BY event_id, ingested_time DESC
LIMIT 1 BY event_id
LIMIT 1000
"""

EVENTS_LIST_SQL = """
SELECT event_id, event_type, category, asset_id, asset_type, source_type, collector_id,
       event_time, observed_time, ingested_time, action, outcome, severity_hint, actor_type,
       actor_name, actor_id, src_ip, src_port, dst_ip, dst_port, resource_type, resource_name,
       resource_namespace, resource_path, process_name, process_pid, http_method, http_route,
       http_status, http_request_id, k8s_cluster, k8s_namespace, k8s_node, k8s_pod_name,
       k8s_pod_uid, k8s_container, k8s_container_id, k8s_verb, k8s_resource, k8s_object_name,
       k8s_response_code, k8s_user, k8s_audit_id, gh_repository, gh_commit_sha,
       gh_workflow_path, gh_workflow_run_id, gh_actor_login, service_id, service_name,
       service_instance_id, adapter_id, simulation_run_id, scenario_id, message
FROM extorq.events
WHERE event_time >= {since:DateTime64(3, 'UTC')}
  AND event_time < {until:DateTime64(3, 'UTC')}
  AND (empty({asset_id:String}) OR asset_id = {asset_id:String})
  AND (empty({event_type:String}) OR event_type = {event_type:String})
  AND (empty({event_type_prefix:String}) OR startsWith(event_type, {event_type_prefix:String}))
  AND (empty({source_type:String}) OR source_type = {source_type:String})
  AND (empty({category:String}) OR category = {category:String})
  AND (empty({outcome:String}) OR outcome = {outcome:String})
  AND (empty({actor:String})
       OR actor_name = {actor:String}
       OR k8s_user = {actor:String}
       OR gh_actor_login = {actor:String})
  AND (empty({src_ip:String}) OR src_ip = {src_ip:String} OR has(k8s_source_ips, {src_ip:String}))
  AND (empty({simulation_run_id:String}) OR simulation_run_id = {simulation_run_id:String})
  AND (empty({service_id:String}) OR service_id = {service_id:String})
  AND (empty({scope_asset:String})
       OR asset_id = {scope_asset:String}
       OR startsWith(asset_id, concat({scope_asset:String}, '/')))
ORDER BY event_time DESC, event_id
LIMIT 1 BY event_id
LIMIT {limit:UInt32} OFFSET {offset:UInt32}
"""

EVENT_GET_SQL = """
SELECT event_id, payload, ingested_time, producer_id, batch_id
FROM extorq.events
WHERE event_id = {event_id:String}
ORDER BY ingested_time DESC
LIMIT 1
"""

ALERTS_CITING_EVENT_SQL = """
SELECT DISTINCT alert_id
FROM extorq.alert_evidence
WHERE event_id = {event_id:String}
ORDER BY alert_id
LIMIT {limit:UInt32}
"""

ALERT_ACTIONS_SQL = """
SELECT action_id, occurred_at, actor, role, action, alert_id, details
FROM extorq.analyst_actions
WHERE alert_id = {alert_id:String}
ORDER BY occurred_at DESC, action_id
LIMIT {limit:UInt32}
"""

ASSESSMENTS_DIRECT_SQL = """
SELECT assessment_id, alert_id, context_id, context_input_hash, provider, model, task,
       prompt_version, status, recommendation, uncertain, output, latency_ms, input_tokens,
       output_tokens, provider_request_id, error, created_at, requested_by
FROM extorq.ai_assessments FINAL
WHERE alert_id = {alert_id:String}
ORDER BY created_at DESC, assessment_id
LIMIT {limit:UInt32}
"""

PIPELINE_LATEST_SQL = """
SELECT component, instance, status, last_reported_at, queue_depth, oldest_queued_age_seconds,
       accepted_total, duplicate_total, rejected_total, quarantined_total, written_total,
       write_errors_total, dead_letter_total, last_write_at, details
FROM extorq.v_pipeline_latest
ORDER BY component, instance
LIMIT 500
"""

AI_STATUS_COUNTS_SQL = """
SELECT provider, task, status, uniqExact(assessment_id) AS assessments
FROM extorq.ai_assessments
WHERE created_at >= {since:DateTime64(3, 'UTC')}
GROUP BY provider, task, status
ORDER BY provider, task, status
LIMIT 1000
"""

AI_LATEST_SQL = """
SELECT provider, task,
       max(created_at) AS last_assessment_at,
       argMax(status, created_at) AS last_status,
       argMax(tuple(error), created_at).1 AS last_error,
       if(countIf(status = 'ok') = 0, NULL, maxIf(created_at, status = 'ok')) AS last_ok_at
FROM extorq.ai_assessments
GROUP BY provider, task
ORDER BY provider, task
LIMIT 100
"""

INGEST_QUARANTINE_COUNT_SQL = """
SELECT uniqExact(quarantine_id) AS quarantined
FROM extorq.ingest_quarantine
WHERE received_at >= {since:DateTime64(3, 'UTC')}
"""

INGEST_AUDIT_DECISIONS_SQL = """
SELECT decision, count() AS events
FROM extorq.ingest_audit
WHERE occurred_at >= {since:DateTime64(3, 'UTC')}
GROUP BY decision
ORDER BY decision
LIMIT 100
"""

ALERT_SERIES_SQL = """
SELECT toStartOfInterval(first_seen, INTERVAL {bucket:UInt32} SECOND) AS bucket_start,
       multiIf({group_by:String} = 'severity', toString(severity),
               {group_by:String} = 'rule_id', toString(rule_id),
               {group_by:String} = 'asset_id', toString(asset_id),
               '') AS grp,
       uniqExact(alert_id) AS n
FROM extorq.alerts FINAL
WHERE first_seen >= {since:DateTime64(3, 'UTC')}
  AND first_seen < {until:DateTime64(3, 'UTC')}
  AND (empty({asset_id:String}) OR asset_id = {asset_id:String})
  AND (empty({rule_id:String}) OR rule_id = {rule_id:String})
  AND (empty({severities:Array(String)}) OR has({severities:Array(String)}, severity))
GROUP BY bucket_start, grp
ORDER BY bucket_start, grp
LIMIT {max_rows:UInt32}
"""

EVENT_SERIES_SQL = """
SELECT toStartOfInterval(event_time, INTERVAL {bucket:UInt32} SECOND) AS bucket_start,
       multiIf({group_by:String} = 'source_type', toString(source_type),
               {group_by:String} = 'asset_id', toString(asset_id),
               {group_by:String} = 'event_type', toString(event_type),
               {group_by:String} = 'category', toString(category),
               {group_by:String} = 'outcome', toString(outcome),
               '') AS grp,
       uniqExact(event_id) AS n
FROM extorq.events
WHERE event_time >= {since:DateTime64(3, 'UTC')}
  AND event_time < {until:DateTime64(3, 'UTC')}
  AND (empty({asset_id:String}) OR asset_id = {asset_id:String})
  AND (empty({source_type:String}) OR source_type = {source_type:String})
  AND (empty({event_type:String}) OR event_type = {event_type:String})
  AND (empty({category:String}) OR category = {category:String})
GROUP BY bucket_start, grp
ORDER BY bucket_start, grp
LIMIT {max_rows:UInt32}
"""

# ── Services (0004: v_services = services FINAL, v_service_instances_current) ─────────
# F-19: ``scope_asset`` (the owning asset of the requested service, resolved first) keeps a
# service's instances and events within that asset and its descendants (a cluster's nodes),
# so a producer of another asset cannot place its rows under a service it does not own.

SERVICES_LIST_SQL = """
SELECT service_id, asset_id, service_kind, service_key, name, category, product, version,
       discovered_via, adapter_id, adapter_support, monitoring_status, coverage_note,
       telemetry_sources, endpoints, config_refs, instance_count, last_telemetry_at,
       first_seen, last_seen, present, observed_by
FROM extorq.v_services
WHERE (empty({asset_id:String}) OR asset_id = {asset_id:String})
  AND (empty({service_kind:String}) OR service_kind = {service_kind:String})
  AND (empty({category:String}) OR category = {category:String})
  AND (empty({adapter_support:String}) OR adapter_support = {adapter_support:String})
  AND (empty({monitoring_status:String}) OR monitoring_status = {monitoring_status:String})
  AND ({include_removed:UInt8} = 1 OR present = 1)
ORDER BY asset_id, service_kind, name, service_id
LIMIT {max_rows:UInt32}
"""

SERVICE_GET_SQL = """
SELECT service_id, asset_id, service_kind, service_key, name, category, product, version,
       discovered_via, adapter_id, adapter_support, monitoring_status, coverage_note,
       telemetry_sources, endpoints, config_refs, instance_count, last_telemetry_at,
       first_seen, last_seen, present, observed_by, attributes
FROM extorq.v_services
WHERE service_id = {service_id:String}
ORDER BY last_seen DESC
LIMIT 10
"""

SERVICE_INSTANCES_SQL = """
SELECT instance_id, service_id, asset_id, instance_kind, instance_key, parent_instance_id, state,
       pid, process_name, process_user, namespace, pod_name, pod_uid, container_name,
       container_id, image, node_name, workload_kind, workload_name, started_at, observed_at,
       observed_by, attributes
FROM extorq.v_service_instances_current
WHERE service_id = {service_id:String}
  AND (empty({scope_asset:String})
       OR asset_id = {scope_asset:String}
       OR startsWith(asset_id, concat({scope_asset:String}, '/')))
ORDER BY observed_at DESC, instance_id
LIMIT {limit:UInt32}
"""

# Present instances running ON an asset (e.g. Pods/containers on a Kubernetes node), for
# GET /assets/{id}/services ``hosted``. Their services belong to an ancestor asset.
INSTANCES_ON_ASSET_SQL = """
SELECT instance_id, service_id, asset_id, instance_kind, instance_key, parent_instance_id, state,
       pid, process_name, process_user, namespace, pod_name, pod_uid, container_name,
       container_id, image, node_name, workload_kind, workload_name, started_at, observed_at,
       observed_by, attributes
FROM extorq.v_service_instances_current
WHERE asset_id = {asset_id:String}
ORDER BY service_id, observed_at DESC, instance_id
LIMIT {limit:UInt32}
"""

SERVICES_BY_ID_SQL = """
SELECT service_id, asset_id, service_kind, service_key, name, category, product, version,
       discovered_via, adapter_id, adapter_support, monitoring_status, coverage_note,
       telemetry_sources, endpoints, config_refs, instance_count, last_telemetry_at,
       first_seen, last_seen, present, observed_by
FROM extorq.v_services
WHERE has({service_ids:Array(String)}, service_id)
ORDER BY asset_id, service_kind, name, service_id, last_seen DESC
LIMIT {max_rows:UInt32}
"""

SERVICE_INSTANCES_COUNT_SQL = """
SELECT count() AS total
FROM extorq.v_service_instances_current
WHERE service_id = {service_id:String}
  AND (empty({scope_asset:String})
       OR asset_id = {scope_asset:String}
       OR startsWith(asset_id, concat({scope_asset:String}, '/')))
"""

SERVICE_EVENT_SOURCES_SQL = """
SELECT source_type,
       uniqExact(event_id) AS events,
       max(event_time) AS last_event_at,
       max(ingested_time) AS last_ingested_at
FROM extorq.events
WHERE service_id = {service_id:String}
  AND (empty({scope_asset:String})
       OR asset_id = {scope_asset:String}
       OR startsWith(asset_id, concat({scope_asset:String}, '/')))
  AND event_time >= {since:DateTime64(3, 'UTC')}
  AND event_time < {until:DateTime64(3, 'UTC')}
GROUP BY source_type
ORDER BY source_type
LIMIT 100
"""

SERVICE_AUTH_SUMMARY_SQL = """
SELECT uniqExact(event_id) AS total,
       uniqExactIf(event_id, outcome = 'success') AS success,
       uniqExactIf(event_id, outcome = 'failure') AS failure,
       uniqExactIf(event_id, outcome = 'denied') AS denied,
       uniqExactIf(event_id, outcome = 'unknown') AS unknown,
       uniqExact(actor_name) AS distinct_actors,
       uniqExact(src_ip) AS distinct_sources
FROM extorq.events
WHERE service_id = {service_id:String}
  AND (empty({scope_asset:String})
       OR asset_id = {scope_asset:String}
       OR startsWith(asset_id, concat({scope_asset:String}, '/')))
  AND category = 'authentication'
  AND event_time >= {since:DateTime64(3, 'UTC')}
  AND event_time < {until:DateTime64(3, 'UTC')}
"""

SERVICE_AUTH_SOURCES_SQL = """
SELECT assumeNotNull(src_ip) AS source_ip,
       uniqExact(event_id) AS events,
       uniqExactIf(event_id, outcome IN ('failure', 'denied')) AS failures,
       max(event_time) AS last_seen
FROM extorq.events
WHERE service_id = {service_id:String}
  AND (empty({scope_asset:String})
       OR asset_id = {scope_asset:String}
       OR startsWith(asset_id, concat({scope_asset:String}, '/')))
  AND category = 'authentication'
  AND src_ip IS NOT NULL
  AND event_time >= {since:DateTime64(3, 'UTC')}
  AND event_time < {until:DateTime64(3, 'UTC')}
GROUP BY source_ip
ORDER BY failures DESC, events DESC, source_ip
LIMIT {limit:UInt32}
"""

ANALYST_ACTION_COLUMNS: tuple[str, ...] = (
    "action_id",
    "occurred_at",
    "actor",
    "role",
    "action",
    "alert_id",
    "details",
)
ANALYST_ACTION_TYPES: tuple[str, ...] = (
    "String",
    "DateTime64(3, 'UTC')",
    "String",
    "LowCardinality(String)",
    "LowCardinality(String)",
    "Nullable(String)",
    "String",
)
ANALYST_STATE_COLUMNS: tuple[str, ...] = (
    "alert_id",
    "status",
    "assignee",
    "note",
    "updated_by",
    "updated_at",
)
ANALYST_STATE_TYPES: tuple[str, ...] = (
    "String",
    "LowCardinality(String)",
    "Nullable(String)",
    "Nullable(String)",
    "String",
    "DateTime64(3, 'UTC')",
)

#: Every SELECT statement of this module (used by the static-SQL safety test).
ALL_SELECT_SQL: tuple[str, ...] = (
    PING_SQL,
    ASSETS_ALL_SQL,
    ASSET_GET_SQL,
    ASSET_LAST_EVENTS_SQL,
    COLLECTORS_SQL,
    ASSET_CHILDREN_SQL,
    INVENTORY_SUMMARY_SQL,
    EVENT_COUNTS_BY_SOURCE_SQL,
    FINDINGS_LC_LIST_SQL,
    FINDINGS_LC_COUNT_SQL,
    FINDINGS_LC_SEVERITY_SQL,
    FINDINGS_OBS_LIST_SQL,
    FINDINGS_OBS_COUNT_SQL,
    FINDINGS_OBS_SEVERITY_SQL,
    RULES_LATEST_SQL,
    RULE_LATEST_RUNS_SQL,
    RULE_VERSIONS_SQL,
    RULE_RUNS_SQL,
    ALERT_COUNTS_BY_RULE_SQL,
    ALERT_STATUS_COUNTS_FOR_RULE_SQL,
    ALERT_LIST_SQL,
    ALERT_COUNT_SQL,
    ALERT_GET_SQL,
    ANALYST_STATE_GET_SQL,
    OPEN_ALERT_SEVERITY_SQL,
    OPEN_ALERTS_BY_ASSET_SQL,
    EVIDENCE_REFS_SQL,
    EVIDENCE_TOTAL_SQL,
    EVENTS_BY_IDS_SQL,
    EVENTS_LIST_SQL,
    EVENT_GET_SQL,
    ALERTS_CITING_EVENT_SQL,
    ALERT_ACTIONS_SQL,
    ASSESSMENTS_DIRECT_SQL,
    PIPELINE_LATEST_SQL,
    AI_STATUS_COUNTS_SQL,
    AI_LATEST_SQL,
    INGEST_QUARANTINE_COUNT_SQL,
    INGEST_AUDIT_DECISIONS_SQL,
    ALERT_SERIES_SQL,
    EVENT_SERIES_SQL,
    SERVICES_LIST_SQL,
    SERVICE_GET_SQL,
    SERVICE_INSTANCES_SQL,
    SERVICE_INSTANCES_COUNT_SQL,
    INSTANCES_ON_ASSET_SQL,
    SERVICES_BY_ID_SQL,
    SERVICE_EVENT_SOURCES_SQL,
    SERVICE_AUTH_SUMMARY_SQL,
    SERVICE_AUTH_SOURCES_SQL,
)


# ── Identity checks (F-19) ────────────────────────────────────────────────────────


def identity_matches(row: Row) -> bool:
    """A stored service row carries the id its natural key computes to.

    The gateway quarantines mismatches since session 2 (A, F-19); the API re-checks so a
    row stored before that (or written by another path) never stands in for a real service.
    """
    try:
        expected = compute_service_id(
            str(row["asset_id"]), str(row["service_kind"]), str(row["service_key"])
        )
    except (KeyError, TypeError, ValueError):
        return False
    return expected == str(row.get("service_id"))


# ── Row normalisation ─────────────────────────────────────────────────────────────


def _normalise(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, list):
        return [_normalise(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_normalise(item) for item in value)
    return value


def _rows(result: Any) -> list[Row]:
    return [
        {key: _normalise(value) for key, value in row.items()} for row in result.named_results()
    ]


def _strip_prefix(row: Row, prefix: str) -> Row:
    return {(k[len(prefix) :] if k.startswith(prefix) else k): v for k, v in row.items()}


# ── ClickHouse implementation ─────────────────────────────────────────────────────


class ClickHouseRepository:
    """Repository backed by ClickHouse via the platform storage layer."""

    def __init__(
        self,
        reader: ClientProvider | None = None,
        writer: ClientProvider | None = None,
        *,
        lifecycle_cache_seconds: float = 60.0,
    ) -> None:
        self._reader = reader or ClientProvider("api_ro")
        self._writer = writer or ClientProvider("api_writer")
        self._lifecycle_cache_seconds = lifecycle_cache_seconds
        self._lifecycle: tuple[float, bool] | None = None
        self._lifecycle_lock = threading.Lock()

    # -- plumbing --

    def read_client(self) -> Any:
        return self._reader.get()

    def write_client(self) -> Any:
        return self._writer.get()

    def _query(self, sql: str, params: dict[str, Any] | None = None) -> list[Row]:
        result = self.read_client().query(sql, parameters=params or None)
        return _rows(result)

    def _scalar(self, sql: str, params: dict[str, Any], key: str) -> int:
        rows = self._query(sql, params)
        return int(rows[0][key]) if rows else 0

    def ping(self) -> None:
        self._query(PING_SQL)

    # -- assets / coverage --

    def all_assets(self) -> list[Row]:
        return self._query(ASSETS_ALL_SQL)

    def get_asset(self, asset_id: str) -> Row | None:
        rows = self._query(ASSET_GET_SQL, {"asset_id": asset_id})
        return rows[0] if rows else None

    def asset_last_events(self, asset_ids: Sequence[str]) -> list[Row]:
        return self._query(ASSET_LAST_EVENTS_SQL, {"asset_ids": list(asset_ids)})

    def collectors(self, asset_id: str) -> list[Row]:
        return self._query(COLLECTORS_SQL, {"asset_id": asset_id})

    def asset_children(self, asset_id: str) -> list[Row]:
        return self._query(ASSET_CHILDREN_SQL, {"asset_id": asset_id})

    def inventory_summary(self, asset_id: str) -> list[Row]:
        return self._query(INVENTORY_SUMMARY_SQL, {"asset_id": asset_id})

    def event_counts_by_source(self, asset_id: str, since: datetime, until: datetime) -> list[Row]:
        return self._query(
            EVENT_COUNTS_BY_SOURCE_SQL, {"asset_id": asset_id, "since": since, "until": until}
        )

    # -- findings --

    def findings_lifecycle_available(self) -> bool:
        """Whether ``v_findings_current`` exists (cached for ``lifecycle_cache_seconds``)."""
        now = time.monotonic()
        cached = self._lifecycle
        if cached is not None and now - cached[0] < self._lifecycle_cache_seconds:
            return cached[1]
        with self._lifecycle_lock:
            rows = self.read_client().query(FINDINGS_VIEW_EXISTS_SQL).result_rows
            available = bool(rows and int(rows[0][0]) == 1)
            self._lifecycle = (now, available)
            return available

    def _lifecycle_failed(self, exc: Exception) -> None:
        # A broken/unauthorised view must not take the endpoint down: fall back to the
        # observation query and flag lifecycle_available=false in the response.
        log.warning("findings_lifecycle_query_failed", error_type=type(exc).__name__)
        self._lifecycle = (time.monotonic(), False)

    def list_findings(
        self, filters: FindingFilters, limit: int, offset: int
    ) -> tuple[list[Row], int, bool]:
        params = {
            "asset_id": filters.asset_id,
            "severities": list(filters.severities),
            "scanner": filters.scanner,
            "category": filters.category,
            "service_id": filters.service_id,
        }
        if self.findings_lifecycle_available():
            lc_params = {**params, "states": list(filters.states)}
            try:
                rows = self._query(
                    FINDINGS_LC_LIST_SQL, {**lc_params, "limit": limit, "offset": offset}
                )
                total = self._scalar(FINDINGS_LC_COUNT_SQL, lc_params, "total")
                return rows, total, True
            except Exception as exc:  # noqa: BLE001 - documented fallback, flagged in response
                self._lifecycle_failed(exc)
        rows = self._query(FINDINGS_OBS_LIST_SQL, {**params, "limit": limit, "offset": offset})
        total = self._scalar(FINDINGS_OBS_COUNT_SQL, params, "total")
        return [_strip_prefix(row, "f_") for row in rows], total, False

    def finding_severity_counts(
        self, asset_id: str, exclude_assets: Sequence[str] = ()
    ) -> tuple[list[Row], bool]:
        """Lifecycle mode: rows (severity, state, findings); fallback: (severity, findings).

        ``exclude_assets`` leaves those assets' findings out (retired assets in the overview).
        """
        params = {"asset_id": asset_id, "exclude_assets": list(exclude_assets)}
        if self.findings_lifecycle_available():
            try:
                return self._query(FINDINGS_LC_SEVERITY_SQL, params), True
            except Exception as exc:  # noqa: BLE001 - documented fallback, flagged in response
                self._lifecycle_failed(exc)
        return self._query(FINDINGS_OBS_SEVERITY_SQL, params), False

    # -- services --

    def list_services(self, filters: ServiceFilters, max_rows: int) -> list[Row]:
        params = {
            "asset_id": filters.asset_id,
            "service_kind": filters.service_kind,
            "category": filters.category,
            "adapter_support": filters.adapter_support,
            "monitoring_status": filters.monitoring_status,
            "include_removed": 1 if filters.include_removed else 0,
            "max_rows": max_rows,
        }
        return self._query(SERVICES_LIST_SQL, params)

    def get_service(self, service_id: str) -> Row | None:
        """The newest stored row of ``service_id`` whose id matches its natural key (F-19)."""
        rows = self._query(SERVICE_GET_SQL, {"service_id": service_id})
        valid = [row for row in rows if identity_matches(row)]
        if len(valid) < len(rows):
            log.warning("service_rows_identity_mismatch", count=len(rows) - len(valid))
        return valid[0] if valid else None

    def service_instances(
        self, service_id: str, limit: int, scope_asset: str = ""
    ) -> tuple[list[Row], int]:
        params = {"service_id": service_id, "scope_asset": scope_asset}
        rows = self._query(SERVICE_INSTANCES_SQL, {**params, "limit": limit})
        total = self._scalar(SERVICE_INSTANCES_COUNT_SQL, params, "total")
        return rows, total

    def instances_on_asset(self, asset_id: str, limit: int) -> list[Row]:
        return self._query(INSTANCES_ON_ASSET_SQL, {"asset_id": asset_id, "limit": limit})

    def services_by_id(self, service_ids: Sequence[str], max_rows: int) -> list[Row]:
        if not service_ids:
            return []
        return self._query(
            SERVICES_BY_ID_SQL, {"service_ids": list(service_ids), "max_rows": max_rows}
        )

    def service_event_sources(
        self, service_id: str, since: datetime, until: datetime, scope_asset: str = ""
    ) -> list[Row]:
        params = {"service_id": service_id, "since": since, "until": until}
        return self._query(SERVICE_EVENT_SOURCES_SQL, {**params, "scope_asset": scope_asset})

    def service_auth_summary(
        self, service_id: str, since: datetime, until: datetime, scope_asset: str = ""
    ) -> Row:
        params = {"service_id": service_id, "since": since, "until": until}
        rows = self._query(SERVICE_AUTH_SUMMARY_SQL, {**params, "scope_asset": scope_asset})
        return rows[0] if rows else {}

    def service_auth_sources(
        self, service_id: str, since: datetime, until: datetime, limit: int, scope_asset: str = ""
    ) -> list[Row]:
        return self._query(
            SERVICE_AUTH_SOURCES_SQL,
            {
                "service_id": service_id,
                "since": since,
                "until": until,
                "limit": limit,
                "scope_asset": scope_asset,
            },
        )

    # -- rules --

    def rules_latest(self) -> list[Row]:
        return [_strip_prefix(row, "r_") for row in self._query(RULES_LATEST_SQL)]

    def rule_latest_runs(self) -> list[Row]:
        return self._query(RULE_LATEST_RUNS_SQL)

    def rule_versions(self, rule_id: str) -> list[Row]:
        return self._query(RULE_VERSIONS_SQL, {"rule_id": rule_id})

    def rule_runs(self, rule_id: str, status: str, limit: int, offset: int) -> list[Row]:
        return self._query(
            RULE_RUNS_SQL, {"rule_id": rule_id, "status": status, "limit": limit, "offset": offset}
        )

    def alert_counts_by_rule(self) -> list[Row]:
        return self._query(ALERT_COUNTS_BY_RULE_SQL)

    def alert_status_counts_for_rule(self, rule_id: str) -> list[Row]:
        return self._query(ALERT_STATUS_COUNTS_FOR_RULE_SQL, {"rule_id": rule_id})

    # -- alerts --

    @staticmethod
    def _alert_params(filters: AlertFilters) -> dict[str, Any]:
        return {
            "since": filters.since,
            "until": filters.until,
            "asset_id": filters.asset_id,
            "rule_id": filters.rule_id,
            "severities": list(filters.severities),
            "statuses": list(filters.statuses),
            "open_only": 1 if filters.open_only else 0,
            "simulation_run_id": filters.simulation_run_id,
            "service_id": filters.service_id,
        }

    def list_alerts(self, filters: AlertFilters, limit: int, offset: int) -> list[Row]:
        params = {
            **self._alert_params(filters),
            "sort": filters.sort,
            "limit": limit,
            "offset": offset,
        }
        return self._query(ALERT_LIST_SQL, params)

    def count_alerts(self, filters: AlertFilters) -> int:
        return self._scalar(ALERT_COUNT_SQL, self._alert_params(filters), "total")

    def get_alert(self, alert_id: str) -> Row | None:
        rows = self._query(ALERT_GET_SQL, {"alert_id": alert_id})
        return rows[0] if rows else None

    def get_analyst_state(self, alert_id: str) -> Row | None:
        rows = self._query(ANALYST_STATE_GET_SQL, {"alert_id": alert_id})
        return rows[0] if rows else None

    def open_alert_severity_counts(self, asset_id: str) -> list[Row]:
        return self._query(OPEN_ALERT_SEVERITY_SQL, {"asset_id": asset_id})

    def open_alerts_by_asset(self) -> list[Row]:
        return self._query(OPEN_ALERTS_BY_ASSET_SQL)

    def evidence_refs(self, alert_id: str, limit: int) -> list[Row]:
        return self._query(EVIDENCE_REFS_SQL, {"alert_id": alert_id, "limit": limit})

    def evidence_total(self, alert_id: str, array_ids: Sequence[str]) -> int:
        return self._scalar(
            EVIDENCE_TOTAL_SQL, {"alert_id": alert_id, "array_ids": list(array_ids)}, "total"
        )

    def events_by_ids(self, event_ids: Sequence[str]) -> list[Row]:
        if not event_ids:
            return []
        return self._query(EVENTS_BY_IDS_SQL, {"event_ids": list(event_ids)})

    def alert_actions(self, alert_id: str, limit: int) -> list[Row]:
        return self._query(ALERT_ACTIONS_SQL, {"alert_id": alert_id, "limit": limit})

    def assessments_direct(self, alert_id: str, limit: int) -> list[Row]:
        return self._query(ASSESSMENTS_DIRECT_SQL, {"alert_id": alert_id, "limit": limit})

    # -- events --

    def list_events(self, filters: EventFilters, limit: int, offset: int) -> list[Row]:
        params = {
            "since": filters.since,
            "until": filters.until,
            "asset_id": filters.asset_id,
            "event_type": filters.event_type,
            "event_type_prefix": filters.event_type_prefix,
            "source_type": filters.source_type,
            "category": filters.category,
            "outcome": filters.outcome,
            "actor": filters.actor,
            "src_ip": filters.src_ip,
            "simulation_run_id": filters.simulation_run_id,
            "service_id": filters.service_id,
            "scope_asset": filters.scope_asset,
            "limit": limit,
            "offset": offset,
        }
        return self._query(EVENTS_LIST_SQL, params)

    def get_event(self, event_id: str) -> Row | None:
        rows = self._query(EVENT_GET_SQL, {"event_id": event_id})
        return rows[0] if rows else None

    def alerts_citing_event(self, event_id: str, limit: int) -> list[str]:
        rows = self._query(ALERTS_CITING_EVENT_SQL, {"event_id": event_id, "limit": limit})
        return [str(row["alert_id"]) for row in rows]

    # -- health --

    def pipeline_latest(self) -> list[Row]:
        return self._query(PIPELINE_LATEST_SQL)

    def ai_status_counts(self, since: datetime) -> list[Row]:
        return self._query(AI_STATUS_COUNTS_SQL, {"since": since})

    def ai_latest(self) -> list[Row]:
        return self._query(AI_LATEST_SQL)

    def ingest_quarantine_count(self, since: datetime) -> int:
        return self._scalar(INGEST_QUARANTINE_COUNT_SQL, {"since": since}, "quarantined")

    def ingest_audit_decisions(self, since: datetime) -> list[Row]:
        return self._query(INGEST_AUDIT_DECISIONS_SQL, {"since": since})

    # -- series --

    def alert_series(self, query: SeriesQuery) -> list[Row]:
        params = {
            "since": query.since,
            "until": query.until,
            "bucket": query.bucket_seconds,
            "group_by": query.group_by,
            "asset_id": query.asset_id,
            "rule_id": query.rule_id,
            "severities": list(query.severities),
            "max_rows": query.max_rows,
        }
        return self._query(ALERT_SERIES_SQL, params)

    def event_series(self, query: SeriesQuery) -> list[Row]:
        params = {
            "since": query.since,
            "until": query.until,
            "bucket": query.bucket_seconds,
            "group_by": query.group_by,
            "asset_id": query.asset_id,
            "source_type": query.source_type,
            "event_type": query.event_type,
            "category": query.category,
            "max_rows": query.max_rows,
        }
        return self._query(EVENT_SERIES_SQL, params)

    # -- writes --

    def insert_analyst_action(self, row: Row) -> None:
        self.write_client().insert(
            "analyst_actions",
            [[row[column] for column in ANALYST_ACTION_COLUMNS]],
            column_names=list(ANALYST_ACTION_COLUMNS),
            database="extorq",
            column_type_names=list(ANALYST_ACTION_TYPES),
        )

    def insert_analyst_state(self, row: Row) -> None:
        self.write_client().insert(
            "analyst_state",
            [[row[column] for column in ANALYST_STATE_COLUMNS]],
            column_names=list(ANALYST_STATE_COLUMNS),
            database="extorq",
            column_type_names=list(ANALYST_STATE_TYPES),
        )

"""Generate the provisioned ExtorQ Grafana dashboards (``infra/grafana/dashboards/*.json``).

Usage: ``uv run python infra/grafana/generate_dashboards.py`` (writes the JSON files);
``--check`` exits 1 when a committed file differs from the generated output.

Every panel query is defined here so the SQL rules can be tested in one place
(``tests/unit/api/test_grafana_dashboards.py``):

* only explicit columns (never ``SELECT *``), never ``events.raw``/``events.payload`` or
  ``ingest_quarantine.payload_excerpt`` (the ``extorq_grafana`` identity cannot read them);
* duplicate-safe: ``uniqExact(<id>)``, ``LIMIT 1 BY <id>`` or the ``FINAL`` views (``v_*``);
* time-based tables are always bounded with the plugin macro ``$__timeFilter(...)``;
  "current state" panels read the latest-state views and say so in their description;
* no dashboard variables: no stored value is ever interpolated into SQL text.

Telemetry text (paths, routes, user names, commit data) is attacker-controlled; Grafana
renders table cells as text. Panels never use HTML/markdown rendering of stored values.

Some queries are composed from the module constants below (event-type lists, the
severity order, the coverage expression). That happens once, offline, when the JSON is
generated; this script has no runtime input, hence the ``noqa: S608`` markers.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OUTPUT_DIR = Path(__file__).resolve().parent / "dashboards"
DATASOURCE = {"type": "grafana-clickhouse-datasource", "uid": "extorq-clickhouse"}
PLUGIN_VERSION = "4.23.5"
SCHEMA_VERSION = 41

#: ClickHouse plugin result formats (sqlds): 0 = time series (long -> wide), 1 = table.
FORMAT_TIMESERIES = 0
FORMAT_TABLE = 1

SEVERITY_ORDER = (
    "multiIf(severity = 'critical', 4, severity = 'high', 3, severity = 'medium', 2, "
    "severity = 'low', 1, 0)"
)
SSH_FAILURE_TYPES = (
    "'auth.ssh.login_failed', 'auth.ssh.invalid_user', 'auth.ssh.preauth_closed', "
    "'auth.ssh.max_auth_exceeded'"
)
SYSTEMD_PERSISTENCE_TYPES = (
    "'persistence.systemd.unit_created', 'persistence.systemd.unit_modified', "
    "'persistence.systemd.unit_deleted', 'persistence.systemd.unit_enabled'"
)
RBAC_RESOURCES = "'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings'"
#: Endpoint JSON array -> "tcp/22 any (confirmed)" (display only; values are validated
#: contract fields: protocol enum, port int, exposure enum, attribution enum).
ENDPOINTS_TEXT = (
    "arrayStringConcat(arrayMap(e -> concat(JSONExtractString(e, 'protocol'), '/', "
    "toString(JSONExtractUInt(e, 'port')), ' ', JSONExtractString(e, 'exposure'), ' (', "
    "JSONExtractString(e, 'attribution'), ')'), JSONExtractArrayRaw(endpoints)), ', ')"
)


def coverage_sql(alias: str = "") -> str:
    """Effective coverage approximation for dashboards (columns of ``v_services``).

    The API/console additionally checks collector staleness per telemetry source
    (docs/api/README.md, "Service coverage"); dashboards apply record staleness only.
    """
    p = f"{alias}." if alias else ""
    return (
        f"multiIf({p}adapter_support = 'none', 'unsupported', "
        f"{p}adapter_support = 'planned', 'planned', "
        f"{p}monitoring_status = 'unmonitored', 'unmonitored', "
        f"{p}monitoring_status = 'degraded', 'degraded', "
        f"{p}last_seen < now() - INTERVAL 1 HOUR, 'degraded (stale record)', 'monitored')"
    )


COVERAGE_SQL = coverage_sql()
COVERAGE_NOTE = (
    "Coverage: unsupported = no adapter; planned = extension point only, no telemetry; "
    "unmonitored = adapter not enabled; degraded = stale/failing (also when the discovery "
    "record is older than 1 h); monitored = enabled and fresh. The console/API also checks "
    "collector staleness per telemetry source."
)
SEVERITY_MAPPINGS: list[dict[str, Any]] = [
    {
        "type": "value",
        "options": {
            "critical": {"color": "dark-red", "index": 0},
            "high": {"color": "red", "index": 1},
            "medium": {"color": "orange", "index": 2},
            "low": {"color": "yellow", "index": 3},
            "info": {"color": "blue", "index": 4},
        },
    }
]


@dataclass
class Panel:
    title: str
    kind: str  # stat | timeseries | table | bargauge | row
    sql: str = ""
    description: str = ""
    width: int = 12
    height: int = 8
    fmt: int = FORMAT_TABLE
    unit: str = "short"
    bars: bool = False
    stacked: bool = False
    severity_columns: tuple[str, ...] = ()
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Dashboard:
    uid: str
    title: str
    description: str
    panels: list[Panel]
    time_from: str = "now-24h"


def _target(panel: Panel) -> dict[str, Any]:
    return {
        "refId": "A",
        "datasource": DATASOURCE,
        "editorType": "sql",
        "format": panel.fmt,
        "queryType": "timeseries" if panel.fmt == FORMAT_TIMESERIES else "table",
        "pluginVersion": PLUGIN_VERSION,
        "rawSql": panel.sql.strip(),
    }


def _field_config(panel: Panel) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "unit": panel.unit,
        "color": {"mode": "palette-classic" if panel.kind == "timeseries" else "thresholds"},
        "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]},
        "mappings": [],
    }
    if panel.kind == "timeseries":
        defaults["custom"] = {
            "drawStyle": "bars" if panel.bars else "line",
            "lineWidth": 1,
            "fillOpacity": 60 if panel.bars else 10,
            "showPoints": "never",
            "spanNulls": False,
            "stacking": {"mode": "normal" if panel.stacked else "none", "group": "A"},
        }
    if panel.kind == "table":
        defaults["custom"] = {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": True}
    overrides = [
        {
            "matcher": {"id": "byName", "options": column},
            "properties": [
                {"id": "mappings", "value": SEVERITY_MAPPINGS},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}},
            ],
        }
        for column in panel.severity_columns
    ]
    return {"defaults": defaults, "overrides": overrides}


def _options(panel: Panel) -> dict[str, Any]:
    if panel.kind == "stat":
        base: dict[str, Any] = {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "value",
            "graphMode": "none",
            "justifyMode": "auto",
            "textMode": "value_and_name",
            "orientation": "auto",
        }
    elif panel.kind == "timeseries":
        base = {
            "legend": {"displayMode": "table", "placement": "right", "calcs": ["sum"]},
            "tooltip": {"mode": "multi", "sort": "desc"},
        }
    elif panel.kind == "bargauge":
        base = {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": True},
            "orientation": "horizontal",
            "displayMode": "basic",
            "showUnfilled": True,
        }
    elif panel.kind == "table":
        base = {"showHeader": True, "cellHeight": "sm", "footer": {"show": False}}
    else:
        base = {}
    base.update(panel.options)
    return base


def _layout(panels: list[Panel]) -> list[dict[str, Any]]:
    """Left-to-right, top-to-bottom placement on Grafana's 24-column grid."""
    out: list[dict[str, Any]] = []
    x = y = row_height = 0
    for index, panel in enumerate(panels, start=1):
        if panel.kind == "row":
            if x:
                y += row_height
            out.append(
                {
                    "id": index,
                    "type": "row",
                    "title": panel.title,
                    "collapsed": False,
                    "gridPos": {"h": 1, "w": 24, "x": 0, "y": y},
                    "panels": [],
                }
            )
            x, y, row_height = 0, y + 1, 0
            continue
        if x + panel.width > 24:
            x, y, row_height = 0, y + row_height, 0
        out.append(
            {
                "id": index,
                "type": panel.kind,
                "title": panel.title,
                "description": panel.description,
                "datasource": DATASOURCE,
                "gridPos": {"h": panel.height, "w": panel.width, "x": x, "y": y},
                "targets": [_target(panel)],
                "fieldConfig": _field_config(panel),
                "options": _options(panel),
            }
        )
        x += panel.width
        row_height = max(row_height, panel.height)
    return out


def render(dashboard: Dashboard) -> dict[str, Any]:
    return {
        "uid": dashboard.uid,
        "title": dashboard.title,
        "description": dashboard.description,
        "tags": ["extorq"],
        "timezone": "utc",
        "editable": False,
        "graphTooltip": 1,
        "liveNow": False,
        "refresh": "1m",
        "schemaVersion": SCHEMA_VERSION,
        "version": 1,
        "time": {"from": dashboard.time_from, "to": "now"},
        "timepicker": {},
        "templating": {"list": []},
        "annotations": {"list": []},
        "links": [
            {
                "type": "dashboards",
                "title": "ExtorQ dashboards",
                "tags": ["extorq"],
                "asDropdown": True,
                "includeVars": False,
                "keepTime": True,
                "targetBlank": False,
            }
        ],
        "panels": _layout(dashboard.panels),
    }


def row(title: str) -> Panel:
    return Panel(title=title, kind="row")


# ── 1. Security overview ──────────────────────────────────────────────────────────

SECURITY_OVERVIEW = Dashboard(
    uid="extorq-security-overview",
    title="ExtorQ - Security Overview",
    description=(
        "Event volume, detections, open findings and service coverage. Counts are distinct "
        "ids (uniqExact) so duplicate deliveries never inflate them."
    ),
    panels=[
        row("Activity in range"),
        Panel(
            "Events",
            "stat",
            """
SELECT uniqExact(event_id) AS events
FROM extorq.events
WHERE $__timeFilter(event_time)
""",
            "Distinct normalised events with event_time in the selected range.",
            width=6,
            height=4,
        ),
        Panel(
            "Alerts",
            "stat",
            """
SELECT uniqExact(alert_id) AS alerts
FROM extorq.v_alerts
WHERE $__timeFilter(first_seen)
""",
            "Distinct detection alerts first seen in the range (latest alert version).",
            width=6,
            height=4,
        ),
        Panel(
            "Assets reporting events",
            "stat",
            """
SELECT uniqExact(asset_id) AS assets
FROM extorq.events
WHERE $__timeFilter(event_time)
""",
            "Assets with at least one stored event in the range.",
            width=6,
            height=4,
        ),
        Panel(
            "Open findings (current)",
            "stat",
            """
SELECT uniqExact(finding_id) AS open_findings
FROM extorq.v_findings_current
WHERE state = 'open'
""",
            "Current state (not time-filtered): findings observed by the latest succeeded scan "
            "of their scope (v_findings_current). Unverified findings are excluded.",
            width=6,
            height=4,
        ),
        Panel(
            "Event volume by source type",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time, source_type, uniqExact(event_id) AS events
FROM extorq.events
WHERE $__timeFilter(event_time)
GROUP BY time, source_type
ORDER BY time, source_type
""",
            "Distinct events per interval by telemetry source. A gap means no stored events, "
            "which is not proof of zero activity when collection was unhealthy.",
            width=24,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Alerts by severity",
            "timeseries",
            """
SELECT $__timeInterval(first_seen) AS time, severity, uniqExact(alert_id) AS alerts
FROM extorq.v_alerts
WHERE $__timeFilter(first_seen)
GROUP BY time, severity
ORDER BY time, severity
""",
            "Distinct alerts per interval of first_seen, by severity.",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Alerts by rule",
            "timeseries",
            """
SELECT $__timeInterval(first_seen) AS time, rule_id, uniqExact(alert_id) AS alerts
FROM extorq.v_alerts
WHERE $__timeFilter(first_seen)
GROUP BY time, rule_id
ORDER BY time, rule_id
""",
            "Distinct alerts per interval of first_seen, by detection rule.",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("Posture and assets"),
        Panel(
            "Open findings by severity (current)",
            "bargauge",
            f"""
SELECT severity, uniqExact(finding_id) AS findings
FROM extorq.v_findings_current
WHERE state = 'open'
GROUP BY severity
ORDER BY {SEVERITY_ORDER} DESC
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current lifecycle state (not time-filtered).",
            width=8,
        ),
        Panel(
            "Open findings by scanner and asset (current)",
            "table",
            f"""
SELECT asset_id, scanner, severity, uniqExact(finding_id) AS findings
FROM extorq.v_findings_current
WHERE state = 'open'
GROUP BY asset_id, scanner, severity
ORDER BY asset_id, scanner, {SEVERITY_ORDER} DESC
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current lifecycle state (not time-filtered).",
            width=16,
            severity_columns=("severity",),
        ),
        Panel(
            "Events by asset and source",
            "table",
            """
SELECT asset_id, asset_type, source_type, uniqExact(event_id) AS events,
       max(event_time) AS last_event_time, max(ingested_time) AS last_ingested_time
FROM extorq.events
WHERE $__timeFilter(event_time)
GROUP BY asset_id, asset_type, source_type
ORDER BY asset_id, source_type
LIMIT 500
""",
            "Asset/source breakdown of stored events in the range.",
            width=24,
        ),
        row("Recent alerts"),
        Panel(
            "Recent alerts",
            "table",
            """
SELECT a.last_seen AS last_seen, a.rule_id AS rule_id, a.severity AS severity,
       a.confidence AS confidence, a.asset_id AS asset_id,
       if(ifNull(s.status, '') = '', 'new', s.status) AS analyst_status,
       a.event_count AS events, a.summary AS summary
FROM extorq.v_alerts AS a
LEFT JOIN
(
    SELECT alert_id, status FROM extorq.v_analyst_state
) AS s ON s.alert_id = a.alert_id
WHERE $__timeFilter(a.last_seen)
ORDER BY a.last_seen DESC
LIMIT 100
""",
            "Latest alert versions with analyst workflow state (new when no analyst acted). "
            "Investigate in the ExtorQ console.",
            width=24,
            height=10,
            severity_columns=("severity",),
        ),
        row("Service coverage"),
        Panel(
            "Services by coverage state",
            "bargauge",
            f"""
SELECT coverage, count() AS services
FROM
(
    SELECT {COVERAGE_SQL} AS coverage
    FROM extorq.v_services
    WHERE present = 1
)
GROUP BY coverage
ORDER BY coverage
""",  # noqa: S608 - build-time constants only, no runtime input
            COVERAGE_NOTE + " Rows come from v_services (one row per service, FINAL).",
            width=8,
        ),
        Panel(
            "Services by asset, kind and coverage",
            "table",
            f"""
SELECT asset_id, service_kind, {COVERAGE_SQL} AS coverage, count() AS services
FROM extorq.v_services
WHERE present = 1
GROUP BY asset_id, service_kind, coverage
ORDER BY asset_id, service_kind, coverage
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            COVERAGE_NOTE + " A Kubernetes Service (k8s_service) is never a host OS service.",
            width=16,
        ),
    ],
)

# ── 2. Collector and pipeline health ──────────────────────────────────────────────

COLLECTOR_HEALTH = Dashboard(
    uid="extorq-collector-health",
    title="ExtorQ - Collector & Pipeline Health",
    description=(
        "Collector freshness (stale = now - last success > 3 x interval), ingestion lag, "
        "spool/queue depth, rule failures and the ingestion security boundary."
    ),
    time_from="now-6h",
    panels=[
        row("Collectors (latest report)"),
        Panel(
            "Collectors: last success and staleness",
            "table",
            """
SELECT collector_id, collector_type, asset_id, status,
       multiIf(last_success_at IS NULL, 'never succeeded',
               interval_seconds = 0, 'no interval reported',
               dateDiff('second', last_success_at, now()) > 3 * interval_seconds, 'STALE',
               'fresh') AS freshness,
       last_success_at,
       dateDiff('second', last_success_at, now()) AS seconds_since_success,
       interval_seconds, lag_seconds, records_buffered, events_collected,
       last_reported_at, last_error
FROM extorq.v_collector_latest
ORDER BY asset_id, collector_id
LIMIT 500
""",
            "Current state from v_collector_latest (latest report per collector, not "
            "time-filtered). STALE: no success for more than 3 x the collector interval.",
            width=24,
            height=9,
            options={"sortBy": [{"displayName": "freshness", "desc": False}]},
        ),
        Panel(
            "Collector lag",
            "timeseries",
            """
SELECT $__timeInterval(reported_at) AS time, collector_id, max(lag_seconds) AS max_lag_seconds
FROM extorq.collector_health
WHERE $__timeFilter(reported_at) AND lag_seconds IS NOT NULL
GROUP BY time, collector_id
ORDER BY time, collector_id
""",
            "Lag reported by each collector (seconds behind its source).",
            fmt=FORMAT_TIMESERIES,
            unit="s",
        ),
        Panel(
            "Collector buffered records",
            "timeseries",
            """
SELECT $__timeInterval(reported_at) AS time, collector_id,
       max(records_buffered) AS max_records_buffered
FROM extorq.collector_health
WHERE $__timeFilter(reported_at)
GROUP BY time, collector_id
ORDER BY time, collector_id
""",
            "Records waiting in each collector's outbox (gateway unreachable or slow).",
            fmt=FORMAT_TIMESERIES,
        ),
        row("Ingestion and pipeline"),
        Panel(
            "Ingestion lag p95 (event_time to ingestion)",
            "timeseries",
            """
SELECT $__timeInterval(ingested) AS time, e_source_type AS source_type,
       quantileExact(0.95)(greatest(dateDiff('millisecond', evt, ingested), 0)) / 1000
           AS p95_lag_seconds
FROM
(
    SELECT event_id, any(source_type) AS e_source_type, any(event_time) AS evt,
           min(ingested_time) AS ingested
    FROM extorq.events
    WHERE $__timeFilter(ingested_time)
    GROUP BY event_id
)
GROUP BY time, source_type
ORDER BY time, source_type
""",
            "95th percentile of (first ingestion - event_time) per source, one sample per "
            "distinct event. Includes collector polling delay.",
            fmt=FORMAT_TIMESERIES,
            unit="s",
        ),
        Panel(
            "Pipeline queue depth",
            "timeseries",
            """
SELECT $__timeInterval(reported_at) AS time, concat(component, '/', instance) AS component,
       max(queue_depth) AS max_queue_depth
FROM extorq.pipeline_health
WHERE $__timeFilter(reported_at)
GROUP BY time, component
ORDER BY time, component
""",
            "Spool/queue depth reported by gateway and writer instances.",
            fmt=FORMAT_TIMESERIES,
        ),
        Panel(
            "Oldest queued record age",
            "timeseries",
            """
SELECT $__timeInterval(reported_at) AS time, concat(component, '/', instance) AS component,
       max(oldest_queued_age_seconds) AS max_oldest_queued_age_seconds
FROM extorq.pipeline_health
WHERE $__timeFilter(reported_at) AND oldest_queued_age_seconds IS NOT NULL
GROUP BY time, component
ORDER BY time, component
""",
            "Age of the oldest record still waiting in the spool.",
            fmt=FORMAT_TIMESERIES,
            unit="s",
        ),
        Panel(
            "Pipeline components (latest report)",
            "table",
            """
SELECT component, instance, status, last_reported_at,
       dateDiff('second', last_reported_at, now()) AS report_age_seconds,
       queue_depth, accepted_total, duplicate_total, rejected_total, quarantined_total,
       written_total, write_errors_total, dead_letter_total, last_write_at
FROM extorq.v_pipeline_latest
ORDER BY component, instance
LIMIT 200
""",
            "Current state from v_pipeline_latest (not time-filtered). Counters are totals "
            "since the instance started; an old report_age means the instance stopped "
            "reporting (e.g. replaced by a newer container).",
            width=24,
        ),
        row("Detection rules"),
        Panel(
            "Rules: latest run",
            "table",
            """
SELECT rule_id, rule_version, last_run_at, last_status, runs_24h, failures_24h,
       last_duration_ms, missing_sources, last_error
FROM extorq.v_rule_latest_run
ORDER BY rule_id
LIMIT 200
""",
            "Current state from v_rule_latest_run (not time-filtered). missing_sources lists "
            "telemetry requirements without data in the last window (coverage signal).",
            width=14,
        ),
        Panel(
            "Rule run failures",
            "timeseries",
            """
SELECT $__timeInterval(started_at) AS time, rule_id,
       uniqExactIf(run_id, status = 'failed') AS failed_runs
FROM extorq.rule_runs
WHERE $__timeFilter(started_at)
GROUP BY time, rule_id
ORDER BY time, rule_id
""",
            "Distinct failed rule runs per interval.",
            width=10,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("Ingestion security boundary"),
        Panel(
            "Quarantined records by producer",
            "timeseries",
            """
SELECT $__timeInterval(received_at) AS time, producer_id,
       uniqExact(quarantine_id) AS quarantined
FROM extorq.ingest_quarantine
WHERE $__timeFilter(received_at)
GROUP BY time, producer_id
ORDER BY time, producer_id
""",
            "Records rejected by validation (malformed, unknown event type, out-of-range "
            "time, NaN). The payload excerpt is not readable by Grafana.",
            width=8,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Quarantine reasons",
            "table",
            """
SELECT reason, producer_id, record_kind, uniqExact(quarantine_id) AS records,
       max(received_at) AS last_received_at
FROM extorq.ingest_quarantine
WHERE $__timeFilter(received_at)
GROUP BY reason, producer_id, record_kind
ORDER BY records DESC, reason
LIMIT 50
""",
            "Why records were quarantined (reason text is produced by the gateway).",
            width=8,
        ),
        Panel(
            "Ingest authentication/authorization decisions",
            "timeseries",
            """
SELECT $__timeInterval(occurred_at) AS time, decision, uniqExact(audit_id) AS requests
FROM extorq.ingest_audit
WHERE $__timeFilter(occurred_at)
GROUP BY time, decision
ORDER BY time, decision
""",
            "Unauthenticated / denied / forged telemetry attempts recorded by the gateway.",
            width=8,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("Service telemetry"),
        Panel(
            "Monitored services: telemetry freshness",
            "table",
            f"""
SELECT s.asset_id AS asset_id, s.name AS service, s.service_kind AS kind,
       s.adapter_id AS adapter, {coverage_sql("s")} AS coverage,
       s.last_seen AS discovery_refreshed, e.last_event_time AS last_attributed_event,
       ifNull(e.events, 0) AS events_in_range
FROM extorq.v_services AS s
LEFT JOIN
(
    SELECT assumeNotNull(service_id) AS sid, max(event_time) AS last_event_time,
           uniqExact(event_id) AS events
    FROM extorq.events
    WHERE $__timeFilter(event_time) AND service_id IS NOT NULL
    GROUP BY sid
) AS e ON e.sid = s.service_id
WHERE s.present = 1 AND s.adapter_support = 'implemented'
ORDER BY s.asset_id, s.name
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            COVERAGE_NOTE + " Events are those attributed to the service by its adapter.",
            width=24,
        ),
    ],
)

# ── 3. Linux investigation ────────────────────────────────────────────────────────

LINUX = Dashboard(
    uid="extorq-linux",
    title="ExtorQ - Linux Investigation",
    description=(
        "SSH authentication, sudo, systemd persistence and HTTP probing on Linux hosts "
        "(asset_type linux_host). All text fields are attacker-controllable telemetry."
    ),
    panels=[
        row("SSH authentication"),
        Panel(
            "SSH authentication failures by source IP",
            "timeseries",
            f"""
SELECT $__timeInterval(event_time) AS time, ifNull(src_ip, 'unknown') AS source_ip,
       uniqExact(event_id) AS failures
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type IN ({SSH_FAILURE_TYPES})
GROUP BY time, source_ip
ORDER BY time, source_ip
""",  # noqa: S608 - build-time constants only, no runtime input
            "Failed, invalid-user, pre-auth-closed and max-auth-exceeded sshd events (VM-001 "
            "inputs).",
            width=16,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Successful SSH logins",
            "stat",
            """
SELECT uniqExact(event_id) AS logins
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type = 'auth.ssh.login_succeeded'
""",
            "Distinct successful sshd logins in the range.",
            width=8,
        ),
        Panel(
            "SSH failure sources",
            "table",
            f"""
SELECT asset_id, ifNull(src_ip, 'unknown') AS source_ip, uniqExact(event_id) AS failures,
       uniqExact(tuple(src_ip, src_port)) AS connections, uniqExact(actor_name) AS users,
       min(event_time) AS first_seen, max(event_time) AS last_seen
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type IN ({SSH_FAILURE_TYPES})
GROUP BY asset_id, source_ip
ORDER BY failures DESC
LIMIT 50
""",  # noqa: S608 - build-time constants only, no runtime input
            "Per source: distinct failure events, distinct (src_ip, src_port) connections "
            "(VM-001 counts connections) and attempted user names.",
            width=12,
        ),
        Panel(
            "Recent SSH logins",
            "table",
            """
SELECT event_time, asset_id, actor_name AS user, src_ip,
       JSONExtractString(attributes, 'auth_method') AS auth_method
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type = 'auth.ssh.login_succeeded'
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 100
""",
            "Successful sshd logins (auth_method empty when not reported).",
            width=12,
        ),
        row("Privilege use"),
        Panel(
            "sudo commands",
            "table",
            """
SELECT event_time, asset_id, event_type, actor_name AS user,
       JSONExtractString(attributes, 'run_as') AS run_as, outcome,
       process_command_line AS command
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type IN ('auth.sudo.command', 'auth.sudo.failure')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",
            "sudo commands and failures. Command lines are redacted at ingestion for known "
            "secret patterns; treat them as sensitive.",
            width=24,
        ),
        row("Persistence"),
        Panel(
            "systemd persistence changes",
            "table",
            f"""
SELECT event_time, asset_id, event_type, resource_name AS unit, resource_path AS path,
       JSONExtractString(attributes, 'sha256') AS sha256,
       JSONExtractString(attributes, 'exec_start') AS exec_start, source_type
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND (event_type IN ({SYSTEMD_PERSISTENCE_TYPES})
       OR (event_type = 'file.audit.watch'
           AND JSONExtractString(attributes, 'audit_key') = 'extorq_systemd'))
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Unit created/modified/deleted/enabled (inventory diff) and auditd watches on "
            "systemd paths (VM-002 inputs).",
            width=16,
        ),
        Panel(
            "Persistence events by type",
            "timeseries",
            f"""
SELECT $__timeInterval(event_time) AS time, event_type, uniqExact(event_id) AS events
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND (event_type IN ({SYSTEMD_PERSISTENCE_TYPES}, 'system.systemd.daemon_reload')
       OR (event_type = 'file.audit.watch'
           AND JSONExtractString(attributes, 'audit_key') = 'extorq_systemd'))
GROUP BY time, event_type
ORDER BY time, event_type
""",  # noqa: S608 - build-time constants only, no runtime input
            "Distinct persistence-related events per interval.",
            width=8,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("HTTP"),
        Panel(
            "HTTP responses by status class",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time,
       if(http_status IS NULL, 'unknown', concat(toString(intDiv(http_status, 100)), 'xx'))
           AS status_class,
       uniqExact(event_id) AS requests
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type = 'http.request'
GROUP BY time, status_class
ORDER BY time, status_class
""",
            "Requests seen by the web server/application per HTTP status class.",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Route probing: routes with client errors",
            "table",
            """
SELECT http_route AS route, uniqExact(event_id) AS requests,
       uniqExactIf(event_id, http_status >= 400 AND http_status < 500) AS client_errors,
       uniqExact(src_ip) AS sources, max(event_time) AS last_seen
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type = 'http.request'
GROUP BY route
ORDER BY client_errors DESC, requests DESC
LIMIT 50
""",
            "Routes requested in the range (route text is attacker-controlled).",
        ),
        Panel(
            "Probing sources",
            "table",
            """
SELECT ifNull(src_ip, 'unknown') AS source_ip, uniqExact(event_id) AS requests,
       uniqExact(http_route) AS distinct_routes,
       uniqExactIf(event_id, http_status >= 400 AND http_status < 500) AS client_errors,
       min(event_time) AS first_seen, max(event_time) AS last_seen
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type = 'http.request'
GROUP BY source_ip
ORDER BY client_errors DESC, distinct_routes DESC
LIMIT 50
""",
            "Sources ranked by client errors and distinct routes (probing indicators).",
        ),
        Panel(
            "Application authentication failures",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time, event_type, uniqExact(event_id) AS events
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type IN ('app.auth.login_failed', 'app.authz.denied')
GROUP BY time, event_type
ORDER BY time, event_type
""",
            "Structured authentication/authorization failures from the lab web application.",
            width=24,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("Services on Linux hosts"),
        Panel(
            "Services",
            "table",
            f"""
SELECT asset_id, name AS service, service_kind AS kind, category, product,
       adapter_id AS adapter, adapter_support, monitoring_status,
       {COVERAGE_SQL} AS coverage, {ENDPOINTS_TEXT} AS endpoints,
       arrayStringConcat(telemetry_sources, ', ') AS telemetry_sources,
       instance_count, last_seen AS discovery_refreshed, coverage_note
FROM extorq.v_services
WHERE present = 1
  AND asset_id IN (SELECT asset_id FROM extorq.v_assets WHERE asset_type = 'linux_host')
ORDER BY asset_id, coverage, name
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            COVERAGE_NOTE + " Endpoint attribution: confirmed (socket owner observed), "
            "inferred (configuration/well-known port), unknown.",
            width=24,
            height=10,
        ),
    ],
)

# ── 4. Kubernetes investigation ───────────────────────────────────────────────────

KUBERNETES = Dashboard(
    uid="extorq-kubernetes",
    title="ExtorQ - Kubernetes Investigation",
    description=(
        "Kubernetes API audit (verbs, resources, denials, RBAC changes), workload "
        "authentication failures and the node / workload / Service hierarchy."
    ),
    panels=[
        row("API audit"),
        Panel(
            "API requests by verb",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time, ifNull(k8s_verb, 'unknown') AS verb,
       uniqExact(event_id) AS requests
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'k8s.api.request'
GROUP BY time, verb
ORDER BY time, verb
""",
            "Audited API requests (audit policy decides which requests are logged).",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Denied requests (403) by user",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time, ifNull(k8s_user, 'unknown') AS user,
       uniqExact(event_id) AS denied
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'k8s.api.request'
  AND k8s_response_code = 403
GROUP BY time, user
ORDER BY time, user
""",
            "Requests rejected with HTTP 403 (RBAC or Pod Security admission).",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Resources by verb",
            "table",
            """
SELECT ifNull(k8s_resource, 'unknown') AS resource, ifNull(k8s_verb, 'unknown') AS verb,
       uniqExact(event_id) AS requests,
       uniqExactIf(event_id, k8s_response_code = 403) AS denied,
       uniqExact(k8s_user) AS users
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'k8s.api.request'
GROUP BY resource, verb
ORDER BY requests DESC
LIMIT 100
""",
            "Audited requests per (resource, verb).",
            width=10,
        ),
        Panel(
            "Denied requests",
            "table",
            """
SELECT event_time, k8s_user AS user, k8s_verb AS verb, k8s_resource AS resource,
       k8s_namespace AS namespace, k8s_object_name AS object, k8s_response_code AS code,
       arrayStringConcat(k8s_source_ips, ', ') AS source_ips,
       JSONExtractString(attributes, 'pod_security_violation') AS pod_security_violation
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'k8s.api.request'
  AND k8s_response_code = 403
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",
            "403 responses incl. Pod Security violations (K8S-001 inputs).",
            width=14,
        ),
        Panel(
            "RBAC changes",
            "table",
            f"""
SELECT event_time, event_type, k8s_user AS user, k8s_verb AS verb,
       ifNull(k8s_resource, resource_type) AS resource,
       ifNull(k8s_namespace, resource_namespace) AS namespace,
       ifNull(k8s_object_name, resource_name) AS object, k8s_response_code AS code, outcome,
       arrayStringConcat(JSONExtract(attributes, 'risk_flags', 'Array(String)'), ', ')
           AS risk_flags
FROM extorq.events
WHERE $__timeFilter(event_time)
  AND ((event_type = 'k8s.api.request' AND k8s_resource IN ({RBAC_RESOURCES})
        AND k8s_verb IN ('create', 'update', 'patch', 'delete'))
       OR (event_type IN ('k8s.resource.created', 'k8s.resource.updated',
                          'k8s.resource.deleted')
           AND lower(ifNull(resource_type, '')) IN ('role', 'rolebinding', 'clusterrole',
               'clusterrolebinding', {RBAC_RESOURCES})))
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Role/binding changes from the audit log and from inventory diffs with risk flags "
            "(K8S-002 inputs). risk_flags empty when none were computed.",
            width=24,
        ),
        row("Workloads"),
        Panel(
            "Workload authentication failures",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time,
       concat(ifNull(k8s_namespace, '?'), '/', ifNull(k8s_pod_name, '?')) AS pod,
       uniqExact(event_id) AS failures
FROM extorq.events
WHERE $__timeFilter(event_time) AND source_type = 'k8s.container_log'
  AND category = 'authentication' AND outcome IN ('failure', 'denied')
GROUP BY time, pod
ORDER BY time, pod
""",
            "Structured authentication failures in container logs (lab application).",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Container log volume by namespace",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time, ifNull(k8s_namespace, 'unknown') AS namespace,
       uniqExact(event_id) AS lines
FROM extorq.events
WHERE $__timeFilter(event_time) AND source_type = 'k8s.container_log'
GROUP BY time, namespace
ORDER BY time, namespace
""",
            "Container log events collected by the OTel DaemonSet.",
            fmt=FORMAT_TIMESERIES,
        ),
        row("Hierarchy: nodes, workloads, Kubernetes Services, Pods"),
        Panel(
            "Kubernetes nodes",
            "table",
            """
SELECT asset_id, name, parent_asset_id AS cluster, last_seen, observed_by
FROM extorq.v_assets
WHERE asset_type = 'kubernetes_node'
ORDER BY asset_id
LIMIT 200
""",
            "Node assets (k8s:<cluster>/node/<name>), current state.",
            width=8,
        ),
        Panel(
            "Workloads and Kubernetes Services",
            "table",
            f"""
SELECT asset_id, service_kind AS kind, service_key AS key, name, category,
       adapter_id AS adapter, {COVERAGE_SQL} AS coverage, {ENDPOINTS_TEXT} AS endpoints,
       instance_count, last_seen AS discovery_refreshed
FROM extorq.v_services
WHERE present = 1 AND service_kind IN ('k8s_workload', 'k8s_service')
ORDER BY asset_id, kind, key
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            COVERAGE_NOTE + " k8s_workload = controller or bare Pod; k8s_service = logical "
            "Service object (virtual IP/ports), never a host OS service.",
            width=16,
        ),
        Panel(
            "Pods and containers",
            "table",
            """
SELECT i.namespace AS namespace, i.pod_name AS pod, i.container_name AS container,
       i.instance_kind AS kind, i.state AS state, i.node_name AS node,
       i.workload_kind AS workload_kind, i.workload_name AS workload, i.image AS image,
       i.pod_uid AS pod_uid, i.container_id AS container_id, i.observed_at AS observed_at
FROM extorq.v_service_instances_current AS i
WHERE i.instance_kind IN ('pod', 'container')
ORDER BY namespace, pod, container
LIMIT 500
""",
            "Current Pod/container instances of Kubernetes workloads (v_service_instances_"
            "current: latest version, present only).",
            width=24,
        ),
    ],
)

# ── 5. GitHub investigation ───────────────────────────────────────────────────────

GITHUB = Dashboard(
    uid="extorq-github",
    title="ExtorQ - GitHub Investigation",
    description=(
        "Commits, workflow modifications with permission deltas, workflow runs and "
        "repository findings. Commit and workflow text is attacker-controllable."
    ),
    time_from="now-7d",
    panels=[
        row("Activity"),
        Panel(
            "Commits by repository",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time, ifNull(gh_repository, 'unknown') AS repository,
       uniqExact(event_id) AS commits
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'github.commit.observed'
GROUP BY time, repository
ORDER BY time, repository
""",
            "Commits observed by the GitHub collector (time = commit event time).",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Workflow runs by conclusion",
            "timeseries",
            """
SELECT $__timeInterval(event_time) AS time, ifNull(gh_conclusion, 'pending/unknown')
           AS conclusion,
       uniqExact(event_id) AS runs
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'github.workflow_run.observed'
GROUP BY time, conclusion
ORDER BY time, conclusion
""",
            "Observed workflow runs.",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("Workflow security"),
        Panel(
            "Workflow modifications and permission deltas",
            "table",
            """
SELECT event_time, gh_repository AS repository, gh_workflow_path AS workflow,
       gh_commit_sha AS commit, gh_actor_login AS actor,
       multiIf(NOT JSONHas(attributes, 'write_all_added'), 'not reported',
               JSONExtractBool(attributes, 'write_all_added'), 'YES', 'no') AS write_all_added,
       arrayStringConcat(JSONExtract(attributes, 'added_write_scopes', 'Array(String)'), ', ')
           AS added_write_scopes,
       arrayStringConcat(JSONExtract(attributes, 'triggers_added', 'Array(String)'), ', ')
           AS triggers_added,
       arrayStringConcat(JSONExtract(attributes, 'risk_flags', 'Array(String)'), ', ')
           AS risk_flags
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'github.workflow.modified'
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",
            "GH-001 inputs: write-all, added write scopes and dangerous triggers per workflow "
            "change.",
            width=24,
            height=9,
        ),
        Panel(
            "Recent workflow runs",
            "table",
            """
SELECT event_time, gh_repository AS repository, gh_workflow_path AS workflow,
       gh_workflow_run_id AS run_id, gh_event_name AS trigger, gh_conclusion AS conclusion,
       gh_actor_login AS actor, gh_commit_sha AS commit
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'github.workflow_run.observed'
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 100
""",
            "Latest workflow runs.",
            width=14,
        ),
        Panel(
            "Repository setting changes",
            "table",
            """
SELECT event_time, gh_repository AS repository, event_type, gh_actor_login AS actor,
       message
FROM extorq.events
WHERE $__timeFilter(event_time)
  AND event_type IN ('github.repo.settings_changed', 'github.branch_protection.changed')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 100
""",
            "Repository settings and branch protection changes.",
            width=10,
        ),
        row("Findings (current)"),
        Panel(
            "Repository findings",
            "table",
            f"""
SELECT asset_id AS repository, scanner, severity, state, check_id, title,
       resource_path AS path, last_observed_at, latest_scan_status
FROM extorq.v_findings_current
WHERE startsWith(asset_id, 'github:') AND state IN ('open', 'unverified')
ORDER BY {SEVERITY_ORDER} DESC, last_observed_at DESC
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current lifecycle state (not time-filtered): open = seen in the latest succeeded "
            "scan; unverified = presence cannot be confirmed (failed/partial scan).",
            width=16,
            height=9,
            severity_columns=("severity",),
        ),
        Panel(
            "Open findings by scanner",
            "bargauge",
            """
SELECT scanner, uniqExact(finding_id) AS findings
FROM extorq.v_findings_current
WHERE startsWith(asset_id, 'github:') AND state = 'open'
GROUP BY scanner
ORDER BY findings DESC
""",
            "Current lifecycle state (not time-filtered).",
            width=8,
            height=9,
        ),
    ],
)

DASHBOARDS: tuple[Dashboard, ...] = (
    SECURITY_OVERVIEW,
    COLLECTOR_HEALTH,
    LINUX,
    KUBERNETES,
    GITHUB,
)


def file_name(dashboard: Dashboard) -> str:
    return f"{dashboard.uid}.json"


def rendered_files() -> dict[str, str]:
    return {
        file_name(d): json.dumps(render(d), indent=2, ensure_ascii=False, sort_keys=False) + "\n"
        for d in DASHBOARDS
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail if files are out of date")
    args = parser.parse_args(argv)
    files = rendered_files()
    if args.check:
        stale = [
            name
            for name, text in files.items()
            if not (OUTPUT_DIR / name).is_file()
            or (OUTPUT_DIR / name).read_text(encoding="utf-8") != text
        ]
        extra = sorted(p.name for p in OUTPUT_DIR.glob("*.json") if p.name not in files)
        if stale or extra:
            print(f"out of date: {stale}; unexpected: {extra}", file=sys.stderr)
            return 1
        print("dashboards up to date")
        return 0
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (OUTPUT_DIR / name).write_text(text, encoding="utf-8")
        print(f"wrote {OUTPUT_DIR / name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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

Clarity rules (reviewed for every panel):

* the description says what the panel shows, where the data comes from (table or view and
  the collector / telemetry source behind it) and its caveats;
* counts use the ``short`` unit, durations ``s``/``ms``; volume panels are neutral (no
  colour implies good or bad), risk counts and freshness use thresholds or coloured values
  that carry meaning (``VALUE_COLOURS``), and lag/backlog charts draw their thresholds;
* assets are shown by name: the inventory name (``v_assets.name``) on the cross-asset
  dashboards and the host / repository name embedded in the asset id (``<class>:<name>``) on
  the per-class investigation dashboards; the id stays available as the last column.

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
LAUNCHD_TYPES = (
    "'persistence.launchd.item_created', 'persistence.launchd.item_modified', "
    "'persistence.launchd.item_deleted'"
)
RBAC_RESOURCES = "'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings'"
#: Endpoint JSON array -> "tcp/22 any (confirmed)" (display only; values are validated
#: contract fields: protocol enum, port int, exposure enum, attribution enum).
ENDPOINTS_TEXT = (
    "arrayStringConcat(arrayMap(e -> concat(JSONExtractString(e, 'protocol'), '/', "
    "toString(JSONExtractUInt(e, 'port')), ' ', JSONExtractString(e, 'exposure'), ' (', "
    "JSONExtractString(e, 'attribution'), ')'), JSONExtractArrayRaw(endpoints)), ', ')"
)
#: Inventory name of an asset, joined as ``n`` (one row per asset: ``v_assets`` is FINAL).
ASSET_NAMES = "LEFT JOIN (SELECT asset_id AS n_asset_id, name AS n_name FROM extorq.v_assets) AS n"


def asset_name(column: str) -> str:
    """The joined inventory name, or the asset id when no asset record exists (never blank)."""
    return f"if(ifNull(n.n_name, '') = '', {column}, n.n_name)"


def id_name(column: str = "asset_id") -> str:
    """The natural name inside an asset id (``linux:lab-vm-01`` -> ``lab-vm-01``,
    ``github:owner/repo`` -> ``owner/repo``): asset ids are ``<class>:<name>`` by contract."""
    return f"replaceRegexpOne({column}, '^[a-z0-9]+:', '')"


def json_bool(key: str, yes: str, no: str, unknown: str) -> str:
    """A boolean attribute as words; a missing or null value stays ``unknown`` (never ``no``)."""
    return (
        f"multiIf(JSONType(attributes, '{key}') != 'Bool', '{unknown}', "
        f"JSONExtractBool(attributes, '{key}'), '{yes}', '{no}')"
    )


def json_list(key: str) -> str:
    """A string-array attribute joined with commas (empty when absent)."""
    return f"arrayStringConcat(JSONExtract(attributes, '{key}', 'Array(String)'), ', ')"


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

# ── Colours ───────────────────────────────────────────────────────────────────────

#: Threshold steps ``(from value, colour)``; the first step is the base (``None``).
Steps = tuple[tuple[float | None, str], ...]
#: Volume and inventory figures: no colour suggests good or bad.
NEUTRAL: Steps = ((None, "text"),)
#: A count where any non-zero value needs attention (alerts, open findings).
ANY_IS_ATTENTION: Steps = ((None, "green"), (1, "orange"))

#: Value -> colour for table columns that carry a state. Unlisted values keep the text colour.
VALUE_COLOURS: dict[str, dict[str, str]] = {
    "severity": {
        "critical": "dark-red",
        "high": "red",
        "medium": "orange",
        "low": "yellow",
        "info": "blue",
    },
    "health": {"ok": "green", "degraded": "orange", "failed": "red"},
    "freshness": {
        "fresh": "green",
        "STALE": "red",
        "never succeeded": "red",
        "no interval reported": "orange",
    },
    "delivery": {
        "delivering": "green",
        "running_not_delivering": "orange",
        "degraded": "orange",
        "backlogged": "orange",
        "dropping_records": "red",
        "unavailable": "red",
    },
    "rule_status": {"succeeded": "green", "failed": "red", "skipped": "orange"},
    "coverage": {
        "monitored": "green",
        "degraded": "orange",
        "degraded (stale record)": "orange",
        "unmonitored": "orange",
        "planned": "blue",
    },
    "finding_state": {"open": "red", "unverified": "orange", "resolved": "green"},
    "analyst_status": {"new": "orange", "investigating": "yellow", "acknowledged": "blue"},
    "risk_flag": {"YES": "red"},
    "signature": {"unsigned": "red", "signed": "green"},
    "exposure": {"all interfaces": "red", "specific address": "orange", "loopback": "green"},
    "outcome": {"success": "green", "failure": "orange", "denied": "red"},
    "decision": {"accepted": "green", "denied": "red", "unauthenticated": "red"},
}


def _mapping(name: str) -> list[dict[str, Any]]:
    options = {
        value: {"color": colour, "index": index}
        for index, (value, colour) in enumerate(VALUE_COLOURS[name].items())
    }
    return [{"type": "value", "options": options}]


@dataclass
class Panel:
    """One dashboard panel.

    ``description`` must say what the panel shows, where the data comes from and its caveats
    (enforced by the unit test). ``thresholds`` colour stat values and bar gauges; on a time
    series they are drawn as dashed lines when ``threshold_lines`` is set. ``column_colours``
    maps table columns to a ``VALUE_COLOURS`` set and ``column_units`` gives table columns
    their unit (seconds, milliseconds).
    """

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
    thresholds: Steps = NEUTRAL
    threshold_lines: bool = False
    #: Legend values of a time series: ``sum`` for distinct counts per bucket (each item lies
    #: in one bucket, so the sum is the range total); ``max``/``mean`` for levels and lags.
    legend: tuple[str, ...] = ("sum",)
    column_colours: dict[str, str] = field(default_factory=dict)
    column_units: dict[str, str] = field(default_factory=dict)
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
        "thresholds": {
            "mode": "absolute",
            "steps": [{"color": colour, "value": value} for value, colour in panel.thresholds],
        },
        "mappings": [],
    }
    if panel.kind == "timeseries":
        defaults["min"] = 0
        defaults["custom"] = {
            "drawStyle": "bars" if panel.bars else "line",
            "lineWidth": 1,
            "fillOpacity": 60 if panel.bars else 10,
            "showPoints": "never",
            "spanNulls": False,
            "stacking": {"mode": "normal" if panel.stacked else "none", "group": "A"},
            "thresholdsStyle": {"mode": "dashed" if panel.threshold_lines else "off"},
        }
    if panel.kind == "table":
        defaults["custom"] = {
            "align": "auto",
            "cellOptions": {"type": "auto"},
            "inspect": True,
            # Client-side column filters only: nothing typed there reaches the SQL.
            "filterable": True,
        }
    overrides: list[dict[str, Any]] = [
        {
            "matcher": {"id": "byName", "options": column},
            "properties": [
                {"id": "mappings", "value": _mapping(mapping)},
                {"id": "custom.cellOptions", "value": {"type": "color-text"}},
            ],
        }
        for column, mapping in panel.column_colours.items()
    ]
    overrides += [
        {
            "matcher": {"id": "byName", "options": column},
            "properties": [{"id": "unit", "value": unit}],
        }
        for column, unit in panel.column_units.items()
    ]
    return {"defaults": defaults, "overrides": overrides}


def _options(panel: Panel) -> dict[str, Any]:
    if panel.kind == "stat":
        base: dict[str, Any] = {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": "value",
            "graphMode": "none",
            "justifyMode": "auto",
            "textMode": "value",
            "orientation": "auto",
        }
    elif panel.kind == "timeseries":
        base = {
            "legend": {"displayMode": "table", "placement": "right", "calcs": list(panel.legend)},
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
        "All monitored assets at a glance: event volume, detections, open findings and service "
        "coverage. Counts are distinct ids (uniqExact) so duplicate deliveries never inflate "
        "them. Investigate alerts in the ExtorQ console; these panels are for trends."
    ),
    panels=[
        row("Activity in the selected range"),
        Panel(
            "Events",
            "stat",
            """
SELECT uniqExact(event_id) AS events
FROM extorq.events
WHERE $__timeFilter(event_time)
""",
            "Distinct normalised security events whose event_time falls in the selected range, "
            "across every asset. Source: extorq.events (all collectors through the ingest "
            "gateway). Volume only: a high or low number is neither good nor bad by itself.",
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
            "Distinct detection alerts first seen in the range (latest version of each alert). "
            "Source: v_alerts, written only by the detector's versioned SQL rules. Orange when "
            "any alert exists; triage them in the console (Detections).",
            width=6,
            height=4,
            thresholds=ANY_IS_ATTENTION,
        ),
        Panel(
            "Assets reporting events",
            "stat",
            """
SELECT uniqExact(asset_id) AS assets
FROM extorq.events
WHERE $__timeFilter(event_time)
""",
            "Assets with at least one stored event in the range. Source: extorq.events. An asset "
            "missing here sent no telemetry in the range: check Collector & Pipeline Health.",
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
            "Current state, not time-filtered: findings seen by the latest succeeded scan of "
            "their scope. Source: v_findings_current (Trivy, Gitleaks, Semgrep and posture "
            "checks). Unverified findings (failed or partial scans) are excluded.",
            width=6,
            height=4,
            thresholds=ANY_IS_ATTENTION,
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
            "Distinct events per interval by telemetry source (e.g. linux.journald, k8s.audit, "
            "github.api, macos.unified_log). Source: extorq.events. A gap means nothing was "
            "stored, which is not proof of zero activity when collection was unhealthy.",
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
            "Distinct alerts per interval of first_seen, split by the severity the rule assigns. "
            "Source: v_alerts (detector).",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Alerts by rule",
            "timeseries",
            """
SELECT $__timeInterval(first_seen) AS time, concat(rule_id, ' ', rule_title) AS rule,
       uniqExact(alert_id) AS alerts
FROM extorq.v_alerts
WHERE $__timeFilter(first_seen)
GROUP BY time, rule
ORDER BY time, rule
""",
            "Distinct alerts per interval of first_seen, by detection rule (id and title). "
            "Source: v_alerts (detector). Rule logic, false positives and blind spots: "
            "docs/detection-catalog.md.",
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
            "Current state, not time-filtered: open findings per severity across all assets. "
            "Source: v_findings_current (scanner and posture results tied to their scan runs).",
            width=8,
        ),
        Panel(
            "Open findings by asset and scanner (current)",
            "table",
            f"""
SELECT {asset_name("f.f_asset_id")} AS asset, f.f_scanner AS scanner, f.f_severity AS severity,
       f.findings AS findings, f.f_asset_id AS asset_id
FROM
(
    SELECT asset_id AS f_asset_id, scanner AS f_scanner, severity AS f_severity,
           uniqExact(finding_id) AS findings
    FROM extorq.v_findings_current
    WHERE state = 'open'
    GROUP BY f_asset_id, f_scanner, f_severity
) AS f
{ASSET_NAMES} ON n.n_asset_id = f.f_asset_id
ORDER BY asset, scanner, {SEVERITY_ORDER} DESC
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current state, not time-filtered: open findings per asset (inventory name), scanner "
            "and severity. Source: v_findings_current joined to v_assets for the name.",
            width=16,
            column_colours={"severity": "severity"},
        ),
        Panel(
            "Events by asset and source",
            "table",
            f"""
SELECT {asset_name("e.e_asset_id")} AS asset, e.e_asset_type AS asset_type,
       e.e_source_type AS source_type, e.events AS events, e.last_event AS last_event_time,
       e.last_ingested AS last_ingested_time, e.e_asset_id AS asset_id
FROM
(
    SELECT asset_id AS e_asset_id, any(asset_type) AS e_asset_type,
           source_type AS e_source_type, uniqExact(event_id) AS events,
           max(event_time) AS last_event, max(ingested_time) AS last_ingested
    FROM extorq.events
    WHERE $__timeFilter(event_time)
    GROUP BY e_asset_id, e_source_type
) AS e
{ASSET_NAMES} ON n.n_asset_id = e.e_asset_id
ORDER BY asset, source_type
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            "Distinct events per asset and telemetry source in the range, with the newest event "
            "and ingestion times. Source: extorq.events joined to v_assets for the name. A source "
            "whose last event is old is quiet or failing: compare with collector health.",
            width=24,
        ),
        row("Recent alerts"),
        Panel(
            "Recent alerts",
            "table",
            f"""
SELECT a.last_seen AS last_seen, a.rule_id AS rule_id, a.rule_title AS rule_title,
       a.severity AS severity, a.confidence AS confidence, {asset_name("a.asset_id")} AS asset,
       if(ifNull(s.status, '') = '', 'new', s.status) AS analyst_status,
       a.event_count AS events, a.summary AS summary, a.asset_id AS asset_id
FROM extorq.v_alerts AS a
LEFT JOIN
(
    SELECT alert_id, status FROM extorq.v_analyst_state
) AS s ON s.alert_id = a.alert_id
{ASSET_NAMES} ON n.n_asset_id = a.asset_id
WHERE $__timeFilter(a.last_seen)
ORDER BY a.last_seen DESC
LIMIT 100
""",  # noqa: S608 - build-time constants only, no runtime input
            "Latest version of each alert active in the range, with the analyst workflow state "
            "(new when no analyst acted). Source: v_alerts (detector) and v_analyst_state "
            "(console). Confidence is evidence completeness, not a verdict. Investigate in the "
            "ExtorQ console.",
            width=24,
            height=10,
            column_colours={"severity": "severity", "analyst_status": "analyst_status"},
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
            "Current state: present services by effective coverage. Source: v_services (one "
            "row per service, FINAL; reported by host and Kubernetes service discovery). "
            + COVERAGE_NOTE,
            width=8,
        ),
        Panel(
            "Services by asset, kind and coverage",
            "table",
            f"""
SELECT {asset_name("v.v_asset_id")} AS asset, v.v_kind AS service_kind, v.v_coverage AS coverage,
       v.services AS services, v.v_asset_id AS asset_id
FROM
(
    SELECT asset_id AS v_asset_id, service_kind AS v_kind, {COVERAGE_SQL} AS v_coverage,
           count() AS services
    FROM extorq.v_services
    WHERE present = 1
    GROUP BY v_asset_id, v_kind, v_coverage
) AS v
{ASSET_NAMES} ON n.n_asset_id = v.v_asset_id
ORDER BY asset, service_kind, coverage
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current state: present services per asset, kind and coverage. Source: v_services "
            "joined to v_assets. A Kubernetes Service (k8s_service) is never a host OS service. "
            + COVERAGE_NOTE,
            width=16,
            column_colours={"coverage": "coverage"},
        ),
    ],
)

# ── 2. Collector and pipeline health ──────────────────────────────────────────────

COLLECTOR_HEALTH = Dashboard(
    uid="extorq-collector-health",
    title="ExtorQ - Collector & Pipeline Health",
    description=(
        "Is telemetry arriving? Collector freshness (stale = now - last success > 3 x "
        "interval), collector and ingestion lag, spool backlog, detection rule execution and "
        "the ingestion security boundary (quarantine, rejected producers)."
    ),
    time_from="now-6h",
    panels=[
        row("Collectors (latest report)"),
        Panel(
            "Collectors: last success and staleness",
            "table",
            f"""
SELECT c.collector_id AS collector_id, c.collector_type AS collector_type,
       {asset_name("c.asset_id")} AS asset, c.status AS status,
       multiIf(c.last_success_at IS NULL, 'never succeeded',
               c.interval_seconds = 0, 'no interval reported',
               dateDiff('second', c.last_success_at, now()) > 3 * c.interval_seconds, 'STALE',
               'fresh') AS freshness,
       c.last_success_at AS last_success_at,
       dateDiff('second', c.last_success_at, now()) AS seconds_since_success,
       c.interval_seconds AS interval_seconds, c.lag_seconds AS lag_seconds,
       if(c.collector_type = 'k8s_otel', NULL, c.records_buffered) AS records_buffered,
       c.events_collected AS events_collected,
       c.last_reported_at AS last_reported_at, c.last_error AS last_error,
       c.asset_id AS asset_id
FROM extorq.v_collector_latest AS c
{ASSET_NAMES} ON n.n_asset_id = c.asset_id
ORDER BY asset, collector_id
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current state, not time-filtered: the latest health report of every collector. "
            "Source: v_collector_latest (collector SDK and OpenTelemetry delivery reports). "
            "STALE: no successful collection for more than 3 x its interval. "
            "SDK collectors report records buffered in their outbox. The OpenTelemetry panel "
            "reports its queue separately in exporter requests.",
            width=24,
            height=9,
            column_colours={"status": "health", "freshness": "freshness"},
            column_units={
                "seconds_since_success": "s",
                "interval_seconds": "s",
                "lag_seconds": "s",
            },
            options={"sortBy": [{"displayName": "freshness", "desc": False}]},
        ),
        Panel(
            "Kubernetes OpenTelemetry delivery by node and source",
            "table",
            f"""
SELECT {asset_name("c.asset_id")} AS node, c.source_types AS sources,
       multiIf(dateDiff('second', c.last_reported_at, now()) > 3 * c.interval_seconds,
               'unavailable',
               JSONExtractString(c.details, 'delivery_state') IN
                   ('delivering', 'running_not_delivering', 'degraded', 'backlogged',
                    'dropping_records', 'unavailable'),
               JSONExtractString(c.details, 'delivery_state'), 'unknown') AS delivery_state,
       JSONExtract(c.details, 'queue_requests', 'Nullable(UInt64)') AS queue_requests,
       JSONExtract(c.details, 'queue_capacity_requests', 'Nullable(UInt64)') AS queue_capacity,
       JSONExtract(c.details, 'accepted_records', 'Nullable(UInt64)') AS accepted_records,
       JSONExtract(c.details, 'sent_records', 'Nullable(UInt64)') AS exporter_sent_records,
       JSONExtract(c.details, 'send_failed_records', 'Nullable(UInt64)') AS exporter_send_failures,
       JSONExtract(c.details, 'enqueue_failed_records', 'Nullable(UInt64)')
           AS exporter_enqueue_failures,
       c.last_success_at AS last_delivery, c.last_reported_at AS last_report, c.asset_id AS asset_id
FROM extorq.v_collector_latest AS c
{ASSET_NAMES} ON n.n_asset_id = c.asset_id
WHERE c.collector_type = 'k8s_otel'
ORDER BY node, sources
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current reported delivery for each node and source. Source: v_collector_latest "
            "(OpenTelemetry reporter). A report older than three intervals is unavailable. "
            "Queue and exporter counts are shared on the node and must not be summed across "
            "sources. Record counters are cumulative since the Collector started. Blank values "
            "indicate unavailable measurements.",
            width=24,
            height=8,
            column_colours={"delivery_state": "delivery"},
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
            "How far each collector is behind its source (seconds), as it reports it. Source: "
            "extorq.collector_health. Dashed lines: 5 min (attention) and 15 min (detections "
            "run on late data). Collectors that do not report lag are absent.",
            fmt=FORMAT_TIMESERIES,
            unit="s",
            thresholds=((None, "green"), (300, "orange"), (900, "red")),
            threshold_lines=True,
            legend=("max", "lastNotNull"),
        ),
        Panel(
            "Collector buffered records",
            "timeseries",
            """
SELECT $__timeInterval(reported_at) AS time, collector_id,
       max(records_buffered) AS max_records_buffered
FROM extorq.collector_health
WHERE $__timeFilter(reported_at) AND collector_type != 'k8s_otel'
GROUP BY time, collector_id
ORDER BY time, collector_id
""",
            "Records waiting in each SDK collector's durable outbox (gateway unreachable or slow). "
            "Source: extorq.collector_health. A growing line means delivery is falling behind. "
            "Dashed lines: 100 and 1000 records. OpenTelemetry queue requests appear separately.",
            fmt=FORMAT_TIMESERIES,
            thresholds=((None, "green"), (100, "orange"), (1000, "red")),
            threshold_lines=True,
            legend=("max", "lastNotNull"),
        ),
        row("Ingestion and pipeline"),
        Panel(
            "Ingestion lag p95 (event time to ingestion)",
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
            "95th percentile of (first ingestion - event_time) per telemetry source, one sample "
            "per distinct event. Source: extorq.events. Includes collector polling intervals and "
            "source clock skew. Dashed lines: 2 min and 10 min.",
            fmt=FORMAT_TIMESERIES,
            unit="s",
            thresholds=((None, "green"), (120, "orange"), (600, "red")),
            threshold_lines=True,
            legend=("max", "mean"),
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
            "Records waiting in each pipeline component (the gateway and writer share one "
            "SQLite spool). Source: extorq.pipeline_health. A depth that keeps growing means the "
            "writer cannot keep up or ClickHouse refuses writes. Dashed lines: 1000 and 10000.",
            fmt=FORMAT_TIMESERIES,
            thresholds=((None, "green"), (1000, "orange"), (10000, "red")),
            threshold_lines=True,
            legend=("max", "lastNotNull"),
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
            "Age of the oldest record still waiting in the spool. Source: "
            "extorq.pipeline_health. The writer normally drains the spool within seconds. "
            "Dashed lines: 1 min and 5 min.",
            fmt=FORMAT_TIMESERIES,
            unit="s",
            thresholds=((None, "green"), (60, "orange"), (300, "red")),
            threshold_lines=True,
            legend=("max", "lastNotNull"),
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
            "Current state, not time-filtered: the latest report of each gateway, writer, "
            "detector and ai-worker instance. Source: v_pipeline_latest. Counters are totals "
            "since the instance started; an old report_age means the instance stopped "
            "reporting (for example replaced by a newer container).",
            width=24,
            column_colours={"status": "health"},
            column_units={"report_age_seconds": "s"},
        ),
        row("Detection rules"),
        Panel(
            "Rules: latest run",
            "table",
            """
SELECT r.rule_id AS rule_id, ifNull(d.d_title, '') AS title, r.rule_version AS rule_version,
       r.last_run_at AS last_run_at, r.last_status AS last_status, r.runs_24h AS runs_24h,
       r.failures_24h AS failures_24h, r.last_duration_ms AS last_duration_ms,
       arrayStringConcat(r.missing_sources, ', ') AS missing_sources, r.last_error AS last_error
FROM extorq.v_rule_latest_run AS r
LEFT JOIN
(
    SELECT rule_id AS d_rule_id, argMax(title, loaded_at) AS d_title
    FROM extorq.detection_rules
    GROUP BY d_rule_id
) AS d ON d.d_rule_id = r.rule_id
ORDER BY rule_id
LIMIT 200
""",
            "Current state, not time-filtered: the latest run of every detection rule. Sources: "
            "v_rule_latest_run (written by the detector) and detection_rules (titles). "
            "missing_sources lists required telemetry with no data in the last window: the rule "
            "is blind there, which is a coverage signal, not a failure.",
            width=14,
            column_colours={"last_status": "rule_status"},
            column_units={"last_duration_ms": "ms"},
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
            "Distinct failed rule runs per interval and rule. Source: extorq.rule_runs "
            "(detector). Any bar is worth a look: the sanitised error is in Rules: latest run.",
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
            "Records the gateway rejected after authentication (malformed, unknown event type, "
            "out-of-range time, NaN). Source: extorq.ingest_quarantine. The payload excerpt is "
            "not readable by Grafana.",
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
            "Why records were quarantined in the range, per producer and record kind. Source: "
            "extorq.ingest_quarantine (reason text is written by the gateway).",
            width=8,
        ),
        Panel(
            "Ingest authentication and authorization decisions",
            "timeseries",
            """
SELECT $__timeInterval(occurred_at) AS time, decision, uniqExact(audit_id) AS requests
FROM extorq.ingest_audit
WHERE $__timeFilter(occurred_at)
GROUP BY time, decision
ORDER BY time, decision
""",
            "Requests the gateway refused or audited (bad token, producer not allowed for a "
            "kind, source or asset). Source: extorq.ingest_audit. Unexpected spikes mean forged "
            "or misconfigured telemetry producers.",
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
SELECT {asset_name("s.asset_id")} AS asset, s.name AS service, s.service_kind AS kind,
       s.adapter_id AS adapter, {coverage_sql("s")} AS coverage,
       s.last_seen AS discovery_refreshed, e.last_event_time AS last_attributed_event,
       ifNull(e.events, 0) AS events_in_range, s.asset_id AS asset_id
FROM extorq.v_services AS s
LEFT JOIN
(
    SELECT assumeNotNull(service_id) AS sid, max(event_time) AS last_event_time,
           uniqExact(event_id) AS events
    FROM extorq.events
    WHERE $__timeFilter(event_time) AND service_id IS NOT NULL
    GROUP BY sid
) AS e ON e.sid = s.service_id
{ASSET_NAMES} ON n.n_asset_id = s.asset_id
WHERE s.present = 1 AND s.adapter_support = 'implemented'
ORDER BY asset, service
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            "Services with an implemented adapter: when discovery last refreshed them and their "
            "newest attributed event in the range. Sources: v_services and extorq.events (events "
            "the adapter attributed to the service). A quiet service is not necessarily broken. "
            + COVERAGE_NOTE,
            width=24,
            column_colours={"coverage": "coverage"},
        ),
    ],
)

# ── 3. Linux investigation ────────────────────────────────────────────────────────

LINUX = Dashboard(
    uid="extorq-linux",
    title="ExtorQ - Linux Investigation",
    description=(
        "Linux hosts (asset_type linux_host): SSH authentication, sudo, accounts, systemd and "
        "cron persistence, HTTP probing and application logins. Sources: linux.journald, "
        "linux.auditd, linux.inventory, linux.nginx, linux.app (Linux SSH collector). host = "
        "the name inside the asset id. All text fields are attacker-controllable telemetry."
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
            "Failed, invalid-user, pre-auth-closed and max-auth-exceeded sshd events per source "
            "address (VM-001 inputs). Source: linux.journald. Behind NAT every client shares one "
            "address.",
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
            "Distinct successful sshd logins in the range on Linux hosts. Source: "
            "linux.journald. Compare with the failures: success after a failure burst matters.",
            width=8,
        ),
        Panel(
            "SSH failure sources",
            "table",
            f"""
SELECT {id_name()} AS host, ifNull(src_ip, 'unknown') AS source_ip,
       uniqExact(event_id) AS failures, uniqExact(tuple(src_ip, src_port)) AS connections,
       uniqExact(actor_name) AS users, min(event_time) AS first_seen,
       max(event_time) AS last_seen
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type IN ({SSH_FAILURE_TYPES})
GROUP BY host, source_ip
ORDER BY failures DESC
LIMIT 50
""",  # noqa: S608 - build-time constants only, no runtime input
            "Per host and source: distinct failure events, distinct (src_ip, src_port) "
            "connections (VM-001 counts connections, threshold 5 in 5 min) and attempted user "
            "names. Source: linux.journald.",
            width=12,
        ),
        Panel(
            "Recent SSH logins",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, actor_name AS user, src_ip,
       JSONExtractString(attributes, 'auth_method') AS auth_method
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type = 'auth.ssh.login_succeeded'
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 100
""",  # noqa: S608 - build-time constants only, no runtime input
            "Successful sshd logins, newest first. Source: linux.journald. auth_method is empty "
            "when sshd did not report it.",
            width=12,
        ),
        row("Privilege use and accounts"),
        Panel(
            "sudo commands and failures",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, event_type, actor_name AS user,
       JSONExtractString(attributes, 'run_as') AS run_as, outcome,
       process_command_line AS command
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type IN ('auth.sudo.command', 'auth.sudo.failure')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "sudo commands and denials, newest first. Source: linux.journald. Command lines are "
            "redacted at ingestion for known secret patterns; still treat them as sensitive.",
            width=14,
            column_colours={"outcome": "outcome"},
        ),
        Panel(
            "Local accounts and cron changes",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, event_type, actor_name AS account,
       JSONExtractString(attributes, 'uid') AS uid, JSONExtractString(attributes, 'shell') AS shell,
       resource_path AS path, JSONExtractString(attributes, 'sha256') AS sha256
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND event_type IN ('account.user.created', 'account.user.deleted', 'persistence.cron.changed')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Local accounts that appeared or disappeared and cron configuration changes between "
            "inventory snapshots (VM-003 and VM-004 inputs). Source: linux.inventory. The change "
            "time is the snapshot that saw it, not the second it happened.",
            width=10,
        ),
        row("Persistence"),
        Panel(
            "systemd persistence changes",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, event_type, resource_name AS unit, resource_path AS path,
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
            "systemd units created, modified, deleted or enabled and auditd watches on systemd "
            "paths: the VM-002 inputs. Sources: linux.inventory (snapshot diff), linux.auditd "
            "(watch key extorq_systemd). Both sources agreeing raises VM-002's confidence.",
            width=16,
        ),
        Panel(
            "Persistence events by type",
            "timeseries",
            f"""
SELECT $__timeInterval(event_time) AS time, event_type, uniqExact(event_id) AS events
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'linux_host'
  AND (event_type IN ({SYSTEMD_PERSISTENCE_TYPES}, 'system.systemd.daemon_reload',
                      'persistence.cron.changed')
       OR (event_type = 'file.audit.watch'
           AND JSONExtractString(attributes, 'audit_key') = 'extorq_systemd'))
GROUP BY time, event_type
ORDER BY time, event_type
""",  # noqa: S608 - build-time constants only, no runtime input
            "Distinct persistence-related events per interval (systemd units, daemon reloads, "
            "cron changes, auditd systemd watches). Sources: linux.inventory, linux.journald, "
            "linux.auditd.",
            width=8,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("HTTP and web application"),
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
            "Requests seen by web servers and applications per HTTP status class. Sources: "
            "linux.nginx, linux.apache, linux.app. A rise in 4xx often means probing.",
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
            "Routes requested in the range, ranked by 4xx answers (HTTP-001 looks for many "
            "probe-like paths from one source). Sources: linux.nginx, linux.apache, linux.app. "
            "Route text is attacker-controlled; query strings are stripped at collection.",
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
            "Client addresses ranked by client errors and distinct routes (probing indicators). "
            "Sources: linux.nginx, linux.apache, linux.app.",
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
            "Structured login failures and authorization denials written by web applications on "
            "Linux hosts (the lab-portal app's JSON log; APP-001 inputs). Source: linux.app.",
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
SELECT {id_name()} AS host, name AS service, service_kind AS kind, category, product,
       adapter_id AS adapter, adapter_support, monitoring_status,
       {COVERAGE_SQL} AS coverage, {ENDPOINTS_TEXT} AS endpoints,
       arrayStringConcat(telemetry_sources, ', ') AS telemetry_sources,
       instance_count, last_seen AS discovery_refreshed, coverage_note
FROM extorq.v_services
WHERE present = 1
  AND asset_id IN (SELECT asset_id FROM extorq.v_assets WHERE asset_type = 'linux_host')
ORDER BY host, coverage, name
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current state: services discovered on Linux hosts (systemd units, processes, "
            "listening sockets) with their adapter and coverage. Source: v_services (Linux "
            "service discovery). Endpoint attribution: confirmed (socket owner observed), "
            "inferred (configuration or well-known port), unknown. " + COVERAGE_NOTE,
            width=24,
            height=10,
            column_colours={"coverage": "coverage"},
        ),
    ],
)

# ── 4. Kubernetes investigation ───────────────────────────────────────────────────

KUBERNETES = Dashboard(
    uid="extorq-kubernetes",
    title="ExtorQ - Kubernetes Investigation",
    description=(
        "Kubernetes clusters: API audit (verbs, denials, RBAC changes, exec into Pods, secret "
        "access, Pod admissions), workload authentication failures and the node / workload / "
        "Service hierarchy. Sources: k8s.audit and k8s.container_log (OTel collector in the "
        "cluster), k8s.api_inventory. The audit policy decides which requests are logged."
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
            "Audited Kubernetes API requests per verb. Source: k8s.audit (API server audit log). "
            "Volume only; the audit policy decides which requests appear.",
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
            "Requests rejected with HTTP 403 (RBAC or Pod Security admission) per user. Source: "
            "k8s.audit.",
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
            "Audited requests per (resource, verb) with denials and distinct users. Source: "
            "k8s.audit.",
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
            "403 responses, newest first, including Pod Security violations (K8S-001 inputs: a "
            "privileged Pod refused by an enforcing namespace). Source: k8s.audit.",
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
       {json_list("risk_flags")} AS risk_flags
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
            "Role and binding changes from the audit log and from inventory diffs with risk "
            "flags: the K8S-002 inputs. Sources: k8s.audit, k8s.api_inventory. risk_flags is "
            "empty when none were computed.",
            width=24,
            column_colours={"outcome": "outcome"},
        ),
        Panel(
            "Interactive exec and attach into Pods",
            "table",
            """
SELECT event_time, k8s_user AS user, k8s_namespace AS namespace, k8s_object_name AS pod,
       k8s_subresource AS subresource, k8s_verb AS verb, k8s_response_code AS code,
       arrayStringConcat(k8s_source_ips, ', ') AS source_ips
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'k8s.api.request'
  AND k8s_resource = 'pods' AND k8s_subresource IN ('exec', 'attach')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",
            "kubectl exec / attach sessions into Pods, newest first (K8S-003 inputs). Source: "
            "k8s.audit. The command itself is not stored (only the request path, redacted).",
            width=12,
        ),
        Panel(
            "Secret access",
            "table",
            """
SELECT event_time, k8s_user AS user, k8s_verb AS verb,
       if(ifNull(k8s_namespace, '') = '', 'all namespaces', k8s_namespace) AS scope,
       k8s_object_name AS secret, k8s_response_code AS code,
       arrayStringConcat(k8s_source_ips, ', ') AS source_ips
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'k8s.api.request'
  AND k8s_resource = 'secrets' AND k8s_verb IN ('get', 'list', 'watch')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",
            "Reads of Secret objects, newest first; scope 'all namespaces' is a cluster-wide "
            "list (K8S-004 inputs). Source: k8s.audit. Controllers read secrets routinely: look "
            "at the user. Secret values are never collected.",
            width=12,
        ),
        Panel(
            "Pod creations and admission outcome",
            "table",
            """
SELECT event_time, k8s_user AS user, k8s_namespace AS namespace, k8s_object_name AS pod,
       k8s_response_code AS code,
       JSONExtractString(attributes, 'pod_security_violation') AS pod_security_violation,
       substring(JSONExtractRaw(attributes, 'request_summary'), 1, 300) AS request_summary
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'k8s.api.request'
  AND k8s_resource = 'pods' AND ifNull(k8s_subresource, '') = '' AND k8s_verb = 'create'
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",
            "Pod create requests with the admission result: 201 admitted, 403 refused "
            "(K8S-001 refused privileged Pods, K8S-005 privileged or host-namespace Pods that "
            "were admitted). Source: k8s.audit; request_summary is the normaliser's summary of "
            "the Pod spec (truncated to 300 characters).",
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
            "Structured authentication failures that applications write to their container logs "
            "(the lab-portal web app logs login failures as JSON), per Pod. Source: "
            "k8s.container_log.",
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
            "Container log events per namespace, collected by the OTel DaemonSet. Source: "
            "k8s.container_log. Volume only.",
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
            "Current state: node assets (k8s:<cluster>/node/<name>) and their cluster. Source: "
            "v_assets (Kubernetes inventory collector).",
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
            "Current state: workloads (controllers or bare Pods) and logical Kubernetes Service "
            "objects (virtual IP and ports, never a host OS service). Source: v_services "
            "(Kubernetes inventory collector). " + COVERAGE_NOTE,
            width=16,
            column_colours={"coverage": "coverage"},
        ),
        Panel(
            "Pods and containers",
            "table",
            """
SELECT i.namespace AS namespace, i.pod_name AS pod, i.container_name AS container,
       i.instance_kind AS kind, i.state AS state, i.node_name AS node,
       i.workload_kind AS workload_kind, i.workload_name AS workload, i.image AS image,
       i.observed_at AS observed_at, i.pod_uid AS pod_uid, i.container_id AS container_id
FROM extorq.v_service_instances_current AS i
WHERE i.instance_kind IN ('pod', 'container')
ORDER BY namespace, pod, container
LIMIT 500
""",
            "Current state: Pod and container instances of Kubernetes workloads (latest version, "
            "present only) with the node they run on. Source: v_service_instances_current "
            "(Kubernetes inventory collector).",
            width=24,
        ),
    ],
)

# ── 5. GitHub investigation ───────────────────────────────────────────────────────

GITHUB = Dashboard(
    uid="extorq-github",
    title="ExtorQ - GitHub Investigation",
    description=(
        "GitHub repositories: commits, workflow changes with permission and trigger deltas, "
        "credential-shaped strings in commits (redacted), workflow runs, settings changes and "
        "repository findings. Source: github.api (GitHub collector, read-only API polling). "
        "Commit and workflow text is attacker-controllable."
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
            "Commits observed by the GitHub collector per repository (time = commit time as "
            "GitHub reports it). Source: github.api.",
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
            "Observed GitHub Actions workflow runs per conclusion (success, failure, cancelled, "
            "pending). Source: github.api.",
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("Workflow and commit security"),
        Panel(
            "Workflow modifications and permission deltas",
            "table",
            f"""
SELECT event_time, gh_repository AS repository, gh_workflow_path AS workflow,
       gh_commit_sha AS commit, gh_actor_login AS actor,
       {json_bool("write_all_added", "YES", "no", "not reported")} AS write_all_added,
       {json_list("added_write_scopes")} AS added_write_scopes,
       {json_list("triggers_added")} AS triggers_added,
       {json_list("risk_flags")} AS risk_flags
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'github.workflow.modified'
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Every commit that changed a workflow, with the permission analysis before/after: "
            "write-all added, added write scopes, dangerous triggers (pull_request_target) and "
            "risk flags such as untrusted checkout, unpinned third-party actions or untrusted "
            "context in run steps (GH-001 to GH-004 inputs). Source: github.api.",
            width=24,
            height=9,
            column_colours={"write_all_added": "risk_flag"},
        ),
        Panel(
            "Credential-shaped strings committed (redacted)",
            "table",
            """
SELECT event_time, gh_repository AS repository, gh_commit_sha AS commit,
       gh_actor_login AS actor, resource_path AS path,
       JSONExtractString(attributes, 'pattern') AS pattern,
       JSONExtractString(attributes, 'line') AS line,
       JSONExtractString(attributes, 'redacted_match') AS redacted_match
FROM extorq.events
WHERE $__timeFilter(event_time) AND event_type = 'github.secret.exposed'
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",
            "Commits that added a string matching a credential pattern (GH-005 inputs). Source: "
            "github.api. Only the pattern name, file, line and a redacted match are stored, "
            "never the value. Gitleaks findings on the repository are under Findings.",
            width=24,
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
            "Latest workflow runs with their trigger event and conclusion. Source: github.api.",
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
            "Repository settings and branch protection changes detected between polls. Source: "
            "github.api. Organisation audit logs are not available to the collector.",
            width=10,
        ),
        row("Findings (current)"),
        Panel(
            "Repository findings",
            "table",
            f"""
SELECT {id_name()} AS repository, scanner, severity, state, check_id, title,
       resource_path AS path, last_observed_at, latest_scan_status
FROM extorq.v_findings_current
WHERE startsWith(asset_id, 'github:') AND state IN ('open', 'unverified')
ORDER BY {SEVERITY_ORDER} DESC, last_observed_at DESC
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current state, not time-filtered: open = seen by the latest succeeded scan; "
            "unverified = presence cannot be confirmed (failed or partial scan). Source: "
            "v_findings_current (Gitleaks, Semgrep, Trivy and repository posture checks).",
            width=16,
            height=9,
            column_colours={"severity": "severity", "state": "finding_state"},
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
            "Current state, not time-filtered: open repository findings per scanner. Source: "
            "v_findings_current.",
            width=8,
            height=9,
        ),
    ],
)

# ── 6. macOS investigation ────────────────────────────────────────────────────────

MACOS = Dashboard(
    uid="extorq-macos",
    title="ExtorQ - macOS Investigation",
    description=(
        "macOS hosts (asset_type macos_host): launch items, listening sockets, local and sudo "
        "authentication failures, installed applications with their code signature and the "
        "host's services. Sources: macos.launchd, macos.inventory, macos.unified_log (native "
        "macOS collector). host = the name inside the asset id. Text fields are telemetry."
    ),
    panels=[
        row("Persistence: launch items"),
        Panel(
            "Launch item changes",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, event_type, resource_path AS plist,
       JSONExtractString(attributes, 'label') AS label,
       if(JSONType(attributes, 'program') = 'String', JSONExtractString(attributes, 'program'),
          JSONExtractRaw(attributes, 'program')) AS program,
       {json_bool("run_at_load", "yes", "no", "unknown")} AS run_at_load,
       JSONExtractString(attributes, 'scope') AS scope,
       JSONExtractString(attributes, 'sha256') AS sha256
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'macos_host'
  AND event_type IN ({LAUNCHD_TYPES})
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "LaunchAgent / LaunchDaemon plists created, modified or deleted, newest first "
            "(MAC-001 inputs; MAC-002 looks at the program: a shell, interpreter or "
            "user-writable path). Source: macos.launchd. Plist contents beyond these fields are "
            "not collected.",
            width=16,
        ),
        Panel(
            "Launch item changes by type",
            "timeseries",
            f"""
SELECT $__timeInterval(event_time) AS time, event_type, uniqExact(event_id) AS events
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'macos_host'
  AND event_type IN ({LAUNCHD_TYPES})
GROUP BY time, event_type
ORDER BY time, event_type
""",  # noqa: S608 - build-time constants only, no runtime input
            "Distinct launch item changes per interval. Source: macos.launchd.",
            width=8,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        row("Network exposure"),
        Panel(
            "Listening sockets opened and closed",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, event_type, process_name AS process,
       net_protocol AS protocol, dst_ip AS address, dst_port AS port,
       multiIf(dst_ip IS NULL, 'unknown',
               dst_ip IN ('127.0.0.1', '::1'), 'loopback',
               dst_ip IN ('0.0.0.0', '::', '*'), 'all interfaces',
               'specific address') AS exposure
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'macos_host'
  AND event_type IN ('network.listener.opened', 'network.listener.closed')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Listening sockets that appeared or disappeared between inventory snapshots, with "
            "the owning process (MAC-003 inputs: all-interface listeners of processes that are "
            "not allow-listed). Source: macos.inventory. A listener shorter than one snapshot "
            "interval can be missed.",
            width=24,
            column_colours={"exposure": "exposure"},
        ),
        row("Authentication"),
        Panel(
            "Authentication failures by type",
            "timeseries",
            f"""
SELECT $__timeInterval(event_time) AS time, event_type, uniqExact(event_id) AS failures
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'macos_host'
  AND event_type IN ('auth.sudo.failure', 'auth.local.failure', {SSH_FAILURE_TYPES})
GROUP BY time, event_type
ORDER BY time, event_type
""",  # noqa: S608 - build-time constants only, no runtime input
            "sudo denials, local authentication failures (authd / opendirectoryd) and SSH "
            "failures per interval (MAC-004 inputs). Source: macos.unified_log. SSH events exist "
            "only when Remote Login is enabled.",
            width=12,
            fmt=FORMAT_TIMESERIES,
            bars=True,
            stacked=True,
        ),
        Panel(
            "Recent authentication failures",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, event_type, actor_name AS user,
       JSONExtractString(attributes, 'reason') AS reason,
       JSONExtractString(attributes, 'subsystem') AS subsystem, src_ip
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'macos_host'
  AND event_type IN ('auth.sudo.failure', 'auth.local.failure', {SSH_FAILURE_TYPES})
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Authentication failures, newest first, with the user and the reason macOS logged. "
            "Source: macos.unified_log. Passwords are never logged or collected.",
            width=12,
        ),
        row("Software"),
        Panel(
            "Applications installed and removed",
            "table",
            f"""
SELECT event_time, {id_name()} AS host, event_type, resource_name AS application,
       resource_path AS path, JSONExtractString(attributes, 'bundle_id') AS bundle_id,
       JSONExtractString(attributes, 'version') AS version,
       {json_bool("signed", "signed", "unsigned", "unknown")} AS signature,
       JSONExtractString(attributes, 'signature_team_id') AS team_id
FROM extorq.events
WHERE $__timeFilter(event_time) AND asset_type = 'macos_host'
  AND event_type IN ('software.installed', 'software.removed')
ORDER BY event_time DESC
LIMIT 1 BY event_id
LIMIT 200
""",  # noqa: S608 - build-time constants only, no runtime input
            "Application bundles that appeared in or left an inventoried application directory, "
            "with the code-signature status when it could be determined (MAC-005 inputs: "
            "unsigned applications). Source: macos.inventory. unknown = the signature could not "
            "be checked; it is never reported as signed.",
            width=24,
            column_colours={"signature": "signature"},
        ),
        row("Services on macOS hosts"),
        Panel(
            "macOS services",
            "table",
            f"""
SELECT {id_name()} AS host, name AS service, service_kind AS kind, category, product,
       adapter_id AS adapter, {COVERAGE_SQL} AS coverage, {ENDPOINTS_TEXT} AS endpoints,
       instance_count, last_seen AS discovery_refreshed, coverage_note
FROM extorq.v_services
WHERE present = 1
  AND asset_id IN (SELECT asset_id FROM extorq.v_assets WHERE asset_type = 'macos_host')
ORDER BY host, coverage, name
LIMIT 500
""",  # noqa: S608 - build-time constants only, no runtime input
            "Current state: launchd jobs, processes and listeners discovered on macOS hosts with "
            "their adapter and coverage. Source: v_services (macOS service discovery). "
            + COVERAGE_NOTE,
            width=24,
            height=10,
            column_colours={"coverage": "coverage"},
        ),
    ],
)

DASHBOARDS: tuple[Dashboard, ...] = (
    SECURITY_OVERVIEW,
    COLLECTOR_HEALTH,
    LINUX,
    KUBERNETES,
    GITHUB,
    MACOS,
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

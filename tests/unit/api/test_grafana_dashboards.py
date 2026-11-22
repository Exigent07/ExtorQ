"""Static checks of the Grafana deliverables (owner: D1): dashboards, provisioning, image.

The SQL executes for real in tests/integration/api (throwaway ClickHouse with the real
extorq_grafana role, and through the running Grafana); these tests enforce the rules
that must hold for every panel without any infrastructure.
"""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
GRAFANA_DIR = REPO_ROOT / "infra" / "grafana"
DASHBOARD_DIR = GRAFANA_DIR / "dashboards"

EXPECTED = {
    "extorq-security-overview": "ExtorQ - Security Overview",
    "extorq-collector-health": "ExtorQ - Collector & Pipeline Health",
    "extorq-linux": "ExtorQ - Linux Investigation",
    "extorq-kubernetes": "ExtorQ - Kubernetes Investigation",
    "extorq-github": "ExtorQ - GitHub Investigation",
    "extorq-macos": "ExtorQ - macOS Investigation",
}
#: Objects extorq_grafana may read (0002 + 0004 grants; 0008 dropped simulation_runs).
#: analyst_actions, investigation_contexts and context_relationships are deliberately absent.
GRANTED = {
    "events", "assets", "inventory_items", "scan_runs", "finding_observations",
    "detection_rules", "rule_runs", "alerts", "alert_evidence", "analyst_state",
    "ai_assessments", "collector_health", "pipeline_health", "ingest_audit",
    "ingest_quarantine", "services", "service_instances",
    "v_assets", "v_alerts", "v_analyst_state", "v_inventory_current", "v_collector_latest",
    "v_pipeline_latest", "v_rule_latest_run", "v_findings_current", "v_services",
    "v_service_instances_current",
}  # fmt: skip
#: Append-only / versioned tables: panels over them must be bounded by the time picker.
TIME_BOUNDED = {
    "events", "alerts", "v_alerts", "rule_runs", "collector_health", "pipeline_health",
    "ingest_quarantine", "ingest_audit", "finding_observations", "scan_runs",
}  # fmt: skip
AGGREGATE_ALIAS = re.compile(
    r"\b(?:max|min|sum|avg|any|uniqExact|count)\((\w+)\)\s+AS\s+(\w+)", re.IGNORECASE
)
#: Storage removed by migration 0008 (contract schema 2.0): a query naming it fails.
DROPPED = re.compile(r"\b(simulation_run_ids?|scenario_id|simulation_runs)\b")
#: Product decisions of 2026-11-22: no simulation category, no Gemini, no "lab" labels.
#: A standalone "lab" only: resource names such as lab-portal or extorq-lab are real names.
REMOVED_WORDING = re.compile(r"simulat|gemini|(?<![\w-])lab(?![\w-])", re.IGNORECASE)


def _load_generator() -> ModuleType:
    path = GRAFANA_DIR / "generate_dashboards.py"
    spec = importlib.util.spec_from_file_location("extorq_grafana_generate", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


GENERATOR = _load_generator()


def _dashboards() -> list[dict[str, Any]]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(DASHBOARD_DIR.glob("*.json"))
    ]


def _panels() -> list[tuple[str, dict[str, Any]]]:
    return [
        (dashboard["uid"], panel)
        for dashboard in _dashboards()
        for panel in dashboard["panels"]
        if panel["type"] != "row"
    ]


PANELS = _panels()


def test_committed_dashboards_match_the_generator(capsys: pytest.CaptureFixture[str]) -> None:
    assert GENERATOR.main(["--check"]) == 0, capsys.readouterr().err


def test_expected_dashboards_with_stable_uids() -> None:
    dashboards = {d["uid"]: d for d in _dashboards()}
    assert {uid: d["title"] for uid, d in dashboards.items()} == EXPECTED
    for dashboard in dashboards.values():
        assert dashboard["editable"] is False
        assert dashboard["tags"] == ["extorq"]
        assert dashboard["timezone"] == "utc"
        assert dashboard["refresh"] == "1m"
        assert dashboard["templating"]["list"] == []  # nothing is interpolated into SQL
        ids = [p["id"] for p in dashboard["panels"]]
        assert len(ids) == len(set(ids))
        for panel in dashboard["panels"]:
            grid = panel["gridPos"]
            assert grid["x"] >= 0 and grid["x"] + grid["w"] <= 24


@pytest.mark.parametrize(("uid", "panel"), PANELS, ids=[f"{u}:{p['title']}" for u, p in PANELS])
def test_panel_sql_rules(uid: str, panel: dict[str, Any]) -> None:
    assert panel["datasource"] == {"type": "grafana-clickhouse-datasource",
                                   "uid": "extorq-clickhouse"}  # fmt: skip
    assert len(panel["targets"]) == 1
    target = panel["targets"][0]
    assert target["datasource"]["uid"] == "extorq-clickhouse"
    assert target["editorType"] == "sql"
    sql = target["rawSql"]
    assert sql and panel["description"]
    lowered = sql.lower()

    assert not re.search(r"select\s+\*", lowered), "explicit columns only"
    assert not re.search(r"\b(raw|payload|payload_excerpt)\b", lowered), "no raw/payload"
    assert not re.search(r"\$(?!__)", sql), "no dashboard variables in SQL"

    tables = set(re.findall(r"\bextorq\.(\w+)", sql))
    assert tables, "fully qualified table names"
    assert tables <= GRANTED, tables - GRANTED
    if tables & TIME_BOUNDED:
        assert "$__timeFilter(" in sql, "time-based tables must be bounded by $__timeFilter"
    if "alerts" in tables:
        pytest.fail("read alerts through v_alerts (latest version per alert)")
    if "events" in tables:
        # Distinct counts (uniqExact), one row per event (LIMIT 1 BY / GROUP BY event_id).
        assert "uniqExact(" in sql or "LIMIT 1 BY event_id" in sql or "GROUP BY event_id" in sql, (
            "event queries must be duplicate-safe"
        )
        assert "count()" not in sql, "count() over events double-counts duplicates"
    for column, alias in AGGREGATE_ALIAS.findall(sql):
        assert column != alias, f"aggregate alias {alias} shadows a column (ILLEGAL_AGGREGATION)"

    if target["format"] == GENERATOR.FORMAT_TIMESERIES:
        assert panel["type"] == "timeseries"
        assert target["queryType"] == "timeseries"
        assert "$__timeInterval(" in sql and " AS time" in sql
        assert re.search(r"ORDER BY time\b", sql)
    else:
        assert target["format"] == GENERATOR.FORMAT_TABLE
        assert target["queryType"] == "table"


def test_otel_health_keeps_queue_requests_separate_from_records() -> None:
    panels = {p["title"]: p for uid, p in PANELS if uid == "extorq-collector-health"}
    delivery = panels["Kubernetes OpenTelemetry delivery by node and source"]
    sql = delivery["targets"][0]["rawSql"]
    assert "c.source_types AS sources" in sql
    assert "last_reported_at, now()) > 3 * c.interval_seconds" in sql
    assert "'queue_requests', 'Nullable(UInt64)'" in sql
    assert "'queue_capacity_requests', 'Nullable(UInt64)'" in sql
    assert "'dropping_records', 'unavailable'" in sql
    buffered_sql = panels["Collector buffered records"]["targets"][0]["rawSql"]
    assert "collector_type != 'k8s_otel'" in buffered_sql


def test_service_coverage_panels_exist() -> None:
    titles = {p["title"] for _, p in PANELS}
    assert {
        "Services by coverage state",
        "Services by asset, kind and coverage",
        "Monitored services: telemetry freshness",
        "Services",
        "macOS services",
        "Workloads and Kubernetes Services",
        "Pods and containers",
        "Kubernetes nodes",
    } <= titles


def test_dashboards_never_name_dropped_storage_or_removed_concepts() -> None:
    """Schema 2.0: no simulation columns/table in SQL; no simulation, Gemini or "lab" wording
    in titles and descriptions (resource names such as lab-portal stay allowed)."""
    for dashboard in _dashboards():
        assert not REMOVED_WORDING.search(dashboard["title"] + " " + dashboard["description"])
        for panel in dashboard["panels"]:
            text = f"{panel['title']} {panel.get('description', '')}"
            assert not REMOVED_WORDING.search(text), (dashboard["uid"], panel["title"])
            for target in panel.get("targets", []):
                assert not DROPPED.search(target["rawSql"]), (dashboard["uid"], panel["title"])


@pytest.mark.parametrize(("uid", "panel"), PANELS, ids=[f"{u}:{p['title']}" for u, p in PANELS])
def test_panel_description_states_its_source(uid: str, panel: dict[str, Any]) -> None:
    """Every panel says where its data comes from (table/view and telemetry source)."""
    description = panel["description"]
    assert re.search(r"\bSources?: ", description), (uid, panel["title"])
    assert len(description) >= 60, "say what the panel shows, not just its source"


def test_units_and_colours_carry_meaning() -> None:
    """Durations have a time unit, lag/backlog charts draw thresholds, and volume stats are
    neutral (no colour claims good or bad for a plain count)."""
    for uid, panel in PANELS:
        defaults = panel["fieldConfig"]["defaults"]
        overrides = {
            o["matcher"]["options"]: {p["id"]: p["value"] for p in o["properties"]}
            for o in panel["fieldConfig"]["overrides"]
        }
        sql = panel["targets"][0]["rawSql"]
        for column in re.findall(r"\bAS (\w*(?:_seconds|_ms))\b", sql):
            unit = overrides.get(column, {}).get("unit", defaults["unit"])
            assert unit in ("s", "ms"), (uid, panel["title"], column)
        if panel["type"] == "timeseries" and re.search(r"lag|age|depth|buffered", panel["title"]):
            assert defaults["custom"]["thresholdsStyle"]["mode"] == "dashed", panel["title"]
            assert len(defaults["thresholds"]["steps"]) == 3, panel["title"]
        if panel["type"] == "stat" and panel["title"] in ("Events", "Assets reporting events"):
            assert defaults["thresholds"]["steps"] == [{"color": "text", "value": None}]


def test_cross_asset_tables_show_asset_names() -> None:
    """Tables over several asset classes show the inventory name next to the id."""
    for title in (
        "Recent alerts",
        "Events by asset and source",
        "Open findings by asset and scanner (current)",
        "Services by asset, kind and coverage",
        "Collectors: last success and staleness",
        "Monitored services: telemetry freshness",
    ):
        panel = next(p for _, p in PANELS if p["title"] == title)
        sql = panel["targets"][0]["rawSql"]
        assert "extorq.v_assets" in sql and " AS asset," in sql, title


def test_datasource_provisioning_uses_the_least_privileged_identity() -> None:
    data = yaml.safe_load(
        (GRAFANA_DIR / "provisioning" / "datasources" / "extorq-clickhouse.yaml").read_text()
    )
    (source,) = data["datasources"]
    assert source["uid"] == "extorq-clickhouse"
    assert source["type"] == "grafana-clickhouse-datasource"
    assert source["editable"] is False
    json_data = source["jsonData"]
    assert json_data["username"] == "extorq_grafana"
    assert (json_data["host"], json_data["port"], json_data["protocol"]) == (
        "clickhouse",
        8123,
        "http",
    )
    assert json_data["defaultDatabase"] == "extorq"
    # The secret is referenced by file path only, never inlined.
    assert source["secureJsonData"] == {"password": "$__file{/run/secrets/extorq_grafana_password}"}


def test_dashboard_provider_is_read_only_and_matches_the_image_path() -> None:
    data = yaml.safe_load((GRAFANA_DIR / "provisioning" / "dashboards" / "extorq.yaml").read_text())
    (provider,) = data["providers"]
    assert provider["folder"] == "ExtorQ" and provider["folderUid"] == "extorq"
    assert provider["allowUiUpdates"] is False
    assert provider["disableDeletion"] is True
    dockerfile = (GRAFANA_DIR / "Dockerfile").read_text()
    assert f"dashboards/ {provider['options']['path']}/" in dockerfile


def test_dockerfile_pins_and_hardens() -> None:
    dockerfile = (GRAFANA_DIR / "Dockerfile").read_text()
    assert re.search(r"^FROM grafana/grafana:13\.\d+\.\d+@sha256:[0-9a-f]{64}$", dockerfile, re.M)
    assert f"ARG CLICKHOUSE_PLUGIN_VERSION={GENERATOR.PLUGIN_VERSION}" in dockerfile
    assert "GF_INSTALL_PLUGINS" not in dockerfile  # no runtime plugin downloads
    for setting in (
        "GF_PLUGINS_PREINSTALL_DISABLED=true",
        "GF_PLUGINS_PLUGIN_ADMIN_ENABLED=false",
        "GF_AUTH_ANONYMOUS_ENABLED=false",
        "GF_USERS_ALLOW_SIGN_UP=false",
        "GF_SECURITY_ALLOW_EMBEDDING=false",
        "GF_SECURITY_COOKIE_SAMESITE=strict",
        "GF_SECURITY_DISABLE_GRAVATAR=true",
        "GF_ANALYTICS_REPORTING_ENABLED=false",
        "GF_ANALYTICS_CHECK_FOR_UPDATES=false",
        "GF_SNAPSHOTS_EXTERNAL_ENABLED=false",
        "GF_PUBLIC_DASHBOARDS_ENABLED=false",
    ):
        assert setting in dockerfile, setting
    users = re.findall(r"^USER (\S+)$", dockerfile, re.M)
    assert users[-1] == "472"  # runs as the unprivileged grafana user
    assert "PASSWORD" not in dockerfile.replace("GF_SECURITY_ADMIN_PASSWORD__FILE", "")

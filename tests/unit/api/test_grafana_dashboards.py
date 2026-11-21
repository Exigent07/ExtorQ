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
}
#: Objects extorq_grafana may read (0002 + 0004 grants). analyst_actions,
#: investigation_contexts and context_relationships are deliberately absent.
GRANTED = {
    "events", "assets", "inventory_items", "scan_runs", "finding_observations",
    "detection_rules", "rule_runs", "alerts", "alert_evidence", "analyst_state",
    "ai_assessments", "collector_health", "pipeline_health", "ingest_audit",
    "ingest_quarantine", "simulation_runs", "services", "service_instances",
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


def test_service_coverage_panels_exist() -> None:
    titles = {p["title"] for _, p in PANELS}
    assert {
        "Services by coverage state",
        "Services by asset, kind and coverage",
        "Monitored services: telemetry freshness",
        "Services",
        "Workloads and Kubernetes Services",
        "Pods and containers",
        "Kubernetes nodes",
    } <= titles


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

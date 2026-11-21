"""Every Grafana panel query on a throwaway ClickHouse as the real extorq_grafana role.

Runs with ``-m integration``; does NOT use the shared stack. The harness applies the real
migrations (0001-0004) and the roles/profiles of 0002, seeds SYNTHETIC rows only and
removes the container. The plugin macros are expanded the way grafana-clickhouse-datasource
4.x does (``$__timeFilter(c)`` -> ``c >= toDateTime(from) AND c <= toDateTime(to)``,
``$__timeInterval(c)`` -> ``toStartOfInterval(toDateTime(c), INTERVAL n second)``); the
expansion inputs are the committed dashboard files only. The live check through Grafana
itself is tests/integration/api/test_grafana_live.py.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from api_ch_harness import Dataset, EphemeralClickHouse, seed, unavailable_reason

pytestmark = pytest.mark.integration

DASHBOARD_DIR = Path(__file__).resolve().parents[3] / "infra" / "grafana" / "dashboards"
_TIME_FILTER = re.compile(r"\$__timeFilter\(([^)]+)\)")
_TIME_INTERVAL = re.compile(r"\$__timeInterval\(([^)]+)\)")


def expand_macros(sql: str, start: datetime, end: datetime, interval_seconds: int) -> str:
    """Plugin-equivalent expansion of the two macros the dashboards use."""
    lo, hi = int(start.timestamp()), int(end.timestamp())
    sql = _TIME_FILTER.sub(
        lambda m: f"{m[1]} >= toDateTime({lo}) AND {m[1]} <= toDateTime({hi})", sql
    )
    sql = _TIME_INTERVAL.sub(
        lambda m: f"toStartOfInterval(toDateTime({m[1]}), INTERVAL {interval_seconds} second)",
        sql,
    )
    assert "$" not in sql, "unexpanded macro or variable"
    return sql


def _panels() -> list[tuple[str, str, str]]:
    out = []
    for path in sorted(DASHBOARD_DIR.glob("*.json")):
        dashboard = json.loads(path.read_text(encoding="utf-8"))
        for panel in dashboard["panels"]:
            for target in panel.get("targets", []):
                out.append((dashboard["uid"], panel["title"], target["rawSql"]))
    return out


PANELS = _panels()


@pytest.fixture(scope="module")
def clickhouse() -> Iterator[EphemeralClickHouse]:
    reason = unavailable_reason()
    if reason:
        pytest.skip(reason)
    ch = EphemeralClickHouse()
    try:
        ch.start()
        ch.migrate()
        yield ch
    finally:
        ch.stop()


@pytest.fixture(scope="module")
def dataset(clickhouse: EphemeralClickHouse) -> Dataset:
    return seed(clickhouse.client("default"), datetime.now(UTC))


@pytest.fixture(scope="module")
def run(clickhouse: EphemeralClickHouse, dataset: Dataset) -> Any:
    grafana = clickhouse.client("d1_grafana")

    def execute(uid: str, title: str) -> list[dict[str, Any]]:
        sql = next(q for u, t, q in PANELS if (u, t) == (uid, title))
        expanded = expand_macros(
            sql, dataset.now - timedelta(days=1), dataset.now + timedelta(hours=1), 300
        )
        return list(grafana.query(expanded).named_results())

    return execute


@pytest.mark.parametrize(("uid", "title", "sql"), PANELS, ids=[f"{u}:{t}" for u, t, _ in PANELS])
def test_panel_executes_as_grafana_role(run: Any, uid: str, title: str, sql: str) -> None:
    run(uid, title)


def test_grafana_role_cannot_read_raw_or_payload(clickhouse: EphemeralClickHouse) -> None:
    grafana = clickhouse.client("d1_grafana")
    for sql in (
        "SELECT raw FROM extorq.events LIMIT 1",
        "SELECT payload FROM extorq.events LIMIT 1",
        "SELECT payload_excerpt FROM extorq.ingest_quarantine LIMIT 1",
    ):
        with pytest.raises(Exception, match=r"ACCESS_DENIED|Not enough privileges"):
            grafana.query(sql)


def test_overview_counts_are_duplicate_safe(run: Any) -> None:
    # e1 was delivered twice: 4 distinct events, not 5.
    assert run("extorq-security-overview", "Events") == [{"events": 4}]
    assert run("extorq-security-overview", "Alerts") == [{"alerts": 2}]
    assert run("extorq-security-overview", "Open findings (current)") == [{"open_findings": 1}]
    coverage = {
        r["coverage"]: r["services"]
        for r in run("extorq-security-overview", "Services by coverage state")
    }
    assert coverage == {"monitored": 2, "planned": 1, "unsupported": 1}  # tombstone excluded
    recent = run("extorq-security-overview", "Recent alerts")
    statuses = {r["severity"]: r["analyst_status"] for r in recent}
    assert statuses == {"high": "new", "critical": "closed_false_positive"}
    series = run("extorq-security-overview", "Event volume by source type")
    assert sum(r["events"] for r in series) == 4


def test_investigation_panels_return_the_evidence(run: Any, dataset: Dataset) -> None:
    sources = run("extorq-linux", "SSH failure sources")
    assert [(r["source_ip"], r["failures"], r["connections"], r["users"]) for r in sources] == [
        ("10.0.2.2", 2, 1, 2)
    ]
    denied = run("extorq-kubernetes", "Denied requests")
    assert [(r["user"], r["verb"], r["resource"], r["code"]) for r in denied] == [
        ("synthetic-user", "create", "pods", 403)
    ]
    workflows = run("extorq-github", "Workflow modifications and permission deltas")
    assert [(w["actor"], w["write_all_added"]) for w in workflows] == [("synthetic-dev", "YES")]
    collectors = {
        r["collector_id"]: r["freshness"]
        for r in run("extorq-collector-health", "Collectors: last success and staleness")
    }
    assert collectors == {"synthetic-linux": "fresh", "synthetic-github": "STALE"}
    services = run("extorq-linux", "Services")
    ssh = next(s for s in services if s["service"] == "ssh")
    assert ssh["endpoints"] == "tcp/22 any (confirmed)"
    assert ssh["coverage"] == "monitored"
    freshness = run("extorq-collector-health", "Monitored services: telemetry freshness")
    ssh_fresh = next(r for r in freshness if r["service"] == "ssh")
    assert ssh_fresh["events_in_range"] == 2
    k8s = run("extorq-kubernetes", "Workloads and Kubernetes Services")
    assert {(r["kind"], r["coverage"]) for r in k8s} == {
        ("k8s_workload", "monitored"),
        ("k8s_service", "unsupported"),
    }
    pods = run("extorq-kubernetes", "Pods and containers")
    assert [(p["pod"], p["node"]) for p in pods] == [("lab-portal-0", "extorq-lab-control-plane")]
    nodes = run("extorq-kubernetes", "Kubernetes nodes")
    assert [(n["asset_id"], n["cluster"]) for n in nodes] == [(dataset.k8s_node, dataset.k8s)]

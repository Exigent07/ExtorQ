"""Overview and health: staleness, coverage, explicit empty-source flags."""

from __future__ import annotations

from datetime import timedelta

from api_fakes import (
    NOW,
    FakeIntegrations,
    FakeRepository,
    alert_row,
    asset_row,
    collector_row,
    latest_run_row,
    pipeline_row,
    rule_row,
)
from fastapi.testclient import TestClient

from extorq.api import service
from extorq.api.lifecycle import Estate


def test_collector_staleness_rules() -> None:
    fresh = service.collector_status(collector_row(), NOW)
    assert fresh.stale is False and fresh.stale_reason is None
    edge = service.collector_status(
        collector_row(last_success_at=NOW - timedelta(seconds=180)), NOW
    )
    assert edge.stale is False  # exactly 3 x interval is not yet stale
    old = service.collector_status(collector_row(last_success_at=NOW - timedelta(seconds=181)), NOW)
    assert old.stale is True
    assert old.stale_reason == "last success 181s ago exceeds 3 x interval (180s)"
    never = service.collector_status(collector_row(last_success_at=None), NOW)
    assert never.stale is True
    assert never.stale_reason == "no successful collection has been reported"
    no_interval = service.collector_status(collector_row(interval_seconds=0), NOW)
    assert no_interval.stale is True


def test_coverage_status_per_asset_and_class() -> None:
    ok = service.collector_status(collector_row(), NOW)
    stale = service.collector_status(collector_row("b", last_success_at=None), NOW)
    failing = service.collector_status(collector_row("c", status="failed"), NOW)
    assert service.coverage_status([]) == "missing"
    assert service.coverage_status([ok]) == "ok"
    assert service.coverage_status([stale]) == "stale"
    assert service.coverage_status([ok, stale]) == "degraded"
    assert service.coverage_status([failing]) == "degraded"

    assets = [asset_row(), asset_row("macos:workstation-01", asset_type="macos_host")]
    estate = Estate(assets, [ok], {}, NOW, stale_seconds=3600, retire_seconds=86400)
    events = [{"asset_id": "linux:lab-vm-01", "asset_type": "linux_host", "last_event_at": NOW}]
    coverage = estate.class_coverage(assets, events, include_retired=False)
    by_type = {c.asset_type: c for c in coverage}
    assert [c.asset_type for c in coverage][:4] == [
        "macos_host",
        "linux_host",
        "kubernetes_cluster",
        "github_repository",
    ]
    assert by_type["linux_host"].status == "ok"
    assert by_type["linux_host"].last_event_at == NOW
    assert by_type["macos_host"].status == "missing"
    assert by_type["macos_host"].assets_without_collector == 1
    assert by_type["kubernetes_cluster"].assets_total == 0
    assert by_type["kubernetes_cluster"].status == "missing"
    assert by_type["kubernetes_cluster"].expected is True


def test_overview_with_empty_store_fabricates_nothing(
    client: TestClient, analyst: dict[str, str]
) -> None:
    body = client.get("/api/v1/overview", headers=analyst).json()
    assert body["open_alerts"]["total"] == 0
    assert body["open_findings"]["lifecycle_available"] is False
    assert body["open_findings"]["source"] == "finding_observations"
    assert "unavailable" in body["open_findings"]["note"]
    assert body["alerts_over_time"]["points"] == []
    assert body["recent_important_alerts"] == []
    health = body["collection_health"]
    assert health["no_collector_reports"] is True
    assert health["no_pipeline_reports"] is True
    assert health["no_rule_runs"] is True
    assert {c["status"] for c in body["asset_coverage"]} == {"missing"}
    assert all(c["assets_total"] == 0 for c in body["asset_coverage"])


def test_overview_counts_open_alerts_and_recent_important(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    high = alert_row("h", severity="high")
    low = alert_row("l", severity="low")
    closed = alert_row("c", severity="critical")
    repo.alerts.extend([high, low, closed])
    repo.states[closed["alert_id"]] = {
        "alert_id": closed["alert_id"],
        "status": "closed_false_positive",
        "assignee": None,
        "note": None,
        "updated_by": "bob",
        "updated_at": NOW,
    }
    repo.alert_series_rows = [{"bucket_start": NOW - timedelta(hours=1), "grp": "high", "n": 1}]
    body = client.get("/api/v1/overview", headers=analyst).json()
    assert body["open_alerts"] == {
        "info": 0,
        "low": 1,
        "medium": 0,
        "high": 1,
        "critical": 0,
        "total": 2,
    }
    recent = {a["alert_id"]: a["analyst_status"] for a in body["recent_important_alerts"]}
    assert recent == {high["alert_id"]: "new", closed["alert_id"]: "closed_false_positive"}
    assert body["alerts_over_time"]["points"] == [
        {"bucket_start": "2026-11-21T11:00:00Z", "group": "high", "count": 1}
    ]
    query = repo.last_call("alert_series")
    assert query.bucket_seconds == 3600
    assert query.group_by == "severity"


def test_health_storage_unreachable(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.ping_error = ConnectionError("synthetic")
    body = client.get("/api/v1/health", headers=analyst).json()
    assert body["storage"] == {"reachable": False, "error": "ClickHouse is unreachable"}
    assert body["collectors"] == [] and body["pipeline"] == [] and body["rules"] == []
    assert body["ingest"] is None
    assert body["notes"]


def test_health_pipeline_staleness_and_superseded_instances(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.pipeline = [
        pipeline_row("writer", "old", last_reported_at=NOW - timedelta(hours=2)),
        pipeline_row("writer", "new"),
        pipeline_row("ingest", "gone", last_reported_at=NOW - timedelta(hours=1)),
    ]
    body = client.get("/api/v1/health", headers=analyst).json()
    rows = {(p["component"], p["instance"]): p for p in body["pipeline"]}
    assert rows[("writer", "old")]["stale"] is True
    assert rows[("writer", "old")]["superseded"] is True
    assert rows[("writer", "new")]["stale"] is False
    assert rows[("ingest", "gone")]["stale"] is True
    assert rows[("ingest", "gone")]["superseded"] is False


def test_health_rules_ai_and_ingest(
    client: TestClient,
    analyst: dict[str, str],
    repo: FakeRepository,
    integrations: FakeIntegrations,
) -> None:
    repo.rules = [
        rule_row("VM-001"),
        rule_row("VM-002"),
        rule_row("GH-001", enabled=0),
    ]
    repo.latest_runs = [
        latest_run_row("VM-001"),
        latest_run_row("K8S-001", last_status="failed", failures_24h=3),
    ]
    repo.ai_counts = [
        {"provider": "google-gemini", "task": "summary", "status": "ok", "assessments": 2},
        {"provider": "google-gemini", "task": "summary", "status": "timeout", "assessments": 1},
    ]
    repo.ai_last = [
        {
            "provider": "google-gemini",
            "task": "summary",
            "last_assessment_at": NOW,
            "last_status": "timeout",
            "last_error": "TimeoutError",
            "last_ok_at": NOW - timedelta(hours=1),
        }
    ]
    repo.quarantined = 4
    repo.audit_decisions = [{"decision": "denied", "events": 2}]
    body = client.get("/api/v1/health", headers=analyst).json()

    rules = {r["rule_id"]: r for r in body["rules"]}
    assert rules["VM-001"]["run_stale"] is False
    assert rules["VM-002"]["run_stale"] is True  # registered, never ran
    assert rules["VM-002"]["last_run"] is None
    assert rules["GH-001"]["run_stale"] is None  # disabled: not applicable
    assert rules["K8S-001"]["last_run"]["last_status"] == "failed"  # run without registry row

    ai = {(a["provider"], a["task"]): a for a in body["ai"]}
    gemini = ai[("google-gemini", "summary")]
    assert gemini["status_counts"] == {"ok": 2, "timeout": 1}
    assert gemini["last_status"] == "timeout"
    assert gemini["configured"] is True and gemini["enabled"] is False
    jev = ai[("typesafe-jev", "triage")]
    assert jev["status_counts"] == {} and jev["last_assessment_at"] is None
    assert body["ingest"] == {
        "window_hours": 24,
        "quarantined_records": 4,
        "audit_decisions": {"denied": 2},
    }
    assert body["ai_configuration_source"] == "fake"


def test_overview_collection_summary_counts(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.assets = [asset_row()]
    repo.collector_rows = [
        collector_row("ok"),
        collector_row("stale", last_success_at=NOW - timedelta(hours=1)),
        collector_row("failing", status="failed"),
    ]
    repo.rules = [rule_row("VM-001")]
    repo.latest_runs = [latest_run_row("VM-001", last_status="failed", failures_24h=2)]
    repo.pipeline = [pipeline_row()]
    body = client.get("/api/v1/overview", headers=analyst).json()
    summary = body["collection_health"]
    assert summary["collectors_total"] == 3
    assert summary["collectors_ok"] == 1
    assert summary["collectors_stale"] == 1
    assert summary["collectors_failing"] == 1
    assert summary["rules_failing"] == 1
    assert summary["rule_failures_24h"] == 2
    assert summary["pipeline_components"] == 1
    assert summary["no_collector_reports"] is False
    linux = next(c for c in body["asset_coverage"] if c["asset_type"] == "linux_host")
    assert linux["status"] == "degraded"

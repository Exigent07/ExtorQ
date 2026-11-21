"""Assets, findings, rules and time-series endpoints."""

from __future__ import annotations

from datetime import timedelta

import pytest
from api_fakes import (
    NOW,
    FakeRepository,
    alert_row,
    asset_row,
    collector_row,
    event_row,
    latest_run_row,
    rule_row,
)
from fastapi.testclient import TestClient

from extorq.api import service
from extorq.api.schemas import TimeRange

# ── assets ────────────────────────────────────────────────────────────────────────


def test_asset_list_derives_coverage_last_event_and_open_alerts(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.assets = [
        asset_row(),
        asset_row("github:owner/extorq-lab", asset_type="github_repository"),
    ]
    repo.collector_rows = [collector_row()]
    event = event_row()
    repo.events[event["event_id"]] = event
    repo.alerts.append(alert_row())
    body = client.get("/api/v1/assets", headers=analyst).json()
    items = {a["asset_id"]: a for a in body["items"]}
    linux = items["linux:lab-vm-01"]
    assert linux["coverage_status"] == "ok"
    assert linux["collectors_total"] == 1
    assert linux["open_alerts"] == 1
    assert linux["last_event_at"] == "2026-11-21T11:00:00Z"
    github = items["github:owner/extorq-lab"]
    assert github["coverage_status"] == "missing"
    assert github["last_event_at"] is None
    assert body["page"]["total"] == 2


def test_asset_detail_supports_slash_ids_and_ranges(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    asset_id = "github:owner/extorq-lab"
    repo.assets = [asset_row(asset_id, asset_type="github_repository")]
    repo.inventory[asset_id] = [
        {"item_type": "github_workflow", "items": 3, "last_observed_at": NOW}
    ]
    repo.event_counts[asset_id] = [
        {
            "source_type": "github.api",
            "events": 7,
            "last_event_at": NOW,
            "last_ingested_at": NOW,
        }
    ]
    response = client.get(
        f"/api/v1/assets/{asset_id}",
        headers=analyst,
        params={"since": "2026-11-20T00:00:00Z", "until": "2026-11-21T00:00:00Z"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["asset"]["attributes"] == {"os_name": "synthetic"}
    assert body["asset"]["coverage_status"] == "missing"
    assert body["inventory"][0]["items"] == 3
    assert body["event_counts"][0]["events"] == 7
    assert body["findings_summary"]["lifecycle_available"] is False
    assert body["findings"] == []
    since_arg = repo.last_call("event_counts_by_source")[1]
    assert since_arg.isoformat() == "2026-11-20T00:00:00+00:00"


def test_asset_detail_404_and_validation(client: TestClient, analyst: dict[str, str]) -> None:
    assert client.get("/api/v1/assets/linux:missing-01", headers=analyst).status_code == 404
    assert client.get("/api/v1/assets/BAD ID", headers=analyst).status_code == 422


# ── findings ──────────────────────────────────────────────────────────────────────


def _finding(fid: str, severity: str = "high") -> dict[str, object]:
    return {
        "finding_id": fid * 32,
        "asset_id": "linux:lab-vm-01",
        "scanner": "trivy",
        "check_id": "CVE-0000-0000",
        "category": "vulnerability",
        "severity": severity,
        "title": "synthetic finding",
        "first_observed_at": NOW - timedelta(days=1),
        "last_observed_at": NOW,
        "last_scan_run_id": "f" * 32,
        "cve_ids": ["CVE-0000-0000"],
        "cvss_score": 7.5,
        "state": "open",
    }


def test_findings_fallback_hides_state_and_flags_lifecycle(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.findings = [_finding("a"), _finding("b", "low")]
    body = client.get("/api/v1/findings", headers=analyst, params={"severity": "high"}).json()
    assert body["lifecycle_available"] is False
    assert body["source"] == "finding_observations"
    assert [f["severity"] for f in body["items"]] == ["high"]
    # Without the lifecycle view the API never asserts open/resolved.
    assert body["items"][0]["state"] is None
    assert body["note"]


def test_findings_state_filter_requires_lifecycle(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    response = client.get("/api/v1/findings", headers=analyst, params={"state": "open"})
    assert response.status_code == 400
    repo.lifecycle = True
    repo.findings = [_finding("a")]
    body = client.get("/api/v1/findings", headers=analyst, params={"state": "open"}).json()
    assert body["lifecycle_available"] is True
    assert body["items"][0]["state"] == "open"


# ── rules ─────────────────────────────────────────────────────────────────────────


def test_rules_list_filters_and_derives_run_staleness(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.rules = [
        rule_row("VM-001"),
        rule_row("VM-002", severity="medium"),
        rule_row("GH-001", enabled=0),
    ]
    repo.latest_runs = [latest_run_row("VM-001", last_run_at=NOW - timedelta(minutes=10))]
    repo.alerts = [alert_row("x")]
    body = client.get("/api/v1/rules", headers=analyst).json()
    rules = {r["rule_id"]: r for r in body["items"]}
    assert rules["VM-001"]["run_stale"] is True  # 600s > 3 x 60s
    assert rules["VM-001"]["alerts_open"] == 1
    assert rules["VM-002"]["run_stale"] is True and rules["VM-002"]["last_run"] is None
    assert rules["GH-001"]["run_stale"] is None
    assert body["page"]["total"] == 3
    only = client.get(
        "/api/v1/rules", headers=analyst, params={"severity": "medium", "limit": 1}
    ).json()
    assert [r["rule_id"] for r in only["items"]] == ["VM-002"]
    disabled = client.get("/api/v1/rules", headers=analyst, params={"enabled": "false"}).json()
    assert [r["rule_id"] for r in disabled["items"]] == ["GH-001"]


def test_rule_detail_versions_runs_and_alert_status(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.rules = [
        rule_row("VM-001", version="1.1.0", loaded_at=NOW - timedelta(hours=1)),
        rule_row("VM-001", version="1.0.0", loaded_at=NOW - timedelta(days=1)),
    ]
    repo.latest_runs = [latest_run_row("VM-001")]
    repo.runs["VM-001"] = [
        {
            "run_id": "1" * 32,
            "rule_version": "1.1.0",
            "started_at": NOW - timedelta(seconds=40),
            "finished_at": NOW - timedelta(seconds=39),
            "window_start": NOW - timedelta(minutes=15),
            "window_end": NOW - timedelta(seconds=40),
            "status": "succeeded",
            "rows_matched": 1,
            "alerts_created": 1,
            "alerts_updated": 0,
            "duration_ms": 9,
            "error": None,
            "missing_sources": ["linux.auditd"],
            "detector_instance": "det-1",
        }
    ]
    repo.alerts = [alert_row("y")]
    body = client.get("/api/v1/rules/VM-001", headers=analyst).json()
    assert body["rule"]["version"] == "1.1.0"
    assert body["rule"]["schedule"] == {"interval_seconds": 60, "lookback_seconds": 900}
    assert [v["version"] for v in body["versions"]] == ["1.1.0", "1.0.0"]
    assert body["recent_runs"][0]["missing_sources"] == ["linux.auditd"]
    assert body["alerts_by_status"] == {"new": 1}
    assert body["run_stale"] is False
    assert client.get("/api/v1/rules/VM-404", headers=analyst).status_code == 404
    assert client.get("/api/v1/rules/vm-001", headers=analyst).status_code == 422


# ── time series ───────────────────────────────────────────────────────────────────


def test_bucket_selection() -> None:
    day = TimeRange(since=NOW - timedelta(days=1), until=NOW)
    assert service.choose_bucket(day, None) == 300
    hour = TimeRange(since=NOW - timedelta(hours=1), until=NOW)
    assert service.choose_bucket(hour, None) == 60
    month = TimeRange(since=NOW - timedelta(days=31), until=NOW)
    assert service.choose_bucket(month, None) == 21600
    assert service.choose_bucket(day, 3600) == 3600


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/api/v1/timeseries/alerts", {"bucket_seconds": 7}),
        ("/api/v1/timeseries/events", {"bucket_seconds": 60, "since": "2026-11-10T00:00:00Z"}),
        ("/api/v1/timeseries/events", {"since": "2026-10-01T00:00:00Z"}),
    ],
)
def test_timeseries_rejects_bad_buckets_and_ranges(
    client: TestClient, analyst: dict[str, str], path: str, params: dict[str, object]
) -> None:
    assert client.get(path, headers=analyst, params=params).status_code == 400


def test_timeseries_events_grouped_points(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.event_series_rows = [
        {"bucket_start": NOW - timedelta(hours=1), "grp": "linux.journald", "n": 12},
        {"bucket_start": NOW - timedelta(hours=1), "grp": "k8s.audit", "n": 3},
    ]
    body = client.get(
        "/api/v1/timeseries/events",
        headers=analyst,
        params={"group_by": "source_type", "bucket_seconds": 3600},
    ).json()
    assert body["metric"] == "events"
    assert body["bucket_seconds"] == 3600
    assert body["group_by"] == "source_type"
    assert [p["group"] for p in body["points"]] == ["linux.journald", "k8s.audit"]
    assert body["truncated"] is False
    query = repo.last_call("event_series")
    assert query.group_by == "source_type"


def test_timeseries_alerts_ungrouped_has_null_group(
    client: TestClient, analyst: dict[str, str], repo: FakeRepository
) -> None:
    repo.alert_series_rows = [{"bucket_start": NOW - timedelta(hours=2), "grp": "", "n": 2}]
    body = client.get("/api/v1/timeseries/alerts", headers=analyst).json()
    assert body["points"] == [{"bucket_start": "2026-11-21T10:00:00Z", "group": None, "count": 2}]
    assert body["group_by"] is None
    assert (
        client.get(
            "/api/v1/timeseries/alerts", headers=analyst, params={"group_by": "summary"}
        ).status_code
        == 422
    )

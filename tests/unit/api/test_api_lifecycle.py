"""Asset and collector lifecycle (active / stale / retired) and what the rollups leave out.

All rows are SYNTHETIC (api_fakes). The scenario mirrors the live situation the rules were
written for: a mechanics-test GitHub repository whose one-off collector stopped a day ago,
an SDK heartbeat self-test on the macOS host, a Kubernetes node covered by its cluster's
collector and a scanner-only asset refreshed once a day.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from api_fakes import (
    NOW,
    FakeRepository,
    alert_row,
    asset_row,
    collector_row,
    event_row,
    service_row,
)
from fastapi.testclient import TestClient

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.lifecycle import Estate, is_reporting, last_event_map

H = timedelta(hours=1)
STALE = 3600
RETIRE = 86400

LAB_REPO = "github:synthetic/extorq-lab"
TEST_REPO = "github:octo-synthetic/hello-world"
TEST_ACCOUNT = "github:octo-synthetic"
MAC = "macos:workstation-01"
CLUSTER = "k8s:extorq-lab"
NODE = "k8s:extorq-lab/node/extorq-lab-control-plane"


def _collector(collector_id: str, **kw: Any) -> s.CollectorStatus:
    return service.collector_status(collector_row(collector_id, **kw), NOW)


def _silent(collector_id: str, age: timedelta, **kw: Any) -> s.CollectorStatus:
    """A collector whose latest report (and success) is ``age`` old."""
    when = NOW - age
    return _collector(
        collector_id, last_reported_at=when, last_attempt_at=when, last_success_at=when, **kw
    )


def _estate(
    assets: list[dict[str, Any]],
    collectors: list[s.CollectorStatus],
    events: dict[str, Any] | None = None,
) -> Estate:
    return Estate(assets, collectors, events or {}, NOW, stale_seconds=STALE, retire_seconds=RETIRE)


# ── pure rules ───────────────────────────────────────────────────────────────────


def test_reporting_window_is_the_retirement_window_or_three_intervals() -> None:
    assert is_reporting(_silent("a", timedelta(hours=23), interval_seconds=120), NOW, RETIRE)
    assert not is_reporting(_silent("b", timedelta(hours=25), interval_seconds=120), NOW, RETIRE)
    # A daily scanner stays configured for 3 x its interval (72 h).
    assert is_reporting(_silent("c", timedelta(hours=60), interval_seconds=86400), NOW, RETIRE)
    assert not is_reporting(_silent("d", timedelta(hours=73), interval_seconds=86400), NOW, RETIRE)


def test_active_when_observed_and_covered() -> None:
    estate = _estate(
        [asset_row(LAB_REPO, asset_type="github_repository")],
        [_collector("github-repos", asset_id=LAB_REPO, interval_seconds=120)],
    )
    lifecycle = estate.lifecycle(LAB_REPO)
    assert lifecycle is not None
    assert lifecycle.state == "active" and lifecycle.reason is None
    assert lifecycle.last_observed_at == NOW - timedelta(minutes=5)
    assert estate.retired_asset_ids == frozenset()


def test_unconfigured_asset_goes_stale_then_retired_and_is_never_deleted() -> None:
    def state(observed_age: timedelta, collector_age: timedelta) -> tuple[str, str | None]:
        estate = _estate(
            [asset_row(TEST_REPO, asset_type="github_repository", last_seen=NOW - observed_age)],
            [_silent("github-mechanics-test", collector_age, asset_id=TEST_REPO)],
        )
        lifecycle = estate.lifecycle(TEST_REPO)
        assert lifecycle is not None
        return lifecycle.state, lifecycle.reason

    assert state(timedelta(minutes=10), timedelta(minutes=5))[0] == "active"
    # 16 h after a one-off test run: the collector still counts as configured (< 24 h).
    stale, reason = state(16 * H, 15 * H)
    assert stale == "stale"
    assert reason == (
        "last observed 57600s ago (threshold 3600s); "
        "a collector covering it reported within the retirement window"
    )
    # The asset is old but its collector reported 23 h ago: not retired yet.
    assert state(30 * H, 23 * H)[0] == "stale"
    retired, reason = state(30 * H, 25 * H)
    assert retired == "retired"
    assert reason == (
        "no collector covering it has reported within 86400s and it was last observed 108000s ago"
    )


def test_retirement_boundary_is_exclusive() -> None:
    estate = _estate(
        [asset_row(TEST_ACCOUNT, asset_type="github_account", last_seen=NOW - 24 * H)], []
    )
    assert estate.lifecycle(TEST_ACCOUNT).state == "stale"  # type: ignore[union-attr]
    estate = _estate(
        [
            asset_row(
                TEST_ACCOUNT,
                asset_type="github_account",
                last_seen=NOW - 24 * H - timedelta(milliseconds=1),
            )
        ],
        [],
    )
    assert estate.lifecycle(TEST_ACCOUNT).state == "retired"  # type: ignore[union-attr]


def test_asset_without_collector_but_observed_recently_is_active() -> None:
    # e.g. the GitHub owner account refreshed by the repository collector on every poll.
    estate = _estate([asset_row("github:synthetic", asset_type="github_account")], [])
    assert estate.lifecycle("github:synthetic").state == "active"  # type: ignore[union-attr]


def test_events_count_as_observation() -> None:
    asset = asset_row(TEST_REPO, asset_type="github_repository", last_seen=NOW - 40 * H)
    estate = _estate([asset], [], {TEST_REPO: NOW - timedelta(minutes=2)})
    lifecycle = estate.lifecycle(TEST_REPO)
    assert lifecycle is not None and lifecycle.state == "active"
    assert lifecycle.last_observed_at == NOW - timedelta(minutes=2)
    # A source clock ahead of ours never makes an asset stale.
    estate = _estate([asset], [], {TEST_REPO: NOW + H})
    assert estate.lifecycle(TEST_REPO).state == "active"  # type: ignore[union-attr]


def test_daily_scanner_asset_is_not_stale_between_scans() -> None:
    asset = asset_row("github:synthetic/scanned", asset_type="github_repository")
    asset["last_seen"] = NOW - 30 * H
    scanner = _silent(
        "scanner.trivy", 30 * H, asset_id="github:synthetic/scanned", interval_seconds=86400
    )
    estate = _estate([asset], [scanner])
    assert estate.lifecycle("github:synthetic/scanned").state == "active"  # type: ignore[union-attr]


def test_node_is_covered_by_its_cluster_and_never_retired_while_it_reports() -> None:
    cluster = _collector("k8s-inventory", asset_id=CLUSTER, interval_seconds=60)
    assets = [
        asset_row(CLUSTER, asset_type="kubernetes_cluster"),
        asset_row(NODE, asset_type="kubernetes_node", parent_asset_id=CLUSTER),
    ]
    assert _estate(assets, [cluster]).lifecycle(NODE).state == "active"  # type: ignore[union-attr]
    assets[1]["last_seen"] = NOW - 48 * H
    lifecycle = _estate(assets, [cluster]).lifecycle(NODE)
    assert lifecycle is not None and lifecycle.state == "stale"


def test_self_test_is_not_coverage_and_retires_when_it_stops() -> None:
    mac = asset_row(MAC, asset_type="macos_host")
    telemetry = _collector("macos-workstation-01", asset_id=MAC, source_types=["macos.unified_log"])
    heartbeat = _silent(
        "sdk-heartbeat-example",
        16 * H,
        asset_id=MAC,
        collector_type="heartbeat",
        source_types=["extorq.pipeline"],
    )
    assert heartbeat.self_test is True and telemetry.self_test is False
    estate = _estate([mac], [telemetry, heartbeat])
    assert [c.collector_id for c in estate.coverage_collectors(MAC)] == ["macos-workstation-01"]
    item = estate.asset_item(mac, 0)
    assert item.coverage_status == "ok" and item.collectors_total == 1
    assert item.collectors_stale == 0
    # Within the retirement window the stopped self-test is stale, afterwards retired.
    assert {c.collector_id: c.lifecycle_state for c in estate.collectors(include_retired=True)} == {
        "macos-workstation-01": "active",
        "sdk-heartbeat-example": "stale",
    }
    old_heartbeat = heartbeat.model_copy(update={"last_reported_at": NOW - 25 * H})
    estate = _estate([mac], [telemetry, old_heartbeat])
    assert [c.collector_id for c in estate.collectors(include_retired=False)] == [
        "macos-workstation-01"
    ]
    assert estate.retired_collectors == 1


def test_a_self_test_does_not_keep_an_asset_configured() -> None:
    asset = asset_row(MAC, asset_type="macos_host", last_seen=NOW - 30 * H)
    heartbeat = _collector(
        "sdk-heartbeat-example",
        asset_id=MAC,
        collector_type="heartbeat",
        source_types=["extorq.pipeline"],
    )
    assert _estate([asset], [heartbeat]).lifecycle(MAC).state == "retired"  # type: ignore[union-attr]


def test_collectors_of_a_retired_asset_are_retired_and_keep_their_coverage() -> None:
    repo_asset = asset_row(TEST_REPO, asset_type="github_repository", last_seen=NOW - 40 * H)
    mechanics = _silent("github-mechanics-test", 40 * H, asset_id=TEST_REPO, interval_seconds=120)
    estate = _estate([repo_asset], [mechanics])
    assert estate.is_retired(TEST_REPO)
    (collector,) = estate.collectors(include_retired=True)
    assert collector.lifecycle_state == "retired"
    assert estate.collectors(include_retired=False) == []
    item = estate.asset_item(repo_asset, 0)
    assert item.lifecycle_state == "retired"
    assert item.coverage_status == "stale"  # what stopped stays visible on the asset itself


def test_class_coverage_leaves_retired_assets_out_unless_asked() -> None:
    assets = [
        asset_row(LAB_REPO, asset_type="github_repository"),
        asset_row(TEST_REPO, asset_type="github_repository", last_seen=NOW - 40 * H),
        asset_row(
            "github:octo-synthetic/action", asset_type="github_repository", last_seen=NOW - 40 * H
        ),
    ]
    collectors = [
        _collector("github-repos", asset_id=LAB_REPO, interval_seconds=120),
        _silent("github-mechanics-test", 40 * H, asset_id=TEST_REPO, interval_seconds=120),
    ]
    events: list[dict[str, Any]] = [
        {"asset_id": LAB_REPO, "asset_type": "github_repository", "last_event_at": NOW - 10 * H},
        {"asset_id": TEST_REPO, "asset_type": "github_repository", "last_event_at": NOW - 2 * H},
    ]
    estate = _estate(assets, collectors, last_event_map(events))
    # The test repo had an event 2 h ago: observed, so not retired; drop that event.
    assert not estate.is_retired(TEST_REPO)
    events[1]["last_event_at"] = NOW - 40 * H
    estate = _estate(assets, collectors, last_event_map(events))
    assert estate.retired_asset_ids == {TEST_REPO, "github:octo-synthetic/action"}

    (github,) = [
        c
        for c in estate.class_coverage(assets, events, include_retired=False)
        if c.asset_type == "github_repository"
    ]
    assert (github.status, github.assets_total, github.assets_ok, github.assets_retired) == (
        "ok",
        1,
        1,
        2,
    )
    assert github.assets_stale == 0 and github.assets_without_collector == 0
    assert github.last_event_at == NOW - 10 * H

    (everything,) = [
        c
        for c in estate.class_coverage(assets, events, include_retired=True)
        if c.asset_type == "github_repository"
    ]
    assert (everything.status, everything.assets_total, everything.assets_retired) == (
        "degraded",
        3,
        2,
    )
    assert everything.assets_stale == 1 and everything.assets_without_collector == 1


# ── endpoints ────────────────────────────────────────────────────────────────────


@pytest.fixture
def estate_repo(repo: FakeRepository) -> FakeRepository:
    """Lab repo (active), retired mechanics-test repo + account, macOS with a heartbeat."""
    repo.assets = [
        asset_row(LAB_REPO, asset_type="github_repository"),
        asset_row(TEST_REPO, asset_type="github_repository", last_seen=NOW - 40 * H),
        asset_row(TEST_ACCOUNT, asset_type="github_account", last_seen=NOW - 40 * H),
        asset_row(MAC, asset_type="macos_host"),
    ]
    repo.collector_rows = [
        collector_row("github-repos", asset_id=LAB_REPO, interval_seconds=120),
        collector_row(
            "github-mechanics-test",
            asset_id=TEST_REPO,
            interval_seconds=120,
            last_reported_at=NOW - 40 * H,
            last_attempt_at=NOW - 40 * H,
            last_success_at=NOW - 40 * H,
        ),
        collector_row("macos-workstation-01", asset_id=MAC, source_types=["macos.unified_log"]),
        collector_row(
            "sdk-heartbeat-example",
            asset_id=MAC,
            collector_type="heartbeat",
            source_types=["extorq.pipeline"],
            last_reported_at=NOW - 40 * H,
            last_attempt_at=NOW - 40 * H,
            last_success_at=NOW - 40 * H,
        ),
    ]
    for label, asset_id, asset_type, when in (
        ("lab", LAB_REPO, "github_repository", NOW - 10 * H),
        ("test", TEST_REPO, "github_repository", NOW - 40 * H),
        ("mac", MAC, "macos_host", NOW - timedelta(minutes=1)),
    ):
        event = event_row(label, asset_id=asset_id, asset_type=asset_type, event_time=when)
        repo.events[event["event_id"]] = event
    return repo


def test_asset_list_leaves_retired_assets_out_by_default(
    client: TestClient, viewer: dict[str, str], estate_repo: FakeRepository
) -> None:
    body = client.get("/api/v1/assets", headers=viewer).json()
    assert [i["asset_id"] for i in body["items"]] == [LAB_REPO, MAC]
    assert body["retired_excluded"] == 2
    assert body["page"]["total"] == 2
    assert {i["lifecycle_state"] for i in body["items"]} == {"active"}
    mac = next(i for i in body["items"] if i["asset_id"] == MAC)
    assert (mac["coverage_status"], mac["collectors_total"], mac["collectors_stale"]) == (
        "ok",
        1,
        0,
    )

    full = client.get("/api/v1/assets", headers=viewer, params={"include_retired": "true"}).json()
    assert full["retired_excluded"] == 0 and full["page"]["total"] == 4
    retired = {i["asset_id"]: i for i in full["items"] if i["lifecycle_state"] == "retired"}
    assert set(retired) == {TEST_REPO, TEST_ACCOUNT}
    assert retired[TEST_REPO]["lifecycle_reason"].startswith(
        "no collector covering it has reported within 86400s"
    )
    assert retired[TEST_REPO]["last_observed_at"].startswith("2026-11-19T20:00:00")

    typed = client.get(
        "/api/v1/assets", headers=viewer, params={"asset_type": "github_repository"}
    ).json()
    assert [i["asset_id"] for i in typed["items"]] == [LAB_REPO]
    assert typed["retired_excluded"] == 1


def test_retired_asset_detail_stays_available(
    client: TestClient, viewer: dict[str, str], estate_repo: FakeRepository
) -> None:
    response = client.get("/api/v1/assets/github%3Aocto-synthetic%2Fhello-world", headers=viewer)
    assert response.status_code == 200
    body = response.json()
    assert body["asset"]["lifecycle_state"] == "retired"
    assert [(c["collector_id"], c["lifecycle_state"]) for c in body["collectors"]] == [
        ("github-mechanics-test", "retired")
    ]
    mac = client.get("/api/v1/assets/macos%3Aworkstation-01", headers=viewer).json()
    assert [c["collector_id"] for c in mac["collectors"]] == ["macos-workstation-01"]
    assert mac["asset"]["coverage_status"] == "ok"


def test_overview_rollups_leave_retired_assets_out(
    client: TestClient, viewer: dict[str, str], estate_repo: FakeRepository
) -> None:
    estate_repo.alerts = [alert_row("old", asset_id=TEST_REPO, asset_type="github_repository")]
    estate_repo.finding_counts = [
        {"asset_id": LAB_REPO, "severity": "high", "findings": 3},
        {"asset_id": TEST_REPO, "severity": "critical", "findings": 2},
    ]
    estate_repo.services = [service_row(asset_id=TEST_REPO), service_row("lab.service")]
    estate_repo.services[1]["asset_id"] = LAB_REPO
    estate_repo.services[1]["service_id"] = service_row("lab.service", asset_id=LAB_REPO)[
        "service_id"
    ]

    body = client.get("/api/v1/overview", headers=viewer).json()
    classes = {c["asset_type"]: c for c in body["asset_coverage"]}
    assert classes["github_repository"]["status"] == "ok"
    assert classes["github_repository"]["assets_total"] == 1
    assert classes["github_repository"]["assets_retired"] == 1
    assert classes["github_account"]["assets_total"] == 0
    assert classes["github_account"]["assets_retired"] == 1
    assert classes["macos_host"]["status"] == "ok"  # the stopped heartbeat is not coverage
    # Findings of the retired repository are not in the KPI; its open alert still is.
    assert body["open_findings"]["counts"]["critical"] == 0
    assert body["open_findings"]["counts"]["high"] == 3
    assert body["open_alerts"]["total"] == 1
    health = body["collection_health"]
    assert (health["collectors_total"], health["collectors_stale"]) == (2, 0)
    assert health["collectors_retired"] == 2
    assert body["service_coverage"]["coverage"]["total"] == 1
    lifecycle = body["lifecycle"]
    assert lifecycle["retired_asset_ids"] == [TEST_ACCOUNT, TEST_REPO]
    assert (lifecycle["active"], lifecycle["stale"], lifecycle["retired"]) == (2, 0, 2)
    assert lifecycle["include_retired"] is False
    assert (lifecycle["stale_after_seconds"], lifecycle["retire_after_seconds"]) == (3600, 86400)
    assert ("finding_severity_counts", ("", (TEST_ACCOUNT, TEST_REPO))) in estate_repo.calls

    full = client.get("/api/v1/overview", headers=viewer, params={"include_retired": "true"}).json()
    classes = {c["asset_type"]: c for c in full["asset_coverage"]}
    assert classes["github_repository"]["assets_total"] == 2
    assert classes["github_repository"]["status"] == "degraded"
    assert full["open_findings"]["counts"]["critical"] == 2
    assert full["collection_health"]["collectors_total"] == 4
    assert full["service_coverage"]["coverage"]["total"] == 2
    assert full["lifecycle"]["include_retired"] is True


def test_health_lists_retired_collectors_only_on_request(
    client: TestClient, viewer: dict[str, str], estate_repo: FakeRepository
) -> None:
    body = client.get("/api/v1/health", headers=viewer).json()
    assert [c["collector_id"] for c in body["collectors"]] == [
        "github-repos",
        "macos-workstation-01",
    ]
    assert body["collectors_retired"] == 2
    assert any("2 retired collector(s) not listed" in note for note in body["notes"])
    full = client.get("/api/v1/health", headers=viewer, params={"include_retired": "true"}).json()
    states = {c["collector_id"]: (c["lifecycle_state"], c["self_test"]) for c in full["collectors"]}
    assert states == {
        "github-repos": ("active", False),
        "github-mechanics-test": ("retired", False),
        "macos-workstation-01": ("active", False),
        "sdk-heartbeat-example": ("retired", True),
    }
    assert not any("retired collector" in note for note in full["notes"])

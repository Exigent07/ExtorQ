"""The analyst API in-process against the LIVE stack (real ClickHouse, real telemetry).

Runs with ``-m integration``; skips unless ``docs/team/status/A.md`` announces
``STACK READY`` and ClickHouse answers as ``extorq_api_ro`` (debug proxy 127.0.0.1:18123).

READ-ONLY: only GET endpoints are called and no row is written to the shared stack. The
data is whatever arrived through the real ingestion path; assertions are about shapes,
consistency with direct SQL and honest empty states, never about fabricated values. The
service token is a random per-run value in a temp file (the real token is not used).
"""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from extorq.api.app import create_app
from extorq.api.integrations import PlatformIntegrations
from extorq.api.repository import ClickHouseRepository
from extorq.api.settings import ApiSettings

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[3]
STATUS_A = REPO_ROOT / "docs" / "team" / "status" / "A.md"


@pytest.fixture(scope="module")
def live_repo() -> ClickHouseRepository:
    if not STATUS_A.is_file() or "STACK READY" not in STATUS_A.read_text(encoding="utf-8"):
        pytest.skip("shared stack not announced ready (docs/team/status/A.md)")
    repo = ClickHouseRepository()
    try:
        repo.ping()
    except Exception as exc:  # noqa: BLE001 - any failure means the live store is unusable
        pytest.skip(f"live ClickHouse not reachable as extorq_api_ro: {type(exc).__name__}")
    return repo


@pytest.fixture(scope="module")
def client(
    live_repo: ClickHouseRepository, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[tuple[TestClient, dict[str, str]]]:
    token = secrets.token_urlsafe(32)
    path = tmp_path_factory.mktemp("d1-live") / "token"
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)
    app = create_app(
        settings=ApiSettings(service_token_file=path),
        repository=live_repo,
        integrations=PlatformIntegrations(),
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "X-ExtorQ-User": "d1-live-test",
        "X-ExtorQ-Role": "viewer",
    }
    with TestClient(app) as test_client:
        yield test_client, headers


#: Seconds between API requests. The ``extorq_api_ro`` quota (1200 ClickHouse queries per
#: minute) is SHARED with the compose API and every console user; one request costs about
#: 3-15 queries, so an unpaced run could starve them (observed in session 3).
LIVE_PACE_SECONDS = float(os.environ.get("EXTORQ_LIVE_PACE_SECONDS", "0.8"))


def _get(client: tuple[TestClient, dict[str, str]], path: str, **params: Any) -> Any:
    test_client, headers = client
    time.sleep(LIVE_PACE_SECONDS)
    response = test_client.get(path, headers=headers, params=params or None)
    assert response.status_code == 200, (path, response.status_code, response.text[:500])
    return response.json()


def _scalar(repo: ClickHouseRepository, sql: str) -> int:
    # Static SQL literals only (no values): direct cross-checks of API numbers.
    return int(repo.read_client().query(sql).result_rows[0][0])


def _consistent(repo: ClickHouseRepository, sql: str, api_value: Callable[[], int]) -> None:
    """The API number lies between direct counts taken before and after the API call.

    Collectors keep writing while the test runs; a count may grow between two queries.
    """
    before = _scalar(repo, sql)
    value = api_value()
    after = _scalar(repo, sql)
    assert min(before, after) <= value <= max(before, after), (sql, before, value, after)


def test_every_collection_endpoint_answers_with_real_data(
    client: tuple[TestClient, dict[str, str]],
) -> None:
    for path in (
        "/api/v1/overview",
        "/api/v1/assets",
        "/api/v1/findings",
        "/api/v1/rules",
        "/api/v1/alerts",
        "/api/v1/events",
        "/api/v1/health",
        "/api/v1/services",
        "/api/v1/timeseries/alerts",
        "/api/v1/timeseries/events",
    ):
        _get(client, path)
    series = _get(client, "/api/v1/timeseries/events", group_by="source_type")
    assert all(p["count"] > 0 for p in series["points"])  # sparse, never invented zeros


def test_assets_and_their_services(
    client: tuple[TestClient, dict[str, str]], live_repo: ClickHouseRepository
) -> None:
    assets = _get(client, "/api/v1/assets", limit=200)
    _consistent(
        live_repo,
        "SELECT count() FROM extorq.v_assets",
        lambda: _get(client, "/api/v1/assets", limit=1)["page"]["total"],
    )
    for asset in assets["items"]:
        encoded = quote(asset["asset_id"], safe="")
        detail = _get(client, f"/api/v1/assets/{encoded}")
        assert detail["asset"]["asset_id"] == asset["asset_id"]
        summary = detail["services_summary"]
        services = _get(client, f"/api/v1/assets/{encoded}/services", limit=200)
        # One shared coverage function (session 3 review fix): identical summaries.
        assert services["summary"] == summary
        assert services["page"]["total"] == summary["coverage"]["total"]
        if not summary["reported"]:
            assert summary["note"] and services["items"] == []
        for hosted in services["hosted"]:
            # Workloads of an ANCESTOR asset; only instances reported on this asset.
            assert asset["asset_id"].startswith(hosted["service"]["asset_id"] + "/")
            assert all(i["asset_id"] == asset["asset_id"] for i in hosted["instances"])
        if asset["asset_type"] == "kubernetes_node":
            assert detail["asset"]["collectors_inherited"] == detail["asset"]["collectors_total"]


def test_service_inventory_matches_storage_and_details_resolve(
    client: tuple[TestClient, dict[str, str]], live_repo: ClickHouseRepository
) -> None:
    listing = _get(client, "/api/v1/services", limit=200)

    def present_total() -> int:
        response = _get(client, "/api/v1/services", limit=1)
        return int(response["summary"]["coverage"]["total"] + response["invalid_records"])

    _consistent(live_repo, "SELECT count() FROM extorq.v_services WHERE present = 1", present_total)
    summary = listing["summary"]
    assert summary["reported"] is (summary["coverage"]["total"] + summary["removed"] > 0)
    counts = summary["coverage"]
    assert counts["total"] == sum(
        counts[k] for k in ("monitored", "degraded", "unmonitored", "planned", "unsupported")
    )
    for item in listing["items"][:25]:
        detail = _get(client, f"/api/v1/services/{item['service_id']}")
        assert detail["service"]["service_id"] == item["service_id"]
        assert detail["service"]["coverage_state"] == item["coverage_state"]
        for event in detail["recent_events"]:
            assert event["service_id"] == item["service_id"]
        for alert in detail["alerts"]:
            assert item["service_id"] in alert["service_ids"]
        assert detail["instances_total"] >= len(detail["instances"])
    for state in ("planned", "unsupported", "unmonitored"):
        # Unsupported / planned / unmonitored services are listed, never hidden (both
        # numbers come from the same request, so concurrent discovery cannot skew them).
        filtered = _get(client, "/api/v1/services", coverage=state, limit=200)
        assert filtered["page"]["total"] == filtered["summary"]["coverage"][state]
        assert all(i["coverage_state"] == state for i in filtered["items"])


def test_health_reflects_collector_reports(
    client: tuple[TestClient, dict[str, str]], live_repo: ClickHouseRepository
) -> None:
    health = _get(client, "/api/v1/health")
    assert health["storage"]["reachable"] is True
    _consistent(
        live_repo,
        "SELECT count() FROM extorq.v_collector_latest",
        lambda: len(_get(client, "/api/v1/health")["collectors"]),
    )
    for collector in health["collectors"]:
        if collector["last_success_at"] is None:
            assert collector["stale"] is True
    rules = _get(client, "/api/v1/rules", limit=200)
    _consistent(
        live_repo,
        "SELECT uniqExact(rule_id) FROM extorq.detection_rules",
        lambda: _get(client, "/api/v1/rules", limit=1)["page"]["total"],
    )
    for rule in rules["items"][:20]:
        _get(client, f"/api/v1/rules/{rule['rule_id']}")


def test_findings_and_events_are_consistent(
    client: tuple[TestClient, dict[str, str]], live_repo: ClickHouseRepository
) -> None:
    findings = _get(client, "/api/v1/findings", limit=200)
    sql = (
        "SELECT count() FROM extorq.v_findings_current"
        if findings["lifecycle_available"]
        else "SELECT uniqExact(finding_id) FROM extorq.finding_observations"
    )
    _consistent(live_repo, sql, lambda: _get(client, "/api/v1/findings", limit=1)["page"]["total"])
    events = _get(client, "/api/v1/events", limit=50)
    ids = [e["event_id"] for e in events["items"]]
    assert len(ids) == len(set(ids))  # duplicate deliveries collapse
    for event_id in ids[:5]:
        detail = _get(client, f"/api/v1/events/{event_id}")
        assert detail["event"]["event_id"] == event_id


def test_alert_drilldown_when_alerts_exist(client: tuple[TestClient, dict[str, str]]) -> None:
    alerts = _get(client, "/api/v1/alerts", limit=20)
    if not alerts["items"]:
        pytest.skip("no alerts in the live store yet (detector/scenarios pending)")
    for alert in alerts["items"][:10]:
        detail = _get(client, f"/api/v1/alerts/{alert['alert_id']}")
        resolved = {e["event_id"] for e in detail["evidence"]}
        assert resolved.isdisjoint(detail["unresolved_evidence_ids"])
        _get(client, f"/api/v1/alerts/{alert['alert_id']}/assessments")

"""Service-aware monitoring endpoints (schema 1.1): inventory, coverage, detail, routing.

All data is SYNTHETIC (see api_fakes.py).
"""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import quote

import pytest
from api_fakes import (
    NOW,
    SYN,
    FakeRepository,
    alert_row,
    asset_row,
    collector_row,
    event_row,
    hexid,
    instance_row,
    service_row,
)
from fastapi.testclient import TestClient

from extorq.api import service
from extorq.api.schemas import CollectorStatus

CLUSTER = "k8s:extorq-lab"
NODE = "k8s:extorq-lab/node/extorq-lab-control-plane"


def _seed_mixed(repo: FakeRepository) -> dict[str, str]:
    """One service per coverage state on the Linux VM plus Kubernetes kinds."""
    repo.assets = [
        asset_row(),
        asset_row(CLUSTER, asset_type="kubernetes_cluster"),
        asset_row(NODE, asset_type="kubernetes_node", parent_asset_id=CLUSTER),
    ]
    repo.collector_rows = [
        collector_row(),  # linux.journald, fresh
        collector_row(
            "k8s-inventory",
            asset_id=CLUSTER,
            source_types=["k8s.api_inventory", "k8s.container_log"],
        ),
    ]
    rows = {
        "monitored": service_row("ssh.service"),
        "unmonitored": service_row(
            "nginx.service",
            category="http_server",
            adapter_id="nginx",
            monitoring_status="unmonitored",
            telemetry_sources=["linux.nginx"],
        ),
        "planned": service_row(
            "vsftpd.service",
            category="ftp",
            adapter_id="ftp",
            adapter_support="planned",
            monitoring_status="unmonitored",
            telemetry_sources=[],
            coverage_note="planned adapter 'ftp': discovered only, no telemetry collected",
        ),
        "unsupported": service_row(
            "cron.service",
            category="unknown",
            adapter_id=None,
            adapter_support="none",
            monitoring_status="unmonitored",
            telemetry_sources=[],
            endpoints="[]",
        ),
        "removed": service_row("old.service", present=0),
        "workload": service_row(
            "extorq-apps/Deployment/lab-portal",
            asset_id=CLUSTER,
            service_kind="k8s_workload",
            category="web_application",
            adapter_id="webapp-json",
            telemetry_sources=["k8s.container_log"],
            endpoints="[]",
        ),
        "k8s_service": service_row(
            "extorq-apps/lab-portal",
            asset_id=CLUSTER,
            service_kind="k8s_service",
            category="web_application",
            adapter_id=None,
            adapter_support="none",
            monitoring_status="unmonitored",
            telemetry_sources=[],
            endpoints=(
                '[{"address":"10.96.0.20","attribution":"confirmed",'
                '"attribution_basis":"Service spec","exposure":"private","port":80,'
                '"protocol":"tcp"}]'
            ),
        ),
    }
    repo.services = list(rows.values())
    return {name: row["service_id"] for name, row in rows.items()}


# ── list + coverage derivation ────────────────────────────────────────────────────


def test_empty_inventory_is_reported_explicitly(client: TestClient, viewer: dict[str, str]) -> None:
    body = client.get("/api/v1/services", headers=viewer).json()
    assert body["items"] == []
    assert body["summary"]["reported"] is False
    assert body["summary"]["coverage"]["total"] == 0
    assert "no service discovery records" in body["summary"]["note"]
    assert body["page"]["total"] == 0


def test_every_coverage_state_is_listed_never_hidden(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    ids = _seed_mixed(repo)
    body = client.get("/api/v1/services", headers=viewer).json()
    states = {i["service_id"]: i["coverage_state"] for i in body["items"]}
    assert states[ids["monitored"]] == "monitored"
    assert states[ids["unmonitored"]] == "unmonitored"
    assert states[ids["planned"]] == "planned"
    assert states[ids["unsupported"]] == "unsupported"
    assert states[ids["workload"]] == "monitored"
    assert states[ids["k8s_service"]] == "unsupported"
    assert ids["removed"] not in states  # tombstones only on request
    summary = body["summary"]
    assert summary["reported"] is True
    assert summary["removed"] == 1
    assert summary["coverage"] == {
        "monitored": 2,
        "degraded": 0,
        "unmonitored": 1,
        "planned": 1,
        "unsupported": 2,
        "total": 6,
    }
    kinds = {k["service_kind"]: k["coverage"]["total"] for k in summary["by_kind"]}
    # A Kubernetes Service is counted apart from host services and workloads.
    assert kinds == {"host_service": 4, "k8s_workload": 1, "k8s_service": 1}

    with_removed = client.get(
        "/api/v1/services", headers=viewer, params={"include_removed": "true"}
    ).json()
    removed = next(i for i in with_removed["items"] if i["service_id"] == ids["removed"])
    assert removed["present"] is False


def test_planned_item_carries_collector_note_and_no_telemetry(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    ids = _seed_mixed(repo)
    items = client.get("/api/v1/services", headers=viewer).json()["items"]
    planned = next(i for i in items if i["service_id"] == ids["planned"])
    assert planned["adapter_support"] == "planned"
    assert planned["telemetry_sources"] == []
    assert planned["coverage_note"].startswith("planned adapter")


def test_stale_collector_downgrades_monitored_to_degraded_with_reason(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    repo.assets = [asset_row()]
    repo.collector_rows = [collector_row(last_success_at=NOW - timedelta(hours=2))]
    svc = service_row()
    repo.services = [svc]
    item = client.get("/api/v1/services", headers=viewer).json()["items"][0]
    assert item["monitoring_status"] == "monitored"  # as reported
    assert item["coverage_state"] == "degraded"  # effective now
    assert any(
        "linux.journald" in r and "linux-ssh" in r and "stale" in r
        for r in item["coverage_reasons"]
    )


def test_stale_discovery_record_downgrades_monitored(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    repo.collector_rows = [collector_row()]
    repo.services = [service_row(last_seen=NOW - timedelta(hours=2))]
    item = client.get("/api/v1/services", headers=viewer).json()["items"][0]
    assert item["report_stale"] is True
    assert item["report_age_seconds"] == pytest.approx(7200)
    assert item["coverage_state"] == "degraded"
    assert "cannot be confirmed" in item["coverage_reasons"][0]


def test_source_without_any_collector_health_does_not_invent_staleness() -> None:
    evaluator = service.ServiceEvaluator([], NOW, 3600)
    item = evaluator.item(service_row())
    assert item.coverage_state == "monitored"
    assert item.coverage_reasons == []


def test_nothing_is_ever_upgraded() -> None:
    state, _ = service.effective_coverage(
        "implemented",
        "degraded",
        report_stale=False,
        report_age=1.0,
        stale_seconds=3600,
        stale_sources={},
    )
    assert state == "degraded"
    state, reasons = service.effective_coverage(
        "planned",
        "monitored",  # inconsistent report: still planned, never monitored
        report_stale=True,
        report_age=99999.0,
        stale_seconds=3600,
        stale_sources={},
    )
    assert state == "planned"
    assert reasons  # staleness is still disclosed


def test_cluster_collector_covers_node_assets() -> None:
    cluster_collector = service.collector_status(
        collector_row("k8s-otel", asset_id=CLUSTER, source_types=["k8s.container_log"]), NOW
    )
    other = service.collector_status(collector_row("other", asset_id="k8s:extorq-lab2"), NOW)
    assert service.collectors_for_asset(NODE, [cluster_collector, other]) == [cluster_collector]
    assert service.collectors_for_asset(CLUSTER, [other]) == []


def test_filters_reach_storage_and_coverage_filter_paginates(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    _seed_mixed(repo)
    body = client.get(
        "/api/v1/services",
        headers=viewer,
        params={"kind": "host_service", "asset_id": "linux:lab-vm-01", "limit": 1},
    ).json()
    filters, max_rows = repo.last_call("list_services")
    assert filters.service_kind == "host_service"
    assert filters.asset_id == "linux:lab-vm-01"
    assert filters.include_removed is True  # tombstones are read for the summary
    assert max_rows > 1000
    assert body["page"] == {
        "limit": 1,
        "offset": 0,
        "returned": 1,
        "has_more": True,
        "next_offset": 1,
        "total": 4,
    }
    planned = client.get("/api/v1/services", headers=viewer, params={"coverage": "planned"}).json()
    assert [i["coverage_state"] for i in planned["items"]] == ["planned"]
    # The summary describes the whole filtered scope (chips stay stable).
    assert planned["summary"]["coverage"]["total"] == 6


@pytest.mark.parametrize(
    ("param", "value"),
    [
        ("kind", "systemd"),
        ("adapter_support", "maybe"),
        ("monitoring_status", "fine"),
        ("coverage", "great"),
        ("asset_id", "BAD ASSET"),
        ("limit", "1000"),
    ],
)
def test_invalid_filters_are_rejected(
    client: TestClient, viewer: dict[str, str], param: str, value: str
) -> None:
    response = client.get("/api/v1/services", headers=viewer, params={param: value})
    assert response.status_code == 422


def test_invalid_stored_rows_are_skipped_and_counted(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    repo.services = [service_row(), service_row("x.service", service_kind="mystery")]
    body = client.get("/api/v1/services", headers=viewer).json()
    assert len(body["items"]) == 1
    assert body["invalid_records"] == 1


def test_endpoints_keep_attribution_and_exposure(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    ids = _seed_mixed(repo)
    items = {
        i["service_id"]: i for i in client.get("/api/v1/services", headers=viewer).json()["items"]
    }
    ssh = items[ids["monitored"]]
    assert ssh["endpoints"] == [
        {
            "protocol": "tcp",
            "address": "0.0.0.0",  # noqa: S104 - synthetic bind address under test
            "port": 22,
            "exposure": "any",
            "attribution": "confirmed",
            "attribution_basis": "socket owner",
        }
    ]
    assert ssh["exposures"] == ["any"]
    assert items[ids["unsupported"]]["exposures"] == []
    assert items[ids["k8s_service"]]["exposures"] == ["private"]


def test_untrusted_service_strings_are_returned_verbatim_as_json(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    repo.services = [service_row(name="<img src=x onerror=alert(1)>")]
    response = client.get("/api/v1/services", headers=viewer)
    assert response.headers["content-type"].startswith("application/json")
    assert response.json()["items"][0]["name"] == "<img src=x onerror=alert(1)>"


# ── per-asset services and routing ────────────────────────────────────────────────


def test_asset_services_and_summary(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    ids = _seed_mixed(repo)
    response = client.get(f"/api/v1/assets/{quote(CLUSTER, safe='')}/services", headers=viewer)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["asset"]["asset_type"] == "kubernetes_cluster"
    assert {i["service_id"] for i in body["items"]} == {ids["workload"], ids["k8s_service"]}
    assert {k["service_kind"] for k in body["summary"]["by_kind"]} == {
        "k8s_workload",
        "k8s_service",
    }


def test_asset_services_unknown_asset_is_404(client: TestClient, viewer: dict[str, str]) -> None:
    response = client.get("/api/v1/assets/linux:nope-01/services", headers=viewer)
    assert response.status_code == 404


def test_services_without_asset_record_are_still_listed(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    repo.services = [service_row(asset_id="linux:unreported-01")]
    body = client.get("/api/v1/assets/linux:unreported-01/services", headers=viewer).json()
    assert body["asset"] is None
    assert len(body["items"]) == 1


def test_encoded_asset_id_ending_in_services_is_the_asset_detail(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    tricky = "github:owner/services"
    repo.assets = [asset_row(tricky, asset_type="github_repository")]
    detail = client.get(f"/api/v1/assets/{quote(tricky, safe='')}", headers=viewer)
    assert detail.status_code == 200, detail.text
    assert detail.json()["asset"]["asset_id"] == tricky
    sub = client.get(f"/api/v1/assets/{quote(tricky, safe='')}/services", headers=viewer)
    assert sub.status_code == 200
    assert sub.json()["asset_id"] == tricky


def test_asset_detail_has_services_summary_and_kubernetes_nodes(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    _seed_mixed(repo)
    body = client.get(f"/api/v1/assets/{CLUSTER}", headers=viewer).json()
    assert body["services_summary"]["coverage"]["total"] == 2
    assert body["child_assets"] == [
        {
            "asset_id": NODE,
            "asset_type": "kubernetes_node",
            "name": f"{SYN}-{NODE}",
            "display_name": None,
            "environment": "lab",
            "criticality": "medium",
        }
    ]
    linux = client.get("/api/v1/assets/linux:lab-vm-01", headers=viewer).json()
    assert linux["services_summary"]["removed"] == 1
    assert linux["child_assets"] == []


def test_overview_reports_service_coverage(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    _seed_mixed(repo)
    body = client.get("/api/v1/overview", headers=viewer).json()
    assert body["service_coverage"]["coverage"]["total"] == 6
    empty = FakeRepository()
    assert service.services_summary([], truncated=False).reported is False
    assert empty.services == []


# ── service detail ────────────────────────────────────────────────────────────────


def _seed_detail(repo: FakeRepository) -> str:
    repo.assets = [asset_row()]
    repo.collector_rows = [collector_row()]
    svc = service_row(
        endpoints=(
            '[{"address":"0.0.0.0","attribution":"confirmed","exposure":"any","port":22,'
            '"protocol":"tcp"},{"port":99999,"protocol":"tcp","attribution":"confirmed"}]'
        )
    )
    repo.services = [svc]
    sid = svc["service_id"]
    repo.instances = [instance_row(svc), instance_row(svc, "pid:200", pid=200)]
    repo.service_sources[sid] = [
        {"source_type": "linux.journald", "events": 12, "last_event_at": NOW,
         "last_ingested_at": NOW},
        {"source_type": "linux.auditd", "events": 1, "last_event_at": NOW,
         "last_ingested_at": NOW},
    ]  # fmt: skip
    repo.auth_summary[sid] = {
        "total": 12, "success": 2, "failure": 10, "denied": 0, "unknown": 0,
        "distinct_actors": 3, "distinct_sources": 1,
    }  # fmt: skip
    repo.auth_sources[sid] = [
        {"source_ip": "10.0.2.2", "events": 12, "failures": 10, "last_seen": NOW}
    ]
    attributed = event_row("svc-e1", service_id=sid, service_name="ssh")
    unattributed = event_row("other-e2")
    repo.events = {e["event_id"]: e for e in (attributed, unattributed)}
    finding = {
        "finding_id": hexid("finding:sshd"),
        "asset_id": "linux:lab-vm-01",
        "scanner": "linux-posture",
        "check_id": "linux.ssh.password_auth",
        "category": "misconfiguration",
        "severity": "medium",
        "title": f"{SYN} password authentication enabled",
        "last_observed_at": NOW,
    }
    repo.findings = [
        {**finding, "service_id": sid},
        {**finding, "finding_id": hexid("finding:other"), "service_id": None},
    ]
    repo.alerts = [alert_row("svc", service_ids=[sid]), alert_row("other")]
    return sid


def test_service_detail_drilldown(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    sid = _seed_detail(repo)
    response = client.get(f"/api/v1/services/{sid}", headers=viewer)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["service"]["service_id"] == sid
    assert body["service"]["coverage_state"] == "monitored"
    assert body["service"]["invalid_endpoints"] == 1
    assert len(body["service"]["endpoints"]) == 1
    assert any("failed validation" in n for n in body["notes"])
    assert body["asset"]["asset_id"] == "linux:lab-vm-01"
    assert body["instances_total"] == 2
    assert {i["pid"] for i in body["instances"]} == {100, 200}
    assert body["instances"][0]["user"] == "root"
    assert body["instances"][0]["stale"] is False

    telemetry = {t["source_type"]: t for t in body["telemetry"]}
    assert telemetry["linux.journald"]["declared"] is True
    assert telemetry["linux.journald"]["collection"] == "fresh"
    assert telemetry["linux.journald"]["events"] == 12
    assert telemetry["linux.journald"]["collectors"][0]["collector_id"] == "linux-ssh"
    # Observed in attributed events but not declared, and no collector reports it.
    assert telemetry["linux.auditd"]["declared"] is False
    assert telemetry["linux.auditd"]["collection"] == "no_collector_health"

    auth = body["auth_activity"]
    assert auth["total"] == 12
    assert auth["by_outcome"] == {"success": 2, "failure": 10}
    assert auth["top_sources"][0] == {
        "src_ip": "10.0.2.2",
        "events": 12,
        "failures": 10,
        "last_seen": "2026-11-21T12:00:00Z",
    }
    assert [e["service_id"] for e in body["recent_events"]] == [sid]
    assert [f["service_id"] for f in body["findings"]] == [sid]
    assert body["findings_total"] == 1
    assert [a["service_ids"] for a in body["alerts"]] == [[sid]]
    assert body["alerts_total"] == 1
    since = repo.last_call("service_event_sources")[1]
    assert since == NOW - timedelta(hours=24)


def test_service_detail_without_data_is_empty_not_invented(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    svc = service_row()
    repo.services = [svc]
    body = client.get(f"/api/v1/services/{svc['service_id']}", headers=viewer).json()
    assert body["asset"] is None
    assert body["instances"] == [] and body["instances_total"] == 0
    assert body["auth_activity"]["total"] == 0
    assert body["auth_activity"]["by_outcome"] == {}
    assert body["recent_events"] == [] and body["findings"] == [] and body["alerts"] == []
    assert body["telemetry"][0]["events"] == 0
    assert body["telemetry"][0]["last_event_at"] is None
    assert any("parent asset record" in n for n in body["notes"])
    assert any("collection freshness cannot be confirmed" in n for n in body["notes"])


def test_service_detail_errors(client: TestClient, viewer: dict[str, str]) -> None:
    assert client.get(f"/api/v1/services/{'a' * 32}", headers=viewer).status_code == 404
    assert client.get("/api/v1/services/not-a-hex-id", headers=viewer).status_code == 422
    bad_range = client.get(
        f"/api/v1/services/{'a' * 32}",
        headers=viewer,
        params={"since": "2026-11-21T10:00:00"},  # naive timestamps are refused
    )
    assert bad_range.status_code in (400, 404)


def test_service_endpoints_require_authentication(client: TestClient) -> None:
    for path in ("/api/v1/services", f"/api/v1/services/{'a' * 32}",
                 "/api/v1/assets/linux:lab-vm-01/services"):  # fmt: skip
        assert client.get(path).status_code == 401


def test_service_id_filters_on_events_alerts_findings(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    sid = _seed_detail(repo)
    events = client.get("/api/v1/events", headers=viewer, params={"service_id": sid}).json()
    assert [e["service_id"] for e in events["items"]] == [sid]
    assert repo.last_call("list_events").service_id == sid
    alerts = client.get("/api/v1/alerts", headers=viewer, params={"service_id": sid}).json()
    assert alerts["page"]["total"] == 1
    findings = client.get("/api/v1/findings", headers=viewer, params={"service_id": sid}).json()
    assert [f["service_id"] for f in findings["items"]] == [sid]
    for path in ("/api/v1/events", "/api/v1/alerts", "/api/v1/findings"):
        bad = client.get(path, headers=viewer, params={"service_id": "x' OR 1=1"})
        assert bad.status_code == 422, path


def test_collector_status_type_is_reused_for_sources() -> None:
    status = service.collector_status(collector_row(), NOW)
    assert isinstance(status, CollectorStatus)
    evaluator = service.ServiceEvaluator([status], NOW, 3600)
    assert evaluator.stale_sources("linux:lab-vm-01", ["linux.journald"]) == {}


# ── session 3 review fixes ────────────────────────────────────────────────────────


def _seed_node_service(repo: FakeRepository, *, cluster_collector_stale: bool) -> str:
    """A SYNTHETIC service on a Kubernetes node whose only source is a CLUSTER collector."""
    repo.assets = [
        asset_row(CLUSTER, asset_type="kubernetes_cluster"),
        asset_row(NODE, asset_type="kubernetes_node", parent_asset_id=CLUSTER),
    ]
    success = NOW - (timedelta(hours=2) if cluster_collector_stale else timedelta(seconds=30))
    repo.collector_rows = [
        collector_row(
            "k8s-otel",
            asset_id=CLUSTER,
            source_types=["k8s.container_log"],
            last_success_at=success,
        )
    ]
    svc = service_row(
        "kubelet.service",
        asset_id=NODE,
        category="unknown",
        adapter_id="k8s-container-log",
        telemetry_sources=["k8s.container_log"],
        endpoints="[]",
    )
    repo.services = [svc]
    return str(svc["service_id"])


@pytest.mark.parametrize(
    ("stale", "state"),
    [(True, "degraded"), (False, "monitored")],
)
def test_node_service_coverage_is_identical_in_every_view(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository, stale: bool, state: str
) -> None:
    """Regression (review): GET /assets/{node} evaluated the node's services with the node's
    own collectors only (none), GET /assets/{node}/services with the cluster collectors that
    cover the node: one service read monitored=1 in one view and degraded=1 in the other at
    the same instant. Both now use one shared function."""
    sid = _seed_node_service(repo, cluster_collector_stale=stale)
    node = quote(NODE, safe="")
    expected = {
        "monitored": 0,
        "degraded": 0,
        "unmonitored": 0,
        "planned": 0,
        "unsupported": 0,
        "total": 1,
    } | {state: 1}

    detail = client.get(f"/api/v1/assets/{node}", headers=viewer)
    assert detail.status_code == 200, detail.text
    listing = client.get(f"/api/v1/assets/{node}/services", headers=viewer)
    assert listing.status_code == 200, listing.text
    across = client.get("/api/v1/services", headers=viewer, params={"asset_id": NODE}).json()
    overview = client.get("/api/v1/overview", headers=viewer).json()
    one = client.get(f"/api/v1/services/{sid}", headers=viewer).json()

    assert detail.json()["services_summary"]["coverage"] == expected
    assert listing.json()["summary"]["coverage"] == expected
    assert across["summary"]["coverage"] == expected
    assert overview["service_coverage"]["coverage"] == expected
    assert listing.json()["items"][0]["coverage_state"] == state
    assert one["service"]["coverage_state"] == state
    by_kind = detail.json()["services_summary"]["by_kind"]
    assert by_kind == listing.json()["summary"]["by_kind"]
    if stale:
        reasons = listing.json()["items"][0]["coverage_reasons"]
        assert any("k8s-otel" in r and "stale" in r for r in reasons)
        assert one["service"]["coverage_reasons"] == reasons


def test_finding_attribution_is_the_latest_observations_in_every_endpoint(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    """Every endpoint takes a finding's service from its row (v_findings_current.service_id:
    latest observation wins, NULL clears an older link) and the service filter matches it."""
    sid = _seed_detail(repo)
    attributed, cleared = hexid("finding:sshd"), hexid("finding:other")
    expected = {attributed: sid, cleared: None}

    listing = client.get("/api/v1/findings", headers=viewer).json()["items"]
    assert {f["finding_id"]: f["service_id"] for f in listing} == expected
    asset = client.get("/api/v1/assets/linux:lab-vm-01", headers=viewer).json()["findings"]
    assert {f["finding_id"]: f["service_id"] for f in asset} == expected
    filtered = client.get("/api/v1/findings", headers=viewer, params={"service_id": sid}).json()
    assert [f["finding_id"] for f in filtered["items"]] == [attributed]
    assert filtered["page"]["total"] == 1
    detail = client.get(f"/api/v1/services/{sid}", headers=viewer).json()
    assert [(f["finding_id"], f["service_id"]) for f in detail["findings"]] == [(attributed, sid)]
    assert detail["findings_total"] == 1
    assert repo.last_call("list_findings").service_id == sid


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        ({"service_id": "ab" * 16}, "ab" * 16),
        ({"service_id": None}, None),  # latest observation unattributed: link cleared
        ({"service_id": ""}, None),
        ({}, None),
    ],
)
def test_finding_service_id_never_invents_a_link(
    row: dict[str, object], expected: str | None
) -> None:
    assert service.finding_service_id(row) == expected


def test_node_asset_coverage_inherits_the_cluster_collectors(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    """A Kubernetes node is covered by its cluster's collectors (the rule services already
    used): the node is no longer reported 'missing' in the list, detail and overview."""
    _seed_node_service(repo, cluster_collector_stale=False)
    repo.assets.append(asset_row("linux:lab-vm-01"))
    repo.collector_rows.append(collector_row())  # the VM's own collector
    node = quote(NODE, safe="")

    detail = client.get(f"/api/v1/assets/{node}", headers=viewer).json()
    assert [c["collector_id"] for c in detail["collectors"]] == ["k8s-otel"]
    assert detail["collectors"][0]["asset_id"] == CLUSTER  # reported for the ancestor
    asset = detail["asset"]
    assert (asset["collectors_total"], asset["collectors_inherited"]) == (1, 1)
    assert asset["coverage_status"] == "ok"

    items = client.get("/api/v1/assets", headers=viewer).json()["items"]
    listing = {a["asset_id"]: a for a in items}
    assert listing[NODE]["coverage_status"] == "ok"
    assert listing[NODE]["collectors_inherited"] == 1
    assert listing[CLUSTER]["collectors_inherited"] == 0  # its own collector
    # The cluster never inherits from its nodes, and other assets are unaffected.
    assert listing["linux:lab-vm-01"]["collectors_total"] == 1
    assert listing["linux:lab-vm-01"]["collectors_inherited"] == 0

    classes = client.get("/api/v1/overview", headers=viewer).json()["asset_coverage"]
    nodes = next(c for c in classes if c["asset_type"] == "kubernetes_node")
    assert (nodes["assets_ok"], nodes["assets_without_collector"], nodes["status"]) == (1, 0, "ok")


def test_collector_prefix_match_is_segment_aware() -> None:
    near_miss = service.collector_status(collector_row("x", asset_id="linux:lab-vm-0"), NOW)
    assert service.collectors_for_asset("linux:lab-vm-01", [near_miss]) == []


def test_node_lists_the_cluster_workloads_running_on_it(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    """GET /assets/{node}/services ``hosted``: the cluster's workloads with their Pods and
    containers on this node (D2's per-node Pod list); the node's own summary is unchanged."""
    ids = _seed_mixed(repo)
    workload = next(r for r in repo.services if r["service_id"] == ids["workload"])
    pod = instance_row(
        workload,
        "pod-uid-1",
        asset_id=NODE,
        instance_kind="pod",
        pid=None,
        process_name=None,
        process_user=None,
        namespace="extorq-apps",
        pod_name=f"{SYN}-lab-portal-0",
        pod_uid="pod-uid-1",
        node_name="extorq-lab-control-plane",
    )
    container = instance_row(
        workload,
        "container-1",
        asset_id=NODE,
        instance_kind="container",
        pid=None,
        process_name=None,
        process_user=None,
        parent_instance_id=pod["instance_id"],
        container_name="lab-portal",
        pod_name=f"{SYN}-lab-portal-0",
    )
    elsewhere = instance_row(workload, "pod-uid-2", asset_id=f"{CLUSTER}/node/other-node")
    repo.instances = [pod, container, elsewhere]

    body = client.get(f"/api/v1/assets/{quote(NODE, safe='')}/services", headers=viewer).json()
    assert body["items"] == [] and body["summary"]["coverage"]["total"] == 0
    assert [h["service"]["service_id"] for h in body["hosted"]] == [ids["workload"]]
    hosted = body["hosted"][0]
    assert hosted["service"]["service_kind"] == "k8s_workload"
    assert hosted["instances_on_asset"] == 2
    assert {i["instance_kind"] for i in hosted["instances"]} == {"pod", "container"}
    assert all(i["asset_id"] == NODE for i in hosted["instances"])
    assert body["hosted_truncated"] is False
    # The cluster itself hosts nothing (its workloads are its own items).
    cluster = client.get(f"/api/v1/assets/{quote(CLUSTER, safe='')}/services", headers=viewer)
    assert cluster.json()["hosted"] == []


def test_hosted_instances_cannot_attach_to_a_foreign_or_forged_service(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    """F-19 defence in depth: an instance on the node that names a service of an unrelated
    asset, or a stored service row whose id does not match its natural key, is not shown."""
    ids = _seed_mixed(repo)
    linux_ssh = next(r for r in repo.services if r["service_id"] == ids["monitored"])
    forged = service_row(
        "extorq-apps/Deployment/forged",
        asset_id=CLUSTER,
        service_kind="k8s_workload",
        service_id=hexid("forged-service"),
    )
    repo.services.append(forged)
    repo.instances = [
        instance_row(linux_ssh, "pid:1", asset_id=NODE),  # VM service, not an ancestor
        instance_row(forged, "pod-x", asset_id=NODE, instance_kind="pod"),
    ]
    body = client.get(f"/api/v1/assets/{quote(NODE, safe='')}/services", headers=viewer).json()
    assert body["hosted"] == []


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/overview",
        f"/api/v1/assets/{quote(NODE, safe='')}",
        f"/api/v1/assets/{quote(NODE, safe='')}/services",
        "/api/v1/services",
    ],
)
def test_collector_health_is_read_once_per_request(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository, path: str
) -> None:
    """One evaluator per request: the asset's coverage, its services' coverage and the
    hosted workloads all use the same collector snapshot (and one storage query)."""
    _seed_node_service(repo, cluster_collector_stale=True)
    repo.calls.clear()
    assert client.get(path, headers=viewer).status_code == 200
    assert [args for name, args in repo.calls if name == "collectors"] == [""]


# ── F-19: a service's rows stay on its own asset subtree ──────────────────────────


def test_rows_of_another_asset_never_appear_under_a_service(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    """F-19 (review): events and instances tagged with a service id are shown under that
    service only when they belong to the service's asset or a descendant (cluster -> node).
    A producer of the macOS host naming the VM's ssh service cannot plant rows there."""
    sid = _seed_detail(repo)
    genuine = event_row("svc-e1", service_id=sid, service_name="ssh")
    planted = event_row(
        "planted", service_id=sid, service_name="ssh", asset_id="macos:workstation-01"
    )
    repo.events = {e["event_id"]: e for e in (genuine, planted)}
    svc = repo.get_service(sid)
    assert svc is not None
    repo.instances.append(instance_row(svc, "pid:666", asset_id="macos:workstation-01"))

    detail = client.get(f"/api/v1/services/{sid}", headers=viewer).json()
    assert [e["event_id"] for e in detail["recent_events"]] == [genuine["event_id"]]
    assert detail["instances_total"] == 2  # the two VM processes, not the planted one
    assert {i["asset_id"] for i in detail["instances"]} == {"linux:lab-vm-01"}
    scopes = {args for name, args in repo.calls if name == "service_scope"}
    assert scopes == {"linux:lab-vm-01"}  # telemetry and auth aggregates are scoped too

    listing = client.get("/api/v1/events", headers=viewer, params={"service_id": sid}).json()
    assert [e["event_id"] for e in listing["items"]] == [genuine["event_id"]]
    assert repo.last_call("list_events").scope_asset == "linux:lab-vm-01"
    # Without a service filter nothing is scoped (both events are listed).
    everything = client.get("/api/v1/events", headers=viewer).json()
    assert len(everything["items"]) == 2


def test_cluster_service_keeps_its_node_rows(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    ids = _seed_mixed(repo)
    workload = next(r for r in repo.services if r["service_id"] == ids["workload"])
    repo.instances = [instance_row(workload, "pod-1", asset_id=NODE, instance_kind="pod")]
    detail = client.get(f"/api/v1/services/{ids['workload']}", headers=viewer).json()
    assert [i["asset_id"] for i in detail["instances"]] == [NODE]


def test_a_forged_service_row_never_stands_in_for_the_real_one(
    client: TestClient, viewer: dict[str, str], repo: FakeRepository
) -> None:
    """A newer row carrying the ssh service's id but another asset (identity mismatch) is
    ignored by the detail and by the listings (counted as invalid)."""
    real = service_row()
    forged = {
        **service_row(asset_id="macos:workstation-01"),
        "service_id": real["service_id"],
        "last_seen": NOW,
    }
    repo.services = [real, forged]
    detail = client.get(f"/api/v1/services/{real['service_id']}", headers=viewer).json()
    assert detail["service"]["asset_id"] == "linux:lab-vm-01"
    listing = client.get("/api/v1/services", headers=viewer).json()
    assert [i["asset_id"] for i in listing["items"]] == ["linux:lab-vm-01"]
    assert listing["invalid_records"] == 1
    only_forged = FakeRepository()
    assert only_forged.get_service(real["service_id"]) is None
    repo.services = [forged]
    gone = client.get(f"/api/v1/services/{real['service_id']}", headers=viewer)
    assert gone.status_code == 404

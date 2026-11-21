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
    repo.findings = [finding, {**finding, "finding_id": hexid("finding:other")}]
    repo.finding_attribution = {finding["finding_id"]: sid}
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

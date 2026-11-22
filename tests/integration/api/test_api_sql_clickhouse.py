"""The analyst API's SQL and endpoints against a real, throwaway ClickHouse 26.8.

Runs with ``-m integration``. Does NOT use the shared compose stack: it starts its own
container (see api_ch_harness.py), applies the real 0001/0003 migrations, queries with a
readonly=2 identity and writes with an INSERT-only identity, and seeds only SYNTHETIC rows
that are destroyed with the container.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from api_ch_harness import Dataset, EphemeralClickHouse, seed, unavailable_reason
from fastapi.testclient import TestClient

from extorq.api.app import create_app
from extorq.api.integrations import PlatformIntegrations
from extorq.api.repository import (
    AlertFilters,
    ClickHouseRepository,
    ClientProvider,
    EventFilters,
    FindingFilters,
    SeriesQuery,
    ServiceFilters,
)
from extorq.api.settings import ApiSettings

pytestmark = pytest.mark.integration


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
def repo(clickhouse: EphemeralClickHouse, dataset: Dataset) -> ClickHouseRepository:
    reader = clickhouse.client("d1_api_ro")
    writer = clickhouse.client("d1_api_writer")
    return ClickHouseRepository(
        ClientProvider("api_ro", lambda _role: reader),
        ClientProvider("api_writer", lambda _role: writer),
        lifecycle_cache_seconds=0,
    )


@pytest.fixture(scope="module")
def api(
    repo: ClickHouseRepository, tmp_path_factory: pytest.TempPathFactory
) -> tuple[TestClient, dict[str, str]]:
    token = secrets.token_urlsafe(32)
    path: Path = tmp_path_factory.mktemp("d1") / "token"
    path.write_text(token, encoding="utf-8")
    app = create_app(
        settings=ApiSettings(service_token_file=path),
        repository=repo,
        integrations=PlatformIntegrations(),
    )
    headers = {"Authorization": f"Bearer {token}", "X-ExtorQ-User": "alice"}
    return TestClient(app), headers


def _window(ds: Dataset) -> tuple[datetime, datetime]:
    return ds.now - timedelta(days=1), ds.now + timedelta(days=1)


# ── repository semantics ──────────────────────────────────────────────────────────


def test_assets_are_deduplicated_and_latest_version_wins(
    repo: ClickHouseRepository, dataset: Dataset
) -> None:
    rows, total = repo.list_assets("", "", 50, 0)
    assert total == 4  # linux (2 versions), github, k8s cluster, k8s node
    linux = next(r for r in rows if r["asset_id"] == dataset.linux)
    assert linux["criticality"] == "high"
    assert linux["last_seen"].tzinfo is not None
    detail = repo.get_asset(dataset.linux)
    assert detail is not None and '"os_name"' in detail["attributes"]


def test_duplicate_event_delivery_never_double_counts(
    repo: ClickHouseRepository, dataset: Dataset
) -> None:
    since, until = _window(dataset)
    events = repo.list_events(EventFilters(since=since, until=until), 100, 0)
    ids = [e["event_id"] for e in events]
    assert sorted(ids) == sorted(set(ids))
    assert len(ids) == 4
    counts = {
        r["source_type"]: r["events"]
        for r in repo.event_counts_by_source(dataset.linux, since, until)
    }
    assert counts == {"linux.journald": 2}
    series = repo.event_series(SeriesQuery(since=since, until=until, bucket_seconds=86400))
    assert sum(int(p["n"]) for p in series) == 4


def test_event_filters(repo: ClickHouseRepository, dataset: Dataset) -> None:
    since, until = _window(dataset)

    def ids(**kw: Any) -> set[str]:
        rows = repo.list_events(EventFilters(since=since, until=until, **kw), 100, 0)
        return {r["event_id"] for r in rows}

    e = dataset.event_ids
    assert ids(actor="root") == {e["e1"]}
    assert ids(actor="synthetic-user") == {e["e4"]}  # k8s user
    assert ids(actor="synthetic-dev") == {e["e3"]}  # GitHub actor login
    assert ids(src_ip="10.0.2.2") == {e["e1"], e["e2"], e["e4"]}  # incl. k8s source IPs
    assert ids(event_type_prefix="auth.ssh.") == {e["e1"], e["e2"]}
    assert ids(source_type="k8s.audit", outcome="denied") == {e["e4"]}
    assert ids(asset_id=dataset.github) == {e["e3"]}
    assert ids(actor="nobody") == set()


def test_alerts_final_state_join_and_filters(repo: ClickHouseRepository, dataset: Dataset) -> None:
    since, until = _window(dataset)
    base = AlertFilters(since=since, until=until)
    rows = {r["alert_id"]: r for r in repo.list_alerts(base, 50, 0)}
    a1, a2 = dataset.alert_ids["a1"], dataset.alert_ids["a2"]
    assert set(rows) == {a1, a2}
    assert rows[a1]["event_count"] == 7  # latest version (FINAL)
    assert rows[a1]["analyst_status"] == "new"
    assert int(rows[a1]["analyst_state_recorded"]) == 0
    assert rows[a2]["analyst_status"] == "closed_false_positive"  # latest state wins
    assert repo.count_alerts(base) == 2
    open_only = AlertFilters(since=since, until=until, open_only=True)
    assert [r["alert_id"] for r in repo.list_alerts(open_only, 50, 0)] == [a1]
    assert repo.count_alerts(open_only) == 1
    by_status = AlertFilters(since=since, until=until, statuses=("closed_false_positive",))
    assert [r["alert_id"] for r in repo.list_alerts(by_status, 50, 0)] == [a2]
    by_severity = AlertFilters(since=since, until=until, sort="severity")
    assert [r["alert_id"] for r in repo.list_alerts(by_severity, 50, 0)] == [a2, a1]
    assert repo.count_alerts(AlertFilters(since=since, until=until, severities=("low",))) == 0
    sev = {r["severity"]: r["alerts"] for r in repo.open_alert_severity_counts("")}
    assert sev == {"high": 1}
    assert repo.open_alerts_by_asset() == [{"asset_id": dataset.linux, "open_alerts": 1}]


def test_evidence_resolution(repo: ClickHouseRepository, dataset: Dataset) -> None:
    a1 = dataset.alert_ids["a1"]
    refs = repo.evidence_refs(a1, 100)
    assert refs[0]["role"] == "trigger"
    assert refs[0]["event_id"] == dataset.event_ids["e1"]
    alert = repo.get_alert(a1)
    assert alert is not None
    assert repo.evidence_total(a1, alert["evidence_event_ids"]) == 3
    events = repo.events_by_ids([dataset.event_ids["e1"], dataset.event_ids["missing"]])
    assert [e["event_id"] for e in events] == [dataset.event_ids["e1"]]  # duplicate collapsed
    assert repo.alerts_citing_event(dataset.event_ids["e1"], 10) == [a1]
    stored = repo.get_event(dataset.event_ids["e1"])
    assert stored is not None and '"event_id"' in stored["payload"]


def test_rules_runs_and_latest_versions(repo: ClickHouseRepository, dataset: Dataset) -> None:
    latest = repo.rules_latest()
    assert [(r["rule_id"], r["version"]) for r in latest] == [("VM-001", "1.1.0")]
    runs = repo.rule_runs("VM-001", "", 50, 0)
    assert [r["status"] for r in runs] == ["succeeded", "failed"]  # duplicate row collapsed
    assert len(repo.rule_runs("VM-001", "failed", 50, 0)) == 1
    summary = repo.rule_latest_runs()[0]
    assert summary["last_status"] == "succeeded"
    assert int(summary["failures_24h"]) == 1
    assert [v["version"] for v in repo.rule_versions("VM-001")] == ["1.1.0", "1.0.0"]
    counts = repo.alert_counts_by_rule()[0]
    assert (counts["alerts_total"], counts["alerts_open"]) == (2, 1)
    statuses = {
        r["analyst_status"]: r["alerts"] for r in repo.alert_status_counts_for_rule("VM-001")
    }
    assert statuses == {"new": 1, "closed_false_positive": 1}


def test_health_views(repo: ClickHouseRepository, dataset: Dataset) -> None:
    collectors = {c["collector_id"]: c for c in repo.collectors("")}
    assert collectors["synthetic-linux"]["status"] == "ok"  # latest report wins
    assert collectors["synthetic-github"]["last_success_at"] < dataset.now - timedelta(hours=1)
    assert [c["collector_id"] for c in repo.collectors(dataset.github)] == ["synthetic-github"]
    pipeline = {(p["component"], p["instance"]) for p in repo.pipeline_latest()}
    assert pipeline == {("writer", "synthetic-w1"), ("ingest", "synthetic-old")}
    since = dataset.now - timedelta(days=1)
    assert repo.ai_status_counts(since) == [
        {"provider": "google-gemini", "task": "summary", "status": "timeout", "assessments": 1}
    ]
    last = repo.ai_latest()[0]
    assert last["last_status"] == "timeout" and last["last_ok_at"] is None
    assert repo.ingest_quarantine_count(since) == 1
    assert repo.ingest_audit_decisions(since) == [{"decision": "denied", "events": 1}]
    inventory = repo.inventory_summary(dataset.linux)
    assert [(i["item_type"], i["items"]) for i in inventory] == [("package", 1)]


def test_findings_lifecycle_view_and_fallback(
    repo: ClickHouseRepository, dataset: Dataset, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert repo.findings_lifecycle_available() is True
    trivy = FindingFilters(scanner="trivy")
    rows, total, lifecycle = repo.list_findings(trivy, 50, 0)
    assert lifecycle is True and total == 2
    states = {r["finding_id"]: r["state"] for r in rows}
    assert states == {
        dataset.finding_ids["open"]: "open",
        dataset.finding_ids["resolved"]: "resolved",
    }
    open_only, open_total, _ = repo.list_findings(
        FindingFilters(scanner="trivy", states=("open",)), 50, 0
    )
    assert open_total == 1 and open_only[0]["severity"] == "critical"
    counts, lc = repo.finding_severity_counts(dataset.linux)
    assert lc is True
    assert sorted((c["severity"], c["state"], c["findings"]) for c in counts) == [
        ("critical", "open", 1),
        ("low", "open", 2),  # synthetic-posture attribution cases
        ("medium", "resolved", 1),
    ]
    monkeypatch.setattr(repo, "findings_lifecycle_available", lambda: False)
    rows, total, lifecycle = repo.list_findings(FindingFilters(severities=("critical",)), 50, 0)
    assert lifecycle is False and total == 1
    assert rows[0]["first_observed_at"] < rows[0]["last_observed_at"]
    fallback_counts, lc = repo.finding_severity_counts("")
    assert lc is False
    assert sorted((c["severity"], c["findings"]) for c in fallback_counts) == [
        ("critical", 1),
        ("low", 2),
        ("medium", 1),
    ]


def test_alert_series_buckets(repo: ClickHouseRepository, dataset: Dataset) -> None:
    since, until = _window(dataset)
    points = repo.alert_series(
        SeriesQuery(since=since, until=until, bucket_seconds=3600, group_by="severity")
    )
    assert sorted((p["grp"], p["n"]) for p in points) == [("critical", 1), ("high", 1)]
    for point in points:
        assert point["bucket_start"].minute == 0 and point["bucket_start"].second == 0


# ── end-to-end through the FastAPI app ────────────────────────────────────────────


def test_every_read_endpoint_validates_against_real_rows(
    api: tuple[TestClient, dict[str, str]], dataset: Dataset
) -> None:
    client, headers = api
    viewer = {**headers, "X-ExtorQ-Role": "viewer"}
    a1 = dataset.alert_ids["a1"]
    paths = [
        "/api/v1/overview",
        "/api/v1/assets",
        f"/api/v1/assets/{dataset.linux}",
        f"/api/v1/assets/{dataset.github}",
        "/api/v1/findings",
        "/api/v1/rules",
        "/api/v1/rules/VM-001",
        "/api/v1/alerts",
        f"/api/v1/alerts/{a1}",
        f"/api/v1/alerts/{a1}/assessments",
        "/api/v1/events",
        f"/api/v1/events/{dataset.event_ids['e1']}",
        "/api/v1/health",
        "/api/v1/timeseries/alerts?group_by=rule_id",
        "/api/v1/timeseries/events?group_by=source_type",
    ]
    for path in paths:
        response = client.get(path, headers=viewer)
        assert response.status_code == 200, (path, response.text[:500])

    overview = client.get("/api/v1/overview", headers=viewer).json()
    assert overview["open_alerts"]["total"] == 1
    assert overview["open_findings"]["lifecycle_available"] is True
    assert overview["open_findings"]["counts"]["critical"] == 1
    linux_cov = next(c for c in overview["asset_coverage"] if c["asset_type"] == "linux_host")
    assert linux_cov["status"] == "ok"
    github_cov = next(
        c for c in overview["asset_coverage"] if c["asset_type"] == "github_repository"
    )
    assert github_cov["status"] == "stale"

    detail = client.get(f"/api/v1/alerts/{a1}", headers=viewer).json()
    assert [e["event_id"] for e in detail["evidence"]] == [
        dataset.event_ids["e1"],
        dataset.event_ids["e2"],
    ]
    assert detail["unresolved_evidence_ids"] == [dataset.event_ids["missing"]]
    assert detail["evidence_total"] == 3
    assert detail["rule"]["version"] == "1.0.0" or detail["rule"]["version"] == "1.1.0"

    assessments = client.get(f"/api/v1/alerts/{a1}/assessments", headers=viewer).json()
    assert [a["status"] for a in assessments["items"]] == ["timeout"]

    health = client.get("/api/v1/health", headers=viewer).json()
    stale = {c["collector_id"]: c["stale"] for c in health["collectors"]}
    assert stale == {"synthetic-linux": False, "synthetic-github": True}
    assert health["ingest"]["quarantined_records"] == 1

    event = client.get(f"/api/v1/events/{dataset.event_ids['e1']}", headers=viewer).json()
    assert event["event"]["actor"]["name"] == "root"
    assert event["alert_ids"] == [a1]


def test_context_endpoint_reports_missing_correlation_clearly(
    api: tuple[TestClient, dict[str, str]], dataset: Dataset
) -> None:
    client, headers = api
    response = client.get(
        f"/api/v1/alerts/{dataset.alert_ids['a1']}/context",
        headers={**headers, "X-ExtorQ-Role": "viewer"},
    )
    try:
        import extorq.correlation.store  # noqa: F401
    except ImportError:
        assert response.status_code == 503
        assert "extorq.correlation" in response.json()["detail"]
    else:
        assert response.status_code in (200, 404, 500, 503), response.text


def test_state_mutation_round_trip_with_insert_only_identity(
    api: tuple[TestClient, dict[str, str]], dataset: Dataset
) -> None:
    client, headers = api
    a1 = dataset.alert_ids["a1"]
    analyst = {**headers, "X-ExtorQ-Role": "analyst"}
    viewer = {**headers, "X-ExtorQ-Role": "viewer"}
    denied = client.post(
        f"/api/v1/alerts/{a1}/state", headers=viewer, json={"status": "acknowledged"}
    )
    assert denied.status_code == 403
    response = client.post(
        f"/api/v1/alerts/{a1}/state",
        headers=analyst,
        json={"status": "investigating", "assignee": "alice", "note": "synthetic test note"},
    )
    assert response.status_code == 200, response.text
    action_id = response.json()["action_id"]
    detail = client.get(f"/api/v1/alerts/{a1}", headers=viewer).json()
    assert detail["analyst_state"]["status"] == "investigating"
    assert detail["analyst_state"]["recorded"] is True
    assert detail["actions"][0]["action_id"] == action_id
    assert detail["actions"][0]["details"]["status"] == "investigating"
    updated_at = detail["analyst_state"]["updated_at"]
    conflict = client.post(
        f"/api/v1/alerts/{a1}/state",
        headers=analyst,
        json={"status": "acknowledged", "expected_updated_at": "2020-01-01T00:00:00Z"},
    )
    assert conflict.status_code == 409
    ok = client.post(
        f"/api/v1/alerts/{a1}/state",
        headers=analyst,
        json={"status": "acknowledged", "expected_updated_at": updated_at},
    )
    assert ok.status_code == 200, ok.text


# ── service model (0004, schema 1.1) ─────────────────────────────────────────────


def test_services_final_dedup_present_and_filters(
    repo: ClickHouseRepository, dataset: Dataset
) -> None:
    sid = dataset.service_ids
    present = {r["service_id"]: r for r in repo.list_services(ServiceFilters(), 100)}
    assert set(present) == {sid["ssh"], sid["ftp"], sid["workload"], sid["k8s_service"]}
    assert present[sid["ssh"]]["monitoring_status"] == "monitored"  # newest version wins
    assert present[sid["ssh"]]["last_seen"].tzinfo is not None
    assert '"attribution":"confirmed"' in present[sid["ssh"]]["endpoints"]
    everything = repo.list_services(ServiceFilters(include_removed=True), 100)
    assert sid["gone"] in {r["service_id"] for r in everything}
    by_kind = repo.list_services(ServiceFilters(service_kind="k8s_service"), 100)
    assert [r["service_id"] for r in by_kind] == [sid["k8s_service"]]
    planned = repo.list_services(ServiceFilters(adapter_support="planned"), 100)
    assert [r["service_id"] for r in planned] == [sid["ftp"]]
    on_linux = repo.list_services(ServiceFilters(asset_id=dataset.linux), 100)
    assert {r["service_id"] for r in on_linux} == {sid["ssh"], sid["ftp"]}
    assert len(repo.list_services(ServiceFilters(), 1)) == 1  # max_rows bound
    record = repo.get_service(sid["ssh"])
    assert record is not None and '"origin"' in record["attributes"]
    assert repo.get_service("f" * 32) is None


def test_service_instances_latest_and_present_only(
    repo: ClickHouseRepository, dataset: Dataset
) -> None:
    ssh = dataset.service_ids["ssh"]
    rows, total = repo.service_instances(ssh, 50, scope_asset=dataset.linux)
    assert total == 1  # pid:7 is a tombstone; pid:100 has two versions; pid:666 is planted
    assert rows[0]["pid"] == 100 and rows[0]["process_user"] == "root"
    # F-19: the planted instance (GitHub asset naming the VM's ssh service) is in storage,
    # but the scope of the service's asset keeps it out.
    _, unscoped = repo.service_instances(ssh, 50)
    assert unscoped == 2
    assert rows[0]["observed_at"] >= dataset.now - timedelta(seconds=1)
    pods, _ = repo.service_instances(dataset.service_ids["workload"], 50)
    assert pods[0]["asset_id"] == dataset.k8s_node and pods[0]["pod_uid"] == "synthetic-pod-uid"


def test_service_telemetry_auth_and_events_are_duplicate_safe(
    repo: ClickHouseRepository, dataset: Dataset
) -> None:
    since, until = _window(dataset)
    ssh = dataset.service_ids["ssh"]
    sources = repo.service_event_sources(ssh, since, until, scope_asset=dataset.linux)
    assert [(r["source_type"], r["events"]) for r in sources] == [("linux.journald", 2)]
    # F-19: over a window that contains the planted event (3 days old, macOS asset, VM ssh
    # service id) only the scoped aggregates and listings leave it out.
    wide = dataset.now - timedelta(days=4)
    unscoped = repo.service_event_sources(ssh, wide, until)
    assert sorted((r["source_type"], r["events"]) for r in unscoped) == [
        ("linux.journald", 2),
        ("macos.unified_log", 1),
    ]
    scoped = repo.service_event_sources(ssh, wide, until, scope_asset=dataset.linux)
    assert [(r["source_type"], r["events"]) for r in scoped] == [("linux.journald", 2)]
    assert repo.service_auth_summary(ssh, wide, until, scope_asset=dataset.linux)["total"] == 2
    assert repo.service_auth_summary(ssh, wide, until)["total"] == 3
    top_scoped = repo.service_auth_sources(ssh, wide, until, 10, scope_asset=dataset.linux)
    assert [(r["source_ip"], r["events"]) for r in top_scoped] == [("10.0.2.2", 2)]
    listed = repo.list_events(
        EventFilters(since=wide, until=until, service_id=ssh, scope_asset=dataset.linux), 50, 0
    )
    assert dataset.event_ids["planted"] not in {e["event_id"] for e in listed}
    assert len(listed) == 2
    summary = repo.service_auth_summary(ssh, since, until, scope_asset=dataset.linux)
    assert (summary["total"], summary["failure"], summary["success"]) == (2, 2, 0)
    assert (summary["distinct_actors"], summary["distinct_sources"]) == (2, 1)
    top = repo.service_auth_sources(ssh, since, until, 10, scope_asset=dataset.linux)
    assert [(r["source_ip"], r["events"], r["failures"]) for r in top] == [("10.0.2.2", 2, 2)]
    events = repo.list_events(EventFilters(since=since, until=until, service_id=ssh), 50, 0)
    assert sorted(e["event_id"] for e in events) == sorted(
        [dataset.event_ids["e1"], dataset.event_ids["e2"]]
    )
    assert {e["service_name"] for e in events} == {"ssh"}
    nothing = repo.service_event_sources(dataset.service_ids["ftp"], since, until)
    assert nothing == []
    empty = repo.service_auth_summary(dataset.service_ids["ftp"], since, until)
    assert empty["total"] == 0


def _expected_attribution(dataset: Dataset) -> dict[str, str | None]:
    f, sid = dataset.finding_ids, dataset.service_ids
    return {
        f["resolved"]: None,  # never attributed
        f["open"]: None,  # attributed by an OLDER scan only: cleared by the latest
        f["gained"]: sid["ssh"],  # attributed by the latest scan
        f["moved"]: sid["ftp"],  # ssh earlier, ftp latest: latest wins
    }


@pytest.mark.parametrize("lifecycle", [True, False])
def test_finding_service_attribution_follows_the_latest_observation(
    repo: ClickHouseRepository,
    dataset: Dataset,
    monkeypatch: pytest.MonkeyPatch,
    lifecycle: bool,
) -> None:
    """v_findings_current.service_id semantics (C3, migration 0005): the attribution of the
    finding's latest observation, NULL included. The observation fallback agrees."""
    if not lifecycle:
        monkeypatch.setattr(repo, "findings_lifecycle_available", lambda: False)
    rows, total, used = repo.list_findings(FindingFilters(asset_id=dataset.linux), 50, 0)
    assert used is lifecycle and total == 4
    assert {r["finding_id"]: r["service_id"] for r in rows} == _expected_attribution(dataset)
    f, sid = dataset.finding_ids, dataset.service_ids
    for name, want in (("ssh", [f["gained"]]), ("ftp", [f["moved"]]), ("gone", [])):
        got, count, _ = repo.list_findings(FindingFilters(service_id=sid[name]), 50, 0)
        assert [r["finding_id"] for r in got] == want, name
        assert count == len(want), name


def test_alert_service_filter_and_children(repo: ClickHouseRepository, dataset: Dataset) -> None:
    since, until = _window(dataset)
    ssh_alerts = AlertFilters(since=since, until=until, service_id=dataset.service_ids["ssh"])
    rows = repo.list_alerts(ssh_alerts, 50, 0)
    assert [r["alert_id"] for r in rows] == [dataset.alert_ids["a1"]]
    assert rows[0]["service_ids"] == [dataset.service_ids["ssh"]]
    assert repo.count_alerts(ssh_alerts) == 1
    alert = repo.get_alert(dataset.alert_ids["a1"])
    assert alert is not None and alert["service_ids"] == [dataset.service_ids["ssh"]]
    children = repo.asset_children(dataset.k8s)
    assert [(c["asset_id"], c["asset_type"]) for c in children] == [
        (dataset.k8s_node, "kubernetes_node")
    ]


def test_service_endpoints_end_to_end(
    api: tuple[TestClient, dict[str, str]], dataset: Dataset
) -> None:
    client, headers = api
    viewer = {**headers, "X-ExtorQ-Role": "viewer"}
    sid = dataset.service_ids
    listing = client.get("/api/v1/services", headers=viewer)
    assert listing.status_code == 200, listing.text[:500]
    body = listing.json()
    states = {i["service_id"]: i["coverage_state"] for i in body["items"]}
    assert states == {
        sid["ssh"]: "monitored",  # synthetic-linux collector is fresh
        sid["ftp"]: "planned",
        # The workload's source (k8s.container_log) has no collector health report:
        # nothing stale is invented, the record itself is fresh.
        sid["workload"]: "monitored",
        sid["k8s_service"]: "unsupported",
    }
    assert body["summary"]["removed"] == 1
    kinds = {k["service_kind"] for k in body["summary"]["by_kind"]}
    assert kinds == {"host_service", "k8s_workload", "k8s_service"}

    detail = client.get(f"/api/v1/services/{sid['ssh']}", headers=viewer)
    assert detail.status_code == 200, detail.text[:500]
    d = detail.json()
    # F-19 end to end: a window containing the planted event and the planted instance.
    wide = client.get(
        f"/api/v1/services/{sid['ssh']}",
        headers=viewer,
        params={"since": (dataset.now - timedelta(days=4)).isoformat()},
    ).json()
    assert dataset.event_ids["planted"] not in {e["event_id"] for e in wide["recent_events"]}
    assert {i["asset_id"] for i in wide["instances"]} == {dataset.linux}
    assert sum(t["events"] for t in wide["telemetry"]) == 2
    planted_listing = client.get(
        "/api/v1/events",
        headers=viewer,
        params={"service_id": sid["ssh"], "since": (dataset.now - timedelta(days=4)).isoformat()},
    ).json()
    assert dataset.event_ids["planted"] not in {e["event_id"] for e in planted_listing["items"]}
    assert d["service"]["endpoints"][0]["attribution"] == "confirmed"
    assert d["instances_total"] == 1
    assert d["telemetry"][0]["source_type"] == "linux.journald"
    assert d["telemetry"][0]["events"] == 2
    assert d["auth_activity"]["by_outcome"] == {"failure": 2}
    assert [f["finding_id"] for f in d["findings"]] == [dataset.finding_ids["gained"]]
    assert d["findings_total"] == 1
    assert [a["alert_id"] for a in d["alerts"]] == [dataset.alert_ids["a1"]]

    # Finding attribution is identical in every endpoint (latest observation wins).
    expected = _expected_attribution(dataset)

    def attribution(items: list[dict[str, Any]]) -> dict[str, str | None]:
        return {i["finding_id"]: i["service_id"] for i in items}

    findings = client.get("/api/v1/findings", headers=viewer, params={"asset_id": dataset.linux})
    assert attribution(findings.json()["items"]) == expected
    asset = client.get(f"/api/v1/assets/{dataset.linux}", headers=viewer).json()
    assert attribution(asset["findings"]) == expected
    for name, finding in (("ssh", "gained"), ("ftp", "moved")):
        filtered = client.get(
            "/api/v1/findings", headers=viewer, params={"service_id": sid[name]}
        ).json()
        assert [i["finding_id"] for i in filtered["items"]] == [dataset.finding_ids[finding]]
        assert filtered["page"]["total"] == 1
        one = client.get(f"/api/v1/services/{sid[name]}", headers=viewer).json()
        assert attribution(one["findings"]) == {dataset.finding_ids[finding]: sid[name]}

    # One shared coverage function: the asset detail summary equals the services endpoint's.
    for asset_id in (dataset.linux, dataset.k8s, dataset.k8s_node, dataset.github):
        encoded = quote(asset_id, safe="")
        summary = client.get(f"/api/v1/assets/{encoded}", headers=viewer).json()
        listing = client.get(f"/api/v1/assets/{encoded}/services", headers=viewer).json()
        assert summary["services_summary"] == listing["summary"], asset_id

    # The node hosts the cluster workload's Pod (real SQL: instances on an asset + services by
    # id, ancestor and identity checks); the node's own inventory stays empty.
    node = quote(dataset.k8s_node, safe="")
    on_node = client.get(f"/api/v1/assets/{node}/services", headers=viewer).json()
    assert on_node["items"] == []
    assert [h["service"]["service_id"] for h in on_node["hosted"]] == [sid["workload"]]
    assert [i["pod_uid"] for i in on_node["hosted"][0]["instances"]] == ["synthetic-pod-uid"]
    assert on_node["hosted"][0]["instances_on_asset"] == 1

    on_cluster = client.get(f"/api/v1/assets/{dataset.k8s}/services", headers=viewer).json()
    assert {i["service_id"] for i in on_cluster["items"]} == {sid["workload"], sid["k8s_service"]}
    cluster = client.get(f"/api/v1/assets/{dataset.k8s}", headers=viewer).json()
    assert [c["asset_id"] for c in cluster["child_assets"]] == [dataset.k8s_node]
    assert cluster["services_summary"]["coverage"]["total"] == 2
    events = client.get(
        "/api/v1/events",
        headers=viewer,
        params={
            "service_id": sid["ssh"],
            "since": "2020-01-01T00:00:00Z",
            "until": "2020-01-31T00:00:00Z",
        },
    )
    assert events.status_code == 200 and events.json()["items"] == []
    overview = client.get("/api/v1/overview", headers=viewer).json()
    assert overview["service_coverage"]["coverage"]["total"] == 4

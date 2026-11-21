"""Kubernetes inventory / service hierarchy / Events / posture collector.

Fixtures ``tests/fixtures/kubernetes/api/*.json`` are REAL list responses captured
from extorq-lab with the read-only extorq-inventory identity (provenance in the
fixtures README). Tests that need a change (new binding, deletion, failure) derive
it from those real objects and say so. The API is served by httpx.MockTransport;
credentials in the generated kubeconfig are synthetic.
"""

from __future__ import annotations

import base64
import copy
import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from extorq.contracts.catalog import validate_event_semantics
from extorq.contracts.identity import finding_id
from extorq.contracts.ingest import INGEST_RECORD_ADAPTER
from extorq.ingest.otlp_k8s import (
    container_instance_id,
    k8s_service_service_id,
    pod_instance_id,
    workload_service_id,
)
from extorq_collectors.kubernetes.collector import (
    EVENTS_OK_KV,
    KubernetesCollectorError,
    KubernetesInventoryCollector,
)
from extorq_collectors.kubernetes.hierarchy import build_hierarchy, image_product_version
from extorq_collectors.kubernetes.model import (
    KIND_BY_NAME,
    RESOURCE_KINDS,
    DiffContext,
    OwnerIndex,
    object_state,
    resource_change_event,
    top_level_workloads,
)
from extorq_collectors.kubernetes.posture import run_posture_scan
from extorq_collectors.sdk.base import CollectorContext
from extorq_collectors.sdk.config import CollectorConfig
from extorq_collectors.sdk.state import StateStore

API = Path(__file__).resolve().parents[2] / "fixtures" / "kubernetes" / "api"
AUDIT = Path(__file__).resolve().parents[2] / "fixtures" / "kubernetes" / "audit"
NOW = datetime(2026, 11, 21, 15, 0, tzinfo=UTC)
SYNTHETIC_CA = "-----BEGIN CERTIFICATE-----\nU1lOVEhFVElD\n-----END CERTIFICATE-----\n"
LAB_PORTAL_CONTAINER = "9a26595a7720f95398dbb763f3fd4974636295d1eebf0d9890d40b44512680ac"
CM_HASH = "ce9207e8c00c50e59e500e6e0e4b3119"  # kube-controller-manager kubelet config hash


def load(resource: str) -> dict[str, Any]:
    return json.loads((API / f"{resource}.json").read_text())


def real_view() -> dict[str, list[dict[str, Any]]]:
    return {
        rk.kind: [{**i, "kind": rk.kind} for i in load(rk.resource)["items"]]
        for rk in RESOURCE_KINDS
    }


def first_seen(_sid: str, created: datetime | None) -> datetime:
    return created or NOW


class FakeApi:
    """Serves the captured lists; tests mutate ``docs`` / ``status`` per path."""

    def __init__(self) -> None:
        self.docs: dict[str, Any] = {rk.path: load(rk.resource) for rk in RESOURCE_KINDS}
        self.docs["/api/v1/events"] = load("events")
        self.docs["/version"] = load("version")
        self.status: dict[str, int] = {}
        self.methods: set[str] = set()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.methods.add(request.method)
        path = request.url.path
        if path in self.status:
            return httpx.Response(self.status[path], json={"kind": "Status", "reason": "x"})
        if path not in self.docs:
            return httpx.Response(404, json={"kind": "Status", "reason": "NotFound"})
        return httpx.Response(200, json=self.docs[path])


@pytest.fixture
def harness(tmp_path: Path) -> tuple[KubernetesInventoryCollector, CollectorContext, FakeApi, Path]:
    token = tmp_path / "inventory.token"
    token.write_text("synthetic-test-token")
    kubeconfig = tmp_path / "kubeconfig"
    kubeconfig.write_text(
        json.dumps(
            {
                "clusters": [
                    {
                        "name": "c",
                        "cluster": {
                            "server": "https://127.0.0.1:6443",
                            "certificate-authority-data": base64.b64encode(
                                SYNTHETIC_CA.encode()
                            ).decode(),
                        },
                    }
                ],
                "users": [{"name": "u", "user": {"tokenFile": str(token)}}],
                "contexts": [{"name": "x", "context": {"cluster": "c", "user": "u"}}],
                "current-context": "x",
            }
        )
    )
    api = FakeApi()
    collector = KubernetesInventoryCollector(
        transport=httpx.MockTransport(api), kubeconfig_path=kubeconfig
    )
    config = CollectorConfig(
        collector_id="k8s-inventory",
        producer_id="k8s-inventory-extorq-lab",
        asset_id="k8s:extorq-lab",
        module="extorq_collectors.kubernetes.collector:KubernetesInventoryCollector",
        interval_seconds=60,
        settings={},
    )
    db = tmp_path / "state.db"
    ctx = CollectorContext(config, StateStore(db), collector_version="1.0.0")
    return collector, ctx, api, db


def run_cycle(
    collector: KubernetesInventoryCollector, ctx: CollectorContext, db: Path
) -> list[dict[str, Any]]:
    """One cycle; returns ONLY the records it added to the outbox."""
    before = _outbox_ids(db)
    ctx.begin_cycle()
    collector.collect(ctx)
    conn = sqlite3.connect(db)
    rows = conn.execute("SELECT seq, record FROM outbox ORDER BY seq").fetchall()
    conn.close()
    return [json.loads(r) for seq, r in rows if seq not in before]


def _outbox_ids(db: Path) -> set[int]:
    if not db.exists():
        return set()
    conn = sqlite3.connect(db)
    try:
        return {r[0] for r in conn.execute("SELECT seq FROM outbox")}
    except sqlite3.OperationalError:
        return set()
    finally:
        conn.close()


def events_of(records: list[dict[str, Any]], event_type: str | None = None) -> list[dict[str, Any]]:
    return [
        r["data"]
        for r in records
        if r["kind"] == "event" and (event_type is None or r["data"]["event_type"] == event_type)
    ]


# ── collector end to end ──────────────────────────────────────────────


def test_baseline_cycle_emits_valid_catalog_records(harness: Any) -> None:
    collector, ctx, api, db = harness
    records = run_cycle(collector, ctx, db)
    kinds = Counter(r["kind"] for r in records)
    assert kinds["service"] == 14 and kinds["service_instance"] == 24
    assert kinds["scan_run"] == 1 and kinds["finding"] == 20 and kinds["asset"] == 2
    assert kinds["inventory_item"] > 200
    assert api.methods == {"GET"}
    for record in records:
        INGEST_RECORD_ADAPTER.validate_python(record)
        if record["kind"] == "event":
            data = record["data"]
            assert (
                validate_event_semantics(
                    data["event_type"], data["category"], data["source"]["source_type"]
                )
                is None
            )
    created = events_of(records, "k8s.resource.created")
    assert created and all(e["attributes"]["baseline"] is True for e in created)
    assert len(events_of(records, "k8s.event.observed")) == 47
    assert len(events_of(records, "service.discovered")) == 14
    assert ctx.health_details["posture_status"] == "succeeded"


def test_second_cycle_without_changes_emits_only_the_posture_scan(harness: Any) -> None:
    collector, ctx, _api, db = harness
    run_cycle(collector, ctx, db)
    records = run_cycle(collector, ctx, db)
    assert Counter(r["kind"] for r in records) == Counter({"scan_run": 1, "finding": 20})


def test_new_cluster_admin_binding_then_deletion(harness: Any) -> None:
    collector, ctx, api, db = harness
    run_cycle(collector, ctx, db)
    # The real ClusterRoleBinding created during fixture capture (audit responseObject),
    # renamed with a simulation marker for this test.
    crb = json.loads((AUDIT / "rbac_crb_cluster_admin_create.json").read_text())["responseObject"]
    crb = copy.deepcopy(crb)
    crb["metadata"]["name"] = "extorq-sim-abcd1234ef"
    crb["subjects"][0]["name"] = "extorq-sim-abcd1234ef"
    path = KIND_BY_NAME["ClusterRoleBinding"].path
    api.docs[path] = copy.deepcopy(api.docs[path])
    api.docs[path]["items"].append(crb)
    records = run_cycle(collector, ctx, db)
    (created,) = events_of(records, "k8s.resource.created")
    assert created["resource"] == {
        "type": "clusterrolebindings",
        "name": "extorq-sim-abcd1234ef",
        "id": crb["metadata"]["uid"],
        "namespace": None,
        "path": None,
    }
    assert "cluster_admin" in created["attributes"]["risk_flags"]
    assert "baseline" not in created["attributes"]
    assert created["simulation"]["run_id"] == "abcd1234ef"
    assert created["event_time"].startswith("2026-11-21T10:18:31")  # creationTimestamp
    assert (
        json.loads(created["attributes"]["object_summary"])["role_ref"]
        == "ClusterRole/cluster-admin"
    )
    items = [r["data"] for r in records if r["kind"] == "inventory_item"]
    assert [i["item_key"] for i in items] == ["ClusterRoleBinding//extorq-sim-abcd1234ef"]
    findings = [r["data"] for r in records if r["kind"] == "finding"]
    assert any(
        f["check_id"] == "K8S-RBAC-001" and f["resource"]["name"] == "extorq-sim-abcd1234ef"
        for f in findings
    )
    api.docs[path]["items"].pop()
    records = run_cycle(collector, ctx, db)
    (deleted,) = events_of(records, "k8s.resource.deleted")
    assert deleted["resource"]["name"] == "extorq-sim-abcd1234ef"
    tombstones = [r["data"] for r in records if r["kind"] == "inventory_item"]
    assert tombstones[0]["present"] is False


def test_failed_list_is_never_reported_as_deletion(harness: Any) -> None:
    collector, ctx, api, db = harness
    run_cycle(collector, ctx, db)
    api.status[KIND_BY_NAME["ClusterRoleBinding"].path] = 403
    records = run_cycle(collector, ctx, db)
    assert events_of(records, "k8s.resource.deleted") == []
    (scan,) = [r["data"] for r in records if r["kind"] == "scan_run"]
    assert scan["status"] == "partial"
    assert scan["coverage"]["skipped"][0]["check"] == "rbac"
    assert "ClusterRoleBinding" in ctx.health_details["kinds_failed"]
    # Recovery: the binding list comes back unchanged -> still nothing deleted or created.
    del api.status[KIND_BY_NAME["ClusterRoleBinding"].path]
    records = run_cycle(collector, ctx, db)
    assert events_of(records, "k8s.resource.deleted") == []
    assert events_of(records, "k8s.resource.created") == []


def test_expired_token_fails_the_cycle(harness: Any) -> None:
    collector, ctx, api, db = harness
    api.status["/version"] = 401
    with pytest.raises(KubernetesCollectorError, match="401"):
        run_cycle(collector, ctx, db)


def test_events_poll_gap_beyond_ttl_is_reported(harness: Any) -> None:
    collector, ctx, _api, db = harness
    run_cycle(collector, ctx, db)
    ctx.state.set(EVENTS_OK_KV, (datetime.now(UTC) - timedelta(hours=2)).isoformat())
    records = run_cycle(collector, ctx, db)
    (gap,) = events_of(records, "extorq.collector.gap_detected")
    assert gap["source"]["source_type"] == "k8s.events"
    assert gap["attributes"]["gap_reason"] == "poll_gap_exceeds_event_ttl"
    assert gap["attributes"]["gap_seconds"] >= 7000


def test_pod_events_reference_the_workload_service(harness: Any) -> None:
    collector, ctx, _api, db = harness
    records = run_cycle(collector, ctx, db)
    pods = {p["metadata"]["name"]: p["metadata"]["uid"] for p in load("pods")["items"]}
    weak_pod = next(n for n in pods if n.startswith("weak-log-reader-"))
    sid = workload_service_id("extorq-posture-lab", "Deployment", "weak-log-reader")
    observed = events_of(records, "k8s.event.observed")
    weak = [e for e in observed if e["kubernetes"]["pod_name"] == weak_pod]
    assert weak, "the capture holds Events of the current weak-log-reader pod"
    for event in weak:
        assert event["service"]["service_id"] == sid
        assert event["service"]["adapter_id"] == "k8s-events"
        assert event["service"]["instance_id"] == pod_instance_id(sid, pods[weak_pod])
    # Events of pods that no longer exist keep their identity fields but no service.
    gone = [e for e in observed if e["kubernetes"]["pod_name"] == "b2-fixture-barepod"]
    assert gone and all(e["service"] is None for e in gone)
    assert all(e["source"]["source_type"] == "k8s.events" for e in observed)


# ── service hierarchy ─────────────────────────────────────────────────


def hierarchy(view: dict[str, list[dict[str, Any]]] | None = None) -> Any:
    view = view or real_view()
    owners = OwnerIndex.build(view["ReplicaSet"], view["Job"])
    return build_hierarchy(
        view, owners, now=NOW, collector_id="k8s-inventory", first_seen=first_seen
    )


def test_workloads_services_and_instances_use_shared_identities() -> None:
    h = hierarchy()
    sid = workload_service_id("extorq-apps", "Deployment", "lab-portal")
    svc = h.services[sid]
    assert svc.service_kind.value == "k8s_workload"
    assert svc.adapter_id == "webapp-json" and svc.category.value == "web_application"
    assert svc.monitoring_status.value == "monitored" and svc.instance_count == 1
    assert svc.product == "lab-portal" and svc.version is None  # content-hash tag is no version
    container = h.instances[container_instance_id(sid, LAB_PORTAL_CONTAINER)]
    pod = h.instances[pod_instance_id(sid, "f1e96337-4cff-459a-9d1c-8e28b7a747f5")]
    assert container.parent_instance_id == pod.instance_id
    assert container.container_id == LAB_PORTAL_CONTAINER
    assert container.attributes["runtime"] == "containerd"
    assert pod.asset_id == "k8s:extorq-lab/node/extorq-lab-control-plane"


def test_static_pod_instance_is_keyed_by_the_kubelet_config_hash() -> None:
    h = hierarchy()
    name = "kube-controller-manager-extorq-lab-control-plane"
    sid = workload_service_id("kube-system", "Pod", name)
    pod = h.instances[pod_instance_id(sid, CM_HASH)]
    assert pod.instance_key == CM_HASH
    assert pod.pod_uid != CM_HASH  # the mirror pod's API uid is kept separately
    assert pod.attributes["static_pod"] is True
    assert h.services[sid].attributes["static_pod"] is True


def test_kubernetes_service_is_not_a_host_service_and_ports_are_inferred() -> None:
    h = hierarchy()
    svc = h.services[k8s_service_service_id("extorq-apps", "lab-portal")]
    assert svc.service_kind.value == "k8s_service"
    assert svc.adapter_support.value == "none" and svc.monitoring_status.value == "unmonitored"
    assert svc.attributes["backing_workloads"] == ["extorq-apps/Deployment/lab-portal"]
    node_ports = [e for e in svc.endpoints if e.port == 30080]
    assert node_ports and all(e.attribution.value == "inferred" for e in svc.endpoints)
    assert node_ports[0].exposure == "private"


def test_log_agent_readiness_drives_coverage() -> None:
    view = real_view()
    agent = next(p for p in view["Pod"] if p["metadata"]["name"].startswith("extorq-otel-"))
    for cond in agent["status"]["conditions"]:
        if cond["type"] == "Ready":
            cond["status"] = "False"
    h = hierarchy(view)
    lab = h.services[workload_service_id("extorq-apps", "Deployment", "lab-portal")]
    assert lab.monitoring_status.value == "degraded"
    assert "not Ready" in (lab.coverage_note or "")
    own = h.services[workload_service_id("extorq-system", "DaemonSet", "extorq-otel-collector")]
    assert own.monitoring_status.value == "unmonitored"


def test_owner_resolution() -> None:
    view = real_view()
    owners = OwnerIndex.build(view["ReplicaSet"], view["Job"])
    refs = {p["metadata"]["name"]: owners.workload_of(p) for p in view["Pod"]}
    lab = next(v for k, v in refs.items() if k.startswith("lab-portal-"))
    assert lab is not None and (lab.kind, lab.name) == ("Deployment", "lab-portal")
    cm = refs["kube-controller-manager-extorq-lab-control-plane"]
    assert cm is not None and cm.kind == "Pod"
    kindnet = next(v for k, v in refs.items() if k.startswith("kindnet-"))
    assert kindnet is not None and kindnet.kind == "DaemonSet"
    # A ReplicaSet not listed yet: unknown, never guessed.
    empty = OwnerIndex.build([], [])
    pod = next(p for p in view["Pod"] if p["metadata"]["name"].startswith("lab-portal-"))
    assert empty.workload_of(pod) is None
    workloads = top_level_workloads(view)
    assert "extorq-apps/ReplicaSet/" not in " ".join(workloads)  # owned by a Deployment


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        ("registry.k8s.io/kube-apiserver:v1.37.0", ("kube-apiserver", "v1.37.0")),
        ("extorq/lab-portal:2aa9e4797693", ("lab-portal", None)),
        (
            "alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1",
            ("alpine", "3.19"),
        ),
        ("docker.io/kindest/kindnetd:v20260820-69b56db7", ("kindnetd", None)),
        (None, (None, None)),
    ],
)
def test_image_product_version(image: Any, expected: tuple[str | None, str | None]) -> None:
    assert image_product_version(image) == expected


# ── object state and change events ────────────────────────────────────


def test_scheduling_does_not_count_as_a_pod_change() -> None:
    pod = copy.deepcopy(next(p for p in real_view()["Pod"]))
    before = object_state(KIND_BY_NAME["Pod"], pod)
    pod["spec"]["nodeName"] = "another-node"
    pod["status"]["phase"] = "Failed"
    assert object_state(KIND_BY_NAME["Pod"], pod) == before


def test_updated_event_lists_changed_sections_and_added_flags() -> None:
    rk = KIND_BY_NAME["ClusterRoleBinding"]
    crb = json.loads((AUDIT / "rbac_crb_cluster_admin_create.json").read_text())["responseObject"]
    narrow = copy.deepcopy(crb)
    narrow["roleRef"]["name"] = "view"
    before = object_state(rk, narrow)
    after = object_state(rk, crb)
    assert before is not None and after is not None
    event = resource_change_event(
        "updated",
        rk,
        after,
        ctx=DiffContext("k8s-inventory", "1.0.0", NOW, False),
        obj=crb,
        previous=before,
    )
    assert event.attributes["changed_fields"] == ["role_ref"]
    assert event.attributes["risk_flags_added"] == ["cluster_admin"]
    assert event.attributes["time_source"] == "managed_fields"
    assert event.attributes["field_managers"] == ["kubectl-create"]


# ── posture ───────────────────────────────────────────────────────────


def posture(
    view: dict[str, list[dict[str, Any]]],
    failed: dict[str, str] | None = None,
    started: datetime = NOW,
) -> Any:
    owners = OwnerIndex.build(view["ReplicaSet"], view["Job"])
    workloads = dict(top_level_workloads(view))
    for pod in view["Pod"]:
        ref = owners.workload_of(pod)
        if ref is not None and ref.kind == "Pod":
            workloads.setdefault(ref.key, (ref, pod))
    return run_posture_scan(
        view=view,
        failed_kinds=failed or {},
        workloads=workloads,
        collector_id="k8s-inventory",
        collector_version="1.0.0",
        producer_id="k8s-inventory-extorq-lab",
        started_at=started,
        now=started,
    )


def test_posture_findings_on_the_real_cluster() -> None:
    result = posture(real_view())
    by_check = Counter(f.check_id for f in result.findings)
    weak = [f for f in result.findings if f.resource and f.resource.name == "weak-log-reader"]
    assert {f.check_id for f in weak} >= {
        "K8S-POD-003",
        "K8S-POD-005",
        "K8S-POD-008",
        "K8S-POD-009",
        "K8S-POD-010",
        "K8S-POD-011",
    }
    assert all(f.accepted_risk is None for f in weak)  # deliberately weak, not accepted
    otel = [f for f in result.findings if f.resource and f.resource.name == "extorq-otel-collector"]
    assert otel and all(f.accepted_risk is not None for f in otel)
    assert not any(
        f.resource and f.resource.name == "lab-portal" and f.check_id.startswith("K8S-POD")
        for f in result.findings
    )  # restricted-compliant workload: clean
    assert by_check["K8S-RBAC-005"] == 1  # kubeadm anonymous cluster-info binding
    assert result.scan_run.status.value == "succeeded"
    assert result.scan_run.scope.targets[0] == "cluster:extorq-lab"
    assert "namespace:kube-system" not in result.scan_run.scope.targets
    for finding in result.findings:
        assert finding.scan_run_id == result.scan_run.scan_run_id


def test_finding_ids_are_stable_across_scans() -> None:
    first = posture(real_view(), started=NOW)
    second = posture(real_view(), started=NOW + timedelta(minutes=1))
    assert first.scan_run.scan_run_id != second.scan_run.scan_run_id
    assert {f.finding_id for f in first.findings} == {f.finding_id for f in second.findings}
    weak = finding_id(
        "k8s:extorq-lab",
        "extorq-posture-k8s",
        "K8S-POD-005",
        "Deployment/extorq-posture-lab/weak-log-reader",
    )
    assert weak in {f.finding_id for f in first.findings}


def test_accepted_risk_annotation_and_bootstrap_rbac() -> None:
    view = real_view()
    crb = next(
        o for o in view["ClusterRoleBinding"] if o["metadata"]["name"] == "kubeadm:cluster-admins"
    )
    crb["metadata"].setdefault("annotations", {})["extorq.io/accepted-risk"] = "operator group"
    result = posture(view)
    (finding,) = [f for f in result.findings if f.check_id == "K8S-RBAC-001"]
    assert finding.accepted_risk is not None
    assert finding.accepted_risk.source == "annotation:extorq.io/accepted-risk"
    # cluster-admin's own bootstrap binding (rbac-defaults) is never evaluated
    assert not any(f.resource and f.resource.name == "cluster-admin" for f in result.findings)


def test_posture_is_partial_when_inputs_are_missing() -> None:
    result = posture(real_view(), failed={"RoleBinding": "403 Forbidden"})
    assert result.scan_run.status.value == "partial"
    assert not any(f.check_id.startswith("K8S-RBAC") for f in result.findings)
    assert result.scan_run.coverage.checks_run == result.scan_run.coverage.checks_total - 8


def test_derived_field_changes_are_not_reported_as_object_updates(harness: Any) -> None:
    """A parser upgrade that changes summaries/flags refreshes items, never fakes updates."""
    collector, ctx, _api, db = harness
    run_cycle(collector, ctx, db)
    import extorq_collectors.kubernetes.model as model

    original = model.security_summary

    def upgraded(kind: str, obj: Any) -> Any:
        summary = original(kind, obj)
        return {**summary, "parser_upgrade": True} if summary else summary

    model.security_summary = upgraded
    try:
        records = run_cycle(collector, ctx, db)
    finally:
        model.security_summary = original
    assert events_of(records, "k8s.resource.updated") == []
    assert any(r["kind"] == "inventory_item" for r in records)

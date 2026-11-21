"""Service-hierarchy enrichment of OTLP records (contract schema 1.1).

Fixture ``otlp/enriched_sample.json`` is a REAL capture from the extorq-lab
collector with container.id / image extraction enabled (provenance:
tests/fixtures/kubernetes/README.md). It holds lab-portal lines (Deployment), a
kindnet line (DaemonSet), a kube-controller-manager line (static pod), a line from
the short-lived bare pod ``b2-fixture-barepod`` (synthetic text, labelled) and two
audit records.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from extorq.contracts.catalog import validate_event_semantics
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import event_id, instance_id, service_id, sha256_hex, stable_id
from extorq.ingest import otlp_k8s
from extorq.ingest.otlp_k8s import (
    apiserver_service_ref,
    canonical_container_id,
    container_instance_id,
    is_static_pod_uid,
    k8s_service_service_id,
    node_asset_id,
    normalize_otlp_logs,
    normalize_otlp_logs_detailed,
    pod_instance_id,
    valid_k8s_name,
    workload_service_id,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "kubernetes"
RECEIVED = datetime(2026, 11, 21, 15, 0, tzinfo=UTC)
PRODUCER = "k8s-otel-extorq-lab"

LAB_PORTAL_CONTAINER_ID = "9a26595a7720f95398dbb763f3fd4974636295d1eebf0d9890d40b44512680ac"
KINDNET_CONTAINER_ID = "431eef9b05d55616a33d9b1b8b4a05147991a8653952be7a951fd917ecba8e18"
BARE_POD_CONTAINER_ID = "a7382438489a70d894c2a67a832c696050184e969adf9402b4dfea429b46ce57"
CONTROLLER_MANAGER_CONFIG_HASH = "ce9207e8c00c50e59e500e6e0e4b3119"


def enriched() -> dict[str, Any]:
    return json.loads((FIXTURES / "otlp" / "enriched_sample.json").read_text())


@pytest.fixture(scope="module")
def events() -> list[SecurityEvent]:
    evs, failures = normalize_otlp_logs(enriched(), producer_id=PRODUCER, received_at=RECEIVED)
    assert failures == []
    return evs


def by_pod(events: list[SecurityEvent], prefix: str) -> list[SecurityEvent]:
    return [
        e
        for e in events
        if e.kubernetes and e.kubernetes.pod_name and e.kubernetes.pod_name.startswith(prefix)
    ]


def test_every_record_becomes_a_catalog_valid_1_1_event(events: list[SecurityEvent]) -> None:
    detailed = normalize_otlp_logs_detailed(enriched(), producer_id=PRODUCER, received_at=RECEIVED)
    # 30 log records: 29 events + 1 audit record at a stage that is not converted.
    assert len(events) == 29
    assert detailed.skipped == 1 and detailed.failures == []
    assert set(detailed.skipped_reasons) <= {"audit_stage_ResponseStarted"}
    for ev in events:
        assert ev.schema_version == "1.1"
        assert (
            validate_event_semantics(ev.event_type, ev.category.value, ev.source.source_type.value)
            is None
        )
        # Round trip through the wire format the gateway stores.
        SecurityEvent.model_validate_json(ev.model_dump_json())


def test_identity_formulas_are_pinned() -> None:
    # Changing these breaks the join between events and inventory records.
    sid = workload_service_id("extorq-apps", "Deployment", "lab-portal")
    assert sid == stable_id(
        "service.v1", "k8s:extorq-lab", "k8s_workload", "extorq-apps/Deployment/lab-portal"
    )
    assert sid == service_id("k8s:extorq-lab", "k8s_workload", "extorq-apps/Deployment/lab-portal")
    assert k8s_service_service_id("extorq-apps", "lab-portal") == service_id(
        "k8s:extorq-lab", "k8s_service", "extorq-apps/lab-portal"
    )
    # A workload and the Kubernetes Service with the same name are different services.
    assert k8s_service_service_id("extorq-apps", "lab-portal") != sid
    assert container_instance_id(sid, "ab" * 32) == instance_id(sid, "container", "ab" * 32)
    assert pod_instance_id(sid, "uid-1") == instance_id(sid, "pod", "uid-1")


def test_lab_portal_events_reference_the_deployment_and_container(
    events: list[SecurityEvent],
) -> None:
    lab = by_pod(events, "lab-portal-")
    assert {e.event_type for e in lab} == {
        "app.auth.login_failed",
        "app.auth.login_succeeded",
        "app.authz.denied",
        "http.request",
    }
    sid = workload_service_id("extorq-apps", "Deployment", "lab-portal")
    for ev in lab:
        assert ev.kubernetes is not None and ev.service is not None
        assert ev.kubernetes.container_id == LAB_PORTAL_CONTAINER_ID
        assert ev.kubernetes.workload_kind == "Deployment"
        assert ev.kubernetes.workload_name == "lab-portal"
        assert ev.kubernetes.node_name == "extorq-lab-control-plane"
        assert ev.service.service_id == sid
        assert ev.service.name == "extorq-apps/lab-portal"
        assert ev.service.instance_id == container_instance_id(sid, LAB_PORTAL_CONTAINER_ID)
        assert ev.service.adapter_id == "webapp-json"
        assert ev.attributes["container_image"] == "extorq/lab-portal:2aa9e4797693"
        assert "static_pod" not in ev.attributes


def test_lab_portal_failed_logins_keep_their_fields(events: list[SecurityEvent]) -> None:
    failed = [e for e in by_pod(events, "lab-portal-") if e.event_type == "app.auth.login_failed"]
    reasons = sorted(str(e.attributes["reason"]) for e in failed)
    assert reasons == ["invalid_password"] * 3 + ["unknown_user"]
    for ev in failed:
        assert ev.outcome.value == "failure"
        assert ev.http is not None and ev.http.route == "/login" and ev.http.status_code == 401
        assert ev.http.user_agent == "extorq-b2-fixture/1.0"
        assert ev.network is not None and ev.network.src_ip is not None


def test_daemonset_container_log(events: list[SecurityEvent]) -> None:
    kindnet = by_pod(events, "kindnet-")
    assert len(kindnet) == 2
    sid = workload_service_id("kube-system", "DaemonSet", "kindnet")
    for ev in kindnet:
        assert ev.event_type == "k8s.container.log"
        assert ev.kubernetes is not None and ev.service is not None
        assert ev.kubernetes.workload_kind == "DaemonSet"
        assert ev.kubernetes.container_id == KINDNET_CONTAINER_ID
        assert ev.service.service_id == sid
        assert ev.service.instance_id == container_instance_id(sid, KINDNET_CONTAINER_ID)
        assert ev.service.adapter_id == "k8s-container-log"
        assert ev.attributes["container_image"] == "docker.io/kindest/kindnetd:v20260820-69b56db7"


def test_static_pod_is_its_own_workload_and_keyed_by_kubelet_uid(
    events: list[SecurityEvent],
) -> None:
    (ev,) = by_pod(events, "kube-controller-manager-")
    name = "kube-controller-manager-extorq-lab-control-plane"
    sid = workload_service_id("kube-system", "Pod", name)
    assert ev.kubernetes is not None and ev.service is not None
    assert ev.kubernetes.pod_uid == CONTROLLER_MANAGER_CONFIG_HASH
    assert ev.kubernetes.workload_kind == "Pod" and ev.kubernetes.workload_name == name
    # k8s_attributes never associates static pods: no container id, no image.
    assert ev.kubernetes.container_id is None
    assert "container_image" not in ev.attributes
    assert ev.attributes["static_pod"] is True
    assert ev.service.service_id == sid
    assert ev.service.instance_id == pod_instance_id(sid, CONTROLLER_MANAGER_CONFIG_HASH)


def test_bare_api_pod_is_not_attributed_without_evidence(events: list[SecurityEvent]) -> None:
    (ev,) = by_pod(events, "b2-fixture-barepod")
    assert ev.event_type == "k8s.container.log"
    assert ev.message is not None and ev.message.startswith("SYNTHETIC FIXTURE")
    assert ev.kubernetes is not None
    assert ev.kubernetes.container_id == BARE_POD_CONTAINER_ID
    assert ev.kubernetes.workload_kind is None and ev.kubernetes.workload_name is None
    assert ev.service is None
    assert "static_pod" not in ev.attributes


def test_audit_events_reference_the_apiserver_of_the_node(events: list[SecurityEvent]) -> None:
    audit = [e for e in events if e.event_type == "k8s.api.request"]
    assert len(audit) == 11
    expected = workload_service_id("kube-system", "Pod", "kube-apiserver-extorq-lab-control-plane")
    for ev in audit:
        assert ev.service is not None
        assert ev.service.service_id == expected
        assert ev.service.name == "kube-system/kube-apiserver-extorq-lab-control-plane"
        assert ev.service.instance_id is None
        assert ev.service.adapter_id == "k8s-audit"


def test_enrichment_does_not_change_event_ids(events: list[SecurityEvent]) -> None:
    doc = enriched()
    for rl in doc["resourceLogs"]:
        res = {a["key"]: a["value"] for a in rl["resource"]["attributes"]}
        if res["extorq.source"]["stringValue"] != "container":
            continue
        record = rl["scopeLogs"][0]["logRecords"][0]
        attrs = {a["key"]: a["value"]["stringValue"] for a in record["attributes"]}
        body = record["body"]["stringValue"]
        native = ":".join(
            [
                res["k8s.pod.uid"]["stringValue"],
                res["k8s.container.name"]["stringValue"],
                attrs["log.iostream"],
                record["timeUnixNano"],
                sha256_hex(body),
            ]
        )
        expected = event_id("k8s.container_log", "k8s:extorq-lab", native)
        assert expected in {e.event_id for e in events}


def test_missing_or_malformed_container_id_stays_unknown() -> None:
    doc = enriched()
    rl = next(
        r
        for r in doc["resourceLogs"]
        if any(
            a["key"] == "k8s.pod.name" and a["value"]["stringValue"].startswith("kindnet-")
            for a in r["resource"]["attributes"]
        )
    )
    for attr in rl["resource"]["attributes"]:
        if attr["key"] == "container.id":
            attr["value"] = {"stringValue": "not-a-container-id; rm -rf /"}
    evs, failures = normalize_otlp_logs(
        {"resourceLogs": [rl]}, producer_id=PRODUCER, received_at=RECEIVED
    )
    assert failures == [] and len(evs) == 2
    sid = workload_service_id("kube-system", "DaemonSet", "kindnet")
    for ev in evs:
        assert ev.kubernetes is not None and ev.kubernetes.container_id is None
        assert ev.service is not None
        # Falls back to the pod instance (UID from the node log path).
        assert ev.service.instance_id == pod_instance_id(
            sid, "ae3845e4-80c6-4057-a99d-ff680b1a8510"
        )


def test_forged_workload_names_are_not_attributed() -> None:
    doc = enriched()
    rl = next(
        r
        for r in doc["resourceLogs"]
        if any(a["key"] == "k8s.daemonset.name" for a in r["resource"]["attributes"])
    )
    for attr in rl["resource"]["attributes"]:
        if attr["key"] == "k8s.daemonset.name":
            attr["value"] = {"stringValue": "Evil/../Name"}
    evs, failures = normalize_otlp_logs(
        {"resourceLogs": [rl]}, producer_id=PRODUCER, received_at=RECEIVED
    )
    assert failures == [] and evs
    for ev in evs:
        # The reported value is kept as (sanitised) source data, but an invalid
        # Kubernetes name never becomes a service identity.
        assert ev.service is None
        assert ev.kubernetes is not None and ev.kubernetes.workload_name == "Evil/../Name"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (f"containerd://{LAB_PORTAL_CONTAINER_ID}", (LAB_PORTAL_CONTAINER_ID, "containerd")),
        (LAB_PORTAL_CONTAINER_ID, (LAB_PORTAL_CONTAINER_ID, None)),
        (f"cri-o://{'ab' * 32}", ("ab" * 32, "cri-o")),
        (LAB_PORTAL_CONTAINER_ID.upper(), (None, None)),
        ("containerd://", (None, None)),
        ("abc", (None, None)),
        (None, (None, None)),
        (123, (None, None)),
    ],
)
def test_canonical_container_id(value: Any, expected: tuple[str | None, str | None]) -> None:
    assert canonical_container_id(value) == expected


def test_names_and_assets() -> None:
    assert (
        node_asset_id("extorq-lab-control-plane") == "k8s:extorq-lab/node/extorq-lab-control-plane"
    )
    assert node_asset_id("Bad_Node") is None
    assert node_asset_id("") is None
    assert node_asset_id(None) is None
    assert valid_k8s_name("a" * 253) == "a" * 253
    assert valid_k8s_name("a" * 254) is None
    assert valid_k8s_name("-leading") is None
    assert workload_service_id("extorq-apps", "deployment", "x") is None  # kind must be a Kind
    assert workload_service_id("extorq-apps", "Deployment", "x/y") is None
    assert is_static_pod_uid(CONTROLLER_MANAGER_CONFIG_HASH)
    assert not is_static_pod_uid("ae3845e4-80c6-4057-a99d-ff680b1a8510")
    ref = apiserver_service_ref("extorq-lab-control-plane")
    assert ref is not None and ref.name == "kube-system/kube-apiserver-extorq-lab-control-plane"
    assert apiserver_service_ref("../etc") is None


def test_parser_version_bumped() -> None:
    assert otlp_k8s.PARSER_VERSION == "1.1.0"


def test_request_summaries_survive_gateway_secret_redaction() -> None:
    """Summaries are JSON consumed by rules: redaction must not rewrite any of their keys."""
    from extorq.common.redaction import redact_text

    names = [
        "psa_denied_privileged_pod",
        "pod_create_allowed",
        "rbac_crb_cluster_admin_create",
        "rbac_role_wildcard_create",
        "rbac_clusterrole_escalate_create",
        "rbac_rolebinding_anonymous_create",
        "psa_denied_ephemeral_container",
    ]
    for name in names:
        line = (FIXTURES / "audit" / f"{name}.json").read_text().rstrip("\n")
        doc = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [{"key": "extorq.source", "value": {"stringValue": "audit"}}]
                    },
                    "scopeLogs": [{"logRecords": [{"body": {"stringValue": line}}]}],
                }
            ]
        }
        (event,), _ = normalize_otlp_logs(doc, producer_id=PRODUCER, received_at=RECEIVED)
        summary = event.attributes.get("request_summary")
        assert isinstance(summary, str), name
        assert redact_text(summary) == (summary, 0), name
        json.loads(summary)


def test_annotation_only_patch_is_flagged_metadata_only() -> None:
    """REAL record: `kubectl annotate` of the kubeadm:cluster-admins binding (kind.sh)."""
    line = (FIXTURES / "audit" / "rbac_crb_annotate_patch.json").read_text().rstrip("\n")
    doc = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [{"key": "extorq.source", "value": {"stringValue": "audit"}}]
                },
                "scopeLogs": [{"logRecords": [{"body": {"stringValue": line}}]}],
            }
        ]
    }
    (event,), _ = normalize_otlp_logs(doc, producer_id=PRODUCER, received_at=RECEIVED)
    assert event.kubernetes is not None and event.kubernetes.verb == "patch"
    # The resulting object is still risky (flags from the response object) ...
    assert event.attributes["risk_flags"] == ["cluster_admin"]
    # ... but the write itself only touched annotations.
    assert event.attributes["metadata_only_change"] is True
    assert event.attributes["metadata_fields_changed"] == ["annotations"]


def test_content_patches_are_not_metadata_only() -> None:
    def audit_event(name: str) -> SecurityEvent:
        line = (FIXTURES / "audit" / f"{name}.json").read_text().rstrip("\n")
        doc = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [{"key": "extorq.source", "value": {"stringValue": "audit"}}]
                    },
                    "scopeLogs": [{"logRecords": [{"body": {"stringValue": line}}]}],
                }
            ]
        }
        (event,), _ = normalize_otlp_logs(doc, producer_id=PRODUCER, received_at=RECEIVED)
        return event

    # merge patch of subjects, and a create: content changes
    for name in ("rbac_crb_patch_subjects", "rbac_crb_cluster_admin_create"):
        assert "metadata_only_change" not in audit_event(name).attributes, name
    # REAL RFC 6902 patch that only adds a label: metadata-only
    labelled = audit_event("pod_patch_json")
    assert labelled.attributes["metadata_only_change"] is True
    assert labelled.attributes["metadata_fields_changed"] == ["labels"]


def test_metadata_only_request_shapes() -> None:
    from extorq.ingest.otlp_k8s import metadata_only_request

    assert metadata_only_request({"metadata": {"labels": {}, "annotations": {}}}) == [
        "annotations",
        "labels",
    ]
    assert metadata_only_request([{"op": "add", "path": "/metadata/labels/x"}]) == ["labels"]
    assert metadata_only_request([{"op": "add", "path": "/subjects/-"}]) is None
    assert metadata_only_request({"metadata": {}, "subjects": []}) is None
    assert metadata_only_request(None) is None

"""Unit tests for extorq.ingest.otlp_k8s using REAL extorq-lab captures.

Fixtures: tests/fixtures/kubernetes/README.md (provenance of every file).
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from extorq.contracts.catalog import validate_event_semantics
from extorq.contracts.event import SecurityEvent
from extorq.contracts.identity import event_id, sha256_hex
from extorq.ingest import otlp_k8s
from extorq.ingest.otlp_k8s import (
    OtlpPayloadError,
    normalize_otlp_logs,
    normalize_otlp_logs_detailed,
    risk_flags_for_summary,
    summarize_k8s_object,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "kubernetes"
RECEIVED = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
PRODUCER = "k8s-otel-extorq-lab"
SYNTHETIC_ENV_VALUE = "synthetic-not-a-secret-123"


def audit_line(name: str) -> str:
    return (FIXTURES / "audit" / f"{name}.json").read_text().rstrip("\n")


def otlp_doc(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / "otlp" / f"{name}.json").read_text())


def wrap_audit(*lines: str, observed: str = "1795256643769262834") -> dict[str, Any]:
    """OTLP wrapping identical to what the collector's file_log/audit pipeline emits."""
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "extorq.source", "value": {"stringValue": "audit"}},
                        {"key": "k8s.cluster.name", "value": {"stringValue": "extorq-lab"}},
                        {
                            "key": "k8s.node.name",
                            "value": {"stringValue": "extorq-lab-control-plane"},
                        },
                        {
                            "key": "extorq.collector.version",
                            "value": {"stringValue": "otelcol-contrib/0.165.0"},
                        },
                    ]
                },
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "observedTimeUnixNano": observed,
                                "body": {"stringValue": line},
                                "attributes": [
                                    {
                                        "key": "log.file.name",
                                        "value": {"stringValue": "kube-apiserver-audit.log"},
                                    }
                                ],
                            }
                            for line in lines
                        ]
                    }
                ],
            }
        ]
    }


def one_audit_event(name: str) -> SecurityEvent:
    events, failures = normalize_otlp_logs(
        wrap_audit(audit_line(name)), producer_id=PRODUCER, received_at=RECEIVED
    )
    assert failures == []
    assert len(events) == 1, name
    return events[0]


def all_audit_fixture_names() -> list[str]:
    return sorted(p.stem for p in (FIXTURES / "audit").glob("*.json"))


# ── audit: K8S-001 evidence ───────────────────────────────────────────


def test_psa_denied_privileged_pod_maps_every_field() -> None:
    raw_line = audit_line("psa_denied_privileged_pod")
    source = json.loads(raw_line)
    ev = one_audit_event("psa_denied_privileged_pod")

    assert ev.event_type == "k8s.api.request"
    assert ev.category.value == "kubernetes_api"
    assert ev.asset_id == "k8s:extorq-lab"
    assert ev.asset_type.value == "kubernetes_cluster"
    assert ev.source.source_type.value == "k8s.audit"
    assert ev.source.collection_method.value == "otel_filelog"
    assert ev.source.collector_id == PRODUCER
    assert ev.source.collector_version == "otelcol-contrib/0.165.0"
    assert ev.source.source_native_id == source["auditID"]
    assert ev.event_id == event_id(
        "k8s.audit", "k8s:extorq-lab", f"{source['auditID']}:ResponseComplete"
    )
    assert ev.event_time == datetime(2026, 11, 21, 10, 18, 31, 174209, tzinfo=UTC) or (
        ev.event_time.isoformat().startswith("2026-11-21T10:18:")
    )
    assert ev.outcome.value == "denied"
    assert ev.action == "create"

    k = ev.kubernetes
    assert k is not None
    assert k.node_name == "extorq-lab-control-plane"
    assert (k.cluster, k.verb, k.resource, k.subresource) == ("extorq-lab", "create", "pods", None)
    assert (k.namespace, k.object_name) == ("extorq-restricted", "b2-fixture-privileged")
    assert k.api_group == ""  # core group
    assert k.response_code == 403
    assert k.audit_id == source["auditID"]
    assert k.stage == "ResponseComplete"
    assert k.user == "kubernetes-admin"
    assert k.user_groups == ["kubeadm:cluster-admins", "system:authenticated"]
    assert k.source_ips == ["172.18.0.1"]
    assert k.user_agent is not None and k.user_agent.startswith("kubectl/v1.36.1")
    assert ev.network is not None and ev.network.src_ip == "172.18.0.1"
    assert ev.actor is not None and ev.actor.type.value == "user"
    assert ev.actor.authenticated is True
    assert (
        ev.resource is not None and ev.resource.path == "/api/v1/namespaces/extorq-restricted/pods"
    )

    a = ev.attributes
    assert a["denied_by"] == "pod_security"
    assert str(a["pod_security_violation"]).startswith(
        'pods "b2-fixture-privileged" is forbidden: violates PodSecurity "baseline:latest"'
    )
    assert a["pod_security_enforce_policy"] == "baseline:latest"
    assert "restricted:latest" in str(a["pod_security_audit_violations"])
    assert a["authz_decision"] == "allow"
    assert "kubeadm:cluster-admins" in str(a["authz_reason"])
    assert a["risk_flags"] == [
        "added_capabilities",
        "dangerous_capabilities",
        "host_network",
        "host_path",
        "host_path_root",
        "host_pid",
        "privileged",
        "run_as_root",
    ]
    summary = json.loads(str(a["request_summary"]))
    assert summary["kind"] == "Pod"
    assert summary["host_pid"] is True and summary["host_network"] is True
    assert summary["privileged"] == ["shell"]
    assert summary["host_path"] == ["/"]
    assert summary["added_capabilities"] == ["NET_ADMIN", "SYS_ADMIN"]
    assert summary["run_as_root"] == ["shell"]
    assert ev.provenance.raw_sha256 == sha256_hex(raw_line)
    assert ev.provenance.parser == "otlp-k8s-audit"
    assert "simulation" not in ev.model_dump()


def test_request_bodies_never_reach_the_event() -> None:
    ev = one_audit_event("psa_denied_privileged_pod")
    dumped = ev.model_dump_json()
    assert SYNTHETIC_ENV_VALUE not in dumped
    assert "FIXTURE_FAKE_PASSWORD" not in dumped
    assert "last-applied-configuration" not in dumped
    assert "requestObject" not in str(ev.raw).replace('"extorqOmitted":["requestObject"', "")
    raw = json.loads(str(ev.raw))
    assert "requestObject" not in raw
    assert raw["extorqOmitted"][0] == "requestObject"
    # authenticator extras keep their keys only (credential ids are not copied into raw)
    assert raw["user"]["extra"] == ["authentication.kubernetes.io/credential-id"]


def test_dry_run_is_flagged() -> None:
    ev = one_audit_event("psa_denied_dry_run")
    assert ev.attributes["dry_run"] is True
    assert ev.attributes["denied_by"] == "pod_security"
    assert ev.message is not None and ev.message.endswith("(dry-run)")


def test_ephemeral_container_denial_summarised() -> None:
    ev = one_audit_event("psa_denied_ephemeral_container")
    assert ev.kubernetes is not None and ev.kubernetes.subresource == "ephemeralcontainers"
    assert ev.kubernetes.verb == "patch"
    summary = json.loads(str(ev.attributes["request_summary"]))
    assert summary["partial"] is True
    assert summary["privileged"] == ["debugger-xt2tb"]
    assert ev.attributes["risk_flags"] == ["privileged"]
    assert ev.attributes["denied_by"] == "pod_security"


def test_admission_denial_is_not_reported_as_pod_security() -> None:
    """Bootstrap mirror pod 403 (missing PriorityClass) carries hostNetwork but no PSA."""
    ev = one_audit_event("bootstrap_mirror_pod_admission_denied")
    assert ev.kubernetes is not None and ev.kubernetes.response_code == 403
    assert ev.attributes["denied_by"] == "admission"
    assert "pod_security_violation" not in ev.attributes
    assert "host_network" in ev.attributes["risk_flags"]
    assert ev.actor is not None and ev.actor.type.value == "system"


def test_rbac_denials_are_authorization() -> None:
    for name in (
        "bootstrap_rbac_forbidden",
        "forbidden_impersonated_secret_list",
        "anonymous_forbidden_secret_list",
    ):
        ev = one_audit_event(name)
        assert ev.attributes["denied_by"] == "authorization", name
        assert ev.outcome.value == "denied"


# ── audit: K8S-002 evidence ───────────────────────────────────────────


def test_cluster_admin_binding_create() -> None:
    ev = one_audit_event("rbac_crb_cluster_admin_create")
    assert ev.outcome.value == "success"
    assert ev.kubernetes is not None
    assert (ev.kubernetes.resource, ev.kubernetes.verb) == ("clusterrolebindings", "create")
    assert ev.kubernetes.api_group == "rbac.authorization.k8s.io"
    assert ev.kubernetes.object_name == "b2-fixture-crb"
    summary = json.loads(str(ev.attributes["request_summary"]))
    assert summary == {
        "kind": "ClusterRoleBinding",
        "role_ref": "ClusterRole/cluster-admin",
        "subjects": ["ServiceAccount:extorq-apps/b2-fixture-sa"],
    }
    assert ev.attributes["risk_flags"] == ["cluster_admin"]
    assert "responseObject" not in json.loads(str(ev.raw))


def test_rbac_patch_summarises_the_resulting_object() -> None:
    ev = one_audit_event("rbac_crb_patch_subjects")
    summary = json.loads(str(ev.attributes["request_summary"]))
    assert summary["subjects"] == [
        "ServiceAccount:extorq-apps/b2-fixture-sa",
        "Group:system:authenticated",
    ]
    assert ev.attributes["risk_flags"] == ["binds_authenticated", "cluster_admin"]


def test_rbac_delete_has_no_summary() -> None:
    ev = one_audit_event("rbac_crb_delete")
    assert ev.kubernetes is not None and ev.kubernetes.verb == "delete"
    assert "request_summary" not in ev.attributes
    assert "risk_flags" not in ev.attributes


@pytest.mark.parametrize(
    ("name", "flags"),
    [
        (
            "rbac_role_wildcard_create",
            [
                "full_wildcard_rule",
                "pod_exec",
                "secrets_access",
                "wildcard_api_groups",
                "wildcard_resources",
                "wildcard_verbs",
            ],
        ),
        ("rbac_rolebinding_anonymous_create", ["binds_anonymous", "binds_unauthenticated"]),
        ("rbac_clusterrole_escalate_create", ["escalation_verbs", "wildcard_non_resource_urls"]),
    ],
)
def test_rbac_risk_flags(name: str, flags: list[str]) -> None:
    assert one_audit_event(name).attributes["risk_flags"] == flags


def test_aggregated_clusterrole_patch_by_controller() -> None:
    ev = one_audit_event("rbac_clusterrole_aggregation_patch")
    summary = json.loads(str(ev.attributes["request_summary"]))
    assert summary["kind"] == "ClusterRole" and summary["aggregated"] is True
    assert ev.actor is not None and ev.actor.type.value == "service_account"
    assert ev.kubernetes is not None
    assert ev.kubernetes.service_account == "kube-system/clusterrole-aggregation-controller"


# ── audit: other request kinds ────────────────────────────────────────


def test_unauthenticated_401_is_converted_from_response_started() -> None:
    ev = one_audit_event("unauthenticated_401")
    assert ev.kubernetes is not None
    assert ev.kubernetes.stage == "ResponseStarted"
    assert ev.kubernetes.response_code == 401
    assert ev.kubernetes.user is None
    assert ev.actor is not None
    assert ev.actor.type.value == "unknown" and ev.actor.authenticated is False
    assert ev.attributes["denied_by"] == "authentication"
    assert ev.outcome.value == "denied"
    assert ev.message is not None and ev.message.startswith("unauthenticated list namespaces")


@pytest.mark.parametrize("name", ["watch_response_started", "pods_exec_response_started"])
def test_other_response_started_records_are_skipped(name: str) -> None:
    result = normalize_otlp_logs_detailed(
        wrap_audit(audit_line(name)), producer_id=PRODUCER, received_at=RECEIVED
    )
    assert result.events == [] and result.failures == []
    assert result.skipped_reasons == Counter({"audit_stage_ResponseStarted": 1})


def test_exec_response_complete() -> None:
    ev = one_audit_event("pods_exec")
    assert ev.kubernetes is not None
    assert (ev.kubernetes.verb, ev.kubernetes.resource, ev.kubernetes.subresource) == (
        "get",
        "pods",
        "exec",
    )
    assert ev.kubernetes.response_code == 101
    assert ev.outcome.value == "success"


def test_secret_write_is_metadata_only() -> None:
    ev = one_audit_event("secret_create_metadata")
    assert ev.attributes["audit_level"] == "Metadata"
    assert "request_summary" not in ev.attributes
    assert "synthetic-fixture-value" not in ev.model_dump_json()


def test_token_request_keeps_only_the_credential_id() -> None:
    ev = one_audit_event("token_request")
    assert ev.kubernetes is not None and ev.kubernetes.subresource == "token"
    assert str(ev.attributes["issued_credential_id"]).startswith("JTI=")
    assert "eyJ" not in ev.model_dump_json()


def test_impersonation_recorded() -> None:
    ev = one_audit_event("forbidden_impersonated_secret_list")
    assert ev.kubernetes is not None and ev.kubernetes.user == "kubernetes-admin"
    assert ev.attributes["impersonated_user"] == (
        "system:serviceaccount:extorq-system:extorq-inventory"
    )


def test_anonymous_actor() -> None:
    ev = one_audit_event("anonymous_forbidden_secret_list")
    assert ev.actor is not None
    assert ev.actor.name == "system:anonymous"
    assert ev.actor.authenticated is False


def test_every_audit_fixture_is_handled_and_catalog_valid() -> None:
    handled = 0
    for name in all_audit_fixture_names():
        result = normalize_otlp_logs_detailed(
            wrap_audit(audit_line(name)), producer_id=PRODUCER, received_at=RECEIVED
        )
        assert result.failures == [], name
        for ev in result.events:
            handled += 1
            assert (
                validate_event_semantics(
                    ev.event_type, ev.category.value, ev.source.source_type.value
                )
                is None
            )
            assert SecurityEvent.model_validate_json(ev.model_dump_json()) == ev
            assert len(ev.model_dump_json().encode()) < 64 * 1024
    assert handled == len(all_audit_fixture_names()) - 2  # two ResponseStarted skips


def test_event_ids_are_deterministic_and_unique() -> None:
    lines = [audit_line(n) for n in all_audit_fixture_names()]
    first, _ = normalize_otlp_logs(wrap_audit(*lines), producer_id=PRODUCER, received_at=RECEIVED)
    later = datetime(2026, 11, 22, tzinfo=UTC)
    second, _ = normalize_otlp_logs(
        wrap_audit(*lines, observed="1795300000000000000"), producer_id=PRODUCER, received_at=later
    )
    assert [e.event_id for e in first] == [e.event_id for e in second]
    assert len({e.event_id for e in first}) == len(first)


@pytest.mark.parametrize("original", ["b2-fixture-crb", "b2-fixture-sa"])
def test_legacy_marker_text_remains_ordinary_audit_evidence(original: str) -> None:
    marker = "extorq-sim-a1b2c3d4e5f6"
    line = audit_line("rbac_crb_cluster_admin_create").replace(original, marker)
    events, fail = normalize_otlp_logs(wrap_audit(line), producer_id=PRODUCER, received_at=RECEIVED)
    assert fail == []
    (event,) = events
    assert marker in event.model_dump_json()
    assert "simulation" not in event.model_dump()
    assert event.provenance.raw_sha256 == sha256_hex(line)


def test_real_audit_otlp_document() -> None:
    result = normalize_otlp_logs_detailed(
        otlp_doc("audit_sample"), producer_id=PRODUCER, received_at=RECEIVED
    )
    assert result.failures == []
    assert result.skipped == 1
    assert [e.kubernetes.response_code for e in result.events if e.kubernetes] == [
        200,
        403,
        201,
        401,
    ]
    for ev in result.events:
        assert ev.observed_time is not None
        assert ev.observed_time.year == 2026


# ── container logs ────────────────────────────────────────────────────


def test_real_container_document() -> None:
    result = normalize_otlp_logs_detailed(
        otlp_doc("containers_sample"), producer_id=PRODUCER, received_at=RECEIVED
    )
    assert result.failures == [] and result.skipped == 0
    assert len(result.events) == 16
    assert {e.event_type for e in result.events} == {"k8s.container.log"}
    by_container = Counter(e.kubernetes.container_name for e in result.events if e.kubernetes)
    assert by_container["logger"] == 6 and by_container["etcd"] == 2
    for ev in result.events:
        assert (
            validate_event_semantics(ev.event_type, ev.category.value, ev.source.source_type.value)
            is None
        )
        assert ev.source.source_type.value == "k8s.container_log"
        assert ev.kubernetes is not None and ev.kubernetes.cluster == "extorq-lab"
        assert ev.attributes["time_source"] == "cri"
        # This capture predates the collector's node-name fallback: k8s_attributes cannot
        # associate static control-plane pods (log-path UID = static-pod hash).
        static = ev.kubernetes.pod_name in {
            "kube-apiserver-extorq-lab-control-plane",
            "etcd-extorq-lab-control-plane",
            "kube-scheduler-extorq-lab-control-plane",
        }
        assert ev.kubernetes.node_name == (None if static else "extorq-lab-control-plane")


def test_container_event_id_formula() -> None:
    doc = otlp_doc("containers_sample")
    rl = doc["resourceLogs"][0]
    res = {a["key"]: a["value"]["stringValue"] for a in rl["resource"]["attributes"]}
    record = rl["scopeLogs"][0]["logRecords"][0]
    stream = next(
        a["value"]["stringValue"] for a in record["attributes"] if a["key"] == "log.iostream"
    )
    body = record["body"]["stringValue"]
    expected = event_id(
        "k8s.container_log",
        "k8s:extorq-lab",
        f"{res['k8s.pod.uid']}:{res['k8s.container.name']}:{stream}:"
        f"{record['timeUnixNano']}:{sha256_hex(body)}",
    )
    events, _ = normalize_otlp_logs(
        {"resourceLogs": [{"resource": rl["resource"], "scopeLogs": [{"logRecords": [record]}]}]},
        producer_id=PRODUCER,
        received_at=RECEIVED,
    )
    assert events[0].event_id == expected


def _logger_events() -> dict[str, SecurityEvent]:
    events, _ = normalize_otlp_logs(
        otlp_doc("containers_sample"), producer_id=PRODUCER, received_at=RECEIVED
    )
    return {
        (e.message or "")[:40]: e
        for e in events
        if e.kubernetes and e.kubernetes.container_name == "logger"
    }


def test_control_characters_are_stripped() -> None:
    ev = next(e for k, e in _logger_events().items() if "control chars" in k)
    assert ev.message == "SYNTHETIC FIXTURE: control chars red and bell  end"
    assert "\x1b" not in ev.model_dump_json() and "\\u001b" not in ev.model_dump_json()


def test_long_recombined_line_is_bounded() -> None:
    ev = next(e for k, e in _logger_events().items() if "long line" in k)
    assert ev.message is not None and len(ev.message) <= 2048
    assert ev.raw is not None and len(ev.raw) <= 16384
    assert ev.provenance.truncated is True


def test_secrets_in_container_logs_are_redacted() -> None:
    ev = next(e for k, e in _logger_events().items() if "Authorization" in k)
    assert "synthetic.fake.token-value" not in ev.model_dump_json()
    assert "synthetic-pass" not in ev.model_dump_json()
    assert ev.provenance.redaction_count == 2


def test_stream_workload_and_log_levels() -> None:
    events, _ = normalize_otlp_logs(
        otlp_doc("containers_sample"), producer_id=PRODUCER, received_at=RECEIVED
    )
    stderr = [e for e in events if e.attributes.get("stream") == "stderr"]
    assert stderr, "real captures include stderr lines"
    coredns = next(e for e in events if e.kubernetes and e.kubernetes.container_name == "coredns")
    assert coredns.kubernetes is not None
    assert (coredns.kubernetes.workload_kind, coredns.kubernetes.workload_name) == (
        "Deployment",
        "coredns",
    )
    kindnet = next(
        e for e in events if e.kubernetes and e.kubernetes.container_name == "kindnet-cni"
    )
    assert kindnet.kubernetes is not None and kindnet.kubernetes.workload_kind == "DaemonSet"
    levels = {
        (e.kubernetes.container_name, e.attributes.get("log_level")) for e in events if e.kubernetes
    }
    assert ("kube-scheduler", "warning") in levels  # klog W prefix
    assert ("etcd", "warn") in levels  # JSON level
    assert ("local-path-provisioner", "debug") in levels  # logfmt level=


# ── lab-portal (B1 schema lab-portal.log.v1) ──────────────────────────


def _lab_events() -> list[SecurityEvent]:
    events, failures = normalize_otlp_logs(
        otlp_doc("lab_portal_sample"), producer_id=PRODUCER, received_at=RECEIVED
    )
    assert failures == []
    return events


def test_lab_portal_event_types() -> None:
    counts = Counter(e.event_type for e in _lab_events())
    assert counts == Counter(
        {
            "http.request": 11,
            "app.auth.login_failed": 6,
            "app.auth.login_succeeded": 1,
            "app.authz.denied": 1,
            "k8s.container.log": 1,  # stderr startup diagnostics are not events of the app schema
        }
    )
    for ev in _lab_events():
        assert (
            validate_event_semantics(ev.event_type, ev.category.value, ev.source.source_type.value)
            is None
        )


def test_lab_portal_login_failed_mapping() -> None:
    ev = next(e for e in _lab_events() if e.event_type == "app.auth.login_failed")
    assert ev.outcome.value == "failure"
    assert ev.actor is not None and ev.actor.name == "lab-admin"
    assert ev.actor.authenticated is False
    assert ev.network is not None and ev.network.src_ip == "10.244.0.1"  # NodePort SNAT
    assert ev.http is not None
    assert (ev.http.method, ev.http.route, ev.http.status_code) == ("POST", "/login", 401)
    assert ev.http.request_id is None  # generated ids are not correlation keys
    assert len(str(ev.attributes["app_request_id"])) == 32
    assert ev.attributes["reason"] == "invalid_password"
    assert ev.attributes["request_id_source"] == "generated"
    assert ev.kubernetes is not None and ev.kubernetes.workload_name == "lab-portal"
    assert ev.provenance.parser == "otlp-k8s-lab-portal"
    assert ev.event_time.year == 2026 and ev.event_time.microsecond % 1000 == 0


def test_lab_portal_success_and_denied() -> None:
    events = _lab_events()
    ok = next(e for e in events if e.event_type == "app.auth.login_succeeded")
    assert ok.outcome.value == "success" and ok.actor is not None and ok.actor.authenticated
    denied = next(e for e in events if e.event_type == "app.authz.denied")
    assert denied.outcome.value == "denied" and denied.http is not None
    assert denied.http.route == "/admin" and denied.attributes["reason"] == "missing_session"
    not_found = next(e for e in events if e.http and e.http.status_code == 404)
    assert not_found.outcome.value == "failure"
    assert not_found.http is not None and not_found.http.route == "/does-not-exist"
    assert "synthetic-query-secret" not in json.dumps([e.model_dump(mode="json") for e in events])


def test_lab_portal_lines_from_other_workloads_are_not_trusted() -> None:
    doc = copy.deepcopy(otlp_doc("lab_portal_sample"))
    for attr in doc["resourceLogs"][0]["resource"]["attributes"]:
        if attr["key"] == "k8s.namespace.name":
            attr["value"]["stringValue"] = "extorq-posture-lab"
    events, _ = normalize_otlp_logs(doc, producer_id=PRODUCER, received_at=RECEIVED)
    assert {e.event_type for e in events} == {"k8s.container.log"}


def test_lab_portal_rejects_extra_keys() -> None:
    doc = copy.deepcopy(otlp_doc("lab_portal_sample"))
    record = next(
        r
        for r in doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
        if '"auth.login_failed"' in r["body"]["stringValue"]
    )
    data = json.loads(record["body"]["stringValue"])
    data["extra"] = "x"
    record["body"]["stringValue"] = json.dumps(data)
    doc["resourceLogs"][0]["scopeLogs"][0]["logRecords"] = [record]
    events, _ = normalize_otlp_logs(doc, producer_id=PRODUCER, received_at=RECEIVED)
    assert events[0].event_type == "k8s.container.log"


# ── malformed input ───────────────────────────────────────────────────


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "x",
        {"resourceLogs": {}},
        {"resourceLogs": ["x"]},
        {"resourceLogs": [{"scopeLogs": {}}]},
        {"resourceLogs": [{"scopeLogs": [{"logRecords": 1}]}]},
    ],
)
def test_envelope_errors_raise(payload: Any) -> None:
    with pytest.raises(OtlpPayloadError):
        normalize_otlp_logs(payload, producer_id=PRODUCER, received_at=RECEIVED)


def test_empty_payload_is_fine() -> None:
    assert normalize_otlp_logs({}, producer_id=PRODUCER, received_at=RECEIVED) == ([], [])


def test_naive_received_at_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        normalize_otlp_logs({}, producer_id=PRODUCER, received_at=datetime(2026, 11, 21))


def test_per_record_failures_have_indexes_and_no_values() -> None:
    good = audit_line("pods_exec")
    secret_like = "Bearer abcdefghijklmnopqrstuvwxyz0123456789"
    payload = wrap_audit(
        good,
        "{not json " + secret_like,
        json.dumps({"kind": "Pod"}),
        json.dumps({**json.loads(good), "auditID": "../../etc"}),
        good,
    )
    payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"].insert(2, "not-an-object")
    events, failures = normalize_otlp_logs(payload, producer_id=PRODUCER, received_at=RECEIVED)
    assert len(events) == 2  # duplicates are kept here; the pipeline dedups by event_id
    assert events[0].event_id == events[1].event_id
    assert failures == [
        (1, "audit_body_not_json"),
        (2, "log_record_not_object"),
        (3, "audit_unexpected_kind"),
        (4, "audit_missing_or_invalid_audit_id"),
    ]
    assert secret_like not in json.dumps(failures)


def test_unexpected_cluster_and_unknown_source() -> None:
    payload = wrap_audit(audit_line("pods_exec"))
    attrs = payload["resourceLogs"][0]["resource"]["attributes"]
    attrs[1]["value"]["stringValue"] = "motorq-security"
    _, failures = normalize_otlp_logs(payload, producer_id=PRODUCER, received_at=RECEIVED)
    assert failures == [(0, "unexpected_cluster_name")]
    unknown = {
        "resourceLogs": [
            {"resource": {}, "scopeLogs": [{"logRecords": [{"body": {"stringValue": "hello"}}]}]}
        ]
    }
    _, failures = normalize_otlp_logs(unknown, producer_id=PRODUCER, received_at=RECEIVED)
    assert failures == [(0, "unknown_record_source")]


def test_container_without_identity_or_time_fails() -> None:
    doc = otlp_doc("containers_sample")
    rl = copy.deepcopy(doc["resourceLogs"][0])
    rl["resource"]["attributes"] = [{"key": "extorq.source", "value": {"stringValue": "container"}}]
    record = rl["scopeLogs"][0]["logRecords"][0]
    record["attributes"] = []
    rl["scopeLogs"] = [{"logRecords": [record]}]
    _, failures = normalize_otlp_logs(
        {"resourceLogs": [rl]}, producer_id=PRODUCER, received_at=RECEIVED
    )
    assert failures == [(0, "container_missing_pod_identity")]


def test_record_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(otlp_k8s, "MAX_LOG_RECORDS", 2)
    line = audit_line("pods_exec")
    _, failures = normalize_otlp_logs(
        wrap_audit(line, line, line), producer_id=PRODUCER, received_at=RECEIVED
    )
    assert failures == [(2, "too_many_log_records")]


def test_spoofed_forwarded_for_does_not_become_src_ip() -> None:
    event = json.loads(audit_line("pods_exec"))
    event["sourceIPs"] = ["203.0.113.66", "not-an-ip", "172.18.0.1"]  # XFF first, peer last
    events, _ = normalize_otlp_logs(
        wrap_audit(json.dumps(event)), producer_id=PRODUCER, received_at=RECEIVED
    )
    assert events[0].network is not None and events[0].network.src_ip == "172.18.0.1"
    assert events[0].kubernetes is not None
    assert events[0].kubernetes.source_ips == ["203.0.113.66", "172.18.0.1"]


# ── shared object analysis (also used by the inventory collector) ─────


def test_summary_is_bounded_for_huge_roles() -> None:
    role = {
        "kind": "ClusterRole",
        "rules": [
            {
                "verbs": ["get", "list"],
                "apiGroups": [f"group{i}.example.com"],
                "resources": [f"resource-{i}-{j}" for j in range(16)],
            }
            for i in range(40)
        ],
    }
    event = json.loads(audit_line("rbac_role_wildcard_create"))
    event["requestObject"] = role
    event["responseObject"] = role
    events, _ = normalize_otlp_logs(
        wrap_audit(json.dumps(event)), producer_id=PRODUCER, received_at=RECEIVED
    )
    text = str(events[0].attributes["request_summary"])
    assert len(text) <= 2000
    assert json.loads(text)["truncated"] is True
    assert events[0].provenance.truncated is True


def test_json_patch_detects_privileged_container() -> None:
    patch = [
        {
            "op": "add",
            "path": "/spec/containers/0/securityContext",
            "value": {"privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}},
        },
        {"op": "replace", "path": "/spec/hostPID", "value": True},
        {"op": "add", "path": "/spec/volumes/-", "value": {"name": "h", "hostPath": {"path": "/"}}},
    ]
    summary = summarize_k8s_object(patch)
    assert summary is not None
    assert summary["privileged"] == ["containers[0]"]
    assert risk_flags_for_summary(summary) == [
        "added_capabilities",
        "dangerous_capabilities",
        "host_path",
        "host_path_root",
        "host_pid",
        "privileged",
    ]


def test_workload_templates_and_cronjobs() -> None:
    deployment = {
        "kind": "Deployment",
        "spec": {
            "template": {"spec": {"hostNetwork": True, "containers": [{"name": "c", "image": "x"}]}}
        },
    }
    cronjob = {
        "kind": "CronJob",
        "spec": {
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {"containers": [{"name": "c", "securityContext": {"runAsUser": 0}}]}
                    }
                }
            }
        },
    }
    assert risk_flags_for_summary(summarize_k8s_object(deployment)) == ["host_network"]
    assert risk_flags_for_summary(summarize_k8s_object(cronjob)) == ["run_as_root"]
    assert summarize_k8s_object({"kind": "ConfigMap", "data": {"k": "v"}}) is None


def test_binding_subject_flags() -> None:
    binding = {
        "kind": "RoleBinding",
        "roleRef": {"kind": "Role", "name": "r"},
        "subjects": [
            {"kind": "Group", "name": "system:serviceaccounts:extorq-apps"},
            {"kind": "ServiceAccount", "name": "default", "namespace": "extorq-apps"},
        ],
    }
    assert risk_flags_for_summary(summarize_k8s_object(binding)) == [
        "binds_all_service_accounts",
        "binds_default_service_account",
    ]

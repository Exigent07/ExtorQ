"""Event records (row parsing, summaries, key fields) and aggregated features. SYNTHETIC data."""

from __future__ import annotations

from correlation_helpers import K8S, T0, ev

from extorq.contracts.alert import DetectionAlert
from extorq.contracts.context import Relationship, RelationshipBasis, RelationshipType
from extorq.correlation.features import compute_features
from extorq.correlation.records import k8s_kind, record_from_row


def _row(**overrides):
    row = {
        "event_id": "e" * 32,
        "event_time": T0,
        "event_type": "auth.ssh.login_failed",
        "source_type": "linux.journald",
        "asset_id": "linux:lab-vm-01",
        "asset_type": "linux_host",
        "outcome": "failure",
        "actor_name": "admin",
        "src_ip": "203.0.113.45",
        "src_port": 50100,
        "attributes": '{"auth_method":"password","invalid_user":true}',
        "k8s_source_ips": [],
        "svc_id": "a" * 32,
        "svc_name": "ssh",
        "svc_instance_id": None,
        "simulation_run_id": None,
    }
    row.update(overrides)
    return row


def test_record_from_row_parses_and_validates():
    rec = record_from_row(_row())
    assert rec is not None
    assert rec.src_ip == "203.0.113.45" and rec.src_port == 50100
    assert rec.attributes == {"auth_method": "password", "invalid_user": True}
    assert rec.service_id == "a" * 32 and rec.service_name == "ssh"
    summary = rec.to_summary()
    assert summary.service_id == "a" * 32
    assert summary.key_fields["network.src_ip"] == "203.0.113.45"
    assert summary.key_fields["attributes.auth_method"] == "password"
    assert summary.summary == "auth.ssh.login_failed user=admin from 203.0.113.45:50100"


def test_record_from_row_rejects_bad_identity_and_drops_invalid_values():
    assert record_from_row(_row(event_id="not-hex")) is None
    assert record_from_row(_row(event_time=T0.replace(tzinfo=None))) is None
    rec = record_from_row(
        _row(svc_id="bogus", src_ip="999.1.1.1", attributes="{not json", simulation_run_id="BAD!")
    )
    assert rec is not None
    assert rec.service_id is None and rec.src_ip is None
    assert rec.attributes == {} and rec.simulation_run_id is None


def test_summaries_strip_control_characters_and_truncate():
    rec = record_from_row(
        _row(
            event_type="http.request",
            source_type="linux.nginx",
            http_method="GET",
            http_route="/a\x1b[31m‮" + "x" * 500,
            http_status=404,
        )
    )
    assert rec is not None
    text = rec.summary_text()
    assert "\x1b" not in text and "‮" not in text
    assert len(text) < 400


def test_unit_names_and_resource_keys():
    created = ev(
        "persistence.systemd.unit_created",
        resource_path="/etc/systemd/system/evil.service",
        resource_name="evil.service",
    )
    watch = ev("file.audit.watch", resource_path="/etc/systemd/system/evil.service")
    assert created.unit_name() == "evil.service" == watch.unit_name()
    assert ("unit", "evil.service") in created.resource_keys() & watch.resource_keys()
    assert k8s_kind("ClusterRoleBinding") == "clusterrolebindings"
    assert k8s_kind("pods") == "pods"
    audit = ev("k8s.api.request", k8s_resource="clusterrolebindings", k8s_object_name="x")
    state = ev(
        "k8s.resource.created",
        source_type="k8s.api_inventory",
        resource_type="ClusterRoleBinding",
        resource_name="x",
    )
    assert audit.resource_keys() & state.resource_keys()


def test_authenticated_principals_exclude_failed_and_anonymous_names():
    failed = ev("auth.ssh.login_failed", actor_name="root")
    ok = ev("auth.ssh.login_succeeded", actor_name="ubuntu", outcome="success")
    anon = ev("k8s.api.request", k8s_user="system:anonymous")
    assert failed.authenticated_principals() == frozenset()
    assert ok.authenticated_principals() == {"ubuntu"}
    assert anon.principals() == frozenset() and anon.authenticated_principals() == frozenset()


def _alert(**kw):
    data = {
        "alert_id": "f" * 32,
        "rule_id": "VM-001",
        "rule_version": "1.0.0",
        "rule_title": "t",
        "severity": "medium",
        "confidence": "high",
        "asset_id": "linux:lab-vm-01",
        "asset_type": "linux_host",
        "group_key": "g",
        "summary": "s",
        "first_seen": T0,
        "last_seen": T0,
        "window_start": T0,
        "window_end": T0,
        "event_count": 1,
        "evidence_event_ids": ["e" * 32],
        "created_at": T0,
        "updated_at": T0,
        "detector_version": "test",
    }
    data.update(kw)
    return DetectionAlert.model_validate(data)


def _rel(event, rtype=RelationshipType.CANDIDATE):
    return Relationship(
        event_id=event.event_id,
        relationship_type=rtype,
        bases=[RelationshipBasis.SHARED_SOURCE_IP],
        strength="moderate",
        time_delta_seconds=0.0,
        explanation="x",
    )


def test_ssh_features_success_after_failures_and_sudo():
    ip = "203.0.113.45"
    evidence = [
        ev("auth.ssh.login_failed", i, src_ip=ip, src_port=50000 + i, actor_name=u)
        for i, u in enumerate(["admin", "oracle", "admin"])
    ]
    success = ev("auth.ssh.login_succeeded", 60, src_ip=ip, actor_name="ubuntu", outcome="success")
    sudo = ev("auth.sudo.command", 90, actor_name="ubuntu", outcome="success")
    unrelated_success = ev(
        "auth.ssh.login_succeeded", 60, src_ip="198.51.100.1", actor_name="x", outcome="success"
    )
    related = [success, sudo, unrelated_success]
    f = compute_features(_alert(), evidence, related, [_rel(e) for e in related])
    assert f["ssh_distinct_usernames"] == 2
    assert f["ssh_distinct_connections"] == 3
    assert f["ssh_success_after_failures"] is True
    assert f["ssh_success_users"] == ["ubuntu"]
    assert f["sudo_after_login"] is True
    assert f["related_candidate"] == 3 and f["causation_established"] is False


def test_http_and_kubernetes_features():
    probes = [
        ev(
            "http.request",
            i,
            source_type="linux.nginx",
            src_ip="10.0.2.2",
            http_status=404,
            http_route=route,
        )
        for i, route in enumerate(["/.env", "/wp-login.php", "/index.html", "/.git/config"])
    ]
    error = ev("http.request", 9, source_type="linux.nginx", http_status=502, http_route="/api")
    f = compute_features(_alert(), probes, [error], [])
    assert f["http_4xx_count"] == 4 and f["http_5xx_count"] == 1
    assert f["http_probe_routes"] == ["/.env", "/.git/config", "/wp-login.php"]

    psa = ev(
        "k8s.api.request",
        asset_id=K8S,
        k8s_response_code=403,
        k8s_user="kubernetes-admin",
        attributes={"pod_security_violation": "privileged"},
    )
    other_403 = ev("k8s.api.request", 5, asset_id=K8S, k8s_response_code=403, k8s_user="bob")
    crb = ev(
        "k8s.api.request",
        9,
        asset_id=K8S,
        k8s_response_code=201,
        attributes={"risk_flags": ["cluster_admin"]},
    )
    f = compute_features(
        _alert(asset_id=K8S, asset_type="kubernetes_cluster"), [psa], [other_403, crb], []
    )
    assert f["k8s_psa_denials"] == 1
    assert f["k8s_forbidden_requests"] == 1
    assert f["k8s_cluster_admin_grants"] == 1
    assert f["k8s_actors"] == ["bob", "kubernetes-admin"]


def test_features_are_deterministic_and_bounded():
    events = [
        ev("http.request", i, source_type="linux.nginx", http_status=404, http_route=f"/.env{i}")
        for i in range(40)
    ]
    a = compute_features(_alert(), events, [], [])
    b = compute_features(_alert(), list(reversed(events)), [], [])
    assert a == b
    assert len(a["http_probe_routes"]) == 10
    assert len(a) <= 64

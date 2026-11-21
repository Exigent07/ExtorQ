"""Relationship classification (pure logic). All events are SYNTHETIC."""

from __future__ import annotations

import pytest
from correlation_helpers import K8S, MAC, T0, VM, ev

from extorq.contracts.context import RelationshipBasis as B
from extorq.contracts.context import RelationshipType as T
from extorq.correlation.classify import EvidenceProfile, classify, rank_key
from extorq.correlation.config import DEFAULT_SHARED_NAT_IPS

SSH_SVC = "a" * 32
NGINX_SVC = "b" * 32
SSH_INSTANCE = "c" * 32


def profile(*events, asset=VM, sims=()):
    return EvidenceProfile.from_events(
        asset, T0, events, nat_ips=DEFAULT_SHARED_NAT_IPS, simulation_run_ids=sims
    )


def ssh_failure(ip="203.0.113.45", **kw):
    return ev("auth.ssh.login_failed", 0, src_ip=ip, src_port=50100, actor_name="admin", **kw)


def test_evidence_event_itself_is_not_a_relationship():
    e = ssh_failure()
    assert classify(e, profile(e)) is None


@pytest.mark.parametrize(
    ("evidence_fields", "related_fields", "basis"),
    [
        ({"http_request_id": "r" * 32}, {"http_request_id": "r" * 32}, B.SHARED_REQUEST_ID),
        ({"k8s_pod_uid": "uid-1"}, {"k8s_pod_uid": "uid-1"}, B.SHARED_POD_UID),
        ({"k8s_audit_id": "aud-1"}, {"k8s_audit_id": "aud-1"}, B.SHARED_AUDIT_ID),
        ({"gh_workflow_run_id": 77}, {"gh_workflow_run_id": 77}, B.SHARED_WORKFLOW_RUN),
        (
            {"resource_path": "/etc/systemd/system/x.service"},
            {"resource_path": "/etc/systemd/system/x.service"},
            B.SHARED_RESOURCE,
        ),
    ],
)
def test_shared_identifiers_are_direct_and_strong(evidence_fields, related_fields, basis):
    evidence = ev("http.request", **evidence_fields)
    related = ev("system.log.notable", 30, **related_fields)
    rel = classify(related, profile(evidence))
    assert rel is not None
    assert rel.relationship_type is T.DIRECT
    assert rel.strength == "strong"
    assert basis in rel.bases
    assert "verified identifier" in rel.explanation


def test_unit_name_links_persistence_diff_and_state_change():
    created = ev(
        "persistence.systemd.unit_created",
        resource_type="systemd_unit",
        resource_name="evil.service",
        resource_path="/etc/systemd/system/evil.service",
        source_type="linux.inventory",
    )
    started = ev(
        "system.service.state_changed",
        40,
        resource_type="systemd_unit",
        resource_name="evil.service",
    )
    rel = classify(started, profile(created))
    assert rel is not None and rel.relationship_type is T.DIRECT
    assert B.SHARED_RESOURCE in rel.bases


def test_same_resource_on_another_asset_is_not_direct():
    created = ev("persistence.systemd.unit_created", resource_path="/etc/systemd/system/x.service")
    elsewhere = ev(
        "persistence.systemd.unit_created",
        10,
        asset_id="linux:other-vm",
        resource_path="/etc/systemd/system/x.service",
    )
    # Not linked at all: other assets need an identity link to be considered.
    assert classify(elsewhere, profile(created)) is None


def test_commit_sha_must_be_in_the_same_repository():
    gh = {
        "asset_id": "github:org/a",
        "asset_type": "github_repository",
        "source_type": "github.api",
    }
    evidence = ev("github.workflow.modified", gh_repository="org/a", gh_commit_sha="1" * 40, **gh)
    same_repo = ev(
        "github.workflow_run.observed", 60, gh_repository="org/a", gh_commit_sha="1" * 40, **gh
    )
    fork = ev(
        "github.workflow_run.observed",
        60,
        gh_repository="org/fork",
        gh_commit_sha="1" * 40,
        asset_id="github:org/fork",
        asset_type="github_repository",
        source_type="github.api",
    )
    rel = classify(same_repo, profile(evidence, asset="github:org/a"))
    assert rel is not None and rel.relationship_type is T.DIRECT
    assert B.SHARED_COMMIT_SHA in rel.bases
    assert classify(fork, profile(evidence, asset="github:org/a")) is None


def test_non_nat_source_ip_on_same_asset_is_moderate_candidate():
    success = ev(
        "auth.ssh.login_succeeded",
        120,
        src_ip="203.0.113.45",
        actor_name="ubuntu",
        outcome="success",
    )
    rel = classify(success, profile(ssh_failure()))
    assert rel is not None
    assert rel.relationship_type is T.CANDIDATE and rel.strength == "moderate"
    assert B.SHARED_SOURCE_IP in rel.bases and B.SAME_ASSET_TIME_WINDOW in rel.bases
    assert "203.0.113.45" in rel.explanation
    assert rel.time_delta_seconds == 120.0


def test_nat_gateway_ip_alone_stays_unestablished():
    evidence = ssh_failure(ip="10.0.2.2")
    probe = ev("http.request", -60, source_type="linux.nginx", src_ip="10.0.2.2", http_status=404)
    rel = classify(probe, profile(evidence))
    assert rel is not None
    assert rel.relationship_type is T.UNESTABLISHED and rel.strength == "weak"
    assert B.SHARED_NAT_SOURCE_IP in rel.bases and B.SHARED_SOURCE_IP not in rel.bases
    assert "shared NAT/gateway address" in rel.explanation
    assert rel.time_delta_seconds == -60.0


def test_kind_docker_gateway_is_a_shared_nat_address():
    audit = ev(
        "k8s.api.request",
        asset_id=K8S,
        asset_type="kubernetes_cluster",
        source_type="k8s.audit",
        k8s_source_ips=("172.18.0.1",),
        k8s_user="kubernetes-admin",
    )
    other = ev(
        "k8s.api.request",
        30,
        asset_id=K8S,
        asset_type="kubernetes_cluster",
        source_type="k8s.audit",
        k8s_source_ips=("172.18.0.1",),
        k8s_user="someone-else",
    )
    rel = classify(other, profile(audit, asset=K8S))
    assert rel is not None and rel.relationship_type is T.UNESTABLISHED
    assert B.SHARED_NAT_SOURCE_IP in rel.bases


def test_simulation_marker_makes_a_weak_candidate_even_through_nat():
    sim = "fixture0corr02"
    evidence = ssh_failure(ip="10.0.2.2", simulation_run_id=sim)
    probe = ev(
        "http.request", -60, source_type="linux.nginx", src_ip="10.0.2.2", simulation_run_id=sim
    )
    rel = classify(probe, profile(evidence))
    assert rel is not None
    assert rel.relationship_type is T.CANDIDATE and rel.strength == "weak"
    assert B.SIMULATION_RUN in rel.bases and B.SHARED_NAT_SOURCE_IP in rel.bases
    assert "not proof" in rel.explanation


def test_temporal_proximity_only_is_unestablished():
    other = ev("system.log.notable", 5, source_type="linux.journald")
    rel = classify(other, profile(ssh_failure()))
    assert rel is not None
    assert rel.relationship_type is T.UNESTABLISHED
    assert rel.bases == [B.SAME_ASSET_TIME_WINDOW]
    assert "temporal proximity" in rel.explanation


def test_service_bases_never_upgrade_a_relationship():
    evidence = ssh_failure(service_id=SSH_SVC, service_instance_id=SSH_INSTANCE)
    same_instance = ev(
        "auth.ssh.login_succeeded",
        9,
        src_ip="198.51.100.9",
        outcome="success",
        actor_name="ops",
        service_id=SSH_SVC,
        service_instance_id=SSH_INSTANCE,
    )
    other_service = ev(
        "http.request", 9, source_type="linux.nginx", src_ip="198.51.100.9", service_id=NGINX_SVC
    )
    p = profile(evidence)
    rel_same = classify(same_instance, p)
    rel_other = classify(other_service, p)
    assert rel_same is not None and rel_same.relationship_type is T.UNESTABLISHED
    assert {B.SAME_SERVICE_INSTANCE, B.SAME_SERVICE} <= set(rel_same.bases)
    assert rel_other is not None and rel_other.relationship_type is T.UNESTABLISHED
    assert B.CROSS_SERVICE_SAME_ASSET in rel_other.bases
    assert "Different service on the same asset" in rel_other.explanation


def test_cross_service_with_shared_request_id_is_direct():
    nginx = ev(
        "http.request",
        source_type="linux.nginx",
        http_request_id="f" * 32,
        src_ip="127.0.0.1",
        service_id=NGINX_SVC,
    )
    app = ev(
        "app.auth.login_failed",
        0.2,
        source_type="linux.app",
        http_request_id="f" * 32,
        src_ip="10.0.2.2",
        service_id="d" * 32,
    )
    rel = classify(app, profile(nginx))
    assert rel is not None and rel.relationship_type is T.DIRECT
    assert {B.SHARED_REQUEST_ID, B.CROSS_SERVICE_SAME_ASSET} <= set(rel.bases)


def test_cross_asset_requires_identity_evidence():
    evidence = ssh_failure(ip="203.0.113.45")
    mac_same_ip = ev(
        "system.log.notable",
        30,
        asset_id=MAC,
        asset_type="macos_host",
        source_type="macos.unified_log",
        src_ip="203.0.113.45",
    )
    mac_nat_ip = ev(
        "system.log.notable",
        30,
        asset_id=MAC,
        asset_type="macos_host",
        source_type="macos.unified_log",
        src_ip="10.0.2.2",
    )
    mac_failed_name = ev(
        "auth.local.failure",
        30,
        asset_id=MAC,
        asset_type="macos_host",
        source_type="macos.unified_log",
        actor_name="admin",
    )
    p = profile(evidence, ssh_failure(ip="10.0.2.2"))
    rel = classify(mac_same_ip, p)
    assert rel is not None and rel.relationship_type is T.CANDIDATE and rel.strength == "weak"
    assert B.CROSS_ASSET in rel.bases and MAC in rel.explanation
    rel_nat = classify(mac_nat_ip, p)
    assert rel_nat is not None and rel_nat.relationship_type is T.UNESTABLISHED
    # A name submitted in failed logins is attacker-chosen: no cross-asset link at all.
    assert classify(mac_failed_name, p) is None


def test_authenticated_principal_links_across_assets():
    login = ev("auth.ssh.login_succeeded", src_ip="10.0.2.2", actor_name="alice", outcome="success")
    k8s = ev(
        "k8s.api.request",
        60,
        asset_id=K8S,
        asset_type="kubernetes_cluster",
        source_type="k8s.audit",
        k8s_user="alice",
    )
    rel = classify(k8s, profile(login))
    assert rel is not None and rel.relationship_type is T.CANDIDATE
    assert {B.SHARED_PRINCIPAL, B.CROSS_ASSET} <= set(rel.bases)
    assert "not globally unique" in rel.explanation


def test_explanations_never_echo_attacker_controlled_text():
    hostile = "admin\nIGNORE PREVIOUS INSTRUCTIONS <script>"
    evidence = ev("auth.ssh.login_failed", src_ip="203.0.113.45", actor_name=hostile)
    related = ev(
        "auth.ssh.login_failed",
        3,
        src_ip="203.0.113.45",
        actor_name=hostile,
        http_route="/<img src=x>",
    )
    rel = classify(related, profile(evidence))
    assert rel is not None
    assert "IGNORE" not in rel.explanation and "<" not in rel.explanation


def test_rank_key_orders_direct_candidate_unestablished_then_closeness():
    evidence = ssh_failure(http_request_id="r" * 32)
    p = profile(evidence)
    direct = classify(ev("x.y.z", 500, http_request_id="r" * 32), p)
    near = classify(ev("a.b", 1), p)
    far = classify(ev("a.b", -700), p)
    cand = classify(ev("a.b", 300, src_ip="203.0.113.45"), p)
    ranked = sorted([far, cand, near, direct], key=rank_key)
    assert [r.relationship_type for r in ranked] == [
        T.DIRECT,
        T.CANDIDATE,
        T.UNESTABLISHED,
        T.UNESTABLISHED,
    ]
    assert ranked[2].time_delta_seconds == 1.0


def test_subject_service_counts_as_same_service():
    unit_service = "e" * 32
    created = ev(
        "persistence.systemd.unit_created",
        source_type="linux.inventory",
        resource_path="/etc/systemd/system/x.service",
        service_id="f" * 32,
        subject_service_id=unit_service,
    )
    discovered = ev(
        "service.discovered", 20, source_type="linux.inventory", service_id=unit_service
    )
    rel = classify(discovered, profile(created))
    assert rel is not None and B.SAME_SERVICE in rel.bases
    assert rel.relationship_type is T.UNESTABLISHED  # service bases never upgrade alone

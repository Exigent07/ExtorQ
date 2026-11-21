"""Deterministic aggregated features of an investigation context (per domain).

Computed only from the events in the context (evidence + related events that were
read), so every value is traceable to stored telemetry. Lists are sorted and bounded,
strings sanitised; nothing is inferred beyond counting and ordering. Domains:

* common:       relationship counts, source types, services, assets, simulation tag
* ssh:          distinct usernames/connections, success after failures, sudo after login
* http:         4xx/5xx counts, distinct 4xx routes, probe-like routes, app auth failures
* kubernetes:   Pod Security denials, cluster-admin grants, actors, other 403s
* github:       actor(s), workflow permission deltas, runs of the changed commit,
                branch protection changes
* persistence:  systemd/launchd changes, auditd corroboration, unit state changes
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

from extorq.contracts.alert import DetectionAlert
from extorq.contracts.context import Relationship, RelationshipType
from extorq.correlation.records import EventRecord
from extorq.detection._compat import sanitize
from extorq.detection.alerts import coerce_attributes

#: Paths typically requested by scanners and exploit probes (case-insensitive, RE2-safe).
PROBE_ROUTE_RE = re.compile(
    r"(\.env|\.git|\.svn|\.aws|\.ssh|\.ht(?:access|passwd)|wp-|wordpress|phpmyadmin|xmlrpc|cgi-bin|"
    r"server-status|actuator|/admin|/manager|/console|/shell|/backup|/config|/debug|"
    r"/vendor/|/etc/passwd|\.\./|\.php|\.asp|\.jsp|/solr|/jenkins|/boaform|/hnap1|"
    r"/owa|/remote/|/api/v1/pods|/druid|/telescope)",
    re.IGNORECASE,
)
SSH_FAILURE_TYPES = frozenset(
    {
        "auth.ssh.login_failed",
        "auth.ssh.invalid_user",
        "auth.ssh.preauth_closed",
        "auth.ssh.max_auth_exceeded",
    }
)
MAX_LIST = 10


def _sorted_bounded(values: Iterable[Any], limit: int = MAX_LIST, chars: int = 128) -> list[str]:
    cleaned = {sanitize(str(v), chars) for v in values if v not in (None, "")}
    return sorted(c for c in cleaned if c)[:limit]


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [
            str(v) for v in value if isinstance(v, str | int | float) and not isinstance(v, bool)
        ]
    return []


def _common(
    evidence: Sequence[EventRecord],
    related: Sequence[EventRecord],
    relationships: Sequence[Relationship],
    alert: DetectionAlert,
) -> dict[str, Any]:
    counts = {t: 0 for t in RelationshipType}
    for rel in relationships:
        counts[rel.relationship_type] += 1
    events = [*evidence, *related]
    evidence_services = {e.service_id for e in evidence if e.service_id}
    related_services = {e.service_id for e in related if e.service_id} - evidence_services
    other_assets = {e.asset_id for e in related if e.asset_id != alert.asset_id}
    return {
        "evidence_events_in_context": len(evidence),
        "related_events": len(relationships),
        "related_direct": counts[RelationshipType.DIRECT],
        "related_candidate": counts[RelationshipType.CANDIDATE],
        "related_unestablished": counts[RelationshipType.UNESTABLISHED],
        "source_types": _sorted_bounded((e.source_type for e in events), 16, 64),
        "evidence_services": len(evidence_services),
        "related_services": len(related_services),
        "cross_service_activity": bool(related_services),
        "related_assets": len(other_assets),
        "simulation_tagged": bool(alert.simulation_run_ids)
        or any(e.simulation_run_id for e in evidence),
        "causation_established": False,
    }


def _ssh(evidence: Sequence[EventRecord], events: Sequence[EventRecord]) -> dict[str, Any]:
    failures = [e for e in evidence if e.event_type in SSH_FAILURE_TYPES]
    if not failures:
        return {}
    first_failure = min(e.event_time for e in failures)
    failure_ips = {e.src_ip for e in failures if e.src_ip}
    successes = [
        e
        for e in events
        if e.event_type == "auth.ssh.login_succeeded"
        and e.src_ip in failure_ips
        and e.event_time >= first_failure
    ]
    success_users = {e.actor_name for e in successes if e.actor_name}
    first_success = min((e.event_time for e in successes), default=None)
    sudo_after = [
        e
        for e in events
        if e.event_type == "auth.sudo.command"
        and first_success is not None
        and e.event_time >= first_success
        and e.actor_name in success_users
    ]
    return {
        "ssh_failure_events": len(failures),
        "ssh_distinct_usernames": len({e.actor_name for e in failures if e.actor_name}),
        "ssh_distinct_connections": len(
            {(e.src_ip, e.src_port) for e in failures if e.src_ip and e.src_port is not None}
        ),
        "ssh_success_after_failures": bool(successes),
        "ssh_success_users": _sorted_bounded(success_users, 8, 64),
        "sudo_after_login": bool(sudo_after),
    }


def _http(events: Sequence[EventRecord]) -> dict[str, Any]:
    http = [e for e in events if e.event_type in ("http.request", "http.server.error")]
    app = [e for e in events if e.event_type.startswith("app.")]
    if not http and not app:
        return {}
    client_errors = [e for e in http if e.http_status is not None and 400 <= e.http_status < 500]
    routes_4xx = {e.http_route for e in client_errors if e.http_route}
    return {
        "http_events": len(http),
        "http_4xx_count": len(client_errors),
        "http_5xx_count": sum(
            1 for e in http if e.http_status is not None and 500 <= e.http_status < 600
        ),
        "http_distinct_routes_4xx": len(routes_4xx),
        "http_probe_routes": _sorted_bounded(
            (r for r in routes_4xx if PROBE_ROUTE_RE.search(r)), MAX_LIST, 128
        ),
        "http_distinct_user_agents": len({e.http_user_agent for e in http if e.http_user_agent}),
        "app_login_failures": sum(1 for e in app if e.event_type == "app.auth.login_failed"),
        "app_authz_denials": sum(1 for e in app if e.event_type == "app.authz.denied"),
    }


def _kubernetes(events: Sequence[EventRecord]) -> dict[str, Any]:
    audit = [e for e in events if e.event_type == "k8s.api.request"]
    state = [e for e in events if e.event_type.startswith("k8s.resource.")]
    if not audit and not state:
        return {}
    psa_ids = {e.event_id for e in audit if e.attributes.get("pod_security_violation")}
    admin = [
        e for e in [*audit, *state] if "cluster_admin" in _str_list(e.attributes.get("risk_flags"))
    ]
    return {
        "k8s_psa_denials": len(psa_ids),
        "k8s_cluster_admin_grants": len(admin),
        "k8s_forbidden_requests": sum(
            1 for e in audit if e.k8s_response_code == 403 and e.event_id not in psa_ids
        ),
        "k8s_actors": _sorted_bounded((e.k8s_user for e in audit), 8, 128),
        "k8s_namespaces": _sorted_bounded((e.k8s_namespace for e in audit), 8, 64),
    }


def _github(evidence: Sequence[EventRecord], events: Sequence[EventRecord]) -> dict[str, Any]:
    gh = [e for e in events if e.event_type.startswith("github.")]
    if not gh:
        return {}
    modified = [e for e in gh if e.event_type == "github.workflow.modified"]
    shas = {e.gh_commit_sha for e in evidence if e.gh_commit_sha}
    scopes: set[str] = set()
    for e in modified:
        scopes.update(_str_list(e.attributes.get("added_write_scopes")))
    return {
        "gh_actors": _sorted_bounded((e.gh_actor_login or e.actor_name for e in evidence), 4, 64),
        "gh_added_write_scopes": _sorted_bounded(scopes, 16, 64),
        "gh_write_all_added": any(e.attributes.get("write_all_added") is True for e in modified),
        "gh_workflow_runs_for_commit": len(
            {
                e.gh_workflow_run_id
                for e in gh
                if e.event_type == "github.workflow_run.observed"
                and e.gh_commit_sha in shas
                and e.gh_workflow_run_id is not None
            }
        ),
        "gh_branch_protection_changes": sum(
            1 for e in gh if e.event_type == "github.branch_protection.changed"
        ),
        "gh_settings_changes": sum(1 for e in gh if e.event_type == "github.repo.settings_changed"),
    }


def _persistence(evidence: Sequence[EventRecord], events: Sequence[EventRecord]) -> dict[str, Any]:
    changes = [e for e in events if e.event_type.startswith("persistence.")]
    if not changes:
        return {}
    units = {u for e in evidence if (u := e.unit_name())}
    paths = {e.resource_path for e in changes if e.resource_path}
    audit = [e for e in events if e.event_type == "file.audit.watch" and e.resource_path in paths]
    return {
        "persistence_changes": len(changes),
        "persistence_units": _sorted_bounded(units, 8, 128),
        "auditd_corroborated": bool(audit),
        "auditd_writers": _sorted_bounded((e.process_executable for e in audit), 4, 128),
        "unit_state_changes": sum(
            1
            for e in events
            if e.event_type == "system.service.state_changed" and e.resource_name in units
        ),
        "package_changes": sum(1 for e in events if e.event_type.startswith("package.")),
    }


def compute_features(
    alert: DetectionAlert,
    evidence: Sequence[EventRecord],
    related: Sequence[EventRecord],
    relationships: Sequence[Relationship],
) -> dict[str, Any]:
    """All feature groups merged into one bounded Attributes mapping."""
    events = [*evidence, *related]
    features: dict[str, Any] = {}
    features.update(_common(evidence, related, relationships, alert))
    features.update(_ssh(evidence, events))
    features.update(_http(events))
    features.update(_kubernetes(events))
    features.update(_github(evidence, events))
    features.update(_persistence(evidence, events))
    return coerce_attributes(features)

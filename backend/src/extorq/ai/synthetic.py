"""Builders for clearly labelled SYNTHETIC InvestigationContexts.

Used ONLY by the Jev evaluation dataset (``eval/jev/``) and unit tests. Every
context built here is synthetic by construction and says so:

* ``builder_version`` is :data:`SYNTHETIC_BUILDER_VERSION`;
* ``limitations`` starts with :data:`SYNTHETIC_NOTICE`;
* timestamps are fixed (2026-11-20 UTC), identities are deterministic, IPs come
  from documentation ranges (RFC 5737) or the lab's private ranges, and actor
  names are invented.

Event shapes follow the event catalog (``extorq.contracts.catalog``) key fields
so the provider sees the same structure real contexts will have. Nothing here
is collected telemetry, and it must never be written to ClickHouse.

Service model (contract 1.1): for Linux-host cases the involved services are
derived deterministically from the events (sshd for ``auth.ssh.*``, nginx for
``linux.nginx``, the lab web app for ``app.auth*``, systemd for
``persistence.systemd.*``), with ``monitoring_status`` derived from the case's
source coverage (failed/stale/gap -> degraded). Cases can also list services
and related assets explicitly.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from extorq.contracts.alert import (
    DedupStrategy,
    DetectionAlert,
    EvidenceConfidence,
    RuleDedup,
    RuleMetadata,
    RuleSchedule,
    TelemetryRequirement,
)
from extorq.contracts.catalog import SourceType
from extorq.contracts.common import (
    AssetType,
    Criticality,
    Environment,
    HealthStatus,
    Outcome,
    Severity,
)
from extorq.contracts.context import (
    AssetSummary,
    EventSummary,
    FindingSummary,
    InvestigationContext,
    Relationship,
    RelationshipBasis,
    RelationshipType,
    ServiceSummary,
    SourceCoverage,
    TimelineEntry,
)
from extorq.contracts.identity import alert_id as make_alert_id
from extorq.contracts.identity import context_id as make_context_id
from extorq.contracts.identity import event_id as make_event_id
from extorq.contracts.identity import input_hash, sha256_hex
from extorq.contracts.identity import service_id as make_service_id
from extorq.contracts.service import AdapterSupport, MonitoringStatus, ServiceCategory, ServiceKind

SYNTHETIC_BUILDER_VERSION = "synthetic-eval-v1"
SYNTHETIC_NOTICE = (
    "SYNTHETIC evaluation data: modelled on ExtorQ event-catalog shapes; not collected telemetry."
)
BASE_TIME = datetime(2026, 11, 20, 10, 0, 0, tzinfo=UTC)

Rel = RelationshipType
B = RelationshipBasis


def _rule(
    rule_id: str,
    title: str,
    description: str,
    severity: Severity,
    asset_types: list[AssetType],
    requires: list[tuple[SourceType, list[str], bool]],
    group_by: list[str],
    mitre: list[str],
    false_positives: list[str],
    blind_spots: list[str],
) -> RuleMetadata:
    return RuleMetadata(
        rule_id=rule_id,
        version="1.0.0",
        title=title,
        description=description,
        severity=severity,
        mitre_techniques=mitre,
        asset_types=asset_types,
        requires=[
            TelemetryRequirement(source_type=s, event_types=types, optional=opt)
            for s, types, opt in requires
        ],
        schedule=RuleSchedule(interval_seconds=60, lookback_seconds=900),
        dedup=RuleDedup(strategy=DedupStrategy.EVENT),
        group_by=group_by,
        false_positives=false_positives,
        blind_spots=blind_spots,
        query_sha256=sha256_hex(f"synthetic-rule:{rule_id}"),
    )


#: Synthetic copies of the five mandatory rules' metadata (evaluation only).
RULES: dict[str, RuleMetadata] = {
    "VM-001": _rule(
        "VM-001",
        "Repeated failed SSH authentication",
        "Five or more failed SSH authentication connections from one source to one host "
        "within five minutes.",
        Severity.MEDIUM,
        [AssetType.LINUX_HOST],
        [
            (
                SourceType.LINUX_JOURNALD,
                [
                    "auth.ssh.login_failed",
                    "auth.ssh.invalid_user",
                    "auth.ssh.preauth_closed",
                    "auth.ssh.max_auth_exceeded",
                ],
                False,
            )
        ],
        ["asset_id", "src_ip"],
        ["T1110"],
        [
            "An SSH client offering several keys before the right one.",
            "Monitoring probes that open and close TCP connections to port 22.",
        ],
        ["Attempts spread across many source addresses below the threshold."],
    ),
    "VM-002": _rule(
        "VM-002",
        "Systemd persistence outside the allow-list",
        "A systemd unit was created, modified or enabled in a persistence location and is not "
        "in the allow-list.",
        Severity.HIGH,
        [AssetType.LINUX_HOST],
        [
            (
                SourceType.LINUX_INVENTORY,
                [
                    "persistence.systemd.unit_created",
                    "persistence.systemd.unit_modified",
                    "persistence.systemd.unit_enabled",
                ],
                False,
            ),
            (SourceType.LINUX_AUDITD, ["file.audit.watch"], True),
        ],
        ["asset_id", "unit_path", "sha256"],
        ["T1543.002"],
        ["Package installs and upgrades that ship or update vendor units."],
        ["Units written and removed between two inventory snapshots."],
    ),
    "K8S-001": _rule(
        "K8S-001",
        "Privileged pod creation denied",
        "A pod creation requesting privileged or host access was denied by the API server.",
        Severity.MEDIUM,
        [AssetType.KUBERNETES_CLUSTER],
        [(SourceType.K8S_AUDIT, ["k8s.api.request"], False)],
        ["audit_id"],
        ["T1611"],
        ["Infrastructure DaemonSets rolled out to a namespace with the restricted profile."],
        ["Requests rejected before reaching the audit stage."],
    ),
    "K8S-002": _rule(
        "K8S-002",
        "Risky RBAC change",
        "A role or binding was created or changed with a risky role reference, subject or rule.",
        Severity.HIGH,
        [AssetType.KUBERNETES_CLUSTER],
        [
            (SourceType.K8S_AUDIT, ["k8s.api.request"], False),
            (SourceType.K8S_API_INVENTORY, ["k8s.resource.created", "k8s.resource.updated"], True),
        ],
        ["cluster", "object", "risk_signature"],
        ["T1098"],
        ["Cluster bootstrap and Helm installs of controllers that need cluster-scoped roles."],
        ["Changes made through aggregated roles."],
    ),
    "GH-001": _rule(
        "GH-001",
        "Workflow permissions escalated",
        "A commit changed a GitHub Actions workflow to add write-all, a sensitive write scope "
        "or a dangerous trigger.",
        Severity.HIGH,
        [AssetType.GITHUB_REPOSITORY],
        [(SourceType.GITHUB_API, ["github.workflow.modified"], False)],
        ["repository", "commit_sha", "workflow_path"],
        ["T1195.002"],
        ["Release or labeler workflows that legitimately need a write scope."],
        ["Changes in reusable workflows referenced from other repositories."],
    ),
}

GH_ASSET = AssetSummary(
    asset_id="github:example-org/extorq-lab",
    asset_type=AssetType.GITHUB_REPOSITORY,
    name="example-org/extorq-lab",
    criticality=Criticality.HIGH,
    environment=Environment.LAB,
)
VM_ASSET = AssetSummary(
    asset_id="linux:lab-vm-01",
    asset_type=AssetType.LINUX_HOST,
    name="lab-vm-01",
    criticality=Criticality.MEDIUM,
    environment=Environment.LAB,
)
K8S_ASSET = AssetSummary(
    asset_id="k8s:extorq-lab",
    asset_type=AssetType.KUBERNETES_CLUSTER,
    name="extorq-lab",
    criticality=Criticality.HIGH,
    environment=Environment.LAB,
)


@dataclass
class Ev:
    """One synthetic event (evidence or related)."""

    key: str
    t: float
    event_type: str
    source_type: SourceType
    outcome: Outcome
    summary: str
    actor: str | None = None
    src_ip: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    evidence: bool = False
    rel: RelationshipType | None = None
    bases: tuple[RelationshipBasis, ...] = ()
    strength: Literal["strong", "moderate", "weak"] = "moderate"
    explanation: str = ""


@dataclass
class CaseSpec:
    case_id: str
    domain: str
    label: str
    description: str
    rule_id: str
    asset: AssetSummary
    confidence: EvidenceConfidence
    group_key: str
    entities: dict[str, str]
    alert_summary: str
    events: list[Ev]
    alert_features: dict[str, Any] = field(default_factory=dict)
    context_features: dict[str, Any] = field(default_factory=dict)
    coverage: list[SourceCoverage] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    findings: list[FindingSummary] = field(default_factory=list)
    event_count: int | None = None
    evidence_truncated: bool = False
    #: Explicit services; None derives them from the events (Linux hosts only).
    services: list[ServiceSummary] | None = None
    related_assets: list[AssetSummary] = field(default_factory=list)


@dataclass(frozen=True)
class SvcDef:
    """A synthetic service definition (natural key + classification)."""

    key: str
    name: str
    kind: ServiceKind
    category: ServiceCategory
    adapter_support: AdapterSupport = AdapterSupport.IMPLEMENTED


#: Synthetic model of the lab VM's discovered services (B1 discovery shapes).
LINUX_SERVICES: dict[str, SvcDef] = {
    "ssh": SvcDef("ssh.service", "sshd", ServiceKind.HOST_SERVICE, ServiceCategory.SSH),
    "nginx": SvcDef(
        "nginx.service", "nginx", ServiceKind.HOST_SERVICE, ServiceCategory.HTTP_SERVER
    ),
    "lab-portal": SvcDef(
        "lab-portal.service",
        "lab-portal",
        ServiceKind.APPLICATION,
        ServiceCategory.WEB_APPLICATION,
    ),
    "systemd": SvcDef(
        "systemd", "systemd", ServiceKind.HOST_SERVICE, ServiceCategory.SERVICE_MANAGER
    ),
}


def _linux_service_key(ev: Ev) -> str | None:
    if ev.event_type.startswith("auth.ssh."):
        return "ssh"
    if ev.source_type is SourceType.LINUX_NGINX:
        return "nginx"
    if ev.event_type.startswith(("app.auth.", "app.authz.")):
        return "lab-portal"
    if ev.event_type.startswith("persistence.systemd."):
        return "systemd"
    return None


def _monitoring_status(source: SourceType, coverage: list[SourceCoverage]) -> MonitoringStatus:
    for c in coverage:
        if c.source_type == source.value:
            problem = c.stale or c.gap_during_window or c.status is not HealthStatus.OK
            return MonitoringStatus.DEGRADED if problem else MonitoringStatus.MONITORED
    return MonitoringStatus.MONITORED


def service_summary(
    asset_id: str,
    definition: SvcDef,
    *,
    role: Literal["evidence", "related"],
    monitoring_status: MonitoringStatus = MonitoringStatus.MONITORED,
) -> ServiceSummary:
    return ServiceSummary(
        service_id=make_service_id(asset_id, definition.kind.value, definition.key),
        asset_id=asset_id,
        name=definition.name,
        service_kind=definition.kind.value,
        category=definition.category.value,
        adapter_support=definition.adapter_support.value,
        monitoring_status=monitoring_status.value,
        role=role,
    )


def _derive_services(spec: CaseSpec) -> tuple[list[ServiceSummary], dict[str, ServiceSummary]]:
    """Services for the case and the event-key -> service mapping."""
    if spec.services is not None:
        return list(spec.services), {}
    if spec.asset.asset_type is not AssetType.LINUX_HOST:
        return [], {}
    by_service: dict[str, list[Ev]] = {}
    for ev in spec.events:
        key = _linux_service_key(ev)
        if key is not None:
            by_service.setdefault(key, []).append(ev)
    services: list[ServiceSummary] = []
    by_event: dict[str, ServiceSummary] = {}
    for key, events in sorted(by_service.items()):
        status = _monitoring_status(events[0].source_type, spec.coverage)
        role: Literal["evidence", "related"] = (
            "evidence" if any(ev.evidence for ev in events) else "related"
        )
        summary = service_summary(
            spec.asset.asset_id, LINUX_SERVICES[key], role=role, monitoring_status=status
        )
        services.append(summary)
        for ev in events:
            by_event[ev.key] = summary
    return services, by_event


def cov(
    source: SourceType,
    *,
    status: HealthStatus = HealthStatus.OK,
    stale: bool = False,
    gap: bool = False,
    lag: float | None = 20.0,
    note: str | None = None,
) -> SourceCoverage:
    return SourceCoverage(
        source_type=source.value,
        collector_id=None,
        status=status,
        last_success_at=None
        if status is HealthStatus.FAILED
        else BASE_TIME + timedelta(minutes=10),
        lag_seconds=lag,
        stale=stale,
        gap_during_window=gap,
        note=note,
    )


def fake_sha(case_id: str, key: str, length: int = 40) -> str:
    return hashlib.sha256(f"synthetic:{case_id}:{key}".encode()).hexdigest()[:length]


def make_context(spec: CaseSpec) -> InvestigationContext:
    """Assemble a contract-valid InvestigationContext from a synthetic case spec."""
    rule = RULES[spec.rule_id]
    ids: dict[str, str] = {}
    for ev in spec.events:
        ids[ev.key] = make_event_id(
            ev.source_type.value, spec.asset.asset_id, f"synthetic:{spec.case_id}:{ev.key}"
        )
    evidence = [ev for ev in spec.events if ev.evidence]
    if not evidence:
        raise ValueError(f"{spec.case_id}: at least one evidence event is required")
    times = {ev.key: BASE_TIME + timedelta(seconds=ev.t) for ev in spec.events}
    first_seen = min(times[ev.key] for ev in evidence)
    last_seen = max(times[ev.key] for ev in evidence)
    bucket = first_seen.replace(second=0, microsecond=0)
    alert_id = make_alert_id(spec.rule_id, spec.group_key, bucket)
    services, service_of = _derive_services(spec)
    alert = DetectionAlert(
        alert_id=alert_id,
        rule_id=spec.rule_id,
        rule_version=rule.version,
        rule_title=rule.title,
        severity=rule.severity,
        confidence=spec.confidence,
        asset_id=spec.asset.asset_id,
        asset_type=spec.asset.asset_type,
        group_key=spec.group_key,
        entities=spec.entities,
        service_ids=[s.service_id for s in services if s.role == "evidence"],
        summary=spec.alert_summary,
        first_seen=first_seen,
        last_seen=last_seen,
        window_start=first_seen - timedelta(minutes=5),
        window_end=last_seen + timedelta(minutes=5),
        event_count=spec.event_count if spec.event_count is not None else len(evidence),
        evidence_event_ids=[ids[ev.key] for ev in evidence],
        evidence_truncated=spec.evidence_truncated,
        features=spec.alert_features,
        mitre_techniques=rule.mitre_techniques,
        created_at=last_seen + timedelta(minutes=1),
        updated_at=last_seen + timedelta(minutes=1),
        detector_version=SYNTHETIC_BUILDER_VERSION,
    )
    evidence_summaries = [
        EventSummary(
            event_id=ids[ev.key],
            event_time=times[ev.key],
            event_type=ev.event_type,
            source_type=ev.source_type.value,
            asset_id=spec.asset.asset_id,
            outcome=ev.outcome,
            actor_name=ev.actor,
            src_ip=ev.src_ip,
            service_id=service_of[ev.key].service_id if ev.key in service_of else None,
            service_name=service_of[ev.key].name if ev.key in service_of else None,
            summary=ev.summary,
            key_fields=ev.fields,
        )
        for ev in sorted(evidence, key=lambda e: e.t)
    ]
    timeline = [
        TimelineEntry(
            event_id=ids[ev.key],
            time=times[ev.key],
            event_type=ev.event_type,
            source_type=ev.source_type.value,
            summary=ev.summary,
            is_evidence=ev.evidence,
            relationship_type=None if ev.evidence else ev.rel,
        )
        for ev in sorted(spec.events, key=lambda e: e.t)
        if ev.evidence or ev.rel is not None
    ]
    relationships = [
        Relationship(
            event_id=ids[ev.key],
            relationship_type=ev.rel,
            bases=list(ev.bases) or [B.SAME_ASSET_TIME_WINDOW],
            strength=ev.strength,
            time_delta_seconds=(times[ev.key] - first_seen).total_seconds(),
            explanation=ev.explanation or "related by " + ", ".join(b.value for b in ev.bases),
        )
        for ev in sorted(spec.events, key=lambda e: e.t)
        if not ev.evidence and ev.rel is not None
    ]
    body: dict[str, Any] = {
        "alert_id": alert_id,
        "builder_version": SYNTHETIC_BUILDER_VERSION,
        "window_start": alert.window_start,
        "window_end": alert.window_end,
        "alert": alert,
        "rule": rule,
        "asset": spec.asset,
        "services": services,
        "related_assets": spec.related_assets,
        "evidence": evidence_summaries,
        "timeline": timeline,
        "relationships": relationships,
        "features": spec.context_features,
        "findings": spec.findings,
        "coverage": spec.coverage,
        "missing_telemetry": spec.missing,
        "limitations": [SYNTHETIC_NOTICE, *spec.limitations],
        "simulation_run_ids": [],
        "truncated": {"evidence": spec.evidence_truncated},
    }
    digest = input_hash(body)
    return InvestigationContext(
        context_id=make_context_id(alert_id, digest),
        created_at=last_seen + timedelta(minutes=2),
        input_hash=digest,
        **body,
    )


def is_synthetic(ctx: InvestigationContext) -> bool:
    return ctx.builder_version == SYNTHETIC_BUILDER_VERSION and SYNTHETIC_NOTICE in ctx.limitations

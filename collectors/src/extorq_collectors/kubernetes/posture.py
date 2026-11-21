"""Kubernetes posture scan ``extorq-posture-k8s`` (owner: B2).

Each collector cycle evaluates the listed objects and emits one :class:`ScanRun`
plus one :class:`PostureFinding` observation per failed check. Lifecycle (open /
resolved) is derived server-side from scan history: a finding resolves only when a
later SUCCEEDED scan with the same scope hash no longer reports it, so a scan whose
inputs could not be listed completely is reported as PARTIAL (never resolving).

Checks evaluate the declared state (pod templates of top-level workloads, bare and
static pods, RBAC objects, namespaces, Services). They do not observe runtime
behaviour. Finding ids are stable: ``finding_id(asset, scanner, check, resource_key)``.
``accepted_risk`` comes from the ``extorq.io/accepted-risk`` annotation on the object
(or on the pod template); the finding stays visible, marked accepted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.contracts.common import Severity
from extorq.contracts.event import Resource
from extorq.contracts.finding import AcceptedRisk, FindingCategory, PostureFinding
from extorq.contracts.identity import finding_id, scope_hash, stable_id
from extorq.contracts.scan import ScanCoverage, ScanRun, ScanScope, ScanStatus, SkippedCheck
from extorq.ingest.otlp_k8s import (
    ASSET_ID,
    k8s_service_service_id,
    risk_flags_for_summary,
    summarize_k8s_object,
)
from extorq_collectors.kubernetes.model import (
    ACCEPTED_RISK_ANNOTATION,
    WorkloadRef,
    as_dict,
    as_list,
    clean,
    is_bootstrap_rbac,
    meta,
    obj_namespace,
    pod_template,
)

SCANNER = "extorq-posture-k8s"
SCOPE_DESCRIPTION = "extorq-posture-k8s: workloads, RBAC, namespaces, services"
DEFAULT_EXCLUDED_NAMESPACES = (
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "local-path-storage",
)
#: hostPath prefixes that give a pod control over the node or other workloads.
SENSITIVE_HOST_PATHS = (
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/root",
    "/var/run",
    "/run",
    "/var/lib/kubelet",
    "/var/lib/containerd",
    "/var/log",
    "/var/run/docker.sock",
    "/run/containerd",
)


@dataclass(frozen=True)
class Check:
    check_id: str
    title: str
    severity: Severity
    category: FindingCategory
    remediation: str
    references: tuple[str, ...] = ()


_PSS = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
_RBAC = "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"
CHECKS: dict[str, Check] = {
    c.check_id: c
    for c in (
        Check(
            "K8S-POD-001",
            "Privileged container",
            Severity.CRITICAL,
            FindingCategory.MISCONFIGURATION,
            "Remove securityContext.privileged; grant only the specific capabilities needed.",
            (_PSS,),
        ),
        Check(
            "K8S-POD-002",
            "Host namespaces shared (hostPID/hostNetwork/hostIPC)",
            Severity.HIGH,
            FindingCategory.MISCONFIGURATION,
            "Do not share host PID/network/IPC namespaces.",
            (_PSS,),
        ),
        Check(
            "K8S-POD-003",
            "hostPath volume",
            Severity.MEDIUM,
            FindingCategory.MISCONFIGURATION,
            "Replace hostPath with a dedicated volume type; if unavoidable mount read-only and "
            "as narrow as possible.",
            (_PSS,),
        ),
        Check(
            "K8S-POD-004",
            "Dangerous Linux capabilities added",
            Severity.HIGH,
            FindingCategory.MISCONFIGURATION,
            "Drop ALL capabilities and add back only what is "
            "required (never SYS_ADMIN, NET_ADMIN, SYS_PTRACE ...).",
            (_PSS,),
        ),
        Check(
            "K8S-POD-005",
            "Container runs as root (runAsUser 0)",
            Severity.MEDIUM,
            FindingCategory.MISCONFIGURATION,
            "Run as a non-root UID and set runAsNonRoot: true.",
            (_PSS,),
        ),
        Check(
            "K8S-POD-006",
            "runAsNonRoot not enforced",
            Severity.LOW,
            FindingCategory.MISCONFIGURATION,
            "Set securityContext.runAsNonRoot: true.",
            (_PSS,),
        ),
        Check(
            "K8S-POD-007",
            "Privilege escalation not disabled",
            Severity.LOW,
            FindingCategory.MISCONFIGURATION,
            "Set allowPrivilegeEscalation: false on every container.",
            (_PSS,),
        ),
        Check(
            "K8S-POD-008",
            "Container without resource limits",
            Severity.LOW,
            FindingCategory.MISCONFIGURATION,
            "Set CPU and memory limits.",
            ("https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/",),
        ),
        Check(
            "K8S-POD-009",
            "Service-account token automounted",
            Severity.LOW,
            FindingCategory.MISCONFIGURATION,
            "Set automountServiceAccountToken: false unless the pod calls the API.",
            (
                "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
            ),
        ),
        Check(
            "K8S-POD-010",
            "No seccomp profile (or Unconfined)",
            Severity.LOW,
            FindingCategory.MISCONFIGURATION,
            "Set seccompProfile.type: RuntimeDefault.",
            (_PSS,),
        ),
        Check(
            "K8S-POD-011",
            "Writable root filesystem",
            Severity.LOW,
            FindingCategory.MISCONFIGURATION,
            "Set readOnlyRootFilesystem: true.",
            (_PSS,),
        ),
        Check(
            "K8S-RBAC-001",
            "Binding grants cluster-admin",
            Severity.HIGH,
            FindingCategory.POSTURE,
            "Bind narrowly scoped roles instead of cluster-admin.",
            (_RBAC,),
        ),
        Check(
            "K8S-RBAC-002",
            "Wildcard RBAC rule",
            Severity.HIGH,
            FindingCategory.POSTURE,
            "Replace '*' verbs/resources/apiGroups with explicit lists.",
            (_RBAC,),
        ),
        Check(
            "K8S-RBAC-003",
            "RBAC escalation verbs (escalate/bind/impersonate)",
            Severity.HIGH,
            FindingCategory.POSTURE,
            "Remove escalate, bind and impersonate verbs.",
            (_RBAC,),
        ),
        Check(
            "K8S-RBAC-004",
            "Role can read Secrets",
            Severity.MEDIUM,
            FindingCategory.POSTURE,
            "Restrict get/list/watch on secrets to named resources or remove it.",
            (_RBAC,),
        ),
        Check(
            "K8S-RBAC-005",
            "Binding to anonymous / unauthenticated users",
            Severity.CRITICAL,
            FindingCategory.POSTURE,
            "Never bind system:anonymous or system:unauthenticated.",
            (_RBAC,),
        ),
        Check(
            "K8S-RBAC-006",
            "Binding to all authenticated users or all service accounts",
            Severity.HIGH,
            FindingCategory.POSTURE,
            "Bind specific users, groups or service accounts.",
            (_RBAC,),
        ),
        Check(
            "K8S-RBAC-007",
            "Binding to a default service account",
            Severity.MEDIUM,
            FindingCategory.POSTURE,
            "Create a dedicated service account per workload.",
            (_RBAC,),
        ),
        Check(
            "K8S-RBAC-008",
            "Role allows pods/exec or pods/attach",
            Severity.MEDIUM,
            FindingCategory.POSTURE,
            "Restrict interactive access to break-glass roles.",
            (_RBAC,),
        ),
        Check(
            "K8S-NS-001",
            "Namespace without Pod Security enforcement (or privileged)",
            Severity.MEDIUM,
            FindingCategory.POSTURE,
            "Label the namespace pod-security.kubernetes.io/enforce=baseline or restricted.",
            ("https://kubernetes.io/docs/concepts/security/pod-security-admission/",),
        ),
        Check(
            "K8S-NS-002",
            "Namespace with workloads but no NetworkPolicy",
            Severity.LOW,
            FindingCategory.POSTURE,
            "Add a default-deny NetworkPolicy and explicit allows.",
            ("https://kubernetes.io/docs/concepts/services-networking/network-policies/",),
        ),
        Check(
            "K8S-SVC-001",
            "Service exposed on node ports / external IPs",
            Severity.LOW,
            FindingCategory.EXPOSURE,
            "Prefer ClusterIP plus an authenticated ingress.",
            ("https://kubernetes.io/docs/concepts/services-networking/service/",),
        ),
    )
}

_RBAC_CHECK_FLAGS: tuple[tuple[str, frozenset[str]], ...] = (
    ("K8S-RBAC-001", frozenset({"cluster_admin"})),
    (
        "K8S-RBAC-002",
        frozenset(
            {
                "wildcard_verbs",
                "wildcard_resources",
                "full_wildcard_rule",
                "wildcard_api_groups",
                "wildcard_non_resource_urls",
            }
        ),
    ),
    ("K8S-RBAC-003", frozenset({"escalation_verbs"})),
    ("K8S-RBAC-004", frozenset({"secrets_access"})),
    ("K8S-RBAC-005", frozenset({"binds_anonymous", "binds_unauthenticated"})),
    ("K8S-RBAC-006", frozenset({"binds_authenticated", "binds_all_service_accounts"})),
    ("K8S-RBAC-007", frozenset({"binds_default_service_account"})),
    ("K8S-RBAC-008", frozenset({"pod_exec"})),
)


@dataclass
class PostureResult:
    scan_run: ScanRun
    findings: list[PostureFinding]
    skipped_objects: int = 0


@dataclass
class _Collector:
    scan_run_id: str
    now: datetime
    findings: dict[str, PostureFinding] = field(default_factory=dict)
    skipped_objects: int = 0

    def add(
        self,
        check_id: str,
        resource_key: str,
        *,
        resource: Resource,
        evidence: str,
        accepted: str | None,
        service_id: str | None = None,
        description: str | None = None,
        attributes: Mapping[str, Any] | None = None,
        severity: Severity | None = None,
    ) -> None:
        check = CHECKS[check_id]
        fid = finding_id(ASSET_ID, SCANNER, check_id, resource_key)
        try:
            self.findings[fid] = PostureFinding(
                finding_id=fid,
                scan_run_id=self.scan_run_id,
                asset_id=ASSET_ID,
                scanner=SCANNER,
                check_id=check_id,
                category=check.category,
                severity=severity or check.severity,
                title=check.title,
                description=description,
                resource=resource,
                service_id=service_id,
                evidence=clean(evidence, 2048),
                remediation=check.remediation,
                references=list(check.references),
                observed_at=self.now,
                accepted_risk=AcceptedRisk(
                    reason=accepted, source=f"annotation:{ACCEPTED_RISK_ANNOTATION}"
                )
                if accepted
                else None,
                attributes=dict(attributes or {}),
            )
        except ValueError:
            self.skipped_objects += 1


def _annotation(obj: Mapping[str, Any], *paths: Sequence[str]) -> str | None:
    for path in paths:
        node: Any = obj
        for part in path:
            node = as_dict(node).get(part)
        value = as_dict(node).get(ACCEPTED_RISK_ANNOTATION)
        if isinstance(value, str) and value.strip():
            return clean(value, 1024)
    return None


def _workload_checks(scan: _Collector, ref: WorkloadRef, obj: Mapping[str, Any]) -> None:
    kind_obj = {**obj, "kind": ref.kind}
    spec = pod_template(kind_obj) if ref.kind != "Pod" else as_dict(obj.get("spec"))
    summary = summarize_k8s_object(kind_obj) or {}
    flags = set(risk_flags_for_summary(summary))
    key = f"{ref.kind}/{ref.namespace}/{ref.name}"
    resource = Resource(type=ref.kind, name=ref.name, namespace=ref.namespace)
    accepted = _annotation(
        obj, ("metadata", "annotations"), ("spec", "template", "metadata", "annotations")
    )
    sid = ref.service_id

    def add(check_id: str, evidence: str, severity: Severity | None = None) -> None:
        scan.add(
            check_id,
            key,
            resource=resource,
            evidence=evidence,
            accepted=accepted,
            service_id=sid,
            severity=severity,
            attributes={"workload_kind": ref.kind, "namespace": ref.namespace},
        )

    if "privileged" in flags:
        add("K8S-POD-001", f"privileged containers: {summary.get('privileged')}")
    host_ns = sorted(flags & {"host_pid", "host_network", "host_ipc"})
    if host_ns:
        add("K8S-POD-002", f"host namespaces: {', '.join(host_ns)}")
    host_paths = list(summary.get("host_path") or [])
    if host_paths:
        sensitive = [
            p
            for p in host_paths
            if any(p == s or (s != "/" and p.startswith(s + "/")) for s in SENSITIVE_HOST_PATHS)
        ]
        add(
            "K8S-POD-003",
            f"hostPath volumes: {', '.join(host_paths[:8])}",
            Severity.HIGH if sensitive else None,
        )
    if "dangerous_capabilities" in flags:
        add("K8S-POD-004", f"added capabilities: {summary.get('added_capabilities')}")
    if summary.get("run_as_root"):
        add("K8S-POD-005", f"containers with runAsUser 0: {summary.get('run_as_root')}")
    pod_sc = as_dict(spec.get("securityContext"))
    containers = [as_dict(c) for c in as_list(spec.get("containers"))[:32]]
    no_nonroot, escalation, no_limits, no_seccomp, writable = [], [], [], [], []
    pod_seccomp = as_dict(pod_sc.get("seccompProfile")).get("type")
    for container in containers:
        name = clean(container.get("name"), 64) or "?"
        sc = as_dict(container.get("securityContext"))
        if sc.get("runAsNonRoot", pod_sc.get("runAsNonRoot")) is not True:
            uid = sc.get("runAsUser", pod_sc.get("runAsUser"))
            if not (isinstance(uid, int) and not isinstance(uid, bool) and uid > 0):
                no_nonroot.append(name)
        if sc.get("allowPrivilegeEscalation") is not False:
            escalation.append(name)
        limits = as_dict(as_dict(container.get("resources")).get("limits"))
        if "cpu" not in limits or "memory" not in limits:
            no_limits.append(name)
        seccomp = as_dict(sc.get("seccompProfile")).get("type") or pod_seccomp
        if seccomp in (None, "Unconfined"):
            no_seccomp.append(name)
        if sc.get("readOnlyRootFilesystem") is not True:
            writable.append(name)
    if no_nonroot:
        add("K8S-POD-006", f"containers without runAsNonRoot/non-zero runAsUser: {no_nonroot}")
    if escalation:
        explicit = any(
            as_dict(c.get("securityContext")).get("allowPrivilegeEscalation") is True
            for c in containers
        )
        add(
            "K8S-POD-007",
            f"containers without allowPrivilegeEscalation=false: {escalation}",
            Severity.MEDIUM if explicit else None,
        )
    if no_limits:
        add("K8S-POD-008", f"containers without cpu+memory limits: {no_limits}")
    if spec.get("automountServiceAccountToken") is not False:
        add(
            "K8S-POD-009",
            "automountServiceAccountToken is not false on the pod spec "
            f"(service account {clean(spec.get('serviceAccountName'), 128) or 'default'})",
        )
    if no_seccomp:
        add("K8S-POD-010", f"containers without a seccomp profile: {no_seccomp}")
    if writable:
        add("K8S-POD-011", f"containers with a writable root filesystem: {writable}")


def _rbac_checks(scan: _Collector, kind: str, obj: Mapping[str, Any]) -> None:
    name = meta(obj).get("name")
    if not isinstance(name, str) or is_bootstrap_rbac(obj):
        return
    namespace = obj_namespace(obj) or None
    summary = summarize_k8s_object({**obj, "kind": kind}) or {}
    flags = set(risk_flags_for_summary(summary))
    key = f"{kind}/{namespace or ''}/{name}"
    resource = Resource(type=kind, name=clean(name, 253), namespace=namespace)
    accepted = _annotation(obj, ("metadata", "annotations"))
    detail = {k: summary.get(k) for k in ("role_ref", "subjects") if summary.get(k)}
    for check_id, wanted in _RBAC_CHECK_FLAGS:
        hit = sorted(flags & wanted)
        if hit:
            evidence = f"{kind} {name}: flags {hit}"
            if detail:
                evidence += f"; {detail}"
            scan.add(
                check_id,
                key,
                resource=resource,
                evidence=evidence,
                accepted=accepted,
                attributes={"risk_flags": sorted(flags)},
            )


def _namespace_checks(
    scan: _Collector, ns_obj: Mapping[str, Any], *, has_workloads: bool, has_netpol: bool
) -> None:
    name = meta(ns_obj).get("name")
    if not isinstance(name, str):
        return
    labels = as_dict(meta(ns_obj).get("labels"))
    enforce = labels.get("pod-security.kubernetes.io/enforce")
    accepted = _annotation(ns_obj, ("metadata", "annotations"))
    resource = Resource(type="Namespace", name=name)
    key = f"Namespace//{name}"
    if enforce is None or enforce == "privileged":
        scan.add(
            "K8S-NS-001",
            key,
            resource=resource,
            accepted=accepted,
            evidence=f"pod-security.kubernetes.io/enforce={enforce or '(unset)'}",
        )
    if has_workloads and not has_netpol:
        scan.add(
            "K8S-NS-002",
            key,
            resource=resource,
            accepted=accepted,
            evidence="pods present, no NetworkPolicy in the namespace",
        )


def _service_checks(scan: _Collector, svc: Mapping[str, Any]) -> None:
    name = meta(svc).get("name")
    namespace = obj_namespace(svc)
    if not isinstance(name, str) or not namespace:
        return
    spec = as_dict(svc.get("spec"))
    svc_type = spec.get("type")
    node_ports: list[int] = sorted(
        int(p["nodePort"])
        for p in map(as_dict, as_list(spec.get("ports")))
        if isinstance(p.get("nodePort"), int)
    )
    external = as_list(spec.get("externalIPs"))
    if svc_type in ("NodePort", "LoadBalancer") or external:
        scan.add(
            "K8S-SVC-001",
            f"Service/{namespace}/{name}",
            resource=Resource(type="Service", name=name, namespace=namespace),
            accepted=_annotation(svc, ("metadata", "annotations")),
            service_id=k8s_service_service_id(namespace, name),
            evidence=f"type {clean(svc_type, 32)}, nodePorts {node_ports[:8]}, "
            f"externalIPs {len(external)}",
        )


def run_posture_scan(
    *,
    view: Mapping[str, list[dict[str, Any]]],
    failed_kinds: Mapping[str, str],
    workloads: Mapping[str, tuple[WorkloadRef, dict[str, Any]]],
    collector_id: str,
    collector_version: str,
    producer_id: str,
    started_at: datetime,
    now: datetime,
    excluded_namespaces: Sequence[str] = DEFAULT_EXCLUDED_NAMESPACES,
) -> PostureResult:
    """Evaluate every check over the listed state (pure)."""
    excluded = set(excluded_namespaces)
    namespaces = sorted(
        n for n in (meta(o).get("name") for o in view.get("Namespace", [])) if isinstance(n, str)
    )
    scanned_ns = [n for n in namespaces if n not in excluded]
    targets = [f"cluster:{ASSET_ID.split(':', 1)[1]}", *[f"namespace:{n}" for n in scanned_ns]]
    scope = ScanScope(
        targets=targets,
        description=SCOPE_DESCRIPTION,
        scope_hash=scope_hash(targets, SCOPE_DESCRIPTION),
    )
    scan_run_id = stable_id("k8s.scanrun.v1", collector_id, started_at.isoformat())
    scan = _Collector(scan_run_id=scan_run_id, now=now)
    needed = {
        "workloads": (
            "Pod",
            "Deployment",
            "DaemonSet",
            "StatefulSet",
            "ReplicaSet",
            "Job",
            "CronJob",
        ),
        "rbac": ("Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"),
        "namespaces": ("Namespace", "Pod", "NetworkPolicy"),
        "services": ("Service",),
    }
    skipped: list[SkippedCheck] = []
    groups_run: set[str] = set()
    for group, kinds in needed.items():
        missing = [k for k in kinds if k in failed_kinds]
        if missing:
            skipped.append(
                SkippedCheck(
                    check=group,
                    reason=clean("; ".join(f"{k}: {failed_kinds[k]}" for k in missing), 1024)
                    or "list failed",
                )
            )
        else:
            groups_run.add(group)
    if "workloads" in groups_run:
        for _key, (ref, obj) in sorted(workloads.items()):
            if ref.namespace not in excluded:
                _workload_checks(scan, ref, obj)
    if "rbac" in groups_run:
        for kind in ("Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"):
            for obj in view.get(kind, []):
                _rbac_checks(scan, kind, obj)
    if "namespaces" in groups_run:
        with_pods = {obj_namespace(p) for p in view.get("Pod", [])}
        with_netpol = {obj_namespace(p) for p in view.get("NetworkPolicy", [])}
        for ns_obj in view.get("Namespace", []):
            name = meta(ns_obj).get("name")
            if isinstance(name, str) and name not in excluded:
                _namespace_checks(
                    scan, ns_obj, has_workloads=name in with_pods, has_netpol=name in with_netpol
                )
    if "services" in groups_run:
        for svc in view.get("Service", []):
            if obj_namespace(svc) not in excluded:
                _service_checks(scan, svc)
    group_checks = {"workloads": 11, "rbac": 8, "namespaces": 2, "services": 1}
    status = (
        ScanStatus.SUCCEEDED
        if not skipped
        else (ScanStatus.PARTIAL if groups_run else ScanStatus.FAILED)
    )
    findings = sorted(scan.findings.values(), key=lambda f: f.finding_id)
    run = ScanRun(
        scan_run_id=scan_run_id,
        scanner=SCANNER,
        scanner_version=collector_version,
        asset_id=ASSET_ID,
        scope=scope,
        started_at=started_at,
        finished_at=now,
        status=status,
        coverage=ScanCoverage(
            checks_total=len(CHECKS),
            checks_run=sum(group_checks[g] for g in groups_run),
            skipped=skipped,
            notes=[
                f"namespaces excluded from workload/namespace/service checks: "
                f"{', '.join(sorted(excluded))}",
                "RBAC objects labelled kubernetes.io/bootstrapping=rbac-defaults or named "
                "system:* are Kubernetes defaults and are not evaluated",
                "declared state only: no runtime (process/network) behaviour is observed",
            ],
        ),
        findings_count=len(findings),
        error=None
        if not skipped
        else clean(f"incomplete inputs: {', '.join(s.check for s in skipped)}", 512),
        producer_id=producer_id,
        attributes={
            "accepted_findings": sum(1 for f in findings if f.accepted_risk),
            "skipped_objects": scan.skipped_objects,
        },
    )
    return PostureResult(scan_run=run, findings=findings, skipped_objects=scan.skipped_objects)


__all__ = ["CHECKS", "DEFAULT_EXCLUDED_NAMESPACES", "SCANNER", "PostureResult", "run_posture_scan"]

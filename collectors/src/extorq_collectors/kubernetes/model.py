"""Pure transformations for the Kubernetes inventory collector (owner: B2).

No I/O: API list items in, contract records out. Everything read from the API is
attacker-influenced (names, labels, annotations, messages, images) and is
sanitised, redacted and bounded before it reaches a record. Nothing is invented:
fields the API does not report stay ``None``.

Identity helpers (service ids, instance ids, node asset ids, container ids) come
from :mod:`extorq.ingest.otlp_k8s` so inventory records and OTLP-normalised
events always reference the same services and instances.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts.asset import InventoryItem, InventoryItemType
from extorq.contracts.common import (
    AssetType,
    CollectionMethod,
    EventCategory,
    Outcome,
    Severity,
)
from extorq.contracts.event import (
    KubernetesInfo,
    Provenance,
    Resource,
    SecurityEvent,
    SourceInfo,
)
from extorq.contracts.identity import canonical_json, event_id, sha256_hex
from extorq.contracts.service import ServiceRef
from extorq.ingest.otlp_k8s import (
    ASSET_ID,
    CLUSTER_NAME,
    POD_WORKLOAD_KIND,
    canonical_container_id,
    container_instance_id,
    is_static_pod_uid,
    pod_instance_id,
    risk_flags_for_summary,
    summarize_k8s_object,
    valid_k8s_name,
    workload_service_id,
    workload_service_key,
)

PARSER = "k8s-inventory"
#: 1.1.0: schema 2.0 (no simulation marker); Namespace Pod Security labels as attributes.
PARSER_VERSION = "1.1.0"
ACCEPTED_RISK_ANNOTATION = "extorq.io/accepted-risk"
STATIC_POD_HASH_ANNOTATION = "kubernetes.io/config.hash"
#: Owner of RBAC objects that Kubernetes itself reconciles at API server start.
BOOTSTRAP_LABEL = ("kubernetes.io/bootstrapping", "rbac-defaults")
SUMMARY_LIMIT = 2000
_KIND_RE = re.compile(r"^[A-Z][A-Za-z0-9]{0,62}$")


@dataclass(frozen=True)
class ResourceKind:
    kind: str
    #: Plural API resource, as in audit ``objectRef.resource`` (events.resource_type).
    resource: str
    api_group: str
    path: str
    namespaced: bool
    item_type: InventoryItemType | None


RESOURCE_KINDS: tuple[ResourceKind, ...] = (
    ResourceKind(
        "Namespace", "namespaces", "", "/api/v1/namespaces", False, InventoryItemType.K8S_NAMESPACE
    ),
    ResourceKind("Node", "nodes", "", "/api/v1/nodes", False, None),
    ResourceKind("Pod", "pods", "", "/api/v1/pods", True, InventoryItemType.K8S_POD),
    ResourceKind("Service", "services", "", "/api/v1/services", True, None),
    ResourceKind(
        "ServiceAccount",
        "serviceaccounts",
        "",
        "/api/v1/serviceaccounts",
        True,
        InventoryItemType.K8S_SERVICE_ACCOUNT,
    ),
    ResourceKind(
        "Deployment",
        "deployments",
        "apps",
        "/apis/apps/v1/deployments",
        True,
        InventoryItemType.K8S_WORKLOAD,
    ),
    ResourceKind(
        "DaemonSet",
        "daemonsets",
        "apps",
        "/apis/apps/v1/daemonsets",
        True,
        InventoryItemType.K8S_WORKLOAD,
    ),
    ResourceKind(
        "StatefulSet",
        "statefulsets",
        "apps",
        "/apis/apps/v1/statefulsets",
        True,
        InventoryItemType.K8S_WORKLOAD,
    ),
    ResourceKind(
        "ReplicaSet",
        "replicasets",
        "apps",
        "/apis/apps/v1/replicasets",
        True,
        InventoryItemType.K8S_WORKLOAD,
    ),
    ResourceKind(
        "Job", "jobs", "batch", "/apis/batch/v1/jobs", True, InventoryItemType.K8S_WORKLOAD
    ),
    ResourceKind(
        "CronJob",
        "cronjobs",
        "batch",
        "/apis/batch/v1/cronjobs",
        True,
        InventoryItemType.K8S_WORKLOAD,
    ),
    ResourceKind(
        "Role",
        "roles",
        "rbac.authorization.k8s.io",
        "/apis/rbac.authorization.k8s.io/v1/roles",
        True,
        InventoryItemType.K8S_ROLE,
    ),
    ResourceKind(
        "RoleBinding",
        "rolebindings",
        "rbac.authorization.k8s.io",
        "/apis/rbac.authorization.k8s.io/v1/rolebindings",
        True,
        InventoryItemType.K8S_BINDING,
    ),
    ResourceKind(
        "ClusterRole",
        "clusterroles",
        "rbac.authorization.k8s.io",
        "/apis/rbac.authorization.k8s.io/v1/clusterroles",
        False,
        InventoryItemType.K8S_ROLE,
    ),
    ResourceKind(
        "ClusterRoleBinding",
        "clusterrolebindings",
        "rbac.authorization.k8s.io",
        "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
        False,
        InventoryItemType.K8S_BINDING,
    ),
    ResourceKind(
        "NetworkPolicy",
        "networkpolicies",
        "networking.k8s.io",
        "/apis/networking.k8s.io/v1/networkpolicies",
        True,
        None,
    ),
)
KIND_BY_NAME: dict[str, ResourceKind] = {rk.kind: rk for rk in RESOURCE_KINDS}
EVENTS_PATH = "/api/v1/events"
WORKLOAD_KINDS = ("Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob")
#: involvedObject.kind -> plural resource for k8s.event.observed resource.type.
_PLURALS = {rk.kind: rk.resource for rk in RESOURCE_KINDS} | {
    "Endpoints": "endpoints",
    "PersistentVolumeClaim": "persistentvolumeclaims",
    "PersistentVolume": "persistentvolumes",
    "Lease": "leases",
}


# ── small helpers ─────────────────────────────────────────────────────


def clean(value: Any, limit: int = 256) -> str | None:
    """Sanitise + redact attacker-influenced text; None stays None."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    cleaned = sanitize_untrusted(redact_text(text)[0], limit)
    return cleaned or None


def clean_list(values: Iterable[Any], limit: int = 64, item_limit: int = 256) -> list[str]:
    out: list[str] = []
    for value in values:
        if len(out) >= limit:
            break
        text = clean(value, item_limit)
        if text:
            out.append(text)
    return out


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def meta(obj: Mapping[str, Any]) -> dict[str, Any]:
    return as_dict(obj.get("metadata"))


def obj_name(obj: Mapping[str, Any]) -> str | None:
    return valid_k8s_name(meta(obj).get("name")) or _loose_name(meta(obj).get("name"))


def _loose_name(value: Any) -> str | None:
    # RBAC object names may contain ':' (e.g. "system:node"); keep them, sanitised.
    if isinstance(value, str) and 0 < len(value) <= 253:
        return sanitize_untrusted(value, 253) or None
    return None


def obj_namespace(obj: Mapping[str, Any]) -> str:
    ns = meta(obj).get("namespace")
    return valid_k8s_name(ns) or ""


def object_key(kind: str, namespace: str, name: str) -> str:
    """Inventory item key ``<Kind>/<namespace>/<name>`` (namespace empty if cluster-scoped)."""
    return f"{kind}/{namespace}/{name}"


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not 10 <= len(value) <= 40:
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def accepted_risk(obj: Mapping[str, Any]) -> str | None:
    annotations = as_dict(meta(obj).get("annotations"))
    return clean(annotations.get(ACCEPTED_RISK_ANNOTATION), 1024)


def is_bootstrap_rbac(obj: Mapping[str, Any]) -> bool:
    labels = as_dict(meta(obj).get("labels"))
    name = meta(obj).get("name")
    return labels.get(BOOTSTRAP_LABEL[0]) == BOOTSTRAP_LABEL[1] or (
        isinstance(name, str) and name.startswith("system:")
    )


def bounded_summary(summary: Mapping[str, Any] | None) -> str | None:
    if not summary:
        return None
    text = canonical_json(summary)
    if len(text) <= SUMMARY_LIMIT:
        return text
    trimmed = {k: (v[:4] if isinstance(v, list) else v) for k, v in summary.items()}
    trimmed["truncated"] = True
    text = canonical_json(trimmed)
    return text if len(text) <= SUMMARY_LIMIT else canonical_json({"truncated": True})


def last_write_time(obj: Mapping[str, Any]) -> datetime | None:
    """Newest ``managedFields[].time``: when the object was last written (by any manager)."""
    newest: datetime | None = None
    for entry in as_list(meta(obj).get("managedFields"))[:64]:
        stamp = parse_time(as_dict(entry).get("time"))
        if stamp and (newest is None or stamp > newest):
            newest = stamp
    return newest


def field_managers(obj: Mapping[str, Any]) -> list[str]:
    names = {as_dict(e).get("manager") for e in as_list(meta(obj).get("managedFields"))[:64]}
    return clean_list(sorted(n for n in names if isinstance(n, str)), 8, 128)


# ── object state (what the snapshot diff compares) ────────────────────


def _spec_without(obj: Mapping[str, Any], *drop: str) -> dict[str, Any]:
    return {k: v for k, v in as_dict(obj.get("spec")).items() if k not in drop}


def object_sections(kind: str, obj: Mapping[str, Any]) -> dict[str, Any]:
    """Security-relevant, non-volatile content per kind (status is never compared)."""
    m = meta(obj)
    labels = as_dict(m.get("labels"))
    sections: dict[str, Any] = {"accepted_risk": accepted_risk(obj)}
    if kind == "Namespace":
        sections["labels"] = labels
    elif kind == "Node":
        status = as_dict(obj.get("status"))
        node_info = as_dict(status.get("nodeInfo"))
        sections["labels"] = labels
        sections["spec"] = _spec_without(obj, "podCIDRs", "providerID")
        sections["versions"] = {
            "kubelet": node_info.get("kubeletVersion"),
            "runtime": node_info.get("containerRuntimeVersion"),
            "kernel": node_info.get("kernelVersion"),
            "os_image": node_info.get("osImage"),
        }
    elif kind == "Pod":
        # nodeName is set by the scheduler after creation; comparing it would turn every
        # pod creation into created + updated.
        sections["spec"] = _spec_without(obj, "nodeName")
    elif kind == "ServiceAccount":
        sections["automount"] = obj.get("automountServiceAccountToken")
        sections["secrets"] = sorted(
            str(as_dict(s).get("name")) for s in as_list(obj.get("secrets"))
        )
        sections["image_pull_secrets"] = sorted(
            str(as_dict(s).get("name")) for s in as_list(obj.get("imagePullSecrets"))
        )
    elif kind in ("Role", "ClusterRole"):
        sections["rules"] = obj.get("rules")
        sections["aggregation"] = obj.get("aggregationRule")
        sections["labels"] = labels
    elif kind in ("RoleBinding", "ClusterRoleBinding"):
        sections["role_ref"] = obj.get("roleRef")
        sections["subjects"] = obj.get("subjects")
    else:
        sections["spec"] = obj.get("spec")
        sections["labels"] = labels
    return sections


#: Pod Security Admission namespace labels (``<prefix><mode>`` and ``<prefix><mode>-version``).
PSA_LABEL_PREFIX = "pod-security.kubernetes.io/"
PSA_MODES = ("enforce", "audit", "warn")


def namespace_pod_security(obj: Mapping[str, Any]) -> dict[str, str]:
    """Pod Security labels of a Namespace as flat attributes; absent labels are omitted.

    ``pod_security_enforce`` is the level admission enforces in that namespace. When the
    label is absent the API server's cluster-wide default applies, which the API does not
    expose (``privileged`` unless an AdmissionConfiguration says otherwise), so it is left
    unset here; the audit normaliser records the level actually enforced per request.
    """
    labels = as_dict(meta(obj).get("labels"))
    out: dict[str, str] = {}
    for mode in PSA_MODES:
        for suffix, key in (("", mode), ("-version", f"{mode}_version")):
            value = clean(labels.get(f"{PSA_LABEL_PREFIX}{mode}{suffix}"), 32)
            if value:
                out[f"pod_security_{key}"] = value
    return out


def security_summary(kind: str, obj: Mapping[str, Any]) -> dict[str, Any] | None:
    """Compact security summary (shared vocabulary with the audit normaliser)."""
    if kind in ("Pod", *WORKLOAD_KINDS, "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"):
        return summarize_k8s_object({**obj, "kind": kind})
    if kind == "Service":
        return service_exposure_summary(obj)
    if kind == "Namespace":
        labels = as_dict(meta(obj).get("labels"))
        psa = {
            mode: labels.get(f"pod-security.kubernetes.io/{mode}")
            for mode in ("enforce", "audit", "warn")
            if isinstance(labels.get(f"pod-security.kubernetes.io/{mode}"), str)
        }
        return {"pod_security": psa} if psa else {"pod_security": {}}
    return None


def service_exposure_summary(obj: Mapping[str, Any]) -> dict[str, Any]:
    spec = as_dict(obj.get("spec"))
    summary: dict[str, Any] = {"type": clean(spec.get("type"), 32) or "ClusterIP"}
    ports = []
    node_ports = []
    for port in as_list(spec.get("ports"))[:32]:
        port = as_dict(port)
        number = port.get("port")
        if isinstance(number, int) and not isinstance(number, bool):
            ports.append(f"{clean(port.get('protocol'), 8) or 'TCP'}/{number}")
        node_port = port.get("nodePort")
        if isinstance(node_port, int) and not isinstance(node_port, bool):
            node_ports.append(node_port)
    if ports:
        summary["ports"] = ports
    if node_ports:
        summary["node_ports"] = sorted(node_ports)
    external = clean_list(as_list(spec.get("externalIPs")), 16, 64)
    if external:
        summary["external_ips"] = external
    return summary


def extra_risk_flags(
    kind: str, obj: Mapping[str, Any], summary: Mapping[str, Any] | None
) -> list[str]:
    """Kind-specific flags beyond the shared pod/RBAC vocabulary."""
    flags: set[str] = set()
    if kind == "Service" and summary:
        if summary.get("type") in ("NodePort", "LoadBalancer") or summary.get("node_ports"):
            flags.add("node_port_exposure")
        if summary.get("type") == "LoadBalancer":
            flags.add("load_balancer_exposure")
        if summary.get("external_ips"):
            flags.add("external_ips")
    if kind == "Namespace" and summary is not None:
        enforce = as_dict(summary.get("pod_security")).get("enforce")
        if enforce is None:
            flags.add("psa_not_enforced")
        elif enforce == "privileged":
            flags.add("psa_privileged")
    return sorted(flags)


def object_state(
    rk: ResourceKind, obj: Mapping[str, Any], *, owner: str | None = None
) -> dict[str, Any] | None:
    """Snapshot item for one object, or None when it has no usable name."""
    name = obj_name(obj)
    if name is None:
        return None
    namespace = obj_namespace(obj) if rk.namespaced else ""
    sections = object_sections(rk.kind, obj)
    summary = security_summary(rk.kind, obj)
    flags = sorted(
        set(risk_flags_for_summary(summary)) | set(extra_risk_flags(rk.kind, obj, summary))
    )
    m = meta(obj)
    state: dict[str, Any] = {
        "kind": rk.kind,
        "namespace": namespace,
        "name": name,
        "uid": clean(m.get("uid"), 64),
        "sections": {k: sha256_hex(canonical_json(v))[:16] for k, v in sections.items()},
        "summary": bounded_summary(summary),
        "risk_flags": flags,
        "accepted_risk": sections.get("accepted_risk"),
        "owner": owner,
        "created_at": iso(parse_time(m.get("creationTimestamp"))),
    }
    if rk.kind == "Namespace":
        # Derived from the labels (already part of "sections"): a parser upgrade that adds
        # it refreshes the inventory item without reporting the namespace as updated.
        state["pod_security"] = namespace_pod_security(obj)
    return state


# ── workloads and owners ──────────────────────────────────────────────


@dataclass(frozen=True)
class WorkloadRef:
    namespace: str
    kind: str
    name: str

    @property
    def key(self) -> str:
        return workload_service_key(self.namespace, self.kind, self.name)

    @property
    def service_id(self) -> str | None:
        return workload_service_id(self.namespace, self.kind, self.name)

    @property
    def label(self) -> str:
        return f"{self.kind}/{self.name}"


def controller_owner(obj: Mapping[str, Any]) -> tuple[str, str, str | None] | None:
    for ref in as_list(meta(obj).get("ownerReferences"))[:16]:
        ref = as_dict(ref)
        if ref.get("controller") is True:
            kind, name = ref.get("kind"), ref.get("name")
            if isinstance(kind, str) and isinstance(name, str) and _KIND_RE.match(kind):
                uid = ref.get("uid")
                return kind, name, uid if isinstance(uid, str) and uid else None
    return None


@dataclass
class OwnerIndex:
    """ReplicaSet / Job owners, to resolve a pod's top-level workload."""

    replicasets: dict[tuple[str, str, str], tuple[str, str, str | None] | None] = field(
        default_factory=dict
    )
    jobs: dict[tuple[str, str, str], tuple[str, str, str | None] | None] = field(
        default_factory=dict
    )

    @classmethod
    def build(
        cls, replicasets: Iterable[Mapping[str, Any]], jobs: Iterable[Mapping[str, Any]]
    ) -> OwnerIndex:
        index = cls()
        for rs in replicasets:
            name = obj_name(rs)
            uid = meta(rs).get("uid")
            if name and isinstance(uid, str) and uid:
                index.replicasets[(obj_namespace(rs), name, uid)] = controller_owner(rs)
        for job in jobs:
            name = obj_name(job)
            uid = meta(job).get("uid")
            if name and isinstance(uid, str) and uid:
                index.jobs[(obj_namespace(job), name, uid)] = controller_owner(job)
        return index

    def workload_of(self, pod: Mapping[str, Any]) -> WorkloadRef | None:
        """Top-level workload of a pod; None when the chain cannot be resolved this cycle."""
        namespace = obj_namespace(pod)
        name = valid_k8s_name(meta(pod).get("name"))
        if not namespace or not name:
            return None
        owner = controller_owner(pod)
        if owner is None or owner[0] == "Node":
            # Bare pod (no controller) or static pod (mirror pod owned by its Node).
            return WorkloadRef(namespace, POD_WORKLOAD_KIND, name)
        kind, owner_name, owner_uid = owner
        if not valid_k8s_name(owner_name) or owner_uid is None:
            return None
        key = (namespace, owner_name, owner_uid)
        if kind == "ReplicaSet":
            if key not in self.replicasets:
                return None  # not listed yet (race) -> unknown, never guessed
            parent = self.replicasets[key]
            if parent and parent[0] == "Deployment" and valid_k8s_name(parent[1]):
                return WorkloadRef(namespace, "Deployment", parent[1])
            return WorkloadRef(namespace, "ReplicaSet", owner_name)
        if kind == "Job":
            if key not in self.jobs:
                return None
            parent = self.jobs[key]
            if parent and parent[0] == "CronJob" and valid_k8s_name(parent[1]):
                return WorkloadRef(namespace, "CronJob", parent[1])
            return WorkloadRef(namespace, "Job", owner_name)
        return WorkloadRef(namespace, kind, owner_name)


def top_level_workloads(
    view: Mapping[str, list[dict[str, Any]]],
) -> dict[str, tuple[WorkloadRef, dict[str, Any]]]:
    """Controllers that are workloads in their own right: key -> (ref, object)."""
    out: dict[str, tuple[WorkloadRef, dict[str, Any]]] = {}
    for kind in WORKLOAD_KINDS:
        for obj in view.get(kind, []):
            namespace, name = obj_namespace(obj), valid_k8s_name(meta(obj).get("name"))
            if not namespace or not name:
                continue
            owner = controller_owner(obj)
            if kind == "ReplicaSet" and owner and owner[0] == "Deployment":
                continue
            if kind == "Job" and owner and owner[0] == "CronJob":
                continue
            ref = WorkloadRef(namespace, kind, name)
            out[ref.key] = (ref, obj)
    return out


def pod_template(obj: Mapping[str, Any]) -> dict[str, Any]:
    """Pod spec of a workload (template) or of a pod."""
    kind = obj.get("kind")
    spec = as_dict(obj.get("spec"))
    if kind == "CronJob":
        return as_dict(
            as_dict(as_dict(as_dict(spec.get("jobTemplate")).get("spec")).get("template")).get(
                "spec"
            )
        )
    if kind in WORKLOAD_KINDS:
        return as_dict(as_dict(spec.get("template")).get("spec"))
    return spec


def static_pod_key(pod: Mapping[str, Any]) -> str | None:
    """kubelet UID of a static pod (config hash), used as its instance key."""
    owner = controller_owner(pod)
    annotations = as_dict(meta(pod).get("annotations"))
    config_hash = annotations.get(STATIC_POD_HASH_ANNOTATION)
    if owner and owner[0] == "Node" and is_static_pod_uid(config_hash):
        return str(config_hash)
    return None


def pod_instance_key(pod: Mapping[str, Any]) -> str | None:
    return static_pod_key(pod) or clean(meta(pod).get("uid"), 64)


# ── events from snapshot diffs ────────────────────────────────────────


def _source(
    collector_id: str,
    collector_version: str,
    source_type: str,
    native_id: str | None,
    method: CollectionMethod = CollectionMethod.API_POLL,
) -> SourceInfo:
    return SourceInfo(
        source_type=source_type,
        collector_id=collector_id,
        collector_version=collector_version,
        collection_method=method,
        source_native_id=native_id[:256] if native_id else None,
    )


def _within_contract_window(value: datetime | None, now: datetime) -> datetime | None:
    if value is None or value > now + timedelta(minutes=5) or value < now - timedelta(days=390):
        return None
    return value


@dataclass(frozen=True)
class DiffContext:
    collector_id: str
    collector_version: str
    now: datetime
    baseline: bool


def resource_change_event(
    change: str,
    rk: ResourceKind,
    state: Mapping[str, Any],
    *,
    ctx: DiffContext,
    obj: Mapping[str, Any] | None,
    previous: Mapping[str, Any] | None = None,
    pod_workload: WorkloadRef | None = None,
    service: ServiceRef | None = None,
) -> SecurityEvent:
    """k8s.resource.created / updated / deleted for one snapshot difference."""
    event_type = f"k8s.resource.{change}"
    namespace = state.get("namespace") or None
    name = str(state["name"])
    uid = state.get("uid")
    key = object_key(rk.kind, state.get("namespace") or "", name)
    m = meta(obj) if obj is not None else {}
    resource_version = clean(m.get("resourceVersion"), 64) if obj is not None else None
    content = sha256_hex(canonical_json(dict(state)))
    native = f"{key}:{uid or ''}:{resource_version or content}:{change}"
    time_source = "observed"
    event_time = ctx.now
    if change == "created":
        created = _within_contract_window(parse_time(m.get("creationTimestamp")), ctx.now)
        if created is not None:
            event_time, time_source = created, "creation_timestamp"
    elif change == "updated" and obj is not None:
        written = _within_contract_window(last_write_time(obj), ctx.now)
        if written is not None:
            event_time, time_source = written, "managed_fields"
    flags = list(state.get("risk_flags") or [])
    attributes: dict[str, Any] = {
        "kind": rk.kind,
        "api_group": rk.api_group or "core",
        "risk_flags": flags,
        "object_summary": state.get("summary"),
        "baseline": True if ctx.baseline else None,
        "accepted_risk": state.get("accepted_risk"),
        "created_at": state.get("created_at"),
        "owner": state.get("owner"),
        "time_source": time_source,
        "resource_version": resource_version,
        "object_uid": uid,
        **as_dict(state.get("pod_security")),
    }
    if obj is not None:
        managers = field_managers(obj)
        if managers:
            attributes["field_managers"] = managers
    if change == "updated" and previous is not None:
        before = as_dict(previous.get("sections"))
        after = as_dict(state.get("sections"))
        attributes["changed_fields"] = sorted(
            k for k in set(before) | set(after) if before.get(k) != after.get(k)
        )
        previous_flags = list(previous.get("risk_flags") or [])
        attributes["previous_risk_flags"] = previous_flags
        added = sorted(set(flags) - set(previous_flags))
        if added:
            attributes["risk_flags_added"] = added
    attributes = {k: v for k, v in attributes.items() if v is not None}
    k8s_fields: dict[str, Any] = {
        "cluster": CLUSTER_NAME,
        "namespace": namespace,
        "resource": rk.resource,
        "api_group": rk.api_group,
        "object_name": name,
    }
    if rk.kind == "Pod" and obj is not None:
        spec = as_dict(obj.get("spec"))
        k8s_fields.update(
            {
                "pod_name": name,
                "pod_uid": uid,
                "node_name": clean(spec.get("nodeName"), 253),
                "service_account": clean(spec.get("serviceAccountName"), 253),
                "workload_kind": pod_workload.kind if pod_workload else None,
                "workload_name": pod_workload.name if pod_workload else None,
            }
        )
    kubernetes = KubernetesInfo(**k8s_fields)
    label = f"{rk.kind} {namespace + '/' if namespace else ''}{name} {change}"
    if flags:
        label += f" (risk: {', '.join(flags[:6])})"
    return SecurityEvent(
        event_id=event_id("k8s.api_inventory", ASSET_ID, native),
        event_type=event_type,
        category=EventCategory.KUBERNETES_API,
        asset_id=ASSET_ID,
        asset_type=AssetType.KUBERNETES_CLUSTER,
        source=_source(ctx.collector_id, ctx.collector_version, "k8s.api_inventory", uid),
        event_time=event_time,
        observed_time=ctx.now,
        action=change,
        outcome=Outcome.SUCCESS,
        resource=Resource(type=rk.resource, name=name, id=uid, namespace=namespace),
        kubernetes=kubernetes,
        service=service,
        message=clean(label, 512),
        attributes=attributes,
        provenance=Provenance(parser=PARSER, parser_version=PARSER_VERSION, raw_sha256=content),
    )


def inventory_item(
    rk: ResourceKind,
    state: Mapping[str, Any],
    *,
    collector_id: str,
    snapshot_id: str,
    now: datetime,
    present: bool = True,
) -> InventoryItem | None:
    if rk.item_type is None:
        return None
    attributes: dict[str, Any] = {
        "kind": rk.kind,
        "namespace": state.get("namespace") or None,
        "name": state.get("name"),
        "uid": state.get("uid"),
        "risk_flags": list(state.get("risk_flags") or []),
        "summary": state.get("summary"),
        "owner": state.get("owner"),
        "accepted_risk": state.get("accepted_risk"),
        "created_at": state.get("created_at"),
        **as_dict(state.get("pod_security")),
    }
    return InventoryItem(
        asset_id=ASSET_ID,
        item_type=rk.item_type,
        item_key=object_key(rk.kind, state.get("namespace") or "", str(state["name"])),
        attributes={k: v for k, v in attributes.items() if v is not None},
        snapshot_id=snapshot_id,
        observed_at=now,
        present=present,
        collector_id=collector_id,
    )


# ── core/v1 Events ────────────────────────────────────────────────────


def event_count(obj: Mapping[str, Any]) -> int:
    series = as_dict(obj.get("series"))
    for value in (series.get("count"), obj.get("count")):
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return 1


def event_time_of(obj: Mapping[str, Any]) -> datetime | None:
    series = as_dict(obj.get("series"))
    for value in (
        series.get("lastObservedTime"),
        obj.get("lastTimestamp"),
        obj.get("eventTime"),
        obj.get("firstTimestamp"),
        meta(obj).get("creationTimestamp"),
    ):
        parsed = parse_time(value)
        if parsed is not None:
            return parsed
    return None


def k8s_event(
    obj: Mapping[str, Any],
    *,
    collector_id: str,
    collector_version: str,
    now: datetime,
    pod_services: Mapping[str, tuple[str, str, str | None]] | None = None,
) -> SecurityEvent | None:
    """k8s.event.observed for one core/v1 Event (one per uid + occurrence count)."""
    m = meta(obj)
    uid = clean(m.get("uid"), 64)
    if not uid:
        return None
    count = event_count(obj)
    involved = as_dict(obj.get("involvedObject"))
    kind = clean(involved.get("kind"), 64)
    name = clean(involved.get("name"), 253)
    namespace = clean(involved.get("namespace"), 253) or clean(m.get("namespace"), 253)
    involved_uid = clean(involved.get("uid"), 64)
    source = as_dict(obj.get("source"))
    event_kind = clean(obj.get("type"), 16)
    reason = clean(obj.get("reason"), 128)
    message = clean(obj.get("message"), 1024)
    stamp = _within_contract_window(event_time_of(obj), now) or now
    attributes: dict[str, Any] = {
        "reason": reason,
        "event_type": event_kind,
        "count": count,
        "source_component": clean(source.get("component"), 128),
        "source_host": clean(source.get("host"), 253),
        "reporting_controller": clean(obj.get("reportingComponent"), 128),
        "action": clean(obj.get("action"), 128),
        "involved_kind": kind,
        "first_seen": iso(parse_time(obj.get("firstTimestamp"))),
    }
    attributes = {k: v for k, v in attributes.items() if v is not None}
    service = None
    k8s_fields: dict[str, Any] = {
        "cluster": CLUSTER_NAME,
        "namespace": namespace,
        "object_name": name,
        "resource": _PLURALS.get(kind or ""),
    }
    if kind == "Pod":
        k8s_fields.update({"pod_name": name, "pod_uid": involved_uid})
        if pod_services and involved_uid and involved_uid in pod_services:
            sid, svc_name, iid = pod_services[involved_uid]
            service = ServiceRef(
                service_id=sid, name=svc_name, instance_id=iid, adapter_id="k8s-events"
            )
    elif kind == "Node":
        k8s_fields["node_name"] = name
    kubernetes = KubernetesInfo(**k8s_fields)
    text = (
        f"{event_kind or 'Event'} {reason or '?'} {kind or '?'} "
        f"{namespace + '/' if namespace else ''}{name or '?'}: {message or ''}"
    )
    return SecurityEvent(
        event_id=event_id("k8s.events", ASSET_ID, f"{uid}:{count}"),
        event_type="k8s.event.observed",
        category=EventCategory.KUBERNETES_WORKLOAD,
        asset_id=ASSET_ID,
        asset_type=AssetType.KUBERNETES_CLUSTER,
        source=_source(collector_id, collector_version, "k8s.events", uid),
        event_time=stamp,
        observed_time=now,
        action=reason,
        severity_hint=Severity.LOW if event_kind == "Warning" else Severity.INFO,
        resource=Resource(
            type=_PLURALS.get(kind or "", (kind or "").lower() or None),
            name=name,
            id=involved_uid,
            namespace=namespace,
        ),
        kubernetes=kubernetes,
        service=service,
        message=clean(text, 2048),
        attributes=attributes,
        provenance=Provenance(
            parser=PARSER,
            parser_version=PARSER_VERSION,
            raw_sha256=sha256_hex(canonical_json(dict(obj))),
        ),
    )


def gap_event(
    *,
    collector_id: str,
    collector_version: str,
    source_type: str,
    reason: str,
    now: datetime,
    detail: Mapping[str, Any],
) -> SecurityEvent:
    attributes = {
        "collector_id": collector_id,
        "source_type": source_type,
        "gap_reason": reason,
        **{k: v for k, v in detail.items() if v is not None},
    }
    return SecurityEvent(
        event_id=event_id(source_type, ASSET_ID, f"gap:{reason}:{canonical_json(dict(detail))}"),
        event_type="extorq.collector.gap_detected",
        category=EventCategory.COLLECTOR,
        asset_id=ASSET_ID,
        asset_type=AssetType.KUBERNETES_CLUSTER,
        source=_source(collector_id, collector_version, source_type, None),
        event_time=now,
        observed_time=now,
        outcome=Outcome.FAILURE,
        message=clean(f"{source_type} telemetry gap: {reason}", 512),
        attributes=attributes,
        provenance=Provenance(parser=PARSER, parser_version=PARSER_VERSION),
    )


__all__ = [
    "ACCEPTED_RISK_ANNOTATION",
    "EVENTS_PATH",
    "KIND_BY_NAME",
    "RESOURCE_KINDS",
    "DiffContext",
    "OwnerIndex",
    "ResourceKind",
    "WorkloadRef",
    "accepted_risk",
    "canonical_container_id",
    "clean",
    "container_instance_id",
    "gap_event",
    "inventory_item",
    "is_bootstrap_rbac",
    "k8s_event",
    "namespace_pod_security",
    "object_key",
    "object_state",
    "pod_instance_id",
    "pod_instance_key",
    "pod_template",
    "resource_change_event",
    "static_pod_key",
    "top_level_workloads",
]

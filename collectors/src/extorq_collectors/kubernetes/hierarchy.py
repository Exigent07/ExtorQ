"""Kubernetes service hierarchy (contract schema 1.1, PLAN section 10).

    k8s:extorq-lab (cluster asset)
      ├─ k8s:extorq-lab/node/<node>       node assets (built in collector.py)
      ├─ Service k8s_workload "<ns>/<Kind>/<name>"   top-level controller, or the Pod
      │    │                                         itself for bare and static pods
      │    └─ ServiceInstance pod "<pod uid>" (kubelet config hash for static pods)
      │         └─ ServiceInstance container "<bare container id>"
      │            asset_id: the node asset once scheduled; the cluster asset while the
      │            scheduler has not bound the pod to a node (A-IC-2)
      └─ Service k8s_service  "<ns>/<name>"          logical Service object; never a
                                                     host operating-system service

Coverage is decided from evidence the inventory identity can see:

* adapter: ``webapp-json`` for lab-portal (structured app security events),
  ``k8s-audit`` for the kube-apiserver static pod, ``k8s-container-log`` otherwise;
  Kubernetes Service objects have no telemetry adapter (``none``);
* status: ``monitored`` when the log agent (extorq-otel-collector) is Ready on every
  node running an instance, ``degraded`` when it is not, ``unmonitored`` without
  running instances or for the agent itself (its own logs are excluded). Telemetry
  freshness is not observable here; it is computed from received events server-side.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.contracts.catalog import SourceType
from extorq.contracts.service import (
    AdapterSupport,
    DiscoveryEvidence,
    InstanceKind,
    MonitoringStatus,
    PortAttribution,
    Service,
    ServiceCategory,
    ServiceEndpoint,
    ServiceInstance,
    ServiceKind,
    ServiceRef,
)
from extorq.ingest.otlp_k8s import (
    ASSET_ID,
    POD_WORKLOAD_KIND,
    canonical_container_id,
    container_instance_id,
    k8s_service_key,
    k8s_service_service_id,
    node_asset_id,
    pod_instance_id,
    risk_flags_for_summary,
    service_display_name,
    summarize_k8s_object,
    valid_k8s_name,
)
from extorq_collectors.kubernetes.adapters import (
    WEBAPP_JSON_ADAPTER_ID,
    K8sAuditAdapter,
    K8sContainerLogAdapter,
    K8sEventsAdapter,
)
from extorq_collectors.kubernetes.model import (
    OwnerIndex,
    WorkloadRef,
    accepted_risk,
    as_dict,
    as_list,
    clean,
    clean_list,
    meta,
    obj_namespace,
    parse_time,
    pod_instance_key,
    pod_template,
    static_pod_key,
    top_level_workloads,
)
from extorq_collectors.services.base import exposure_of

AGENT_NAMESPACE = "extorq-system"
AGENT_NAME = "extorq-otel-collector"
LAB_PORTAL = WorkloadRef("extorq-apps", "Deployment", "lab-portal")
_VERSION_RE = re.compile(r"^v?\d+(\.\d+)+([-+.][0-9A-Za-z.-]{1,40})?$")
_PHASE_STATE = {
    "Running": "running",
    "Pending": "pending",
    "Succeeded": "stopped",
    "Failed": "failed",
}


def image_product_version(image: Any) -> tuple[str | None, str | None]:
    """(product, version) from an image reference: repo basename, version-like tag only."""
    if not isinstance(image, str) or not image or len(image) > 512:
        return None, None
    ref = image.split("@", 1)[0]
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        last, tag = last.split(":", 1)
    product = clean(last, 64)
    version = tag if tag and _VERSION_RE.match(tag) else None
    return product, version


def _ready(pod: Mapping[str, Any]) -> bool:
    for cond in as_list(as_dict(pod.get("status")).get("conditions")):
        cond = as_dict(cond)
        if cond.get("type") == "Ready":
            return cond.get("status") == "True"
    return False


def agent_readiness(pods: list[dict[str, Any]]) -> dict[str, bool]:
    """node -> whether a Ready extorq-otel-collector pod runs there."""
    nodes: dict[str, bool] = {}
    for pod in pods:
        labels = as_dict(meta(pod).get("labels"))
        if (
            obj_namespace(pod) != AGENT_NAMESPACE
            or labels.get("app.kubernetes.io/name") != AGENT_NAME
        ):
            continue
        node = valid_k8s_name(as_dict(pod.get("spec")).get("nodeName"))
        if node:
            nodes[node] = nodes.get(node, False) or _ready(pod)
    return nodes


@dataclass
class Hierarchy:
    services: dict[str, Service] = field(default_factory=dict)
    instances: dict[str, ServiceInstance] = field(default_factory=dict)
    #: pod API uid -> (service id, service name, pod instance id), for k8s.event.observed
    pod_services: dict[str, tuple[str, str, str | None]] = field(default_factory=dict)
    #: "<ns>/<pod>" -> workload, for pod change events
    pod_workloads: dict[str, WorkloadRef] = field(default_factory=dict)
    #: workload key -> ServiceRef (for k8s.resource.* events about workloads/pods)
    refs: dict[str, ServiceRef] = field(default_factory=dict)
    #: node -> whether the log agent (extorq-otel-collector) is Ready there
    agents: dict[str, bool] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


def _adapter_for(ref: WorkloadRef) -> tuple[str, list[str]]:
    if ref == LAB_PORTAL:
        return WEBAPP_JSON_ADAPTER_ID, [
            SourceType.K8S_CONTAINER_LOG.value,
            SourceType.K8S_EVENTS.value,
        ]
    if (
        ref.namespace == "kube-system"
        and ref.kind == POD_WORKLOAD_KIND
        and ref.name.startswith("kube-apiserver-")
    ):
        return K8sAuditAdapter.adapter_id, [
            SourceType.K8S_AUDIT.value,
            SourceType.K8S_CONTAINER_LOG.value,
            SourceType.K8S_EVENTS.value,
        ]
    return K8sContainerLogAdapter.adapter_id, [
        SourceType.K8S_CONTAINER_LOG.value,
        SourceType.K8S_EVENTS.value,
    ]


def _category(ref: WorkloadRef) -> ServiceCategory:
    if ref == LAB_PORTAL:
        return ServiceCategory.WEB_APPLICATION
    if ref.namespace == AGENT_NAMESPACE and ref.name == AGENT_NAME:
        return ServiceCategory.SECURITY_AGENT
    if ref.namespace == "kube-system":
        return ServiceCategory.KUBERNETES_COMPONENT
    return ServiceCategory.UNKNOWN


def _coverage(
    ref: WorkloadRef, running_nodes: set[str], agents: Mapping[str, bool]
) -> tuple[MonitoringStatus, str]:
    if ref.namespace == AGENT_NAMESPACE and ref.name == AGENT_NAME:
        return (
            MonitoringStatus.UNMONITORED,
            "log agent itself: its own logs are excluded from collection (feedback loop); "
            "its health is visible through pod readiness and gateway ingest metrics",
        )
    if not running_nodes:
        return MonitoringStatus.UNMONITORED, "no running instances"
    missing = sorted(n for n in running_nodes if not agents.get(n))
    if missing:
        return (
            MonitoringStatus.DEGRADED,
            f"log agent {AGENT_NAME} not Ready on node(s): {', '.join(missing[:8])}",
        )
    return (
        MonitoringStatus.MONITORED,
        "stdout/stderr collection configured (agent Ready on "
        f"{', '.join(sorted(running_nodes)[:8])}); "
        "delivery is evaluated separately from node telemetry",
    )


def _container_ports(spec: Mapping[str, Any]) -> list[str]:
    ports = []
    for container in as_list(spec.get("containers"))[:16]:
        for port in as_list(as_dict(container).get("ports"))[:16]:
            port = as_dict(port)
            number = port.get("containerPort")
            if isinstance(number, int) and not isinstance(number, bool):
                ports.append(f"{clean(port.get('protocol'), 8) or 'TCP'}/{number}")
    return sorted(set(ports))[:32]


def _replicas(kind: str, obj: Mapping[str, Any]) -> dict[str, Any]:
    status = as_dict(obj.get("status"))
    spec = as_dict(obj.get("spec"))
    if kind in ("Deployment", "StatefulSet", "ReplicaSet"):
        return {
            "replicas_desired": spec.get("replicas"),
            "replicas_ready": status.get("readyReplicas", 0),
        }
    if kind == "DaemonSet":
        return {
            "replicas_desired": status.get("desiredNumberScheduled"),
            "replicas_ready": status.get("numberReady"),
        }
    return {}


def _ints(values: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in values.items() if isinstance(v, int) and not isinstance(v, bool)}


def _pod_state(pod: Mapping[str, Any]) -> str:
    phase = as_dict(pod.get("status")).get("phase")
    return _PHASE_STATE.get(phase, "unknown") if isinstance(phase, str) else "unknown"


def _container_state(status: Mapping[str, Any]) -> tuple[str, datetime | None]:
    state = as_dict(status.get("state"))
    if "running" in state:
        return "running", parse_time(as_dict(state["running"]).get("startedAt"))
    if "terminated" in state:
        term = as_dict(state["terminated"])
        code = term.get("exitCode")
        failed = isinstance(code, int) and not isinstance(code, bool) and code != 0
        return ("failed" if failed else "stopped"), parse_time(term.get("startedAt"))
    if "waiting" in state:
        return "pending", None
    return "unknown", None


def build_hierarchy(
    view: Mapping[str, list[dict[str, Any]]],
    owners: OwnerIndex,
    *,
    now: datetime,
    collector_id: str,
    first_seen: Callable[[str, datetime | None], datetime],
) -> Hierarchy:
    """Services and instances for everything listed this cycle (pure)."""
    out = Hierarchy()
    pods = view.get("Pod", [])
    agents = agent_readiness(pods)
    out.agents = dict(agents)
    workloads = top_level_workloads(view)
    pods_by_workload: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for pod in pods:
        ref = owners.workload_of(pod)
        if ref is None:
            out.notes.append("pod owner chain not resolvable this cycle")
            continue
        pods_by_workload[ref.key].append(pod)
        out.pod_workloads[f"{ref.namespace}/{meta(pod).get('name')}"] = ref
        if ref.kind == POD_WORKLOAD_KIND and ref.key not in workloads:
            workloads[ref.key] = (ref, pod)

    for key, (ref, obj) in sorted(workloads.items()):
        sid = ref.service_id
        if sid is None:
            out.notes.append("workload with an invalid name skipped")
            continue
        name = service_display_name(ref.namespace, ref.name)
        adapter_id, sources = _adapter_for(ref)
        members = pods_by_workload.get(key, [])
        running_nodes = {
            n
            for n in (
                valid_k8s_name(as_dict(p.get("spec")).get("nodeName"))
                for p in members
                if _pod_state(p) == "running"
            )
            if n
        }
        status, note = _coverage(ref, running_nodes, agents)
        spec = (
            pod_template({**obj, "kind": ref.kind})
            if ref.kind != POD_WORKLOAD_KIND
            else as_dict(obj.get("spec"))
        )
        main = as_dict((as_list(spec.get("containers")) or [{}])[0])
        product, version = image_product_version(main.get("image"))
        summary = summarize_k8s_object({**obj, "kind": ref.kind})
        images = clean_list(
            (as_dict(c).get("image") for c in as_list(spec.get("containers"))), 8, 256
        )
        attributes: dict[str, Any] = {
            "namespace": ref.namespace,
            "workload_kind": ref.kind,
            "workload_name": ref.name,
            "images": images,
            "container_ports": _container_ports(spec),
            "service_account": clean(spec.get("serviceAccountName"), 253),
            "risk_flags": risk_flags_for_summary(summary),
            "static_pod": True if ref.kind == POD_WORKLOAD_KIND and static_pod_key(obj) else None,
            "bare_pod": True if ref.kind == POD_WORKLOAD_KIND and not static_pod_key(obj) else None,
            "accepted_risk": accepted_risk(obj),
            "running_instances": sum(1 for p in members if _pod_state(p) == "running"),
            "running_node_asset_ids": [
                node_id for n in sorted(running_nodes)[:64] if (node_id := node_asset_id(n))
            ],
            "running_node_count": len(running_nodes),
            **_ints(_replicas(ref.kind, obj)),
        }
        created = parse_time(meta(obj).get("creationTimestamp"))
        out.services[sid] = Service(
            service_id=sid,
            asset_id=ASSET_ID,
            service_kind=ServiceKind.K8S_WORKLOAD,
            service_key=ref.key,
            name=name,
            category=_category(ref),
            product=product,
            version=version,
            discovered_via=[DiscoveryEvidence.K8S_API],
            adapter_id=adapter_id,
            adapter_support=AdapterSupport.IMPLEMENTED,
            monitoring_status=status,
            coverage_note=note,
            telemetry_sources=sources,
            endpoints=[],
            instance_count=len(members),
            attributes={k: v for k, v in attributes.items() if v not in (None, [])},
            first_seen=first_seen(sid, created),
            last_seen=now,
            observed_by=collector_id,
        )
        out.refs[key] = ServiceRef(service_id=sid, name=name, adapter_id="k8s-inventory")
        for pod in members:
            _pod_instances(out, ref, sid, name, pod, now=now, collector_id=collector_id)

    _k8s_services(out, view, owners, now=now, collector_id=collector_id, first_seen=first_seen)
    out.notes = sorted(set(out.notes))
    return out


def _pod_instances(
    out: Hierarchy,
    ref: WorkloadRef,
    sid: str,
    service_name: str,
    pod: Mapping[str, Any],
    *,
    now: datetime,
    collector_id: str,
) -> None:
    spec = as_dict(pod.get("spec"))
    status = as_dict(pod.get("status"))
    key = pod_instance_key(pod)
    if key is None:
        out.notes.append("pod without a usable uid omitted (no stable instance identity)")
        return
    # Every instance carries an asset_id (the gateway quarantines instances without one,
    # A-IC-2): the node it runs on once scheduled, else the cluster asset that manages it.
    # node_name stays None until the scheduler binds the pod; attributes.asset_scope =
    # "cluster" marks the exception.
    node = valid_k8s_name(spec.get("nodeName"))
    node_asset = node_asset_id(node)
    asset = node_asset or ASSET_ID
    if node_asset is None:
        out.notes.append("unscheduled pod instance attributed to the cluster asset")
    pod_name = clean(meta(pod).get("name"), 253)
    api_uid = clean(meta(pod).get("uid"), 64)
    piid = pod_instance_id(sid, key)
    restarts = 0
    container_statuses: list[tuple[dict[str, Any], str]] = []
    for group, label in (
        ("initContainerStatuses", "init"),
        ("containerStatuses", "main"),
        ("ephemeralContainerStatuses", "ephemeral"),
    ):
        for cs in as_list(status.get(group))[:32]:
            cs = as_dict(cs)
            container_statuses.append((cs, label))
            count = cs.get("restartCount")
            if isinstance(count, int) and not isinstance(count, bool):
                restarts += count
    static_key = static_pod_key(pod)
    out.instances[piid] = ServiceInstance(
        instance_id=piid,
        service_id=sid,
        asset_id=asset,
        instance_kind=InstanceKind.POD,
        instance_key=key,
        state=_pod_state(pod),
        namespace=ref.namespace,
        pod_name=pod_name,
        pod_uid=api_uid,
        node_name=node,
        workload_kind=ref.kind,
        workload_name=ref.name,
        started_at=parse_time(status.get("startTime")),
        observed_at=now,
        observed_by=collector_id,
        attributes={
            k: v
            for k, v in {
                "phase": clean(status.get("phase"), 32),
                # only on the exception, so scheduled instances keep their snapshot form
                "asset_scope": None if node_asset else "cluster",
                "scheduled": None if node_asset else node is not None,
                "qos_class": clean(status.get("qosClass"), 32),
                "ready": _ready(pod),
                "restart_count": restarts,
                "static_pod": True if static_key else None,
                "pod_ip": clean(status.get("podIP"), 64),
                "service_account": clean(spec.get("serviceAccountName"), 253),
            }.items()
            if v is not None
        },
    )
    if api_uid:
        out.pod_services[api_uid] = (sid, service_name, piid)
    for cs, label in container_statuses:
        bare, runtime = canonical_container_id(cs.get("containerID"))
        if bare is None:
            continue  # container not created yet: no runtime identity to report
        state, started = _container_state(cs)
        ciid = container_instance_id(sid, bare)
        restart_count = cs.get("restartCount")
        out.instances[ciid] = ServiceInstance(
            instance_id=ciid,
            service_id=sid,
            asset_id=asset,
            instance_kind=InstanceKind.CONTAINER,
            instance_key=bare,
            parent_instance_id=piid,
            state=state,
            namespace=ref.namespace,
            pod_name=pod_name,
            pod_uid=api_uid,
            container_name=clean(cs.get("name"), 253),
            container_id=bare,
            image=clean(cs.get("image"), 512),
            node_name=node,
            workload_kind=ref.kind,
            workload_name=ref.name,
            started_at=started,
            observed_at=now,
            observed_by=collector_id,
            attributes={
                k: v
                for k, v in {
                    "runtime": runtime,
                    "container_type": label,
                    "ready": cs.get("ready") if isinstance(cs.get("ready"), bool) else None,
                    "restart_count": restart_count
                    if isinstance(restart_count, int) and not isinstance(restart_count, bool)
                    else None,
                    "image_id": clean(cs.get("imageID"), 512),
                }.items()
                if v is not None
            },
        )


def _selector_matches(selector: Mapping[str, Any], labels: Mapping[str, Any]) -> bool:
    return bool(selector) and all(labels.get(k) == v for k, v in selector.items())


def _k8s_services(
    out: Hierarchy,
    view: Mapping[str, list[dict[str, Any]]],
    owners: OwnerIndex,
    *,
    now: datetime,
    collector_id: str,
    first_seen: Callable[[str, datetime | None], datetime],
) -> None:
    node_ips: list[str] = []
    for node in view.get("Node", []):
        for address in as_list(as_dict(node.get("status")).get("addresses")):
            address = as_dict(address)
            if address.get("type") == "InternalIP" and isinstance(address.get("address"), str):
                node_ips.append(address["address"])
    for svc in view.get("Service", []):
        namespace = obj_namespace(svc)
        name = valid_k8s_name(meta(svc).get("name"))
        if not namespace or not name:
            continue
        sid = k8s_service_service_id(namespace, name)
        if sid is None:
            continue
        spec = as_dict(svc.get("spec"))
        selector = {
            k: v
            for k, v in as_dict(spec.get("selector")).items()
            if isinstance(k, str) and isinstance(v, str)
        }
        backing: set[str] = set()
        categories: set[ServiceCategory] = set()
        for pod in view.get("Pod", []):
            if obj_namespace(pod) != namespace:
                continue
            if _selector_matches(selector, as_dict(meta(pod).get("labels"))):
                ref = owners.workload_of(pod)
                if ref is not None and ref.service_id:
                    backing.add(ref.key)
                    categories.add(_category(ref))
        endpoints: list[ServiceEndpoint] = []
        cluster_ips = [
            ip
            for ip in as_list(spec.get("clusterIPs")) or [spec.get("clusterIP")]
            if isinstance(ip, str) and ip not in ("", "None")
        ]
        for port in as_list(spec.get("ports"))[:16]:
            port = as_dict(port)
            protocol = str(port.get("protocol") or "TCP").lower()
            number = port.get("port")
            if (
                protocol not in ("tcp", "udp")
                or not isinstance(number, int)
                or isinstance(number, bool)
            ):
                continue
            addresses: list[str | None] = list(cluster_ips[:2]) or [None]
            for ip in addresses:
                endpoints.append(_endpoint(protocol, ip, number, "Service spec (ClusterIP)"))
            node_port = port.get("nodePort")
            if isinstance(node_port, int) and not isinstance(node_port, bool):
                for ip in node_ips[:8]:
                    endpoints.append(
                        _endpoint(protocol, ip, node_port, "Service spec (NodePort on every node)")
                    )
        summary_flags = []
        svc_type = clean(spec.get("type"), 32) or "ClusterIP"
        if svc_type in ("NodePort", "LoadBalancer"):
            summary_flags.append("node_port_exposure")
        if as_list(spec.get("externalIPs")):
            summary_flags.append("external_ips")
        display = service_display_name(namespace, name)
        out.services[sid] = Service(
            service_id=sid,
            asset_id=ASSET_ID,
            service_kind=ServiceKind.K8S_SERVICE,
            service_key=k8s_service_key(namespace, name),
            name=display,
            category=next(iter(categories)) if len(categories) == 1 else ServiceCategory.UNKNOWN,
            discovered_via=[DiscoveryEvidence.K8S_API],
            adapter_id=None,
            adapter_support=AdapterSupport.NONE,
            monitoring_status=MonitoringStatus.UNMONITORED,
            coverage_note=(
                "logical Kubernetes Service (virtual IP/ports implemented by kube-proxy): no "
                "per-connection telemetry is collected; traffic is visible only in the "
                "backing workloads' logs"
            ),
            telemetry_sources=[],
            endpoints=endpoints[:64],
            attributes={
                k: v
                for k, v in {
                    "namespace": namespace,
                    "type": svc_type,
                    "selector": [f"{k}={v}" for k, v in sorted(selector.items())][:16] or None,
                    "backing_workloads": sorted(backing)[:16] or None,
                    "session_affinity": clean(spec.get("sessionAffinity"), 32),
                    "external_traffic_policy": clean(spec.get("externalTrafficPolicy"), 32),
                    "risk_flags": summary_flags or None,
                    "accepted_risk": accepted_risk(svc),
                }.items()
                if v is not None
            },
            first_seen=first_seen(sid, parse_time(meta(svc).get("creationTimestamp"))),
            last_seen=now,
            observed_by=collector_id,
        )


def _endpoint(protocol: str, address: str | None, port: int, basis: str) -> ServiceEndpoint:
    return ServiceEndpoint(
        protocol=protocol,
        address=address,
        port=port,
        exposure=exposure_of(address),
        # Declared by the API object; kube-proxy implements it with packet rules, so there
        # is no socket owner to observe (PLAN 10.1: never "confirmed" without one).
        attribution=PortAttribution.INFERRED,
        attribution_basis=basis,
    )


__all__ = [
    "AGENT_NAME",
    "AGENT_NAMESPACE",
    "Hierarchy",
    "K8sEventsAdapter",
    "agent_readiness",
    "build_hierarchy",
    "image_product_version",
]

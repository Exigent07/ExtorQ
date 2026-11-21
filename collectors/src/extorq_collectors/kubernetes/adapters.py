"""Kubernetes telemetry adapters (owner: B2), registered in the shared service registry.

These describe what ExtorQ collects for Kubernetes services and what it never
collects. The telemetry itself is produced elsewhere:

* ``k8s-container-log`` (+ B1's ``webapp-json`` schema for lab-portal lines):
  container stdout/stderr shipped by the
  OTel Collector DaemonSet and normalised by ``extorq.ingest.otlp_k8s`` (lab-portal
  JSON lines become app.auth.* / app.authz.denied / http.request);
* ``k8s-audit``: kube-apiserver audit log (same pipeline);
* ``k8s-events``: core/v1 Events polled by the inventory collector.

They never match host-discovery candidates (no products/units/executables), so
registering them does not change Linux/macOS discovery results.
"""

from __future__ import annotations

from typing import ClassVar

from extorq.contracts.catalog import SourceType
from extorq.contracts.service import AdapterSupport, ServiceCategory
from extorq_collectors.services.base import ServiceAdapter
from extorq_collectors.services.registry import register


@register
class K8sContainerLogAdapter(ServiceAdapter):
    adapter_id: ClassVar[str] = "k8s-container-log"
    support: ClassVar[AdapterSupport] = AdapterSupport.IMPLEMENTED
    category: ClassVar[ServiceCategory] = ServiceCategory.OTHER
    source_types: ClassVar[tuple[SourceType, ...]] = (SourceType.K8S_CONTAINER_LOG,)
    description: ClassVar[str] = "Kubernetes container stdout/stderr (OTel file_log, CRI format)"
    collects: ClassVar[tuple[str, ...]] = (
        "container stdout/stderr lines (bounded to 16 KiB, secrets redacted)",
        "pod uid, container id, namespace, node and workload metadata",
    )
    never_collects: ClassVar[tuple[str, ...]] = (
        "the collector's own logs (excluded to avoid a feedback loop)",
        "process, file or network activity inside containers (no runtime instrumentation)",
    )


@register
class K8sAuditAdapter(ServiceAdapter):
    adapter_id: ClassVar[str] = "k8s-audit"
    support: ClassVar[AdapterSupport] = AdapterSupport.IMPLEMENTED
    category: ClassVar[ServiceCategory] = ServiceCategory.KUBERNETES_COMPONENT
    source_types: ClassVar[tuple[SourceType, ...]] = (SourceType.K8S_AUDIT,)
    description: ClassVar[str] = "kube-apiserver audit log (policy infra/kind/audit-policy.yaml)"
    collects: ClassVar[tuple[str, ...]] = (
        "who did what to which object, response code, source IPs, user agent",
        "compact security summary of pod and RBAC request/response bodies",
        "Pod Security and authorization decisions",
    )
    never_collects: ClassVar[tuple[str, ...]] = (
        "Secret, ConfigMap, TokenRequest and TokenReview bodies (Metadata level only)",
        "full request/response bodies (only a bounded security summary is forwarded)",
    )


@register
class K8sEventsAdapter(ServiceAdapter):
    adapter_id: ClassVar[str] = "k8s-events"
    support: ClassVar[AdapterSupport] = AdapterSupport.IMPLEMENTED
    category: ClassVar[ServiceCategory] = ServiceCategory.KUBERNETES_COMPONENT
    source_types: ClassVar[tuple[SourceType, ...]] = (SourceType.K8S_EVENTS,)
    description: ClassVar[str] = "core/v1 Events (reason, type, involved object, message)"
    collects: ClassVar[tuple[str, ...]] = ("Event reason/type/count/message per involved object",)
    never_collects: ClassVar[tuple[str, ...]] = (
        "Events older than the API server's event TTL (about 1 h) when the collector was down",
    )


#: lab-portal JSON security log (schema lab-portal.log.v1) inside Kubernetes. The id is
#: B1's VM adapter id (same log schema), so it is deliberately NOT registered here:
#: two implemented registrations of one id would replace each other in the shared
#: registry. On Kubernetes the lines arrive through the container-log pipeline and are
#: parsed by ``otlp_k8s`` only for the lab-portal container in namespace extorq-apps.
WEBAPP_JSON_ADAPTER_ID = "webapp-json"
WEBAPP_JSON_SOURCES: tuple[SourceType, ...] = (SourceType.K8S_CONTAINER_LOG,)

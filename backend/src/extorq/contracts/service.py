"""Service-aware monitoring contracts (schema 1.1, additive).

Hierarchy (docs/architecture.md, "Service model"):

    Asset (host, Kubernetes node, cluster, repository)
      └─ Service            - something that runs on / belongs to the asset
           (host OS service, application, Kubernetes workload, Kubernetes Service)
           └─ ServiceInstance - a concrete process, container or Pod
                └─ telemetry sources → SecurityEvents (event.service), findings
                   (PostureFinding.service_id), alerts (DetectionAlert.service_ids)

Rules that keep this honest:

* A Service exists only when there is evidence for it (``discovered_via`` is
  never empty). Discovery never assumes a process is a network service, and a
  listening port is attributed to a service only with stated confidence
  (``PortAttribution``): ``confirmed`` (socket owner observed), ``inferred``
  (configuration or well-known port), ``unknown``.
* Coverage is explicit: ``adapter_support`` says whether ExtorQ *can* collect
  service telemetry (implemented / planned / none) and ``monitoring_status``
  whether it *is* collecting it right now (monitored / degraded / unmonitored).
  Unsupported and unmonitored services are reported, never hidden.
* ``K8S_SERVICE`` is a logical Kubernetes Service object; it is never conflated
  with a host operating-system service (``HOST_SERVICE``).
* Service records carry configuration *references* (paths), never configuration
  contents, credentials, FTP file contents, HTTP authorization headers or
  database query text.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field

from extorq.contracts.catalog import SourceType
from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    Attributes,
    ContractModel,
    HexId,
    Identifier,
    IpAddress,
    MediumStr,
    Port,
    SchemaVersion,
    ShortStr,
    UtcDatetime,
)


class ServiceKind(StrEnum):
    #: Operating-system managed service (systemd unit, launchd job).
    HOST_SERVICE = "host_service"
    #: Application identified by configuration/process evidence without its own
    #: service-manager unit (e.g. a web app behind a reverse proxy).
    APPLICATION = "application"
    #: Kubernetes workload controller (Deployment, DaemonSet, StatefulSet, Job, CronJob)
    #: or a bare Pod without a controller.
    K8S_WORKLOAD = "k8s_workload"
    #: Logical Kubernetes Service resource (virtual IP / ports). NOT an OS service.
    K8S_SERVICE = "k8s_service"


class ServiceCategory(StrEnum):
    SSH = "ssh"
    HTTP_SERVER = "http_server"
    WEB_APPLICATION = "web_application"
    SERVICE_MANAGER = "service_manager"
    FTP = "ftp"
    DATABASE = "database"
    DNS = "dns"
    CACHE = "cache"
    KUBERNETES_COMPONENT = "kubernetes_component"
    SECURITY_AGENT = "security_agent"
    OTHER = "other"
    UNKNOWN = "unknown"


class AdapterSupport(StrEnum):
    #: A working, tested telemetry adapter exists for this service type.
    IMPLEMENTED = "implemented"
    #: An extension point is defined but no telemetry is collected yet.
    PLANNED = "planned"
    #: No adapter exists or is planned.
    NONE = "none"


class MonitoringStatus(StrEnum):
    #: Adapter enabled and its telemetry sources are fresh.
    MONITORED = "monitored"
    #: Adapter enabled but its sources are stale, failing or partially unavailable.
    DEGRADED = "degraded"
    #: Discovered but not collected (unsupported, planned, disabled or not configured).
    UNMONITORED = "unmonitored"


class DiscoveryEvidence(StrEnum):
    SYSTEMD_UNIT = "systemd_unit"
    LAUNCHD_JOB = "launchd_job"
    PROCESS = "process"
    LISTENING_SOCKET = "listening_socket"
    CONFIGURATION = "configuration"
    K8S_API = "k8s_api"
    ADAPTER_CONFIG = "adapter_config"


class PortAttribution(StrEnum):
    #: Socket owner (pid/process) observed and belongs to this service's instance.
    CONFIRMED = "confirmed"
    #: Attributed from configuration or a well-known port, without owner evidence.
    INFERRED = "inferred"
    #: Port observed but owner not determinable with the available privileges.
    UNKNOWN = "unknown"


class ServiceEndpoint(ContractModel):
    protocol: Literal["tcp", "udp"]
    #: Bind address as observed; None if not reported.
    address: IpAddress | None = None
    port: Port
    #: Derived from the bind address: 127.0.0.0/8 / ::1 → loopback, RFC1918/ULA → private,
    #: 0.0.0.0 / :: → any, otherwise unknown.
    exposure: Literal["loopback", "private", "any", "unknown"] = "unknown"
    attribution: PortAttribution
    attribution_basis: ShortStr | None = None


class ServiceRef(ContractModel):
    """Reference from a SecurityEvent to the service that produced it.

    Set only when the producing adapter can genuinely attribute the record (e.g.
    sshd journald lines → the ssh service; container log → its Pod's workload).
    """

    service_id: HexId
    name: ShortStr
    instance_id: HexId | None = None
    adapter_id: Identifier | None = None


class Service(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    #: identity.service_id(asset_id, service_kind, service_key)
    service_id: HexId
    #: Parent asset: host, Kubernetes node or cluster, repository.
    asset_id: AssetId
    service_kind: ServiceKind
    #: Natural key: systemd unit name, launchd label, '<namespace>/<kind>/<name>' for
    #: workloads, '<namespace>/<name>' for Kubernetes Services, configured app name.
    service_key: MediumStr
    name: ShortStr
    category: ServiceCategory
    #: Product only when evidenced (unit name, executable, image), e.g. "openssh", "nginx".
    product: ShortStr | None = None
    #: Version only when genuinely observed (package inventory, banner in config); never guessed.
    version: ShortStr | None = None
    discovered_via: list[DiscoveryEvidence] = Field(min_length=1, max_length=8)
    adapter_id: Identifier | None = None
    adapter_support: AdapterSupport
    monitoring_status: MonitoringStatus
    #: Explanation for the coverage state, e.g. "planned adapter: vsftpd log parsing".
    coverage_note: MediumStr | None = None
    telemetry_sources: list[SourceType] = Field(default_factory=list, max_length=16)
    endpoints: list[ServiceEndpoint] = Field(default_factory=list, max_length=64)
    #: Configuration file references (paths only, never contents).
    config_refs: list[MediumStr] = Field(default_factory=list, max_length=16)
    #: Instances currently observed (summary; full detail in ServiceInstance records).
    instance_count: int | None = Field(default=None, ge=0)
    last_telemetry_at: UtcDatetime | None = None
    attributes: Attributes = Field(default_factory=dict)
    first_seen: UtcDatetime
    last_seen: UtcDatetime
    #: False marks a service that is no longer observed (tombstone).
    present: bool = True
    observed_by: Identifier


class InstanceKind(StrEnum):
    PROCESS = "process"
    CONTAINER = "container"
    POD = "pod"


class ServiceInstance(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    #: identity.instance_id(service_id, instance_kind, instance_key)
    instance_id: HexId
    service_id: HexId
    #: Where it runs: host asset or Kubernetes node asset (None if not reported).
    asset_id: AssetId | None = None
    instance_kind: InstanceKind
    #: pid + start time for processes, container id for containers, pod uid for Pods.
    instance_key: MediumStr
    #: e.g. container → its Pod instance.
    parent_instance_id: HexId | None = None
    state: Literal["running", "stopped", "pending", "failed", "unknown"] = "unknown"
    pid: int | None = Field(default=None, ge=0)
    process_name: ShortStr | None = None
    user: ShortStr | None = None
    namespace: ShortStr | None = None
    pod_name: ShortStr | None = None
    pod_uid: ShortStr | None = None
    container_name: ShortStr | None = None
    container_id: ShortStr | None = None
    image: MediumStr | None = None
    node_name: ShortStr | None = None
    workload_kind: ShortStr | None = None
    workload_name: ShortStr | None = None
    started_at: UtcDatetime | None = None
    observed_at: UtcDatetime
    #: False marks an instance that disappeared (tombstone).
    present: bool = True
    observed_by: Identifier
    attributes: Attributes = Field(default_factory=dict)

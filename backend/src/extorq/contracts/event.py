"""SecurityEvent: the normalised event envelope (schema 1.0).

Separate concepts (never conflate them):
  raw observation  -> ``raw`` (sanitized excerpt) + ``provenance.raw_sha256``
  normalized event -> this model
  security finding -> :mod:`extorq.contracts.finding`
  detection alert  -> :mod:`extorq.contracts.alert`
  correlation      -> :mod:`extorq.contracts.context`
  AI assessment    -> :mod:`extorq.contracts.ai`
  analyst state    -> :class:`extorq.contracts.alert.AnalystState`

Unknown values MUST remain ``None``. Collectors never invent fields (for
example, they never copy an IP into ``network.src_ip`` unless the source
reported it as the peer address).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from extorq.contracts.catalog import SourceType
from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    AssetType,
    Attributes,
    CollectionMethod,
    ContractModel,
    EventCategory,
    EventTypeStr,
    HexId,
    Identifier,
    IpAddress,
    Labels,
    LongStr,
    MediumStr,
    Outcome,
    Port,
    SchemaVersion,
    Severity,
    Sha256Hex,
    ShortStr,
    UtcDatetime,
)
from extorq.contracts.service import ServiceRef

MAX_EVENT_BYTES = 64 * 1024


class ActorType(StrEnum):
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    PROCESS = "process"
    GITHUB_USER = "github_user"
    GITHUB_APP = "github_app"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class SourceInfo(ContractModel):
    source_type: SourceType
    collector_id: Identifier
    collector_version: ShortStr
    collection_method: CollectionMethod
    #: Source-native identifier (journald cursor, audit id, commit sha ...), if any.
    source_native_id: ShortStr | None = None


class Actor(ContractModel):
    type: ActorType = ActorType.UNKNOWN
    name: ShortStr | None = None
    id: ShortStr | None = None
    groups: list[ShortStr] = Field(default_factory=list, max_length=32)
    authenticated: bool | None = None


class Resource(ContractModel):
    type: ShortStr | None = None
    name: ShortStr | None = None
    id: ShortStr | None = None
    namespace: ShortStr | None = None
    path: MediumStr | None = None


class Network(ContractModel):
    src_ip: IpAddress | None = None
    src_port: Port | None = None
    dst_ip: IpAddress | None = None
    dst_port: Port | None = None
    protocol: Literal["tcp", "udp", "icmp", "unix", "other"] | None = None
    direction: Literal["inbound", "outbound", "local", "unknown"] | None = None


class ProcessInfo(ContractModel):
    pid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    name: ShortStr | None = None
    executable: MediumStr | None = None
    #: Redacted and truncated command line. Never store secrets passed as args.
    command_line: MediumStr | None = None
    user: ShortStr | None = None
    uid: int | None = Field(default=None, ge=0)


class HttpInfo(ContractModel):
    method: ShortStr | None = None
    #: Path only. Query strings and fragments are stripped before ingestion.
    route: MediumStr | None = None
    status_code: int | None = Field(default=None, ge=100, le=599)
    #: Request/trace id ONLY when genuinely propagated by the source (e.g. nginx $request_id).
    request_id: ShortStr | None = None
    user_agent: MediumStr | None = None
    host: ShortStr | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    bytes_sent: int | None = Field(default=None, ge=0)


class KubernetesInfo(ContractModel):
    cluster: ShortStr | None = None
    namespace: ShortStr | None = None
    pod_name: ShortStr | None = None
    pod_uid: ShortStr | None = None
    container_name: ShortStr | None = None
    #: Runtime container id as bare 64-hex (the runtime name lives in
    #: ServiceInstance.attributes.runtime), only when the source reports it.
    container_id: ShortStr | None = None
    node_name: ShortStr | None = None
    workload_kind: ShortStr | None = None
    workload_name: ShortStr | None = None
    service_account: ShortStr | None = None
    verb: ShortStr | None = None
    api_group: ShortStr | None = None
    resource: ShortStr | None = None
    subresource: ShortStr | None = None
    object_name: ShortStr | None = None
    audit_id: ShortStr | None = None
    stage: ShortStr | None = None
    response_code: int | None = Field(default=None, ge=0, le=999)
    user: ShortStr | None = None
    user_groups: list[ShortStr] = Field(default_factory=list, max_length=32)
    source_ips: list[IpAddress] = Field(default_factory=list, max_length=16)
    user_agent: MediumStr | None = None


class GitHubInfo(ContractModel):
    repository: ShortStr | None = None
    ref: ShortStr | None = None
    commit_sha: ShortStr | None = None
    workflow_path: ShortStr | None = None
    workflow_name: ShortStr | None = None
    workflow_run_id: int | None = Field(default=None, ge=0)
    run_attempt: int | None = Field(default=None, ge=0)
    event_name: ShortStr | None = None
    actor_login: ShortStr | None = None
    conclusion: ShortStr | None = None


class Provenance(ContractModel):
    parser: Identifier
    parser_version: ShortStr
    #: SHA-256 of the original raw record before redaction/truncation.
    raw_sha256: Sha256Hex | None = None
    truncated: bool = False
    redaction_count: int = Field(default=0, ge=0)


class SecurityEvent(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    event_id: HexId
    event_type: EventTypeStr
    category: EventCategory
    asset_id: AssetId
    asset_type: AssetType
    source: SourceInfo
    #: When the activity happened according to the source (UTC).
    event_time: UtcDatetime
    #: When the collector read the record (UTC). Ingestion time is added server-side.
    observed_time: UtcDatetime | None = None
    action: ShortStr | None = None
    outcome: Outcome = Outcome.UNKNOWN
    #: Severity reported by the *source* (e.g. syslog priority). Not a detection verdict.
    severity_hint: Severity | None = None
    actor: Actor | None = None
    resource: Resource | None = None
    network: Network | None = None
    process: ProcessInfo | None = None
    http: HttpInfo | None = None
    kubernetes: KubernetesInfo | None = None
    github: GitHubInfo | None = None
    #: Service that produced the record, when the adapter can genuinely attribute it (1.1).
    service: ServiceRef | None = None
    #: Sanitized, human-readable one-line message (attacker-controlled content!).
    message: MediumStr | None = None
    attributes: Attributes = Field(default_factory=dict)
    labels: Labels = Field(default_factory=dict)
    #: Sanitized source evidence excerpt (redacted, truncated). Untrusted content.
    raw: LongStr | None = None
    provenance: Provenance

    @model_validator(mode="after")
    def _bounded_size(self) -> SecurityEvent:
        size = len(self.model_dump_json().encode("utf-8"))
        if size > MAX_EVENT_BYTES:
            raise ValueError(f"event serialises to {size} bytes (limit {MAX_EVENT_BYTES})")
        return self

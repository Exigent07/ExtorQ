"""Shared primitives for ExtorQ data contracts (schema version 1.0).

Design rules (see docs/data-model.md):

* Every contract model inherits from :class:`ContractModel`, which forbids unknown
  fields so producers cannot smuggle unvalidated data into storage.
* All timestamps are timezone-aware and normalised to UTC. Naive timestamps are
  rejected rather than guessed.
* Unknown values stay unknown: optional fields default to ``None``; never fill a
  field with a placeholder that looks like real telemetry.
* Strings are bounded so a single record cannot exhaust storage or memory.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

#: 1.1 = additive service-model fields (Service, ServiceInstance, event.service, ...).
#: 1.0 records remain valid; consumers must tolerate both.
SCHEMA_VERSION = "1.1"
SchemaVersion = Annotated[str, StringConstraints(pattern=r"^1\.[01]$")]


class ContractModel(BaseModel):
    """Base class for every versioned contract model."""

    # allow_inf_nan=False: NaN/Infinity are not valid JSON and would poison canonical
    # identities and storage (F-IC-1).
    model_config = ConfigDict(extra="forbid", populate_by_name=True, allow_inf_nan=False)


# ── Time ──────────────────────────────────────────────────────────────


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("timestamp must be timezone-aware (UTC); naive timestamps are rejected")
    return value.astimezone(UTC)


UtcDatetime = Annotated[datetime, AfterValidator(_ensure_utc)]


def utc_now() -> datetime:
    """Current time as an aware UTC datetime (millisecond precision, matching storage)."""
    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


# ── Bounded strings and identifiers ───────────────────────────────────

ShortStr = Annotated[str, StringConstraints(max_length=256)]
MediumStr = Annotated[str, StringConstraints(max_length=2048)]
LongStr = Annotated[str, StringConstraints(max_length=16384)]

#: Lower-case identifier for collectors, producers, scanners and rules components.
Identifier = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{1,127}$")]
#: Asset identifiers are namespaced and lower-case, e.g. ``linux:lab-vm-01``,
#: ``k8s:extorq-lab``, ``github:exigent07/extorq-lab``, ``macos:workstation-01``.
AssetId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._:/-]{2,199}$")]
#: 128-bit deterministic identifiers rendered as 32 lower-case hex characters.
HexId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
#: Full SHA-256 digests (64 hex characters).
Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
#: Rule identifiers such as ``VM-001``, ``K8S-002``, ``GH-001``, ``CORR-001``.
RuleId = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]{1,15}-[0-9]{3}$")]
#: Simulation run identifiers (lower-case alphanumerics, 8-32 chars).
SimulationRunId = Annotated[str, StringConstraints(pattern=r"^[a-z0-9]{8,32}$")]
#: Dotted event type such as ``auth.ssh.login_failed``.
EventTypeStr = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,5}$")]
#: MITRE ATT&CK technique id, e.g. ``T1110`` or ``T1543.002``.
MitreTechnique = Annotated[str, StringConstraints(pattern=r"^T[0-9]{4}(\.[0-9]{3})?$")]
SemVer = Annotated[str, StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")]


def _normalize_ip(value: str) -> str:
    return str(ipaddress.ip_address(value.strip()))


#: Normalised textual IPv4/IPv6 address (validated, canonical form).
IpAddress = Annotated[str, AfterValidator(_normalize_ip)]
Port = Annotated[int, Field(ge=0, le=65535)]

# ── Bounded free-form maps ────────────────────────────────────────────

_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
_MAX_ATTR_KEYS = 64
_MAX_ATTR_STR = 2048
_MAX_ATTR_LIST = 64
_MAX_ATTR_LIST_ITEM = 512

Scalar = str | int | float | bool | None
AttributeValue = str | int | float | bool | None | list[str | int | float | bool]


def _bound_attributes(value: dict[str, Any]) -> dict[str, Any]:
    if len(value) > _MAX_ATTR_KEYS:
        raise ValueError(f"at most {_MAX_ATTR_KEYS} attribute keys are allowed")
    for key, item in value.items():
        if not _KEY_RE.match(key):
            raise ValueError(
                f"invalid attribute key {key!r} (expected ^[a-z0-9][a-z0-9_.-]{{0,63}}$)"
            )
        if isinstance(item, str) and len(item) > _MAX_ATTR_STR:
            raise ValueError(f"attribute {key!r} exceeds {_MAX_ATTR_STR} characters")
        if isinstance(item, list):
            if len(item) > _MAX_ATTR_LIST:
                raise ValueError(f"attribute {key!r} list exceeds {_MAX_ATTR_LIST} items")
            for element in item:
                if isinstance(element, str) and len(element) > _MAX_ATTR_LIST_ITEM:
                    raise ValueError(
                        f"attribute {key!r} list item exceeds {_MAX_ATTR_LIST_ITEM} chars"
                    )
    return value


#: Source-specific normalised fields. Values are scalars or short scalar lists.
Attributes = Annotated[dict[str, AttributeValue], AfterValidator(_bound_attributes)]


def _bound_labels(value: dict[str, str]) -> dict[str, str]:
    if len(value) > 32:
        raise ValueError("at most 32 labels are allowed")
    for key, item in value.items():
        if not _KEY_RE.match(key):
            raise ValueError(f"invalid label key {key!r}")
        if len(item) > 256:
            raise ValueError(f"label {key!r} exceeds 256 characters")
    return value


Labels = Annotated[dict[str, str], AfterValidator(_bound_labels)]

# ── Enumerations ──────────────────────────────────────────────────────


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetType(StrEnum):
    MACOS_HOST = "macos_host"
    LINUX_HOST = "linux_host"
    KUBERNETES_CLUSTER = "kubernetes_cluster"
    #: Physical/virtual node of a cluster (asset id "k8s:<cluster>/node/<name>").
    KUBERNETES_NODE = "kubernetes_node"
    KUBERNETES_NAMESPACE = "kubernetes_namespace"
    KUBERNETES_WORKLOAD = "kubernetes_workload"
    GITHUB_ACCOUNT = "github_account"
    GITHUB_REPOSITORY = "github_repository"


class Environment(StrEnum):
    LAB = "lab"
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    UNKNOWN = "unknown"


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    HTTP = "http"
    PERSISTENCE = "persistence"
    CONFIGURATION = "configuration"
    PACKAGE = "package"
    KUBERNETES_API = "kubernetes_api"
    KUBERNETES_WORKLOAD = "kubernetes_workload"
    SOURCE_CONTROL = "source_control"
    CI_CD = "ci_cd"
    SECURITY_PRODUCT = "security_product"
    APPLICATION = "application"
    COLLECTOR = "collector"
    OTHER = "other"


class CollectionMethod(StrEnum):
    SSH_PULL = "ssh_pull"
    NATIVE_COMMAND = "native_command"
    API_POLL = "api_poll"
    API_WATCH = "api_watch"
    FILE_TAIL = "file_tail"
    OTEL_FILELOG = "otel_filelog"
    SCANNER = "scanner"
    SIMULATION_CONTROL = "simulation_control"


class HealthStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    FAILED = "failed"
    DISABLED = "disabled"
    UNKNOWN = "unknown"

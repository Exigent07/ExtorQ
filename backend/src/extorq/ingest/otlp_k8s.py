"""OTLP/HTTP JSON logs from the extorq-lab OTel Collector -> SecurityEvents.

Owner: B2. Imported lazily by A's gateway endpoint ``POST /v1/otlp/v1/logs``::

    events, failures = normalize_otlp_logs(payload, producer_id=..., received_at=...)

``failures`` holds ``(record_index, reason)`` for log records that could not be
normalised (the gateway quarantines them). ``record_index`` is the zero-based
position of the log record in document order across all ``resourceLogs`` /
``scopeLogs``. Records that are *intentionally* not converted (audit stages other
than ResponseComplete/Panic, see below) are neither events nor failures; use
:func:`normalize_otlp_logs_detailed` to obtain their count. Envelope-level
problems (not an OTLP logs document) raise :class:`OtlpPayloadError`.

Two record sources, distinguished by the resource attribute ``extorq.source``
that the collector sets (docs/telemetry/kubernetes.md):

* ``audit``: the body is one kube-apiserver audit event (JSON text). Becomes
  ``k8s.api.request``. Only the ResponseComplete and Panic stages are converted,
  with one verified exception: requests that FAIL AUTHENTICATION (HTTP 401) are
  only ever audited at stage ResponseStarted by the API server's
  failed-authentication filter, so ``ResponseStarted`` + 401 is converted too.
  Request/response bodies are never forwarded: ``attributes.request_summary``
  carries a bounded summary of security-relevant fields only.
* ``container``: a CRI container log line (parsed by the collector's container
  operator). lab-portal JSON lines (schema ``lab-portal.log.v1``, owned by B1)
  from the lab-portal workload become ``app.auth.*`` / ``app.authz.denied`` /
  ``http.request``; everything else becomes ``k8s.container.log``.

All telemetry is untrusted: every string is sanitised, bounded and passed
through :func:`extorq.common.redaction.redact_text`; nothing is ever used to build
queries or commands. Unknown values stay ``None``.

The pure helpers :func:`summarize_k8s_object` and :func:`risk_flags_for_summary`
are shared with the Kubernetes inventory collector so audit events and inventory
diffs use one risk vocabulary.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

from pydantic import ValidationError

from extorq.common.redaction import TRUNCATION_MARKER, redact_text, sanitize_untrusted
from extorq.contracts.catalog import EVENT_CATALOG, SourceType
from extorq.contracts.common import (
    AssetType,
    CollectionMethod,
    Outcome,
)
from extorq.contracts.event import (
    Actor,
    ActorType,
    HttpInfo,
    KubernetesInfo,
    Network,
    Provenance,
    Resource,
    SecurityEvent,
    SimulationTag,
    SourceInfo,
)
from extorq.contracts.identity import (
    canonical_json,
    event_id,
    instance_id,
    service_id,
    sha256_hex,
)
from extorq.contracts.service import InstanceKind, ServiceKind, ServiceRef

#: 1.1.0: container.id + image, ServiceRef to the workload service (schema 1.1).
PARSER_VERSION = "1.1.0"
AUDIT_PARSER = "otlp-k8s-audit"
CONTAINER_PARSER = "otlp-k8s-container"
LAB_PORTAL_PARSER = "otlp-k8s-lab-portal"

ASSET_ID = "k8s:extorq-lab"
CLUSTER_NAME = "extorq-lab"

#: Adapter ids carried in ServiceRef.adapter_id (events.adapter_id).
AUDIT_ADAPTER = "k8s-audit"
CONTAINER_LOG_ADAPTER = "k8s-container-log"
#: Same adapter id as B1's VM adapter for the lab-portal JSON schema.
LAB_PORTAL_ADAPTER = "webapp-json"
#: Workload kind used for pods without a workload controller (bare and static pods).
POD_WORKLOAD_KIND = "Pod"

#: (namespace, container) pairs whose stdout is parsed as lab-portal.log.v1.
#: Restricting by workload prevents any other pod from forging application
#: security events by printing look-alike JSON.
LAB_PORTAL_WORKLOADS: frozenset[tuple[str, str]] = frozenset({("extorq-apps", "lab-portal")})

MAX_LOG_RECORDS = 5000
MAX_AUDIT_BODY_CHARS = 1024 * 1024
MAX_CONTAINER_BODY_CHARS = 256 * 1024
MESSAGE_LIMIT = 2048
RAW_LIMIT = 8192
ATTR_STR_LIMIT = 2048
SUMMARY_LIMIT = 2000
NAME_LIMIT = 256

_STAGES_CONVERTED = frozenset({"ResponseComplete", "Panic"})
_SIM_RE = re.compile(r"extorq-sim-([a-z0-9]{8,32})(?![a-z0-9])")
_AUDIT_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
_KLOG_RE = re.compile(r"^([IWEF])\d{4} \d{2}:\d{2}:\d{2}")
_LEVEL_JSON_RE = re.compile(r'"(?:level|severity|lvl)"\s*:\s*"([A-Za-z]{1,10})"')
_LEVEL_LOGFMT_RE = re.compile(r"(?:^|\s)level=\"?([A-Za-z]{1,10})\b")
_KLOG_LEVELS = {"I": "info", "W": "warning", "E": "error", "F": "fatal"}

#: Linux capabilities that materially weaken container isolation.
DANGEROUS_CAPABILITIES = frozenset(
    {
        "ALL",
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "DAC_OVERRIDE",
        "SYS_RAWIO",
        "SYS_BOOT",
        "SYS_TIME",
        "BPF",
        "PERFMON",
        "NET_RAW",
        "SETFCAP",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "SYSLOG",
        "SYS_RESOURCE",
    }
)
_ESCALATION_VERBS = frozenset({"escalate", "bind", "impersonate"})
_RBAC_KINDS = frozenset({"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"})
_RBAC_RESOURCES = frozenset({"roles", "clusterroles", "rolebindings", "clusterrolebindings"})
_WORKLOAD_TEMPLATE_KINDS = frozenset(
    {
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "ReplicaSet",
        "Job",
        "ReplicationController",
    }
)


class OtlpPayloadError(ValueError):
    """The request body is not an OTLP/JSON ExportLogsServiceRequest."""


# ── Kubernetes service hierarchy (shared with the inventory collector) ──
#
#   asset k8s:extorq-lab (cluster)
#     ├─ asset k8s:extorq-lab/node/<node>                 (AssetType kubernetes_node)
#     ├─ Service k8s_workload  key "<ns>/<Kind>/<name>"    (top-level controller, or
#     │    │                                               "<ns>/Pod/<name>" without one)
#     │    └─ ServiceInstance pod        key = pod UID (kubelet UID for static pods)
#     │         └─ ServiceInstance container key = bare container id (64 hex)
#     └─ Service k8s_service   key "<ns>/<name>"           (logical Service object;
#                                                          never a host OS service)
#
# Both the normaliser (events) and the inventory collector (Service/ServiceInstance
# records) derive ids ONLY through these helpers, so references always match.

_K8S_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_K8S_KIND_RE = re.compile(r"^[A-Z][A-Za-z0-9]{0,62}$")
#: Runtime container id: optional "<runtime>://" prefix + hex id.
_CONTAINER_ID_RE = re.compile(r"^(?:([a-z][a-z0-9.+-]{0,31})://)?([0-9a-f]{12,128})$")
#: kubelet uses the static-pod config hash (32 hex, no dashes) as the pod UID in node
#: log paths and runtime labels; API-created pods have RFC 4122 UUIDs.
_STATIC_POD_UID_RE = re.compile(r"^[0-9a-f]{32}$")


def valid_k8s_name(value: Any) -> str | None:
    """A DNS-1123 name as Kubernetes validates it, else None (never 'repaired')."""
    if isinstance(value, str) and len(value) <= 253 and _K8S_NAME_RE.match(value):
        return value
    return None


def node_asset_id(node_name: Any) -> str | None:
    """Asset id of a cluster node: ``k8s:extorq-lab/node/<name>``."""
    name = valid_k8s_name(node_name)
    if name is None or len(name) > 180:
        return None
    return f"{ASSET_ID}/node/{name}"


def canonical_container_id(value: Any) -> tuple[str | None, str | None]:
    """``(bare id, runtime)`` from ``containerd://<hex>`` or ``<hex>``; ``(None, None)`` if invalid.

    The bare hex id is the canonical form in events (``kubernetes.container_id``) and
    container ServiceInstances, because the OTel processor reports the id without the
    runtime prefix while the API reports ``<runtime>://<id>``.
    """
    if not isinstance(value, str):
        return None, None
    match = _CONTAINER_ID_RE.match(value.strip())
    if not match:
        return None, None
    return match.group(2), match.group(1)


def is_static_pod_uid(uid: Any) -> bool:
    return isinstance(uid, str) and bool(_STATIC_POD_UID_RE.match(uid))


def service_display_name(namespace: str, name: str) -> str:
    return sanitize_untrusted(f"{namespace}/{name}", NAME_LIMIT)


def workload_service_key(namespace: str, kind: str, name: str) -> str:
    return f"{namespace}/{kind}/{name}"


def workload_service_id(namespace: str, kind: str, name: str) -> str | None:
    """service_id of a workload (top-level controller or controller-less Pod)."""
    if not (valid_k8s_name(namespace) and valid_k8s_name(name) and _K8S_KIND_RE.match(kind)):
        return None
    return service_id(
        ASSET_ID, ServiceKind.K8S_WORKLOAD.value, workload_service_key(namespace, kind, name)
    )


def k8s_service_key(namespace: str, name: str) -> str:
    return f"{namespace}/{name}"


def k8s_service_service_id(namespace: str, name: str) -> str | None:
    """service_id of a logical Kubernetes Service object (not an OS service)."""
    if not (valid_k8s_name(namespace) and valid_k8s_name(name)):
        return None
    return service_id(ASSET_ID, ServiceKind.K8S_SERVICE.value, k8s_service_key(namespace, name))


def pod_instance_id(workload_sid: str, pod_key: str) -> str:
    return instance_id(workload_sid, InstanceKind.POD.value, pod_key)


def container_instance_id(workload_sid: str, bare_container_id: str) -> str:
    return instance_id(workload_sid, InstanceKind.CONTAINER.value, bare_container_id)


def apiserver_service_ref(node_name: Any) -> ServiceRef | None:
    """kube-apiserver static pod of ``node_name`` (writer of that node's audit log)."""
    node = valid_k8s_name(node_name)
    if node is None:
        return None
    pod = f"kube-apiserver-{node}"
    sid = workload_service_id("kube-system", POD_WORKLOAD_KIND, pod)
    if sid is None:
        return None
    return ServiceRef(
        service_id=sid, name=service_display_name("kube-system", pod), adapter_id=AUDIT_ADAPTER
    )


@dataclass
class NormalizationResult:
    events: list[SecurityEvent] = field(default_factory=list)
    failures: list[tuple[int, str]] = field(default_factory=list)
    skipped: int = 0
    skipped_reasons: Counter[str] = field(default_factory=Counter)


class _RecordError(Exception):
    """Per-record normalisation failure; the message is a secret-free reason code."""


# ── public entry points ───────────────────────────────────────────────


def normalize_otlp_logs(
    payload: dict[str, Any], *, producer_id: str, received_at: datetime
) -> tuple[list[SecurityEvent], list[tuple[int, str]]]:
    """Normalise an OTLP/JSON logs request into SecurityEvents (see module docstring)."""
    result = normalize_otlp_logs_detailed(payload, producer_id=producer_id, received_at=received_at)
    return result.events, result.failures


def normalize_otlp_logs_detailed(
    payload: dict[str, Any], *, producer_id: str, received_at: datetime
) -> NormalizationResult:
    if received_at.tzinfo is None:
        raise ValueError("received_at must be timezone-aware")
    if not isinstance(payload, Mapping):
        raise OtlpPayloadError("payload must be a JSON object")
    resource_logs = payload.get("resourceLogs")
    if resource_logs is None:
        resource_logs = []
    if not isinstance(resource_logs, list):
        raise OtlpPayloadError("resourceLogs must be an array")
    ctx = _Context(producer_id=producer_id, received_at=received_at.astimezone(UTC))
    result = NormalizationResult()
    for index, resource, record in _iter_records(resource_logs):
        if index >= MAX_LOG_RECORDS:
            result.failures.append((index, "too_many_log_records"))
            continue
        try:
            outcome = _normalize_record(ctx, resource, record)
        except _RecordError as exc:
            result.failures.append((index, str(exc)))
            continue
        except ValidationError as exc:
            result.failures.append((index, _validation_reason(exc)))
            continue
        if isinstance(outcome, SecurityEvent):
            result.events.append(outcome)
        else:
            result.skipped += 1
            result.skipped_reasons[outcome] += 1
    return result


# ── OTLP structure ────────────────────────────────────────────────────


@dataclass(frozen=True)
class _Context:
    producer_id: str
    received_at: datetime


def _iter_records(
    resource_logs: list[Any],
) -> Iterator[tuple[int, dict[str, Any], Any]]:
    index = 0
    for rl in resource_logs:
        if not isinstance(rl, Mapping):
            raise OtlpPayloadError("resourceLogs entries must be objects")
        resource_obj = rl.get("resource")
        if resource_obj is not None and not isinstance(resource_obj, Mapping):
            raise OtlpPayloadError("resource must be an object")
        resource = _attributes_to_dict((resource_obj or {}).get("attributes"))
        scope_logs = rl.get("scopeLogs")
        if scope_logs is None:
            scope_logs = []
        if not isinstance(scope_logs, list):
            raise OtlpPayloadError("scopeLogs must be an array")
        for sl in scope_logs:
            if not isinstance(sl, Mapping):
                raise OtlpPayloadError("scopeLogs entries must be objects")
            records = sl.get("logRecords")
            if records is None:
                records = []
            if not isinstance(records, list):
                raise OtlpPayloadError("logRecords must be an array")
            for record in records:
                yield index, resource, record
                index += 1


def _any_value(value: Any) -> Any:
    """Decode an OTLP/JSON AnyValue into a Python value."""
    if not isinstance(value, Mapping):
        return None
    if "stringValue" in value:
        return value["stringValue"] if isinstance(value["stringValue"], str) else None
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "intValue" in value:
        try:
            return int(value["intValue"])
        except (TypeError, ValueError):
            return None
    if "doubleValue" in value:
        try:
            return float(value["doubleValue"])
        except (TypeError, ValueError):
            return None
    if "arrayValue" in value:
        items = (value["arrayValue"] or {}).get("values") or []
        return [_any_value(v) for v in items[:256]] if isinstance(items, list) else None
    if "kvlistValue" in value:
        return _attributes_to_dict((value["kvlistValue"] or {}).get("values"))
    if "bytesValue" in value:
        return None  # binary bodies are not interpreted
    return None


def _attributes_to_dict(attrs: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if not isinstance(attrs, list):
        return out
    for item in attrs[:256]:
        if isinstance(item, Mapping) and isinstance(item.get("key"), str):
            out[item["key"]] = _any_value(item.get("value"))
    return out


def _unix_nano(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        ns = int(value)
    except (TypeError, ValueError):
        return None
    # Reject 0 ("unset" in OTLP) and values outside 1970..2200.
    if ns <= 0 or ns > 7_258_118_400_000_000_000:
        return None
    return ns


def _ns_to_datetime(ns: int) -> datetime:
    seconds, rem = divmod(ns, 1_000_000_000)
    return datetime.fromtimestamp(seconds, UTC) + timedelta(microseconds=rem // 1000)


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str) or not 10 <= len(value) <= 40:
        return None
    text = value.strip()
    match = re.match(r"^(.*T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$", text)
    if not match:
        return None
    base, frac, tz = match.groups()
    frac = (frac or "")[:7]  # at most microseconds
    try:
        parsed = datetime.fromisoformat(f"{base}{frac}{'+00:00' if tz == 'Z' else tz}")
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


# ── record dispatch ───────────────────────────────────────────────────


def _record_source(resource: dict[str, Any], attrs: dict[str, Any]) -> str:
    declared = resource.get("extorq.source")
    if declared in ("audit", "container"):
        return str(declared)
    file_name = attrs.get("log.file.name")
    if isinstance(file_name, str) and file_name.startswith("kube-apiserver-audit"):
        return "audit"
    if resource.get("k8s.pod.uid") or "log.iostream" in attrs:
        return "container"
    raise _RecordError("unknown_record_source")


def _normalize_record(ctx: _Context, resource: dict[str, Any], record: Any) -> SecurityEvent | str:
    if not isinstance(record, Mapping):
        raise _RecordError("log_record_not_object")
    cluster = resource.get("k8s.cluster.name")
    if cluster is not None and cluster != CLUSTER_NAME:
        raise _RecordError("unexpected_cluster_name")
    attrs = _attributes_to_dict(record.get("attributes"))
    source = _record_source(resource, attrs)
    if source == "audit":
        return _normalize_audit(ctx, resource, record)
    return _normalize_container(ctx, resource, record, attrs)


# ── shared helpers ────────────────────────────────────────────────────


class _Redactor:
    """Sanitise + redact untrusted text, counting replacements for provenance."""

    def __init__(self) -> None:
        self.count = 0
        self.truncated = False

    def text(self, value: Any, limit: int) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            value = str(value)
        redacted, n = redact_text(value)
        self.count += n
        cleaned = sanitize_untrusted(redacted, limit)
        if cleaned.endswith(TRUNCATION_MARKER) and not redacted.endswith(TRUNCATION_MARKER):
            self.truncated = True
        return cleaned or None


def _name(value: Any, limit: int = NAME_LIMIT) -> str | None:
    """Sanitise an identifier-like value (names, namespaces, resources)."""
    if value is None:
        return None
    if not isinstance(value, str):
        value = str(value)
    cleaned = sanitize_untrusted(value, limit)
    return cleaned or None


def _valid_ip(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def simulation_tag(*candidates: Any) -> SimulationTag | None:
    """SimulationTag when any candidate (str or list of str) carries ``extorq-sim-<run_id>``."""
    return _simulation_tag(*candidates)


def _simulation_tag(*candidates: Any) -> SimulationTag | None:
    for candidate in candidates:
        if isinstance(candidate, str):
            match = _SIM_RE.search(candidate)
            if match:
                return SimulationTag(run_id=match.group(1))
        elif isinstance(candidate, list):
            tag = _simulation_tag(*candidate)
            if tag:
                return tag
    return None


def _validation_reason(exc: ValidationError) -> str:
    """Secret-free reason: error locations and types only, never input values."""
    parts = []
    for err in exc.errors()[:3]:
        loc = ".".join(str(p) for p in err.get("loc", ()))[:80]
        parts.append(f"{loc}:{err.get('type', 'error')}")
    return ("invalid_event:" + ";".join(parts))[:512]


def _bounded_attr_list(values: list[str], limit: int = 64, item_limit: int = 512) -> list[str]:
    out: list[str] = []
    for value in values[:limit]:
        cleaned = sanitize_untrusted(value, item_limit)
        if cleaned:
            out.append(cleaned)
    return out


def _collector_version(resource: dict[str, Any]) -> str:
    value = resource.get("extorq.collector.version")
    cleaned = _name(value, 64) if isinstance(value, str) else None
    return cleaned or "unknown"


def _collector_id(producer_id: str) -> str:
    candidate = producer_id.strip().lower()
    if re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,127}", candidate):
        return candidate
    return "k8s-otel-extorq-lab"


def _source(
    ctx: _Context, resource: dict[str, Any], source_type: SourceType, native_id: str | None
) -> SourceInfo:
    return SourceInfo(
        source_type=source_type,
        collector_id=_collector_id(ctx.producer_id),
        collector_version=_collector_version(resource),
        collection_method=CollectionMethod.OTEL_FILELOG,
        source_native_id=native_id[:256] if native_id else None,
    )


def _category(event_type: str) -> Any:
    return EVENT_CATALOG[event_type].category


# ── Kubernetes object analysis (shared with the inventory collector) ──


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _str_list(values: Any, limit: int = 16, item_limit: int = NAME_LIMIT) -> list[str]:
    out = []
    for item in _as_list(values)[:limit]:
        name = _name(item, item_limit) if isinstance(item, str) else None
        if name:
            out.append(name)
    return out


def _pod_spec_of(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Return the pod spec of a Pod, a workload template or a CronJob."""
    kind = obj.get("kind")
    spec = _as_dict(obj.get("spec"))
    if kind == "CronJob":
        return (
            _as_dict(
                _as_dict(
                    _as_dict(_as_dict(spec.get("jobTemplate")).get("spec")).get("template")
                ).get("spec")
            )
            or None
        )
    if kind in _WORKLOAD_TEMPLATE_KINDS:
        return _as_dict(_as_dict(spec.get("template")).get("spec")) or None
    if kind == "Pod" or kind is None:
        # Partial objects (merge patches, ephemeralcontainers) carry no kind.
        keys = {
            "containers",
            "initContainers",
            "ephemeralContainers",
            "volumes",
            "hostPID",
            "hostNetwork",
            "hostIPC",
            "securityContext",
        }
        if keys & spec.keys():
            return spec
    return None


def summarize_pod_spec(spec: dict[str, Any]) -> dict[str, Any]:
    """Security-relevant fields of a pod spec (only those genuinely present)."""
    summary: dict[str, Any] = {}
    for key, out in (
        ("hostPID", "host_pid"),
        ("hostNetwork", "host_network"),
        ("hostIPC", "host_ipc"),
    ):
        if spec.get(key) is True:
            summary[out] = True
    pod_sc = _as_dict(spec.get("securityContext"))
    pod_uid = pod_sc.get("runAsUser")
    privileged: list[str] = []
    root: list[str] = []
    escalation: list[str] = []
    caps: set[str] = set()
    images: list[str] = []
    containers = 0
    for group in ("initContainers", "containers", "ephemeralContainers"):
        for container in _as_list(spec.get(group))[:64]:
            container = _as_dict(container)
            containers += 1
            cname = _name(container.get("name"), 128) or f"#{containers}"
            sc = _as_dict(container.get("securityContext"))
            if sc.get("privileged") is True:
                privileged.append(cname)
            uid = sc.get("runAsUser", pod_uid)
            if uid == 0 and not isinstance(uid, bool):
                root.append(cname)
            if sc.get("allowPrivilegeEscalation") is True:
                escalation.append(cname)
            for cap in _as_list(_as_dict(sc.get("capabilities")).get("add"))[:32]:
                if isinstance(cap, str):
                    caps.add(sanitize_untrusted(cap.upper().removeprefix("CAP_"), 32))
            image = container.get("image")
            if isinstance(image, str) and len(images) < 8:
                images.append(sanitize_untrusted(image, NAME_LIMIT))
    host_paths = []
    for volume in _as_list(spec.get("volumes"))[:64]:
        host_path = _as_dict(_as_dict(volume).get("hostPath"))
        path = host_path.get("path")
        if isinstance(path, str):
            host_paths.append(sanitize_untrusted(path, NAME_LIMIT))
    if privileged:
        summary["privileged"] = privileged[:16]
    if host_paths:
        summary["host_path"] = sorted(set(host_paths))[:16]
    if caps:
        summary["added_capabilities"] = sorted(caps)[:16]
    if root:
        summary["run_as_root"] = root[:16]
    if escalation:
        summary["allow_privilege_escalation"] = escalation[:16]
    sa = spec.get("serviceAccountName")
    if isinstance(sa, str):
        summary["service_account"] = _name(sa, 128)
    if spec.get("automountServiceAccountToken") is not None:
        # Key avoids the word "token": secret redaction would rewrite "..._token":false
        # and corrupt the JSON summary.
        summary["automount_service_account"] = bool(spec.get("automountServiceAccountToken"))
    if images:
        summary["images"] = images
    if containers:
        summary["containers"] = containers
    return summary


def _summarize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, short in (
        ("verbs", "verbs"),
        ("apiGroups", "api_groups"),
        ("resources", "resources"),
        ("resourceNames", "resource_names"),
        ("nonResourceURLs", "non_resource_urls"),
    ):
        values = rule.get(key)
        if isinstance(values, list):
            out[short] = _str_list(values, 16, 128)
    return out


def summarize_rbac_object(obj: dict[str, Any]) -> dict[str, Any]:
    kind = obj.get("kind")
    summary: dict[str, Any] = {}
    if kind in ("Role", "ClusterRole"):
        rules = [_summarize_rule(_as_dict(r)) for r in _as_list(obj.get("rules"))[:32]]
        summary["rules"] = rules
        if obj.get("aggregationRule") is not None:
            summary["aggregated"] = True
    elif kind in ("RoleBinding", "ClusterRoleBinding"):
        ref = _as_dict(obj.get("roleRef"))
        if ref:
            summary["role_ref"] = f"{_name(ref.get('kind'), 64)}/{_name(ref.get('name'), 128)}"
        subjects = []
        for subject in _as_list(obj.get("subjects"))[:32]:
            subject = _as_dict(subject)
            skind = _name(subject.get("kind"), 32) or "?"
            sname = _name(subject.get("name"), 128) or "?"
            sns = _name(subject.get("namespace"), 64)
            subjects.append(f"{skind}:{sns}/{sname}" if sns else f"{skind}:{sname}")
        summary["subjects"] = subjects
    return summary


_CONTAINER_REF_RE = re.compile(r"/(initContainers|containers|ephemeralContainers)/(\d+|-)")
_HOST_NS_KEYS = {"hostPID": "host_pid", "hostNetwork": "host_network", "hostIPC": "host_ipc"}
_POD_SPEC_LIST_KEYS = ("containers", "initContainers", "ephemeralContainers", "volumes")


def _container_ref(path: str) -> str:
    match = _CONTAINER_REF_RE.search(path)
    return f"{match.group(1)}[{match.group(2)}]" if match else sanitize_untrusted(path, 128)


def _json_patch_summary(ops: list[Any]) -> dict[str, Any]:
    """Summary of an RFC 6902 JSON patch: security keys detected from op paths/values."""
    paths: list[str] = []
    found: dict[str, Any] = {}

    def merge(sub: Mapping[str, Any]) -> None:
        for key, val in sub.items():
            if key in (
                "privileged",
                "host_path",
                "added_capabilities",
                "run_as_root",
                "allow_privilege_escalation",
            ) and isinstance(val, list):
                found[key] = sorted(set(found.get(key, [])) | set(val))[:16]
            elif key in ("host_pid", "host_network", "host_ipc") and val is True:
                found[key] = True

    for op in ops[:128]:
        op = _as_dict(op)
        path = op.get("path")
        if not isinstance(path, str):
            continue
        if len(paths) < 16:
            paths.append(sanitize_untrusted(f"{op.get('op', '?')} {path}", 256))
        leaf = path.rsplit("/", 1)[-1]
        value = op.get("value")
        ref = _container_ref(path)
        if leaf in _HOST_NS_KEYS and value is True:
            merge({_HOST_NS_KEYS[leaf]: True})
        elif leaf == "privileged" and value is True:
            merge({"privileged": [ref]})
        elif leaf == "allowPrivilegeEscalation" and value is True:
            merge({"allow_privilege_escalation": [ref]})
        elif leaf == "runAsUser" and value == 0 and not isinstance(value, bool):
            merge({"run_as_root": [ref]})
        elif isinstance(value, dict):
            if leaf == "securityContext" and _CONTAINER_REF_RE.search(path):
                spec: dict[str, Any] = {"containers": [{"name": ref, "securityContext": value}]}
            elif leaf == "capabilities":
                spec = {"containers": [{"name": ref, "securityContext": {"capabilities": value}}]}
            elif "hostPath" in value:
                spec = {"volumes": [value]}
            elif "image" in value or "securityContext" in value:
                spec = {"containers": [value]}
            else:
                spec = _pod_spec_of({"spec": value}) or {}
            merge(summarize_pod_spec(spec))
        elif isinstance(value, list) and leaf in _POD_SPEC_LIST_KEYS:
            merge(summarize_pod_spec({leaf: value}))
        elif isinstance(value, list) and path.endswith("/capabilities/add"):
            merge(
                summarize_pod_spec(
                    {
                        "containers": [
                            {"name": ref, "securityContext": {"capabilities": {"add": value}}}
                        ]
                    }
                )
            )
        elif isinstance(value, str) and path.endswith("/capabilities/add/-"):
            merge(
                {"added_capabilities": [sanitize_untrusted(value.upper().removeprefix("CAP_"), 32)]}
            )
    return {"patch": "json", "ops": len(ops), "paths": paths, **found}


def summarize_k8s_object(obj: Any, *, resource: str | None = None) -> dict[str, Any] | None:
    """Compact, sanitised summary of the security-relevant fields of an object.

    Handles Pods (and partial pod objects such as merge patches and
    ephemeral-container updates), workload templates, CronJobs, RBAC objects and
    RFC 6902 JSON patches. Returns ``None`` when nothing security-relevant can be
    extracted. Values are never copied wholesale (no env, args, annotations).
    """
    if isinstance(obj, list):
        return _json_patch_summary(obj)
    if not isinstance(obj, dict):
        return None
    kind = obj.get("kind")
    if kind in _RBAC_KINDS:
        return {"kind": kind, **summarize_rbac_object(obj)}
    if kind is None and resource in _RBAC_RESOURCES:
        # merge patch on an RBAC object: summarise whatever RBAC fields are present
        inferred = {
            "roles": "Role",
            "clusterroles": "ClusterRole",
            "rolebindings": "RoleBinding",
            "clusterrolebindings": "ClusterRoleBinding",
        }[resource]
        partial = summarize_rbac_object({**obj, "kind": inferred})
        return {"kind": inferred, "partial": True, **partial} if partial else None
    spec = _pod_spec_of(obj)
    if spec is None:
        return None
    summary = summarize_pod_spec(spec)
    if kind is not None:
        summary = {"kind": _name(kind, 64), **summary}
    else:
        summary = {"partial": True, **summary}
    return summary


def risk_flags_for_summary(summary: Mapping[str, Any] | None) -> list[str]:
    """Risk vocabulary shared by audit events and inventory diffs (sorted, unique)."""
    if not summary:
        return []
    flags: set[str] = set()
    if summary.get("privileged"):
        flags.add("privileged")
    for key in ("host_pid", "host_network", "host_ipc"):
        if summary.get(key):
            flags.add(key)
    host_paths = summary.get("host_path") or []
    if host_paths:
        flags.add("host_path")
        if "/" in host_paths:
            flags.add("host_path_root")
    caps = set(summary.get("added_capabilities") or [])
    if caps:
        flags.add("added_capabilities")
        if caps & DANGEROUS_CAPABILITIES:
            flags.add("dangerous_capabilities")
    if summary.get("run_as_root"):
        flags.add("run_as_root")
    if summary.get("allow_privilege_escalation"):
        flags.add("allow_privilege_escalation")
    rules = summary.get("rules") or []
    for rule in rules:
        verbs = set(rule.get("verbs") or [])
        resources = set(rule.get("resources") or [])
        groups = set(rule.get("api_groups") or [])
        if "*" in verbs:
            flags.add("wildcard_verbs")
        if "*" in resources or any(r.startswith("*") for r in resources):
            flags.add("wildcard_resources")
        if "*" in groups:
            flags.add("wildcard_api_groups")
        if "*" in verbs and ("*" in resources) and ("*" in groups or not groups):
            flags.add("full_wildcard_rule")
        if verbs & _ESCALATION_VERBS:
            flags.add("escalation_verbs")
        reads = verbs & {"get", "list", "watch", "*"}
        if reads and ({"secrets", "*"} & resources):
            flags.add("secrets_access")
        if ({"create", "get", "*"} & verbs) and (
            {"pods/exec", "pods/attach", "pods/*", "*"} & resources
        ):
            flags.add("pod_exec")
        if rule.get("non_resource_urls") and "*" in (rule.get("non_resource_urls") or []):
            flags.add("wildcard_non_resource_urls")
    role_ref = summary.get("role_ref")
    if isinstance(role_ref, str) and role_ref == "ClusterRole/cluster-admin":
        flags.add("cluster_admin")
    for subject in summary.get("subjects") or []:
        if subject == "User:system:anonymous":
            flags.add("binds_anonymous")
        elif subject == "Group:system:unauthenticated":
            flags.add("binds_unauthenticated")
        elif subject == "Group:system:authenticated":
            flags.add("binds_authenticated")
        elif subject == "Group:system:serviceaccounts" or subject.startswith(
            "Group:system:serviceaccounts:"
        ):
            flags.add("binds_all_service_accounts")
        elif subject.startswith("ServiceAccount:") and subject.endswith("/default"):
            flags.add("binds_default_service_account")
    return sorted(flags)


def metadata_only_request(request: Any) -> list[str] | None:
    """Metadata keys touched when a patch/update body changes ONLY ``metadata``, else None.

    Merge/strategic patches: the body has no key besides metadata (kind/apiVersion
    allowed). RFC 6902 patches: every op path is under /metadata/. A full update (PUT)
    carries the whole object and is never classified as metadata-only.
    """
    if isinstance(request, list):
        paths = [op.get("path") for op in request[:128] if isinstance(op, Mapping)]
        if paths and all(isinstance(p, str) and p.startswith("/metadata/") for p in paths):
            return sorted({p.split("/")[2] for p in paths if isinstance(p, str)})[:8]
        return None
    if isinstance(request, Mapping) and set(request) - {"kind", "apiVersion"} == {"metadata"}:
        metadata = request.get("metadata")
        if isinstance(metadata, Mapping):
            return sorted(str(k)[:64] for k in metadata if isinstance(k, str))[:8]
    return None


def _bound_summary(summary: dict[str, Any]) -> tuple[str, bool]:
    """Canonical JSON of ``summary`` within SUMMARY_LIMIT characters."""
    text = canonical_json(summary)
    if len(text) <= SUMMARY_LIMIT:
        return text, False
    trimmed = dict(summary)
    for cap in (8, 4, 2, 1):
        for key, value in list(trimmed.items()):
            if isinstance(value, list):
                trimmed[key] = value[:cap]
        trimmed["truncated"] = True
        text = canonical_json(trimmed)
        if len(text) <= SUMMARY_LIMIT:
            return text, True
    for optional in ("images", "paths", "resource_names", "rules", "subjects"):
        trimmed.pop(optional, None)
        text = canonical_json(trimmed)
        if len(text) <= SUMMARY_LIMIT:
            return text, True
    return canonical_json({"truncated": True, "kind": summary.get("kind")}), True


# ── audit events ──────────────────────────────────────────────────────


def _audit_actor(user: dict[str, Any], code: int | None, red: _Redactor) -> Actor:
    username = user.get("username") if isinstance(user.get("username"), str) else None
    groups = [g for g in _as_list(user.get("groups")) if isinstance(g, str)]
    if username is None:
        actor_type = ActorType.UNKNOWN
    elif username.startswith("system:serviceaccount:"):
        actor_type = ActorType.SERVICE_ACCOUNT
    elif username == "system:anonymous":
        actor_type = ActorType.USER
    elif username.startswith("system:"):
        actor_type = ActorType.SYSTEM
    else:
        actor_type = ActorType.USER
    if code == 401:
        authenticated: bool | None = False
    elif "system:unauthenticated" in groups:
        authenticated = False
    elif "system:authenticated" in groups:
        authenticated = True
    else:
        authenticated = None
    return Actor(
        type=actor_type,
        name=_name(username),
        id=_name(user.get("uid")),
        groups=_bounded_attr_list(groups, 32, 256),
        authenticated=authenticated,
    )


def _first_extra(user: dict[str, Any], key: str) -> str | None:
    values = _as_dict(user.get("extra")).get(key)
    if isinstance(values, list) and values and isinstance(values[0], str):
        return _name(values[0], 256)
    return None


def _denied_by(code: int | None, annotations: dict[str, Any], psa_violation: bool) -> str | None:
    if code == 401:
        return "authentication"
    if code != 403:
        return None
    if annotations.get("authorization.k8s.io/decision") == "forbid":
        return "authorization"
    if psa_violation:
        return "pod_security"
    return "admission"


def _outcome_for_code(code: int | None) -> Outcome:
    if code is None:
        return Outcome.UNKNOWN
    if code in (401, 403):
        return Outcome.DENIED
    if code < 400:
        return Outcome.SUCCESS
    return Outcome.FAILURE


def _audit_raw(event: dict[str, Any], red: _Redactor) -> str | None:
    """Evidence excerpt: the audit event minus bodies and authenticator extras."""
    reduced = {k: v for k, v in event.items() if k not in ("requestObject", "responseObject")}
    omitted: list[str] = [k for k in ("requestObject", "responseObject") if k in event]
    user = dict(_as_dict(event.get("user")))
    if "extra" in user:
        user["extra"] = sorted(_as_dict(user["extra"]).keys())
        omitted.append("user.extra.values")
    reduced["user"] = user
    if isinstance(reduced.get("impersonatedUser"), dict) and "extra" in reduced["impersonatedUser"]:
        reduced["impersonatedUser"] = {
            k: v for k, v in reduced["impersonatedUser"].items() if k != "extra"
        }
        omitted.append("impersonatedUser.extra")
    if omitted:
        reduced["extorqOmitted"] = omitted
    return red.text(canonical_json(reduced), RAW_LIMIT)


def _normalize_audit(
    ctx: _Context, resource: dict[str, Any], record: Mapping[str, Any]
) -> SecurityEvent | str:
    body = _any_value(record.get("body"))
    if isinstance(body, str):
        if len(body) > MAX_AUDIT_BODY_CHARS:
            raise _RecordError("audit_body_too_large")
        raw_text = body
        try:
            event = json.loads(body)
        except ValueError as exc:
            raise _RecordError("audit_body_not_json") from exc
    elif isinstance(body, dict):
        event = body
        raw_text = canonical_json(body)
    else:
        raise _RecordError("audit_body_missing")
    if not isinstance(event, dict):
        raise _RecordError("audit_body_not_object")
    if event.get("kind") != "Event" or not str(event.get("apiVersion", "")).startswith(
        "audit.k8s.io/"
    ):
        raise _RecordError("audit_unexpected_kind")
    stage = event.get("stage")
    response = _as_dict(event.get("responseStatus"))
    code_raw = response.get("code")
    code = code_raw if isinstance(code_raw, int) and not isinstance(code_raw, bool) else None
    if stage not in _STAGES_CONVERTED and not (stage == "ResponseStarted" and code == 401):
        return f"audit_stage_{stage if isinstance(stage, str) else 'missing'}"[:64]
    audit_id = event.get("auditID")
    if not isinstance(audit_id, str) or not _AUDIT_ID_RE.match(audit_id):
        raise _RecordError("audit_missing_or_invalid_audit_id")

    red = _Redactor()
    user = _as_dict(event.get("user"))
    object_ref = _as_dict(event.get("objectRef"))
    annotations = {
        k: v
        for k, v in _as_dict(event.get("annotations")).items()
        if isinstance(k, str) and isinstance(v, str)
    }
    verb = _name(event.get("verb"), 64)
    resource_name = _name(object_ref.get("resource"), 128)
    subresource = _name(object_ref.get("subresource"), 64)
    namespace = _name(object_ref.get("namespace"), 253)
    object_name = _name(object_ref.get("name"), 253)
    api_group = None
    if object_ref:
        api_group = _name(object_ref.get("apiGroup"), 128) or ""

    request_uri = event.get("requestURI") if isinstance(event.get("requestURI"), str) else None
    uri_path = None
    dry_run = False
    if request_uri:
        split = urlsplit(request_uri[:4096])
        uri_path = _name(split.path, 2048)
        dry_run = "All" in parse_qs(split.query).get("dryRun", [])

    received = _parse_rfc3339(event.get("requestReceivedTimestamp"))
    stage_ts = _parse_rfc3339(event.get("stageTimestamp"))
    observed_ns = _unix_nano(record.get("observedTimeUnixNano"))
    observed = _ns_to_datetime(observed_ns) if observed_ns else None
    event_time = received or stage_ts or observed or ctx.received_at

    source_ips = [ip for ip in (_valid_ip(v) for v in _as_list(event.get("sourceIPs"))[:16]) if ip]
    username = user.get("username") if isinstance(user.get("username"), str) else None

    # Request summary: RBAC writes prefer the response (full post-change object).
    summary: dict[str, Any] | None = None
    candidates: list[Any] = []
    if resource_name in _RBAC_RESOURCES and code is not None and code < 300:
        candidates.append(event.get("responseObject"))
    candidates.append(event.get("requestObject"))
    for candidate in candidates:
        if candidate is None:
            continue
        if isinstance(candidate, dict) and candidate.get("kind") == "Status":
            continue
        summary = summarize_k8s_object(candidate, resource=resource_name)
        if summary:
            break

    attributes: dict[str, Any] = {
        "audit_level": _name(event.get("level"), 32),
        "api_version": _name(object_ref.get("apiVersion"), 64),
        "stage_timestamp": stage_ts.isoformat().replace("+00:00", "Z") if stage_ts else None,
        "response_reason": _name(response.get("reason"), 64),
    }
    summary_truncated = False
    if summary:
        text, summary_truncated = _bound_summary(summary)
        attributes["request_summary"] = text
        flags = risk_flags_for_summary(summary)
        if flags:
            attributes["risk_flags"] = flags
    if verb in ("patch", "update") and code is not None and code < 300:
        touched = metadata_only_request(event.get("requestObject"))
        if touched is not None:
            # e.g. kubectl annotate/label: the RBAC/pod content itself did not change.
            attributes["metadata_only_change"] = True
            attributes["metadata_fields_changed"] = touched
    message_text = response.get("message") if isinstance(response.get("message"), str) else None
    psa_violation = bool(message_text and "violates PodSecurity" in message_text and code == 403)
    if message_text:
        attributes["response_message"] = red.text(message_text, 1024)
    if psa_violation:
        attributes["pod_security_violation"] = red.text(message_text, ATTR_STR_LIMIT)
    for key, attr in (
        ("pod-security.kubernetes.io/enforce-policy", "pod_security_enforce_policy"),
        ("pod-security.kubernetes.io/audit-violations", "pod_security_audit_violations"),
        ("pod-security.kubernetes.io/exempt", "pod_security_exempt"),
        ("pod-security.kubernetes.io/error", "pod_security_error"),
        ("authorization.k8s.io/decision", "authz_decision"),
        ("authorization.k8s.io/reason", "authz_reason"),
        ("authentication.kubernetes.io/issued-credential-id", "issued_credential_id"),
        ("authentication.k8s.io/legacy-token-autogenerated-secret", "legacy_token_secret"),
        ("authentication.k8s.io/legacy-token-invalidated", "legacy_token_invalidated"),
        ("validation.policy.admission.k8s.io/validation_failure", "admission_policy_failure"),
    ):
        if key in annotations:
            attributes[attr] = red.text(annotations[key], ATTR_STR_LIMIT)
    attributes["denied_by"] = _denied_by(code, annotations, psa_violation)
    if dry_run:
        attributes["dry_run"] = True
    attributes["credential_id"] = _first_extra(user, "authentication.kubernetes.io/credential-id")
    attributes["caller_pod_name"] = _first_extra(user, "authentication.kubernetes.io/pod-name")
    attributes["caller_pod_uid"] = _first_extra(user, "authentication.kubernetes.io/pod-uid")
    attributes["caller_node_name"] = _first_extra(user, "authentication.kubernetes.io/node-name")
    impersonated = _as_dict(event.get("impersonatedUser"))
    impersonated_user = None
    if impersonated:
        impersonated_user = _name(impersonated.get("username"))
        attributes["impersonated_user"] = impersonated_user
        imp_groups = [g for g in _as_list(impersonated.get("groups")) if isinstance(g, str)]
        if imp_groups:
            attributes["impersonated_groups"] = _bounded_attr_list(imp_groups, 32, 256)
    attributes = {k: v for k, v in attributes.items() if v is not None and v != []}

    service_account = None
    if username and username.startswith("system:serviceaccount:"):
        parts = username.split(":")
        if len(parts) == 4:
            service_account = _name(f"{parts[2]}/{parts[3]}")

    user_agent = red.text(event.get("userAgent"), 2048)
    target = "/".join(p for p in (resource_name, subresource) if p) or (uri_path or "-")
    obj = "/".join(p for p in (namespace, object_name) if p)
    message = red.text(
        f"{username or 'unauthenticated'} {verb or '?'} {target}"
        f"{' ' + obj if obj else ''} -> {code if code is not None else '?'}"
        f"{' (dry-run)' if dry_run else ''}",
        MESSAGE_LIMIT,
    )
    raw = _audit_raw(event, red)

    subjects = summary.get("subjects") if summary else None
    simulation = _simulation_tag(object_name, username, impersonated_user, subjects)

    return SecurityEvent(
        event_id=event_id(SourceType.K8S_AUDIT.value, ASSET_ID, f"{audit_id}:{stage}"),
        event_type="k8s.api.request",
        category=_category("k8s.api.request"),
        asset_id=ASSET_ID,
        asset_type=AssetType.KUBERNETES_CLUSTER,
        source=_source(ctx, resource, SourceType.K8S_AUDIT, audit_id),
        event_time=event_time,
        observed_time=observed,
        action=verb,
        outcome=_outcome_for_code(code),
        actor=_audit_actor(user, code, red),
        resource=Resource(
            type=resource_name,
            name=object_name,
            id=_name(object_ref.get("uid"), 128),
            namespace=namespace,
            path=uri_path,
        ),
        network=Network(src_ip=source_ips[-1]) if source_ips else None,
        kubernetes=KubernetesInfo(
            cluster=CLUSTER_NAME,
            namespace=namespace,
            service_account=service_account,
            verb=verb,
            api_group=api_group,
            resource=resource_name,
            subresource=subresource,
            object_name=object_name,
            audit_id=audit_id,
            stage=_name(stage, 32),
            response_code=code if code is not None and 0 <= code <= 999 else None,
            user=_name(username),
            user_groups=_bounded_attr_list(
                [g for g in _as_list(user.get("groups")) if isinstance(g, str)], 32, 256
            ),
            source_ips=source_ips,
            user_agent=user_agent,
        ),
        # The audit file is written by this node's kube-apiserver (kubeadm patch in
        # infra/kind/cluster.yaml); the collector only reads files on its own node.
        service=apiserver_service_ref(resource.get("k8s.node.name")),
        message=message,
        attributes=attributes,
        raw=raw,
        provenance=Provenance(
            parser=AUDIT_PARSER,
            parser_version=PARSER_VERSION,
            raw_sha256=sha256_hex(raw_text),
            truncated=summary_truncated or red.truncated,
            redaction_count=red.count,
        ),
        simulation=simulation,
    )


# ── container logs ────────────────────────────────────────────────────

_LAB_PORTAL_KEYS = frozenset(
    {
        "ts",
        "level",
        "service",
        "event",
        "user",
        "src_ip",
        "request_id",
        "request_id_source",
        "method",
        "route",
        "status",
        "reason",
        "user_agent",
        "duration_ms",
    }
)
_LAB_PORTAL_EVENTS = {
    "auth.login_failed": "app.auth.login_failed",
    "auth.login_succeeded": "app.auth.login_succeeded",
    "authz.denied": "app.authz.denied",
    "http.request": "http.request",
}


def _workload(resource: dict[str, Any]) -> tuple[str | None, str | None]:
    for key, kind in (
        ("k8s.deployment.name", "Deployment"),
        ("k8s.statefulset.name", "StatefulSet"),
        ("k8s.daemonset.name", "DaemonSet"),
        ("k8s.cronjob.name", "CronJob"),
        ("k8s.job.name", "Job"),
        ("k8s.replicaset.name", "ReplicaSet"),
    ):
        name = resource.get(key)
        if isinstance(name, str) and name:
            return kind, _name(name)
    return None, None


def _container_image(resource: dict[str, Any]) -> str | None:
    """``name[:tag]`` from k8s_attributes (container.image.name / container.image.tags)."""
    name = resource.get("container.image.name")
    if not isinstance(name, str) or not name:
        return None
    tags = resource.get("container.image.tags")
    tag = tags[0] if isinstance(tags, list) and tags and isinstance(tags[0], str) else None
    return sanitize_untrusted(f"{name}:{tag}" if tag else name, 512) or None


def _container_service_ref(kubernetes: KubernetesInfo, adapter_id: str) -> ServiceRef | None:
    """ServiceRef to the record's workload service; None without workload evidence.

    Instance: the container (bare runtime id) when k8s_attributes reported it, else
    the pod (keyed by the UID from the node log path, which is the kubelet UID).
    """
    namespace, kind, name = (
        kubernetes.namespace,
        kubernetes.workload_kind,
        kubernetes.workload_name,
    )
    if not (namespace and kind and name):
        return None
    sid = workload_service_id(namespace, kind, name)
    if sid is None:
        return None
    if kubernetes.container_id:
        iid: str | None = container_instance_id(sid, kubernetes.container_id)
    elif kubernetes.pod_uid:
        iid = pod_instance_id(sid, kubernetes.pod_uid)
    else:
        iid = None
    return ServiceRef(
        service_id=sid,
        name=service_display_name(namespace, name),
        instance_id=iid,
        adapter_id=adapter_id,
    )


def _pod_identity_from_path(path: Any) -> tuple[str | None, str | None, str | None, str | None]:
    """(namespace, pod, uid, container) from /var/log/pods/<ns>_<pod>_<uid>/<container>/N.log."""
    if not isinstance(path, str):
        return None, None, None, None
    match = re.match(r"^/var/log/pods/([^_/]+)_([^_/]+)_([^_/]+)/([^/]+)/[^/]+$", path)
    if not match:
        return None, None, None, None
    return match.group(1), match.group(2), match.group(3), match.group(4)


def _log_level(body: str) -> str | None:
    head = body[:512]
    klog = _KLOG_RE.match(head)
    if klog:
        return _KLOG_LEVELS[klog.group(1)]
    for pattern in (_LEVEL_JSON_RE, _LEVEL_LOGFMT_RE):
        found = pattern.search(head)
        if found:
            return found.group(1).lower()
    return None


def _parse_lab_portal(body: str) -> dict[str, Any] | None:
    if not body.startswith("{") or len(body) > 16384:
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict) or set(data.keys()) != _LAB_PORTAL_KEYS:
        return None
    if data.get("service") != "lab-portal" or data.get("event") not in _LAB_PORTAL_EVENTS:
        return None
    return data


def _lab_portal_outcome(event: str, status: int | None) -> Outcome:
    if event == "auth.login_failed":
        return Outcome.FAILURE
    if event == "auth.login_succeeded":
        return Outcome.SUCCESS
    if event == "authz.denied":
        return Outcome.DENIED
    if status is None:
        return Outcome.UNKNOWN
    if status in (401, 403):
        return Outcome.DENIED
    return Outcome.SUCCESS if status < 400 else Outcome.FAILURE


def _normalize_container(
    ctx: _Context, resource: dict[str, Any], record: Mapping[str, Any], attrs: dict[str, Any]
) -> SecurityEvent:
    body_value = _any_value(record.get("body"))
    if body_value is None:
        raise _RecordError("container_body_missing")
    body = body_value if isinstance(body_value, str) else canonical_json(body_value)
    if len(body) > MAX_CONTAINER_BODY_CHARS:
        body = body[:MAX_CONTAINER_BODY_CHARS]
    path_ns, path_pod, path_uid, path_container = _pod_identity_from_path(
        attrs.get("log.file.path")
    )
    namespace = _name(resource.get("k8s.namespace.name") or path_ns, 253)
    pod_name = _name(resource.get("k8s.pod.name") or path_pod, 253)
    pod_uid = _name(resource.get("k8s.pod.uid") or path_uid, 128)
    container = _name(resource.get("k8s.container.name") or path_container, 253)
    if not pod_uid or not container:
        raise _RecordError("container_missing_pod_identity")
    stream = attrs.get("log.iostream")
    stream = stream if stream in ("stdout", "stderr") else None

    time_ns = _unix_nano(record.get("timeUnixNano"))
    observed_ns = _unix_nano(record.get("observedTimeUnixNano"))
    time_source = "cri"
    if time_ns is None:
        time_ns = observed_ns
        time_source = "observed"
    if time_ns is None:
        raise _RecordError("container_missing_timestamp")
    native_key = f"{pod_uid}:{container}:{stream or ''}:{time_ns}:{sha256_hex(body)}"
    eid = event_id(SourceType.K8S_CONTAINER_LOG.value, ASSET_ID, native_key)

    red = _Redactor()
    workload_kind, workload_name = _workload(resource)
    # Static pods are never associated by k8s_attributes (their log-path UID is the
    # kubelet config hash, not the mirror pod UID) and have no controller: the pod
    # itself is the workload. API pods without controller metadata stay unattributed
    # (absence of metadata is not evidence of a bare pod).
    static_pod = is_static_pod_uid(pod_uid)
    if workload_kind is None and static_pod and pod_name:
        workload_kind, workload_name = POD_WORKLOAD_KIND, pod_name
    container_id, _runtime = canonical_container_id(resource.get("container.id"))
    restart = resource.get("k8s.container.restart_count")
    try:
        restart_count = int(restart) if restart is not None else None
    except (TypeError, ValueError):
        restart_count = None
    kubernetes = KubernetesInfo(
        cluster=CLUSTER_NAME,
        namespace=namespace,
        pod_name=pod_name,
        pod_uid=pod_uid,
        container_name=container,
        container_id=container_id,
        node_name=_name(resource.get("k8s.node.name"), 253),
        workload_kind=workload_kind,
        workload_name=workload_name,
    )
    base_attrs: dict[str, Any] = {
        "stream": stream,
        "time_source": time_source,
        "container_restart_count": restart_count,
        "container_image": _container_image(resource),
        "static_pod": True if static_pod else None,
    }
    simulation = _simulation_tag(pod_name, workload_name)
    observed = _ns_to_datetime(observed_ns) if observed_ns else None
    cri_time = _ns_to_datetime(time_ns)

    lab = None
    if (namespace, container) in LAB_PORTAL_WORKLOADS and stream == "stdout":
        lab = _parse_lab_portal(body)
    if lab is not None:
        return _lab_portal_event(
            ctx,
            resource,
            lab,
            body,
            eid,
            native_key,
            kubernetes,
            base_attrs,
            cri_time,
            observed,
            red,
            simulation,
            _container_service_ref(kubernetes, LAB_PORTAL_ADAPTER),
        )

    message = red.text(body, MESSAGE_LIMIT)
    raw = red.text(body, 16384) if len(body) > MESSAGE_LIMIT else None
    level = _log_level(body)
    attributes = {**base_attrs, "log_level": level}
    attributes = {k: v for k, v in attributes.items() if v is not None}
    body_cut = isinstance(body_value, str) and len(body_value) > MAX_CONTAINER_BODY_CHARS
    return SecurityEvent(
        event_id=eid,
        event_type="k8s.container.log",
        category=_category("k8s.container.log"),
        asset_id=ASSET_ID,
        asset_type=AssetType.KUBERNETES_CLUSTER,
        source=_source(ctx, resource, SourceType.K8S_CONTAINER_LOG, None),
        event_time=cri_time,
        observed_time=observed,
        kubernetes=kubernetes,
        service=_container_service_ref(kubernetes, CONTAINER_LOG_ADAPTER),
        message=message,
        attributes=attributes,
        raw=raw,
        provenance=Provenance(
            parser=CONTAINER_PARSER,
            parser_version=PARSER_VERSION,
            raw_sha256=sha256_hex(body_value if isinstance(body_value, str) else body),
            truncated=red.truncated or body_cut,
            redaction_count=red.count,
        ),
        simulation=simulation,
    )


def _lab_portal_event(
    ctx: _Context,
    resource: dict[str, Any],
    data: dict[str, Any],
    body: str,
    eid: str,
    native_key: str,
    kubernetes: KubernetesInfo,
    base_attrs: dict[str, Any],
    cri_time: datetime,
    observed: datetime | None,
    red: _Redactor,
    simulation: SimulationTag | None,
    service: ServiceRef | None,
) -> SecurityEvent:
    app_event = str(data["event"])
    event_type = _LAB_PORTAL_EVENTS[app_event]
    status_raw = data.get("status")
    status = (
        status_raw
        if isinstance(status_raw, int)
        and not isinstance(status_raw, bool)
        and 100 <= status_raw <= 599
        else None
    )
    user = _name(data.get("user"), 64)
    src_ip = _valid_ip(data.get("src_ip"))
    request_id = _name(data.get("request_id"), 128)
    propagated = data.get("request_id_source") == "propagated"
    duration = data.get("duration_ms")
    duration_ms = (
        float(duration)
        if isinstance(duration, int | float) and not isinstance(duration, bool) and duration >= 0
        else None
    )
    route = _name(data.get("route"), 512)
    method = _name(data.get("method"), 16)
    reason = _name(data.get("reason"), 64)
    level = _name(data.get("level"), 16)
    ts = _parse_rfc3339(data.get("ts"))

    attributes = {
        **base_attrs,
        "reason": reason,
        "app_schema": "lab-portal.log.v1",
        "app_level": level,
        "request_id_source": _name(data.get("request_id_source"), 16),
        "app_request_id": None if propagated else request_id,
    }
    attributes = {k: v for k, v in attributes.items() if v is not None}
    authenticated = {
        "auth.login_failed": False,
        "auth.login_succeeded": True,
        "authz.denied": False,
    }.get(app_event)
    actor = (
        Actor(type=ActorType.USER, name=user, authenticated=authenticated)
        if (user or authenticated is not None)
        else None
    )
    message = red.text(
        f"lab-portal {app_event} {method or '?'} {route or '?'} -> {status or '?'}"
        f"{' user=' + user if user else ''}{' src=' + src_ip if src_ip else ''}"
        f"{' reason=' + reason if reason else ''}",
        MESSAGE_LIMIT,
    )
    return SecurityEvent(
        event_id=eid,
        event_type=event_type,
        category=_category(event_type),
        asset_id=ASSET_ID,
        asset_type=AssetType.KUBERNETES_CLUSTER,
        source=_source(ctx, resource, SourceType.K8S_CONTAINER_LOG, None),
        event_time=ts or cri_time,
        observed_time=observed,
        action=app_event,
        outcome=_lab_portal_outcome(app_event, status),
        actor=actor,
        network=Network(src_ip=src_ip) if src_ip else None,
        http=HttpInfo(
            method=method,
            route=route,
            status_code=status,
            request_id=request_id if propagated else None,
            user_agent=red.text(data.get("user_agent"), 512),
            duration_ms=duration_ms,
        ),
        kubernetes=kubernetes,
        service=service,
        message=message,
        attributes=attributes,
        raw=red.text(body, 4096),
        provenance=Provenance(
            parser=LAB_PORTAL_PARSER,
            parser_version=PARSER_VERSION,
            raw_sha256=sha256_hex(body),
            truncated=red.truncated,
            redaction_count=red.count,
        ),
        simulation=simulation or _simulation_tag(user),
    )


__all__ = [
    "ASSET_ID",
    "AUDIT_ADAPTER",
    "CLUSTER_NAME",
    "CONTAINER_LOG_ADAPTER",
    "DANGEROUS_CAPABILITIES",
    "LAB_PORTAL_ADAPTER",
    "LAB_PORTAL_WORKLOADS",
    "PARSER_VERSION",
    "POD_WORKLOAD_KIND",
    "NormalizationResult",
    "OtlpPayloadError",
    "apiserver_service_ref",
    "canonical_container_id",
    "container_instance_id",
    "is_static_pod_uid",
    "k8s_service_key",
    "k8s_service_service_id",
    "metadata_only_request",
    "node_asset_id",
    "normalize_otlp_logs",
    "normalize_otlp_logs_detailed",
    "pod_instance_id",
    "risk_flags_for_summary",
    "service_display_name",
    "simulation_tag",
    "summarize_k8s_object",
    "summarize_pod_spec",
    "summarize_rbac_object",
    "valid_k8s_name",
    "workload_service_id",
    "workload_service_key",
]

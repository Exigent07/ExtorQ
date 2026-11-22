"""Event rows as read by the correlation layer, plus deterministic summaries.

Every string in an event row is untrusted (usernames, routes, object names, log
messages): summaries and key fields are built only from normalised columns, each
value sanitised (control/format characters stripped) and truncated. Nothing here
interprets telemetry text as instructions or markup.

Service attribution (contract 1.1) is read from ``events.service_*`` (migration
0004) with a fallback to the validated ``payload`` JSON for rows written before the
writer filled those columns.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.contracts.catalog import EVENT_CATALOG
from extorq.contracts.common import Outcome
from extorq.contracts.context import EventSummary
from extorq.detection._compat import sanitize
from extorq.detection.alerts import coerce_attributes

#: Static column list (no user input) shared by every event query of the builder.
EVENT_COLUMNS = """
    event_id, event_time, event_type, source_type, asset_id, asset_type, outcome, action,
    actor_name, actor_id, src_ip, src_port, dst_ip, dst_port,
    resource_type, resource_name, resource_namespace, resource_path,
    process_name, process_executable,
    http_method, http_route, http_status, http_request_id, http_user_agent,
    k8s_cluster, k8s_namespace, k8s_pod_name, k8s_pod_uid, k8s_node, k8s_verb, k8s_resource,
    k8s_subresource, k8s_object_name, k8s_audit_id, k8s_response_code, k8s_user,
    k8s_source_ips,
    gh_repository, gh_ref, gh_commit_sha, gh_workflow_path, gh_workflow_run_id, gh_actor_login,
    message, attributes,
    if(service_id IS NULL, nullIf(JSONExtractString(payload, 'service', 'service_id'), ''),
       service_id) AS svc_id,
    if(service_name IS NULL, nullIf(JSONExtractString(payload, 'service', 'name'), ''),
       service_name) AS svc_name,
    if(service_instance_id IS NULL,
       nullIf(JSONExtractString(payload, 'service', 'instance_id'), ''),
       service_instance_id) AS svc_instance_id
"""

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
#: k8s identities that are not principals (anonymous access).
_ANONYMOUS = frozenset({"system:anonymous", "system:unauthenticated"})
_SYSTEMD_DIRS = ("/etc/systemd/", "/lib/systemd/", "/usr/lib/systemd/", "/run/systemd/")
_K8S_KIND_FIX = {"endpoints": "endpoints"}


def _str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text != "" else None


def _ip(value: Any) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def k8s_kind(value: str | None) -> str | None:
    """Normalise a Kubernetes kind/resource name to the lower-case plural resource."""
    if not value:
        return None
    kind = re.sub(r"\s+", "", value).lower()
    if kind in _K8S_KIND_FIX:
        return _K8S_KIND_FIX[kind]
    return kind if kind.endswith("s") else f"{kind}s"


@dataclass(frozen=True)
class EventRecord:
    """One de-duplicated event row (columns of :data:`EVENT_COLUMNS`)."""

    event_id: str
    event_time: datetime
    event_type: str
    source_type: str
    asset_id: str
    asset_type: str
    outcome: str
    action: str | None = None
    actor_name: str | None = None
    actor_id: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    resource_type: str | None = None
    resource_name: str | None = None
    resource_namespace: str | None = None
    resource_path: str | None = None
    process_name: str | None = None
    process_executable: str | None = None
    http_method: str | None = None
    http_route: str | None = None
    http_status: int | None = None
    http_request_id: str | None = None
    http_user_agent: str | None = None
    k8s_cluster: str | None = None
    k8s_namespace: str | None = None
    k8s_pod_name: str | None = None
    k8s_pod_uid: str | None = None
    k8s_node: str | None = None
    k8s_verb: str | None = None
    k8s_resource: str | None = None
    k8s_subresource: str | None = None
    k8s_object_name: str | None = None
    k8s_audit_id: str | None = None
    k8s_response_code: int | None = None
    k8s_user: str | None = None
    k8s_source_ips: tuple[str, ...] = ()
    gh_repository: str | None = None
    gh_ref: str | None = None
    gh_commit_sha: str | None = None
    gh_workflow_path: str | None = None
    gh_workflow_run_id: int | None = None
    gh_actor_login: str | None = None
    message: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    service_id: str | None = None
    service_name: str | None = None
    service_instance_id: str | None = None
    #: Service the record is ABOUT (``attributes.subject_service_id``, e.g. a unit file
    #: change produced by systemd about the unit's own service); B1 interface note 5.
    subject_service_id: str | None = None

    # ── derived identities ────────────────────────────────────────────
    @property
    def all_service_ids(self) -> frozenset[str]:
        """Producing service and subject service (both attributions, when present)."""
        return frozenset(s for s in (self.service_id, self.subject_service_id) if s)

    @property
    def ips(self) -> frozenset[str]:
        found = {ip for ip in (self.src_ip, *self.k8s_source_ips) if ip}
        return frozenset(found)

    def principals(self) -> frozenset[str]:
        """Principal names the source reported (user, k8s user, GitHub login)."""
        names = {self.actor_name, self.k8s_user, self.gh_actor_login}
        return frozenset(n for n in names if n and n not in _ANONYMOUS)

    def authenticated_principals(self) -> frozenset[str]:
        """Principals the source authenticated (usable across assets).

        k8s users are authenticated by the API server, GitHub logins by GitHub; a host
        user name counts only on a successful login (failed attempts submit arbitrary,
        attacker-chosen names).
        """
        names: set[str] = set()
        if self.k8s_user and self.k8s_user not in _ANONYMOUS:
            names.add(self.k8s_user)
        if self.gh_actor_login:
            names.add(self.gh_actor_login)
        if (
            self.actor_name
            and self.outcome == Outcome.SUCCESS.value
            and (self.event_type.startswith("auth.") or self.event_type.startswith("app.auth."))
        ):
            names.add(self.actor_name)
        return frozenset(names)

    def unit_name(self) -> str | None:
        """systemd unit this event concerns (persistence diff, state change, audit path)."""
        if self.resource_type == "systemd_unit" and self.resource_name:
            return self.resource_name
        path = self.resource_path or ""
        if path.startswith(_SYSTEMD_DIRS):
            base = path.rstrip("/").rsplit("/", 1)[-1]
            return base or None
        if self.event_type.startswith("persistence.systemd.") and self.resource_name:
            return self.resource_name
        return None

    def resource_keys(self) -> frozenset[tuple[str, ...]]:
        """Exact resource identities (compared only between events of one asset)."""
        keys: set[tuple[str, ...]] = set()
        if self.resource_path:
            keys.add(("path", self.resource_path))
        if self.gh_workflow_path and self.gh_repository:
            keys.add(("workflow", self.gh_repository, self.gh_workflow_path))
        unit = self.unit_name()
        if unit:
            keys.add(("unit", unit))
        kind = k8s_kind(self.k8s_resource) if self.k8s_object_name else None
        if kind and self.k8s_object_name:
            keys.add(("k8s", self.k8s_namespace or "", kind, self.k8s_object_name))
        if self.source_type == "k8s.api_inventory" and self.resource_name:
            inv_kind = k8s_kind(self.resource_type)
            if inv_kind:
                keys.add(("k8s", self.resource_namespace or "", inv_kind, self.resource_name))
        return frozenset(keys)

    # ── presentation ──────────────────────────────────────────────────
    def summary_text(self) -> str:
        """Deterministic one-line description from normalised fields (sanitised)."""

        def s(value: Any, limit: int = 96) -> str:
            text = sanitize(None if value is None else str(value), limit)
            return text if text else "?"

        et = self.event_type
        if et.startswith("auth.ssh."):
            where = f"{s(self.src_ip, 45)}:{s(self.src_port, 5)}" if self.src_ip else "?"
            return f"{et} user={s(self.actor_name, 64)} from {where}"
        if et in ("http.request", "http.server.error"):
            status = self.http_status if self.http_status is not None else "?"
            return (
                f"{et} {s(self.http_method, 16)} {s(self.http_route, 160)} -> {status} "
                f"from {s(self.src_ip, 45)}"
            )
        if et.startswith("app."):
            return (
                f"{et} user={s(self.actor_name, 64)} route={s(self.http_route, 120)} "
                f"from {s(self.src_ip, 45)}"
            )
        if et == "k8s.api.request":
            parts = (self.k8s_namespace or "-", self.k8s_resource, self.k8s_object_name)
            obj = "/".join(s(x, 80) for x in parts)
            return (
                f"{et} {s(self.k8s_verb, 16)} {obj} by {s(self.k8s_user, 96)} -> "
                f"{self.k8s_response_code if self.k8s_response_code is not None else '?'}"
            )
        if et.startswith("k8s.resource."):
            return (
                f"{et} {s(self.resource_type, 48)} "
                f"{s(self.resource_namespace or '-', 64)}/{s(self.resource_name, 96)}"
            )
        if et.startswith("persistence.") or et.startswith("file.") or et.startswith("config."):
            target = self.resource_path or self.resource_name
            return f"{et} {s(target, 200)}"
        if et == "system.service.state_changed":
            return f"{et} {s(self.resource_name, 120)} {s(self.attributes.get('state'), 32)}"
        if et.startswith("github."):
            sha = (self.gh_commit_sha or "")[:12] or "?"
            return (
                f"{et} {s(self.gh_repository, 100)}@{sha} {s(self.gh_workflow_path, 120)} "
                f"by {s(self.gh_actor_login or self.actor_name, 64)}"
            )
        if et.startswith("auth.sudo."):
            return f"{et} user={s(self.actor_name, 64)} as {s(self.attributes.get('run_as'), 32)}"
        if self.message:
            return f"{et}: {s(self.message, 240)}"
        return et

    def key_fields(self) -> dict[str, Any]:
        """Catalog key fields of this event type that the source populated (bounded)."""
        spec = EVENT_CATALOG.get(self.event_type)
        if spec is None:
            return {}
        out: dict[str, Any] = {}
        for path in spec.key_fields:
            value = self._field(path)
            if value is None or value == "" or value == []:
                continue
            key = path if len(path) <= 64 else path[:64]
            if isinstance(value, str):
                out[key] = sanitize(value, 256)
            elif isinstance(value, list | tuple):
                out[key] = [sanitize(str(v), 128) for v in list(value)[:16]]
            else:
                out[key] = value
        return coerce_attributes(out)

    def _field(self, path: str) -> Any:
        head, _, tail = path.partition(".")
        if head == "attributes":
            value = self.attributes.get(tail)
            if isinstance(value, dict):
                return None
            return value
        mapping: dict[str, Any] = {
            "actor.name": self.actor_name,
            "actor.id": self.actor_id,
            "network.src_ip": self.src_ip,
            "network.src_port": self.src_port,
            "network.dst_ip": self.dst_ip,
            "network.dst_port": self.dst_port,
            "resource.type": self.resource_type,
            "resource.name": self.resource_name,
            "resource.namespace": self.resource_namespace,
            "resource.path": self.resource_path,
            "process.name": self.process_name,
            "process.executable": self.process_executable,
            "http.method": self.http_method,
            "http.route": self.http_route,
            "http.status_code": self.http_status,
            "http.request_id": self.http_request_id,
            "http.user_agent": self.http_user_agent,
            "kubernetes.verb": self.k8s_verb,
            "kubernetes.resource": self.k8s_resource,
            "kubernetes.namespace": self.k8s_namespace,
            "kubernetes.object_name": self.k8s_object_name,
            "kubernetes.user": self.k8s_user,
            "kubernetes.source_ips": list(self.k8s_source_ips),
            "kubernetes.response_code": self.k8s_response_code,
            "kubernetes.audit_id": self.k8s_audit_id,
            "kubernetes.pod_name": self.k8s_pod_name,
            "kubernetes.pod_uid": self.k8s_pod_uid,
            "github.repository": self.gh_repository,
            "github.commit_sha": self.gh_commit_sha,
            "github.ref": self.gh_ref,
            "github.workflow_path": self.gh_workflow_path,
            "github.workflow_run_id": self.gh_workflow_run_id,
            "github.actor_login": self.gh_actor_login,
            "service.service_id": self.service_id,
            "service.name": self.service_name,
        }
        return mapping.get(path)

    def to_summary(self) -> EventSummary:
        try:
            outcome = Outcome(self.outcome)
        except ValueError:
            outcome = Outcome.UNKNOWN
        actor = self.actor_name or self.k8s_user or self.gh_actor_login
        return EventSummary(
            event_id=self.event_id,
            event_time=self.event_time,
            event_type=sanitize(self.event_type, 256),
            source_type=sanitize(self.source_type, 256),
            asset_id=self.asset_id,
            outcome=outcome,
            actor_name=sanitize(actor, 256) if actor else None,
            src_ip=self.src_ip,
            service_id=self.service_id,
            service_name=sanitize(self.service_name, 256) if self.service_name else None,
            summary=sanitize(self.summary_text(), 2048),
            key_fields=self.key_fields(),
        )


def _attributes(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, RecursionError):
        return {}
    return value if isinstance(value, dict) else {}


def record_from_row(row: dict[str, Any]) -> EventRecord | None:
    """Build an :class:`EventRecord`; returns ``None`` for rows that are not usable."""
    event_id = row.get("event_id")
    event_time = row.get("event_time")
    if not isinstance(event_id, str) or not _HEX32.match(event_id):
        return None
    if not isinstance(event_time, datetime) or event_time.tzinfo is None:
        return None
    svc = _str(row.get("svc_id"))
    inst = _str(row.get("svc_instance_id"))
    run_id = row.get("gh_workflow_run_id")
    return EventRecord(
        event_id=event_id,
        event_time=event_time,
        event_type=str(row.get("event_type") or ""),
        source_type=str(row.get("source_type") or ""),
        asset_id=str(row.get("asset_id") or ""),
        asset_type=str(row.get("asset_type") or ""),
        outcome=str(row.get("outcome") or "unknown"),
        action=_str(row.get("action")),
        actor_name=_str(row.get("actor_name")),
        actor_id=_str(row.get("actor_id")),
        src_ip=_ip(row.get("src_ip")),
        src_port=row.get("src_port") if isinstance(row.get("src_port"), int) else None,
        dst_ip=_ip(row.get("dst_ip")),
        dst_port=row.get("dst_port") if isinstance(row.get("dst_port"), int) else None,
        resource_type=_str(row.get("resource_type")),
        resource_name=_str(row.get("resource_name")),
        resource_namespace=_str(row.get("resource_namespace")),
        resource_path=_str(row.get("resource_path")),
        process_name=_str(row.get("process_name")),
        process_executable=_str(row.get("process_executable")),
        http_method=_str(row.get("http_method")),
        http_route=_str(row.get("http_route")),
        http_status=row.get("http_status") if isinstance(row.get("http_status"), int) else None,
        http_request_id=_str(row.get("http_request_id")),
        http_user_agent=_str(row.get("http_user_agent")),
        k8s_cluster=_str(row.get("k8s_cluster")),
        k8s_namespace=_str(row.get("k8s_namespace")),
        k8s_pod_name=_str(row.get("k8s_pod_name")),
        k8s_pod_uid=_str(row.get("k8s_pod_uid")),
        k8s_node=_str(row.get("k8s_node")),
        k8s_verb=_str(row.get("k8s_verb")),
        k8s_resource=_str(row.get("k8s_resource")),
        k8s_subresource=_str(row.get("k8s_subresource")),
        k8s_object_name=_str(row.get("k8s_object_name")),
        k8s_audit_id=_str(row.get("k8s_audit_id")),
        k8s_response_code=(
            row.get("k8s_response_code") if isinstance(row.get("k8s_response_code"), int) else None
        ),
        k8s_user=_str(row.get("k8s_user")),
        k8s_source_ips=tuple(
            ip for ip in (_ip(v) for v in (row.get("k8s_source_ips") or [])) if ip
        ),
        gh_repository=_str(row.get("gh_repository")),
        gh_ref=_str(row.get("gh_ref")),
        gh_commit_sha=_str(row.get("gh_commit_sha")),
        gh_workflow_path=_str(row.get("gh_workflow_path")),
        gh_workflow_run_id=run_id if isinstance(run_id, int) else None,
        gh_actor_login=_str(row.get("gh_actor_login")),
        message=_str(row.get("message")),
        attributes=_attributes(row.get("attributes")),
        service_id=svc if svc and _HEX32.match(svc) else None,
        service_name=_str(row.get("svc_name")),
        service_instance_id=inst if inst and _HEX32.match(inst) else None,
        subject_service_id=_subject_service(row.get("attributes")),
    )


def _subject_service(raw: Any) -> str | None:
    value = _attributes(raw).get("subject_service_id")
    return value if isinstance(value, str) and _HEX32.match(value) else None

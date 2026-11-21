"""Allow-list projection of an InvestigationContext into AI provider input.

Provider inputs are built ONLY from :class:`InvestigationContext` and only from
the fields listed here. Nothing else (raw events, payloads, secrets, file
contents, repository access, SQL) is ever reachable by a provider.

Trust model of the projected payload:

* ExtorQ-generated identifiers and enums (event ids, rule ids, severities,
  outcomes, catalogued event/source types, validated IPs, timestamps, counts)
  are passed as plain JSON values.
* Every string that can carry telemetry content (log-derived summaries, actor
  names, HTTP paths, user agents, commit messages, Kubernetes fields, entity
  values, finding titles, free-form feature strings) is sanitised by
  :func:`extorq.ai.sanitize.clean_untrusted`, truncated, and wrapped as
  ``{"untrusted": "<text>"}`` so it is unmistakably delimited data.
* Raw evidence excerpts are dropped unless ``ai_include_excerpts`` is enabled.
* Services (contract 1.1, ``InvestigationContext.services``) are projected as
  name (untrusted text), kind, category, adapter support, monitoring status,
  role and parent asset id only: never service attributes, configuration paths,
  endpoints or versions. Each service gets a local alias (``svc-1``...) that
  evidence events reference, so 32-hex service ids never appear in provider
  input (they could be confused with citable evidence ids). Enumerated values
  outside the contract enums become ``"unrecognised"``.
* Related assets (cross-asset correlation, 1.1) carry id, type and criticality only.
* The total serialised size is capped; lowest-priority related events, then
  middle evidence events, then findings and features are dropped first, and the
  number of omitted events is stated in the payload.

Simulation markers are excluded from the Jev triage state (activity is judged
on its merits) but stated as a fact for Gemini summaries.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from extorq.ai.sanitize import (
    LIMIT_ACTOR,
    LIMIT_COMMIT_MESSAGE,
    LIMIT_EXCERPT,
    LIMIT_HTTP_PATH,
    LIMIT_K8S_FIELD,
    LIMIT_LOG_MESSAGE,
    LIMIT_SHORT,
    LIMIT_SUMMARY,
    LIMIT_USER_AGENT,
    clean_trusted,
    clean_untrusted,
)
from extorq.contracts.catalog import EVENT_CATALOG, SourceType
from extorq.contracts.common import AssetType
from extorq.contracts.context import (
    EventSummary,
    InvestigationContext,
    Relationship,
    RelationshipType,
    ServiceSummary,
    TimelineEntry,
)
from extorq.contracts.identity import iso_utc
from extorq.contracts.service import AdapterSupport, MonitoringStatus, ServiceCategory, ServiceKind


class Domain(StrEnum):
    GITHUB = "github"
    SSH_HTTP = "ssh_http"
    K8S = "k8s"
    GENERIC = "generic"


_GITHUB_ASSETS = {AssetType.GITHUB_REPOSITORY, AssetType.GITHUB_ACCOUNT}
_K8S_ASSETS = {
    AssetType.KUBERNETES_CLUSTER,
    AssetType.KUBERNETES_NODE,
    AssetType.KUBERNETES_NAMESPACE,
    AssetType.KUBERNETES_WORKLOAD,
}
#: CORR-002 (PLAN 10.2): HTTP probing -> SSH auth failures -> systemd change on one host.
_SSH_HTTP_RULES = {"VM-001", "HTTP-001", "CORR-001", "CORR-002"}
#: Evidence on a Linux host with these event types uses the SSH + HTTP question variant.
_SSH_HTTP_EVENT_PREFIXES = ("auth.ssh.", "http.", "app.auth.", "app.authz.")


def _context_event_types(ctx: InvestigationContext) -> set[str]:
    types = {e.event_type for e in ctx.evidence}
    types.update(t.event_type for t in ctx.timeline)
    return types


def classify_domain(ctx: InvestigationContext) -> Domain:
    """Pick the triage question variant from the rule, asset type and event types."""
    rule_id = ctx.alert.rule_id
    asset_type = ctx.alert.asset_type
    if rule_id.startswith("GH-") or asset_type in _GITHUB_ASSETS:
        return Domain.GITHUB
    if rule_id.startswith("K8S") or asset_type in _K8S_ASSETS:
        return Domain.K8S
    if rule_id in _SSH_HTTP_RULES:
        return Domain.SSH_HTTP
    if asset_type is AssetType.LINUX_HOST:
        evidence_types = {e.event_type for e in ctx.evidence}
        if any(t.startswith(_SSH_HTTP_EVENT_PREFIXES) for t in evidence_types):
            return Domain.SSH_HTTP
    return Domain.GENERIC


@dataclass(frozen=True)
class ProjectionLimits:
    max_evidence: int
    max_related: int
    max_findings: int
    max_features: int
    max_list_items: int
    max_key_fields: int
    max_chars: int
    max_services: int = 12
    max_related_assets: int = 8


JEV_LIMITS = ProjectionLimits(
    max_evidence=8,
    max_related=8,
    max_findings=5,
    max_features=32,
    max_list_items=8,
    max_key_fields=16,
    max_chars=24_000,
    max_services=12,
    max_related_assets=8,
)
GEMINI_LIMITS = ProjectionLimits(
    max_evidence=25,
    max_related=25,
    max_findings=10,
    max_features=48,
    max_list_items=10,
    max_key_fields=24,
    max_chars=60_000,
    max_services=24,
    max_related_assets=16,
)


@dataclass
class Projection:
    domain: Domain
    payload: dict[str, Any]
    presented_event_ids: tuple[str, ...]
    omitted_events: int
    redactions: int
    truncated_strings: int
    dropped_keys: int

    def serialised(self) -> str:
        return json.dumps(self.payload, ensure_ascii=False, separators=(",", ":"))


# ── key_fields allow-list ─────────────────────────────────────────────


def _catalog_field_names() -> frozenset[str]:
    names: set[str] = set()
    for spec in EVENT_CATALOG.values():
        for path in spec.key_fields:
            parts = path.split(".")
            names.add(parts[-1])
            names.add("_".join(parts))
            if parts[0] != "attributes":
                names.add(f"{parts[0]}_{parts[-1]}")
    return frozenset(names)


#: Keys allowed in EventSummary.key_fields: every documented catalog key field
#: (leaf name and flattened form) plus a few documented correlation extras.
ALLOWED_KEY_FIELDS: frozenset[str] = _catalog_field_names() | {
    "message",
    "commit_message",
    "annotations",
    "labels",
    "role_ref",
    "subjects",
    "rules_summary",
    "risk_signature",
    "committer_login",
    "author_login",
    "merged_via_pull_request",
    "pull_request_number",
    "pull_request_approvals",
    "default_branch",
    "unit_path",
    "status",
    "http_status",
    "src_port",
    "dst_port",
    "user_name",
    "kubernetes_user_agent",
    "reason",
}

_DENIED_KEY = re.compile(
    r"(?i)(passw|secret|token|cookie|authori[sz]ation|credential|private[_-]?key|session"
    r"|api[_-]?key|^raw$|^raw_|_raw$|payload|excerpt|file_content|^body$|^diff$|patch|^env$|env_var)"
)
_EXCERPT_KEY = re.compile(r"(?i)excerpt")
_SAFE_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

#: Untrusted free-text limits per key (default LIMIT_SHORT).
_TEXT_LIMITS: dict[str, int] = {
    "message": LIMIT_LOG_MESSAGE,
    "commit_message": LIMIT_COMMIT_MESSAGE,
    "route": LIMIT_HTTP_PATH,
    "http_route": LIMIT_HTTP_PATH,
    "path": LIMIT_HTTP_PATH,
    "resource_path": LIMIT_HTTP_PATH,
    "unit_path": LIMIT_HTTP_PATH,
    "user_agent": LIMIT_USER_AGENT,
    "http_user_agent": LIMIT_USER_AGENT,
    "kubernetes_user_agent": LIMIT_USER_AGENT,
    "command_line": LIMIT_K8S_FIELD,
    "process_command_line": LIMIT_K8S_FIELD,
    "exec_start": LIMIT_K8S_FIELD,
    "request_summary": LIMIT_K8S_FIELD,
    "pod_security_violation": LIMIT_K8S_FIELD,
    "annotations": LIMIT_K8S_FIELD,
    "labels": LIMIT_K8S_FIELD,
    "object_name": LIMIT_K8S_FIELD,
    "kubernetes_object_name": LIMIT_K8S_FIELD,
}


@dataclass
class _Builder:
    limits: ProjectionLimits
    known_secrets: tuple[str, ...]
    include_excerpts: bool
    redactions: int = 0
    truncated: int = 0
    dropped_keys: int = 0
    _seen_ids: list[str] = field(default_factory=list)

    def untrusted(self, value: object, limit: int) -> dict[str, str] | None:
        if value is None:
            return None
        cleaned = clean_untrusted(value, limit, known_secrets=self.known_secrets)
        self.redactions += cleaned.redactions
        self.truncated += int(cleaned.truncated)
        return {"untrusted": cleaned.text}

    def trusted(self, value: object, limit: int) -> str:
        cleaned = clean_trusted(value, limit, known_secrets=self.known_secrets)
        self.redactions += cleaned.redactions
        self.truncated += int(cleaned.truncated)
        return cleaned.text

    def scalar(self, key: str, value: object) -> Any:
        """Numbers and booleans pass; strings and list items become untrusted text."""
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return round(value, 4) if math.isfinite(value) else None
        if isinstance(value, list):
            items = [self.scalar(key, item) for item in value[: self.limits.max_list_items]]
            if len(value) > self.limits.max_list_items:
                items.append({"omitted_items": len(value) - self.limits.max_list_items})
            return items
        limit = LIMIT_EXCERPT if _EXCERPT_KEY.search(key) else _TEXT_LIMITS.get(key, LIMIT_SHORT)
        return self.untrusted(value, limit)

    def attributes(
        self, values: Mapping[str, Any], cap: int, *, allow: frozenset[str] | None
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key in sorted(values):
            if not _SAFE_KEY.match(key):
                self.dropped_keys += 1
                continue
            denied = _DENIED_KEY.search(key) is not None
            if denied and not (self.include_excerpts and _EXCERPT_KEY.search(key)):
                self.dropped_keys += 1
                continue
            if (
                allow is not None
                and key not in allow
                and not (self.include_excerpts and _EXCERPT_KEY.search(key))
            ):
                self.dropped_keys += 1
                continue
            if len(out) >= cap:
                self.dropped_keys += 1
                continue
            out[key] = self.scalar(key, values[key])
        return out


def _iso(value: datetime) -> str:
    return iso_utc(value)


def _event_type(b: _Builder, value: str) -> Any:
    return value if value in EVENT_CATALOG else b.untrusted(value, 64)


_SOURCE_TYPES = {s.value for s in SourceType}


def _source_type(b: _Builder, value: str) -> Any:
    return value if value in _SOURCE_TYPES else b.untrusted(value, 64)


def _evidence_event(
    b: _Builder, e: EventSummary, anchor: datetime, service_refs: Mapping[str, str]
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "event_id": e.event_id,
        "time": _iso(e.event_time),
        "offset_seconds": round((e.event_time - anchor).total_seconds(), 1),
        "event_type": _event_type(b, e.event_type),
        "source_type": _source_type(b, e.source_type),
        "outcome": e.outcome.value,
        "actor": b.untrusted(e.actor_name, LIMIT_ACTOR),
        "src_ip": e.src_ip,
        "summary": b.untrusted(e.summary, LIMIT_SUMMARY),
        "fields": b.attributes(e.key_fields, b.limits.max_key_fields, allow=ALLOWED_KEY_FIELDS),
    }
    if e.service_id is not None and e.service_id in service_refs:
        item["service_ref"] = service_refs[e.service_id]
    elif e.service_name is not None:
        item["service_name"] = b.untrusted(e.service_name, LIMIT_SERVICE_NAME)
    return item


# ── services and related assets (contract 1.1) ───────────────────────

LIMIT_SERVICE_NAME = 80
_SERVICE_KINDS = frozenset(k.value for k in ServiceKind)
_SERVICE_CATEGORIES = frozenset(c.value for c in ServiceCategory)
_ADAPTER_SUPPORT = frozenset(a.value for a in AdapterSupport)
_MONITORING_STATUS = frozenset(m.value for m in MonitoringStatus)
UNRECOGNISED = "unrecognised"
#: The correlation builder reports "unknown" when no service inventory record exists.
UNKNOWN = "unknown"


def _enum_token(value: str, allowed: frozenset[str]) -> str:
    """Contract enum value or ``"unknown"``; anything else becomes ``"unrecognised"``.

    ServiceSummary fields are free strings in the contract, so values are re-validated here.
    """
    return value if value in allowed or value == UNKNOWN else UNRECOGNISED


def _project_services(
    b: _Builder, services: list[ServiceSummary], cap: int
) -> tuple[list[dict[str, Any]], dict[str, str], int]:
    """Allow-listed service summaries, alias map (service_id -> svc-N), omitted count."""
    unique: dict[str, ServiceSummary] = {}
    for svc in services:
        unique.setdefault(svc.service_id, svc)
    # Evidence services first, then related; stable order by name and id.
    ordered = sorted(
        unique.values(), key=lambda s: (s.role != "evidence", s.name.lower(), s.service_id)
    )
    kept = ordered[:cap]
    refs: dict[str, str] = {}
    out: list[dict[str, Any]] = []
    for index, svc in enumerate(kept, start=1):
        alias = f"svc-{index}"
        refs[svc.service_id] = alias
        out.append(
            {
                "ref": alias,
                "name": b.untrusted(svc.name, LIMIT_SERVICE_NAME),
                "kind": _enum_token(svc.service_kind, _SERVICE_KINDS),
                "category": _enum_token(svc.category, _SERVICE_CATEGORIES),
                "adapter_support": _enum_token(svc.adapter_support, _ADAPTER_SUPPORT),
                "monitoring_status": _enum_token(svc.monitoring_status, _MONITORING_STATUS),
                "role": svc.role,
                "asset_id": svc.asset_id,
            }
        )
    return out, refs, len(ordered) - len(kept)


_REL_RANK = {
    RelationshipType.DIRECT: 0,
    RelationshipType.CANDIDATE: 1,
    RelationshipType.UNESTABLISHED: 2,
}
_STRENGTH_RANK = {"strong": 0, "moderate": 1, "weak": 2}


def _related_event(b: _Builder, rel: Relationship, entry: TimelineEntry | None) -> dict[str, Any]:
    item: dict[str, Any] = {
        "event_id": rel.event_id,
        "relationship": rel.relationship_type.value,
        "bases": [basis.value for basis in rel.bases],
        "strength": rel.strength,
        "offset_seconds": round(rel.time_delta_seconds, 1),
        "explanation": b.untrusted(rel.explanation, LIMIT_SHORT),
    }
    if entry is not None:
        item["time"] = _iso(entry.time)
        item["event_type"] = _event_type(b, entry.event_type)
        item["source_type"] = _source_type(b, entry.source_type)
        item["summary"] = b.untrusted(entry.summary, LIMIT_SUMMARY)
    return item


def _sample_evidence(evidence: list[EventSummary], cap: int) -> tuple[list[EventSummary], int]:
    ordered = sorted(evidence, key=lambda e: (e.event_time, e.event_id))
    if len(ordered) <= cap:
        return ordered, 0
    head = math.ceil(cap / 2)
    tail = cap - head
    sample = ordered[:head] + (ordered[-tail:] if tail else [])
    return sample, len(ordered) - len(sample)


def _rank_relationships(ctx: InvestigationContext, evidence_ids: set[str]) -> list[Relationship]:
    rels = [r for r in ctx.relationships if r.event_id not in evidence_ids]
    unique: dict[str, Relationship] = {}
    for rel in sorted(
        rels,
        key=lambda r: (
            _REL_RANK[r.relationship_type],
            _STRENGTH_RANK.get(r.strength, 3),
            abs(r.time_delta_seconds),
            r.event_id,
        ),
    ):
        unique.setdefault(rel.event_id, rel)
    return list(unique.values())


def project_context(
    ctx: InvestigationContext,
    limits: ProjectionLimits,
    *,
    known_secrets: Iterable[str] = (),
    include_excerpts: bool = False,
    include_simulation_marker: bool = False,
) -> Projection:
    """Build the sanitised, size-capped provider payload for ``ctx``."""
    b = _Builder(
        limits=limits, known_secrets=tuple(known_secrets), include_excerpts=include_excerpts
    )
    alert = ctx.alert
    anchor = alert.first_seen
    domain = classify_domain(ctx)

    evidence_sample, omitted_evidence = _sample_evidence(list(ctx.evidence), limits.max_evidence)
    evidence_ids = {e.event_id for e in ctx.evidence}
    ranked = _rank_relationships(ctx, evidence_ids)
    timeline_by_id = {t.event_id: t for t in ctx.timeline}
    related = ranked[: limits.max_related]
    omitted_related = len(ranked) - len(related)

    counts = {t.value: 0 for t in RelationshipType}
    for rel in ranked:
        counts[rel.relationship_type.value] += 1

    entities: dict[str, Any] = {}
    for key in sorted(alert.entities)[:16]:
        if _SAFE_KEY.match(key) and not _DENIED_KEY.search(key):
            entities[key] = b.untrusted(alert.entities[key], LIMIT_SHORT)
        else:
            b.dropped_keys += 1

    services, service_refs, omitted_services = _project_services(
        b, list(ctx.services), limits.max_services
    )
    related_assets = [
        {
            "asset_id": a.asset_id,
            "asset_type": a.asset_type.value,
            "criticality": a.criticality.value,
        }
        for a in ctx.related_assets[: limits.max_related_assets]
        if a.asset_id != ctx.asset.asset_id
    ]

    payload: dict[str, Any] = {
        "alert": {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "rule_version": alert.rule_version,
            "rule_title": b.trusted(alert.rule_title, 160),
            "severity": alert.severity.value,
            "evidence_confidence": alert.confidence.value,
            "event_count": alert.event_count,
            "first_seen": _iso(alert.first_seen),
            "last_seen": _iso(alert.last_seen),
            "active_seconds": round((alert.last_seen - alert.first_seen).total_seconds(), 1),
            "mitre_techniques": list(alert.mitre_techniques),
            "entities": entities,
            "summary": b.untrusted(alert.summary, LIMIT_SUMMARY),
            "evidence_truncated": alert.evidence_truncated,
        },
        "rule": {
            "description": b.trusted(ctx.rule.description, 400),
            "known_false_positives": [b.trusted(x, 200) for x in ctx.rule.false_positives[:4]],
            "blind_spots": [b.trusted(x, 160) for x in ctx.rule.blind_spots[:3]],
        },
        "asset": {
            "asset_id": ctx.asset.asset_id,
            "asset_type": ctx.asset.asset_type.value,
            "name": b.untrusted(ctx.asset.name, 64),
            "criticality": ctx.asset.criticality.value,
            "environment": ctx.asset.environment.value,
        },
        "services": services,
        "omitted_services": omitted_services,
        "related_assets": related_assets,
        "detection_features": b.attributes(alert.features, limits.max_features, allow=None),
        "correlation_features": b.attributes(ctx.features, limits.max_features, allow=None),
        "correlation": {
            "related_direct": counts[RelationshipType.DIRECT.value],
            "related_candidate": counts[RelationshipType.CANDIDATE.value],
            "related_unestablished": counts[RelationshipType.UNESTABLISHED.value],
        },
        "evidence_events": [_evidence_event(b, e, anchor, service_refs) for e in evidence_sample],
        "related_events": [_related_event(b, r, timeline_by_id.get(r.event_id)) for r in related],
        "omitted_events": omitted_evidence + omitted_related,
        "telemetry_coverage": [
            {
                "source_type": _source_type(b, c.source_type),
                "status": c.status.value,
                "stale": c.stale,
                "gap_during_window": c.gap_during_window,
                "lag_seconds": None if c.lag_seconds is None else round(c.lag_seconds, 1),
                "note": None if c.note is None else b.trusted(c.note, 160),
            }
            for c in ctx.coverage[:16]
        ],
        "missing_telemetry": [b.trusted(x, 200) for x in ctx.missing_telemetry[:10]],
        "context_limitations": [b.trusted(x, 200) for x in ctx.limitations[:10]],
        "posture_findings": [
            {
                "check_id": b.untrusted(f.check_id, 80),
                "scanner": b.untrusted(f.scanner, 40),
                "severity": f.severity.value,
                "state": f.state,
                "title": b.untrusted(f.title, LIMIT_SHORT),
            }
            for f in ctx.findings[: limits.max_findings]
        ],
        "context_truncated": {k: v for k, v in sorted(ctx.truncated.items()) if _SAFE_KEY.match(k)},
    }
    if include_simulation_marker:
        payload["simulation_marker_present"] = bool(
            ctx.simulation_run_ids or alert.simulation_run_ids
        )

    omitted = omitted_evidence + omitted_related
    omitted += _shrink_to_fit(payload, limits.max_chars)
    payload["omitted_events"] = omitted

    presented = tuple(
        [e["event_id"] for e in payload["evidence_events"]]
        + [r["event_id"] for r in payload["related_events"]]
    )
    return Projection(
        domain=domain,
        payload=payload,
        presented_event_ids=presented,
        omitted_events=omitted,
        redactions=b.redactions,
        truncated_strings=b.truncated,
        dropped_keys=b.dropped_keys,
    )


def _size(payload: Mapping[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))


def _shrink_to_fit(payload: dict[str, Any], max_chars: int) -> int:
    """Drop lowest-priority content until the payload fits; returns events dropped."""
    dropped = 0
    related: list[Any] = payload["related_events"]
    evidence: list[Any] = payload["evidence_events"]
    while _size(payload) > max_chars and related:
        related.pop()
        dropped += 1
    while _size(payload) > max_chars and len(evidence) > 1:
        evidence.pop(len(evidence) // 2)
        dropped += 1
    if _size(payload) > max_chars:
        payload["posture_findings"] = []
    for key in ("correlation_features", "detection_features"):
        while _size(payload) > max_chars and payload[key]:
            last = sorted(payload[key])[-1]
            del payload[key][last]
    if _size(payload) > max_chars:
        payload["rule"] = {"description": payload["rule"]["description"][:200]}
        for event in evidence:
            event["fields"] = {}
    if _size(payload) > max_chars:
        kept = [s for s in payload["services"] if s.get("role") == "evidence"]
        payload["omitted_services"] += len(payload["services"]) - len(kept)
        payload["services"] = kept
        payload["related_assets"] = []
    if _size(payload) > max_chars:
        raise ValueError("provider input exceeds the configured size cap after minimisation")
    return dropped

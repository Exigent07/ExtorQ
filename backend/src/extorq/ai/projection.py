"""Allow-list projection of an InvestigationContext into Jev's state.

Jev's input is built ONLY from :class:`InvestigationContext` and only from the fields
listed here. Nothing else (raw events, payloads, secrets, file contents, repository
access, SQL) is ever reachable by the provider.

Trust model of the projected payload:

* ExtorQ-generated identifiers and enums (event ids, rule ids, severities, outcomes,
  catalogued event/source types, validated IPs, timestamps, counts) are passed as plain
  JSON values.
* Every string that can carry telemetry content (log-derived summaries, actor names,
  HTTP paths, user agents, commit messages, Kubernetes fields, entity values, finding
  titles, free-form feature strings) is sanitised by
  :func:`extorq.ai.sanitize.clean_untrusted`, truncated, and wrapped as
  ``{"untrusted": "<text>"}`` so it is unmistakably delimited data.
* Raw evidence excerpts are dropped unless ``ai_include_excerpts`` is enabled.
* Evidence ``key_fields`` are normalised before any allow-list, deny-list or size limit
  is applied: the correlation builder keys them by dotted catalog path
  (``kubernetes.verb``, ``attributes.request_summary``, ``http.route``), synthetic
  contexts by flattened or leaf names (``http_route``, ``verb``). Every accepted spelling
  maps to ONE canonical name (:func:`canonical_key_field`), so the same field is never
  projected twice and real evidence reaches the provider. Keys that map to no catalog
  field or documented correlation extra are dropped and counted.
* Services (``InvestigationContext.services``) are projected as name (untrusted text),
  kind, category, adapter support, monitoring status, role and parent asset id only:
  never service attributes, configuration paths, endpoints or versions. Each service
  gets a local alias (``svc-1``...) that evidence events reference, so the only 32-hex
  values in the state are ExtorQ's event and alert ids. Enumerated values outside the
  contract enums become ``"unrecognised"``.
* Related assets (cross-asset correlation) carry id, type and criticality only.
* The total serialised size is capped; lowest-priority related events, then middle
  evidence events, then findings and features are dropped first, and the number of
  omitted events is stated in the payload.
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
    """Question-set variant: decides which domain-specific Noul Jev is asked."""

    GITHUB = "github"
    SSH_HTTP = "ssh_http"
    K8S = "k8s"
    GENERIC = "generic"


#: Evidence families that have a dedicated question variant (lead sentence + domain Noul).
_GITHUB_WORKFLOW_EVENTS = ("github.workflow.",)
_K8S_API_EVENTS = ("k8s.api.", "k8s.resource.")
#: Linux-host rules about SSH and/or HTTP activity on one host. CORR-002 (PLAN 10.2) is the
#: ordered sequence HTTP probing -> SSH auth failures -> systemd change.
_SSH_HTTP_RULES = frozenset({"VM-001", "HTTP-001", "APP-001", "CORR-001", "CORR-002"})
#: Evidence on a Linux host with these event types uses the SSH + HTTP question variant.
_SSH_HTTP_EVENT_PREFIXES = ("auth.ssh.", "http.", "app.auth.", "app.authz.")


def classify_domain(ctx: InvestigationContext) -> Domain:
    """Pick the triage question variant from what the evidence is about.

    Each variant's lead sentence and domain question describe one kind of activity
    (workflow changes, Kubernetes API privilege activity, SSH/HTTP activity on a Linux
    host), so the variant follows the evidence event types, not the rule prefix or the
    asset alone. Otherwise a GitHub alert about a committed credential would be framed as
    a workflow change, and a web-login alert from the Kubernetes-hosted app as an API
    privilege question; both get the neutral generic variant instead. Only when a context
    carries no evidence summaries (e.g. expired events) does the rule family decide.
    """
    rule_id = ctx.alert.rule_id
    linux = ctx.alert.asset_type is AssetType.LINUX_HOST
    types = {e.event_type for e in ctx.evidence}
    if types:
        github = any(t.startswith(_GITHUB_WORKFLOW_EVENTS) for t in types)
        k8s_api = any(t.startswith(_K8S_API_EVENTS) for t in types)
        ssh_http = linux and (
            rule_id in _SSH_HTTP_RULES or any(t.startswith(_SSH_HTTP_EVENT_PREFIXES) for t in types)
        )
    else:
        github = rule_id.startswith("GH-")
        k8s_api = rule_id.startswith("K8S-")
        ssh_http = linux and rule_id in _SSH_HTTP_RULES
    if github:
        return Domain.GITHUB
    if k8s_api:
        return Domain.K8S
    if ssh_http:
        return Domain.SSH_HTTP
    return Domain.GENERIC


@dataclass(frozen=True)
class ProjectionLimits:
    """Item and size bounds of one projection (``max_chars`` caps the serialised JSON)."""

    max_evidence: int
    max_related: int
    max_findings: int
    max_features: int
    max_list_items: int
    max_key_fields: int
    max_chars: int
    max_services: int = 12
    max_related_assets: int = 8


#: Jev's bounds. The provider sees at most 8 evidence and 8 related events; the
#: ``max_chars`` default is lowered further by ``EXTORQ_JEV_MAX_STATE_CHARS`` when set.
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


@dataclass
class Projection:
    """The state sent to Jev plus counters describing what minimisation removed."""

    domain: Domain
    payload: dict[str, Any]
    presented_event_ids: tuple[str, ...]
    omitted_events: int
    redactions: int
    truncated_strings: int
    dropped_keys: int

    def serialised(self) -> str:
        return json.dumps(self.payload, ensure_ascii=False, separators=(",", ":"))


# ── key_fields: canonical names and allow-list ────────────────────────
#
# Spellings accepted for one catalog key field (example ``kubernetes.verb``):
#
# * the dotted catalog path, as keyed by the correlation builder;
# * the canonical name: ``<group>_<leaf>`` (``kubernetes_verb``, ``http_route``,
#   ``network_src_ip``), or the bare leaf for ``attributes.*`` paths (``request_summary``,
#   ``risk_flags``) and for leaves that already carry their group prefix;
# * the fully flattened path (``attributes_request_summary``);
# * the bare leaf (``verb``) when exactly one catalog path ends in it, or when the evidence
#   event's own catalog entry resolves it (``namespace`` of a ``k8s.api.request`` is
#   ``kubernetes_namespace``). A leaf that stays ambiguous keeps its own name: never guessed.
#
# Documented non-catalog correlation keys (below) keep their name; ``attributes.<key>`` maps
# to it. Everything else is dropped and counted.

#: Catalog key fields not projected as fields: the evidence item already carries the
#: service as a local alias (``service_ref``) or as untrusted ``service_name``, and service
#: ids never reach Jev.
_NOT_PROJECTED_PATHS = frozenset({"service.service_id", "service.name"})

#: Documented non-catalog correlation keys (synthetic contexts, correlation extras).
EXTRA_KEY_FIELDS: frozenset[str] = frozenset(
    {
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
        "user_name",
        "kubernetes_user_agent",
    }
)


def _canonical_name(path: str) -> str:
    group, _, leaf = path.partition(".")
    if group == "attributes" or leaf.startswith(f"{group}_"):
        return leaf
    return f"{group}_{leaf}"


def _leaf(path: str) -> str:
    return path.rsplit(".", 1)[-1]


@dataclass(frozen=True)
class _KeyTables:
    #: dotted catalog path -> canonical name (projected paths only)
    canonical: Mapping[str, str]
    #: every accepted spelling -> canonical name
    aliases: Mapping[str, str]
    #: leaves shared by several catalog paths (kept under their own name when unresolved)
    ambiguous_leaves: frozenset[str]
    #: event type -> leaf -> canonical name, for leaves unique within that event type
    event_leaves: Mapping[str, Mapping[str, str]]
    #: event type -> canonical name -> position in the catalog entry (projection priority)
    event_order: Mapping[str, Mapping[str, int]]


def _build_key_tables() -> _KeyTables:
    paths = sorted({p for spec in EVENT_CATALOG.values() for p in spec.key_fields})
    canonical: dict[str, str] = {}
    owner: dict[str, str] = {}
    for path in paths:
        if path in _NOT_PROJECTED_PATHS:
            continue
        name = _canonical_name(path)
        if name in owner:  # never let two catalog fields share a name: fall back to flattening
            name = path.replace(".", "_")
        owner[name] = path
        canonical[path] = name

    aliases: dict[str, str] = {}
    for path, name in canonical.items():
        for spelling in (path, name, path.replace(".", "_")):
            aliases.setdefault(spelling, name)
    by_leaf: dict[str, list[str]] = {}
    for path in canonical:
        by_leaf.setdefault(_leaf(path), []).append(path)
    ambiguous: set[str] = set()
    for leaf, leaf_paths in by_leaf.items():
        if len(leaf_paths) == 1:
            aliases.setdefault(leaf, canonical[leaf_paths[0]])
        elif leaf not in aliases:
            ambiguous.add(leaf)
    for extra in EXTRA_KEY_FIELDS:
        aliases.setdefault(extra, extra)
        aliases.setdefault(f"attributes.{extra}", aliases[extra])

    event_leaves: dict[str, dict[str, str]] = {}
    event_order: dict[str, dict[str, int]] = {}
    for event_type, spec in EVENT_CATALOG.items():
        projected = [p for p in spec.key_fields if p in canonical]
        per_leaf: dict[str, list[str]] = {}
        for path in projected:
            per_leaf.setdefault(_leaf(path), []).append(canonical[path])
        event_leaves[event_type] = {
            leaf: names[0] for leaf, names in per_leaf.items() if len(names) == 1
        }
        event_order[event_type] = {canonical[p]: i for i, p in enumerate(projected)}
    return _KeyTables(canonical, aliases, frozenset(ambiguous), event_leaves, event_order)


_KEYS = _build_key_tables()

#: Canonical key-field names that may reach Jev (catalog fields + documented extras;
#: leaves that stay ambiguous are accepted under their own name).
ALLOWED_KEY_FIELDS: frozenset[str] = (
    frozenset(_KEYS.canonical.values()) | EXTRA_KEY_FIELDS | _KEYS.ambiguous_leaves
)


def canonical_key_field(key: str, event_type: str | None = None) -> str | None:
    """Canonical projected name of an ``EventSummary.key_fields`` key, or ``None``.

    ``event_type`` (the evidence event's catalog type) resolves leaves that are ambiguous
    across the catalog but unique within that event type.
    """
    name = _KEYS.aliases.get(key)
    if name is not None:
        return name
    if event_type is not None:
        name = _KEYS.event_leaves.get(event_type, {}).get(key)
        if name is not None:
            return name
    return key if key in _KEYS.ambiguous_leaves else None


_DENIED_KEY = re.compile(
    r"(?i)(passw|secret|token|cookie|authori[sz]ation|credential|private[_-]?key|session"
    r"|api[_-]?key|^raw$|^raw_|_raw$|payload|excerpt|file_content|^body$|^diff$|patch|^env$|env_var)"
)
_EXCERPT_KEY = re.compile(r"(?i)excerpt")
_SAFE_KEY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")

#: Admission decisions and request summaries carry the decisive Kubernetes detail; the
#: correlation builder already bounds them to 256 characters.
LIMIT_K8S_DETAIL = 256

#: Untrusted free-text limits per canonical key (default LIMIT_SHORT).
_TEXT_LIMITS: dict[str, int] = {
    "message": LIMIT_LOG_MESSAGE,
    "commit_message": LIMIT_COMMIT_MESSAGE,
    "http_route": LIMIT_HTTP_PATH,
    "resource_path": LIMIT_HTTP_PATH,
    "unit_path": LIMIT_HTTP_PATH,
    "github_workflow_path": LIMIT_HTTP_PATH,
    "cwd": LIMIT_HTTP_PATH,
    "http_user_agent": LIMIT_USER_AGENT,
    "kubernetes_user_agent": LIMIT_USER_AGENT,
    "process_command_line": LIMIT_K8S_FIELD,
    "exec_start": LIMIT_K8S_FIELD,
    "request_summary": LIMIT_K8S_DETAIL,
    "pod_security_violation": LIMIT_K8S_DETAIL,
    "annotations": LIMIT_K8S_FIELD,
    "labels": LIMIT_K8S_FIELD,
    "kubernetes_object_name": LIMIT_K8S_FIELD,
}


def _is_denied(*names: str) -> bool:
    """Deny-list check on a key, each of its dotted segments, and its canonical name."""
    return any(_DENIED_KEY.search(part) for name in names for part in (name, *name.split(".")))


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

    def _excerpt_opt_in(self, key: str) -> bool:
        return self.include_excerpts and _EXCERPT_KEY.search(key) is not None

    def attributes(self, values: Mapping[str, Any], cap: int) -> dict[str, Any]:
        """Detection / correlation features (ExtorQ-computed keys; deny-list and cap only)."""
        out: dict[str, Any] = {}
        for key in sorted(values):
            if not _SAFE_KEY.match(key):
                self.dropped_keys += 1
                continue
            if _DENIED_KEY.search(key) and not self._excerpt_opt_in(key):
                self.dropped_keys += 1
                continue
            if len(out) >= cap:
                self.dropped_keys += 1
                continue
            out[key] = self.scalar(key, values[key])
        return out

    def key_fields(self, values: Mapping[str, Any], event_type: str) -> dict[str, Any]:
        """Evidence key fields: canonical names, allow-list, deny-list, then the per-event cap.

        Keys are normalised FIRST so dotted catalog paths (the correlation builder's form)
        and flattened/leaf spellings are treated alike. When several spellings of one field
        are present, the dotted catalog path wins. Fields are kept in the event type's
        catalog order (most decisive first) before the cap applies.
        """
        chosen: dict[str, tuple[int, str]] = {}
        for raw in sorted(values):
            if not _SAFE_KEY.match(raw):
                self.dropped_keys += 1
                continue
            if self._excerpt_opt_in(raw):
                name: str | None = raw
            elif _is_denied(raw):
                self.dropped_keys += 1
                continue
            else:
                name = canonical_key_field(raw, event_type)
            if name is None or (_is_denied(name) and not self._excerpt_opt_in(name)):
                self.dropped_keys += 1
                continue
            rank = 0 if raw in _KEYS.canonical else (1 if raw == name else 2)
            previous = chosen.get(name)
            if previous is not None:
                self.dropped_keys += 1  # duplicate spelling of one field
                if (rank, raw) >= previous:
                    continue
            chosen[name] = (rank, raw)
        order = _KEYS.event_order.get(event_type, {})
        out: dict[str, Any] = {}
        for name in sorted(chosen, key=lambda n: (order.get(n, len(order)), n)):
            if len(out) >= self.limits.max_key_fields:
                self.dropped_keys += 1
                continue
            out[name] = self.scalar(name, values[chosen[name][1]])
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
        "fields": b.key_fields(e.key_fields, e.event_type),
    }
    if e.service_id is not None and e.service_id in service_refs:
        item["service_ref"] = service_refs[e.service_id]
    elif e.service_name is not None:
        item["service_name"] = b.untrusted(e.service_name, LIMIT_SERVICE_NAME)
    return item


# ── services and related assets ──────────────────────────────────────

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
    """At most ``cap`` evidence events, in time order, covering every evidence event type.

    The first event of each event type is kept before anything else (earliest types first
    if there are more types than slots), so every stage of a multi-stage detection stays
    visible: CORR-002's HTTP probes sit between earlier SSH failures and later audit
    records and were lost to plain head/tail sampling. Remaining slots go to the earliest
    and latest events.
    """
    unique = {e.event_id: e for e in evidence}
    ordered = sorted(unique.values(), key=lambda e: (e.event_time, e.event_id))
    if len(ordered) <= cap:
        return ordered, len(evidence) - len(ordered)
    first_of_type: dict[str, EventSummary] = {}
    for event in ordered:
        first_of_type.setdefault(event.event_type, event)
    chosen = {e.event_id for e in list(first_of_type.values())[:cap]}
    rest = [e for e in ordered if e.event_id not in chosen]
    remaining = cap - len(chosen)
    head = math.ceil(remaining / 2)
    tail = remaining - head
    chosen.update(e.event_id for e in rest[:head])
    if tail:
        chosen.update(e.event_id for e in rest[-tail:])
    sample = [e for e in ordered if e.event_id in chosen]
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
) -> Projection:
    """Build the sanitised, size-capped Jev state for ``ctx``.

    Raises ``ValueError`` when the payload cannot fit ``limits.max_chars`` even after
    minimisation; the caller then makes no provider call.
    """
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
        "detection_features": b.attributes(alert.features, limits.max_features),
        "correlation_features": b.attributes(ctx.features, limits.max_features),
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

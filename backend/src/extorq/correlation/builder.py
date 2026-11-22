"""ContextBuilder: deterministic, hashed InvestigationContext for one alert.

``ContextBuilder(read_client).build(alert_id)`` reads stored telemetry only (no AI,
no network calls besides ClickHouse) and returns an :class:`InvestigationContext`:

1. the newest alert version and the rule metadata that produced it
2. evidence events (``alert_evidence`` full set plus the alert array; up to 100 shown,
   head and tail kept when truncated)
3. a rule-family context window ``[first_seen - before, last_seen + after]``
4. related events: (a) events sharing an identifier or attribute with the evidence on
   any asset (request id, pod uid, audit id, commit, workflow run, resource, source IP,
   principal, service), (b) the nearest other events on the alert's
   asset (temporal proximity only); each classified DIRECT / CANDIDATE / UNESTABLISHED
   (classify.py) with bases, strength and explanation
5. services involved (evidence vs related), related assets, aggregated features,
   relevant posture findings, telemetry coverage, missing telemetry, limitations and
   truncation flags
6. ``input_hash`` = SHA-256 of the canonical bundle without ``context_id``,
   ``created_at`` and ``input_hash``; ``context_id = identity.context_id(alert, hash)``

Same stored data + same build time => same hash. Late events, new collector health
reports or a newer rule version produce a different hash (and a new stored context).
Read failures of optional sections (findings, coverage, services) are recorded as
limitations instead of failing the build; the alert, rule and evidence are mandatory.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from pydantic import ValidationError

from extorq.contracts.alert import DetectionAlert, RuleMetadata, RuleRunStatus
from extorq.contracts.catalog import SourceType
from extorq.contracts.common import (
    AssetType,
    Criticality,
    Environment,
    HealthStatus,
    Severity,
    utc_now,
)
from extorq.contracts.context import (
    AssetSummary,
    FindingSummary,
    InvestigationContext,
    Relationship,
    ServiceSummary,
    SourceCoverage,
    TimelineEntry,
)
from extorq.contracts.identity import canonical_json, context_id, input_hash
from extorq.correlation.classify import EvidenceProfile, classify, rank_key
from extorq.correlation.config import CorrelationSettings
from extorq.correlation.features import compute_features
from extorq.correlation.records import EVENT_COLUMNS, EventRecord, record_from_row
from extorq.detection._compat import get_logger, sanitize, sanitize_error
from extorq.detection.clients import DbClient, QueryRows, chunked, wrap
from extorq.detection.service_identity import (
    assets_related,
    reference_allowed,
    valid_service_assets,
)
from extorq.version import __version__

log = get_logger(__name__)

BUILDER_VERSION = f"extorq-correlation/{__version__}"
MAX_EVIDENCE_SHOWN = 100
MAX_TIMELINE = 300
MAX_FINDINGS = 50
MAX_SERVICES = 32
MAX_RELATED_ASSETS = 16
MAX_COVERAGE = 32
MAX_NOTES = 32
HASH_EXCLUDED = ("context_id", "created_at", "input_hash")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_SOURCE_TYPES = {s.value for s in SourceType}
_STATE_RANK = {"open": 0, "unverified": 1, "resolved": 2}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── static SQL (server-side parameters only) ─────────────────────────────────────
ALERT_SQL = (
    "SELECT payload FROM alerts WHERE alert_id = {alert_id:String} ORDER BY updated_at DESC LIMIT 1"
)
EVIDENCE_IDS_SQL = (
    "SELECT event_id FROM alert_evidence WHERE alert_id = {alert_id:String} "
    "AND added_at <= {version_at:DateTime64(3, 'UTC')} "
    "GROUP BY event_id ORDER BY event_id LIMIT 100000"
)
EVENTS_BY_ID_SQL = (
    "SELECT "  # noqa: S608 - static column-list constant; values are server-side params
    + EVENT_COLUMNS
    + " FROM events WHERE event_id IN {ids:Array(String)} "
    "ORDER BY event_time, event_id LIMIT 1 BY event_id"
)
#: Events sharing an identifier/attribute with the evidence (any asset). Host principal
#: names and resources are compared on the alert's asset only; across assets only
#: authenticated principals, IPs, request ids, pod uids, audit ids, commits, runs.
LINKED_SQL = (
    "SELECT "  # noqa: S608 - static column-list constant; values are server-side params
    + EVENT_COLUMNS
    + """ FROM events
WHERE event_time >= {ws:DateTime64(3, 'UTC')} AND event_time <= {we:DateTime64(3, 'UTC')}
  AND event_id NOT IN {evidence:Array(String)}
  AND (
        (http_request_id IS NOT NULL AND http_request_id IN {request_ids:Array(String)})
     OR (k8s_pod_uid IS NOT NULL AND k8s_pod_uid IN {pod_uids:Array(String)})
     OR (k8s_audit_id IS NOT NULL AND k8s_audit_id IN {audit_ids:Array(String)})
     OR (gh_commit_sha IS NOT NULL AND gh_commit_sha IN {commit_shas:Array(String)})
     OR (gh_workflow_run_id IS NOT NULL AND gh_workflow_run_id IN {run_ids:Array(UInt64)})
     OR (src_ip IS NOT NULL AND src_ip IN {ips:Array(String)})
     OR hasAny(k8s_source_ips, {ips:Array(String)})
     OR (k8s_user IS NOT NULL AND k8s_user IN {auth_principals:Array(String)})
     OR (gh_actor_login IS NOT NULL AND gh_actor_login IN {auth_principals:Array(String)})
     OR (actor_name IS NOT NULL AND actor_name IN {auth_principals:Array(String)})
     OR (asset_id = {asset:String} AND (
            (actor_name IS NOT NULL AND actor_name IN {principals:Array(String)})
         OR (resource_path IS NOT NULL AND resource_path IN {paths:Array(String)})
         OR (resource_name IS NOT NULL AND resource_name IN {names:Array(String)})
         OR (k8s_object_name IS NOT NULL AND k8s_object_name IN {names:Array(String)})
         OR (gh_workflow_path IS NOT NULL AND gh_workflow_path IN {paths:Array(String)})
         OR (svc_id IS NOT NULL AND svc_id IN {service_ids:Array(String)})))
  )
ORDER BY (asset_id = {asset:String}) DESC, event_time, event_id
LIMIT 1 BY event_id
LIMIT {limit:UInt32}"""
)
#: Nearest other events on the alert's asset (temporal proximity only).
TEMPORAL_SQL = (
    "SELECT "  # noqa: S608 - static column-list constant; values are server-side params
    + EVENT_COLUMNS
    + """ FROM events
WHERE asset_id = {asset:String}
  AND event_time >= {ws:DateTime64(3, 'UTC')} AND event_time <= {we:DateTime64(3, 'UTC')}
  AND event_id NOT IN {evidence:Array(String)}
ORDER BY abs(toUnixTimestamp64Milli(event_time) - {anchor_ms:Int64}), event_id
LIMIT 1 BY event_id
LIMIT {limit:UInt32}"""
)
RULE_BY_VERSION_SQL = (
    "SELECT rule_id, version, title, description, severity, status, mitre_techniques, "
    "asset_types, requires, schedule, dedup, group_by, params, false_positives, blind_spots, "
    "reference_urls, query_sha256 FROM detection_rules "
    "WHERE rule_id = {rule_id:String} "
    "ORDER BY (version = {version:String}) DESC, loaded_at DESC LIMIT 1"
)
ASSETS_SQL = (
    "SELECT asset_id, argMax(asset_type, last_seen) AS a_type, argMax(name, last_seen) AS a_name, "
    "argMax(criticality, last_seen) AS a_criticality, "
    "argMax(environment, last_seen) AS a_environment "
    "FROM assets WHERE asset_id IN {ids:Array(String)} GROUP BY asset_id"
)
SERVICES_SQL = (
    "SELECT service_id, asset_id, service_kind, service_key, "
    "argMax(name, last_seen) AS s_name, argMax(category, last_seen) AS s_category, "
    "argMax(adapter_support, last_seen) AS s_support, "
    "argMax(monitoring_status, last_seen) AS s_status "
    "FROM services WHERE service_id IN {ids:Array(String)} "
    "GROUP BY service_id, asset_id, service_kind, service_key LIMIT 10000"
)
FINDINGS_CURRENT_SQL = (
    "SELECT finding_id, scanner, check_id, severity, title, state, last_observed_at "
    "FROM v_findings_current WHERE asset_id = {asset:String} AND state != 'resolved' "
    "ORDER BY multiIf(state = 'open', 0, 1), "
    "multiIf(severity = 'critical', 0, severity = 'high', 1, severity = 'medium', 2, "
    "severity = 'low', 3, 4), last_observed_at DESC, finding_id LIMIT {limit:UInt32}"
)
#: 0005 (C3): v_findings_current.service_id. Findings of the alert's evidence services first.
FINDINGS_SERVICE_SQL = (
    "SELECT finding_id, scanner, check_id, severity, title, state, last_observed_at, "
    "ifNull(service_id, '') AS f_service FROM v_findings_current "
    "WHERE asset_id = {asset:String} AND state != 'resolved' "
    "ORDER BY has({services:Array(String)}, ifNull(service_id, '')) DESC, "
    "multiIf(state = 'open', 0, 1), "
    "multiIf(severity = 'critical', 0, severity = 'high', 1, severity = 'medium', 2, "
    "severity = 'low', 3, 4), last_observed_at DESC, finding_id LIMIT {limit:UInt32}"
)
FINDINGS_RAW_SQL = (
    "SELECT finding_id, f_scanner AS scanner, f_check AS check_id, f_severity AS severity, "
    "f_title AS title, 'unverified' AS state, f_last AS last_observed_at FROM ("
    "SELECT finding_id, argMax(scanner, observed_at) AS f_scanner, "
    "argMax(check_id, observed_at) AS f_check, argMax(severity, observed_at) AS f_severity, "
    "argMax(title, observed_at) AS f_title, max(observed_at) AS f_last "
    "FROM finding_observations WHERE asset_id = {asset:String} GROUP BY finding_id) "
    "ORDER BY multiIf(f_severity = 'critical', 0, f_severity = 'high', 1, "
    "f_severity = 'medium', 2, f_severity = 'low', 3, 4), f_last DESC, finding_id "
    "LIMIT {limit:UInt32}"
)
COLLECTORS_SQL = (
    "SELECT collector_id, asset_id, source_types, status, last_success_at, lag_seconds, "
    "interval_seconds FROM v_collector_latest WHERE asset_id IN {assets:Array(String)} "
    "AND hasAny(source_types, {sources:Array(String)}) ORDER BY collector_id LIMIT 500"
)
COLLECTOR_WINDOW_SQL = (
    "SELECT collector_id, asset_id, countIf(status IN ('failed', 'degraded')) AS bad, "
    "count() AS reports "
    "FROM collector_health WHERE collector_id IN {ids:Array(String)} "
    "AND asset_id IN {assets:Array(String)} "
    "AND reported_at >= {ws:DateTime64(3, 'UTC')} AND reported_at <= {we:DateTime64(3, 'UTC')} "
    "GROUP BY collector_id, asset_id"
)
GAP_EVENTS_SQL = (
    "SELECT DISTINCT asset_id, source_type "
    "FROM events WHERE event_type = 'extorq.collector.gap_detected' "
    "AND asset_id IN {assets:Array(String)} AND source_type IN {sources:Array(String)} "
    "AND event_time >= {ws:DateTime64(3, 'UTC')} AND event_time <= {we:DateTime64(3, 'UTC')} "
    "LIMIT 100"
)
SOURCES_PRESENT_SQL = (
    "SELECT source_type, uniqExact(event_id) AS n FROM events "
    "WHERE asset_id = {asset:String} AND source_type IN {sources:Array(String)} "
    "AND event_time >= {ws:DateTime64(3, 'UTC')} AND event_time <= {we:DateTime64(3, 'UTC')} "
    "GROUP BY source_type"
)
RULE_RUN_MISSING_SQL = (
    "SELECT s, count() AS runs FROM rule_runs ARRAY JOIN missing_sources AS s "
    "WHERE rule_id = {rule_id:String} AND status = {status:String} "
    "AND rule_version = {version:String} "
    "AND window_end >= {ws:DateTime64(3, 'UTC')} AND window_start <= {we:DateTime64(3, 'UTC')} "
    "GROUP BY s ORDER BY s LIMIT 32"
)


class ContextBuildError(RuntimeError):
    """The context cannot be built (alert or rule metadata unavailable)."""


class AlertNotFound(ContextBuildError, LookupError):
    """No stored alert with this id."""


def compute_input_hash(body: Mapping[str, Any]) -> str:
    """SHA-256 of the canonical bundle (``body`` = JSON form of an InvestigationContext)."""
    return input_hash({k: v for k, v in body.items() if k not in HASH_EXCLUDED})


def context_input_hash(ctx: InvestigationContext) -> str:
    return compute_input_hash(json.loads(canonical_json(ctx.model_dump(mode="json"))))


def _enum_or(value: Any, enum: type[Any], default: Any) -> Any:
    try:
        return enum(value)
    except (ValueError, TypeError):
        return default


class ContextBuilder:
    """Build InvestigationContexts from stored telemetry (read-only identity)."""

    def __init__(
        self,
        read_client: Any,
        *,
        rules: Mapping[str, RuleMetadata] | None = None,
        settings: CorrelationSettings | None = None,
    ) -> None:
        self.db: DbClient = wrap(read_client)
        self.rules = dict(rules or {})
        self.settings = settings or CorrelationSettings()

    # ── public ────────────────────────────────────────────────────────
    def build(self, alert_id: str, *, now: datetime | None = None) -> InvestigationContext:
        if not isinstance(alert_id, str) or not _HEX32.match(alert_id):
            raise ValueError("alert_id must be 32 lower-case hex characters")
        now = now or utc_now()
        notes = _Notes()
        alert = self._load_alert(alert_id)
        rule = self._load_rule(alert, notes)
        window = self.settings.window_for(alert.rule_id)
        ws = alert.first_seen - timedelta(seconds=window.before_seconds)
        we = alert.last_seen + timedelta(seconds=window.after_seconds)

        evidence, evidence_total = self._evidence(alert)
        if not evidence:
            notes.limit("No evidence event of this alert could be read from the events table.")
        nat = frozenset(self.settings.shared_nat_ips)
        profile = EvidenceProfile.from_events(
            alert.asset_id, alert.first_seen, evidence, nat_ips=nat
        )
        related, relationships, related_truncated = self._related(alert, profile, evidence, ws, we)

        shown = _head_tail(evidence, MAX_EVIDENCE_SHOWN)
        truncated = {
            "evidence": evidence_total > len(shown),
            "related": related_truncated,
        }
        services = self._services(evidence, related, relationships, notes)
        truncated["services"] = services[1]
        related_assets = self._related_assets(alert, related, relationships, notes)
        truncated["related_assets"] = related_assets[1]
        asset = self._asset(alert, notes)
        evidence_services = sorted({sid for e in evidence for sid in e.all_service_ids})
        findings, findings_truncated, service_findings = self._findings(
            alert.asset_id, evidence_services, notes
        )
        truncated["findings"] = findings_truncated
        coverage = self._coverage(rule, evidence, alert, ws, we, now, notes)
        self._missing(rule, alert, ws, we, notes)
        timeline, timeline_truncated = _timeline(shown, related, relationships)
        truncated["timeline"] = timeline_truncated
        interval = rule.params.get("corroboration_seconds", 120)
        features = compute_features(
            alert,
            evidence,
            related,
            relationships,
            nat_ips=nat,
            corroboration_seconds=interval if type(interval) is int and interval > 0 else 120,
        )
        features["findings_on_evidence_services"] = service_findings
        self._limitations(evidence, evidence_total, shown, profile, coverage, notes)

        draft = InvestigationContext(
            context_id="0" * 32,
            alert_id=alert.alert_id,
            builder_version=BUILDER_VERSION,
            created_at=now,
            input_hash="0" * 64,
            window_start=ws,
            window_end=we,
            alert=alert,
            rule=rule,
            asset=asset,
            services=services[0],
            related_assets=related_assets[0],
            evidence=[e.to_summary() for e in shown],
            timeline=timeline,
            relationships=relationships,
            features=features,
            findings=findings,
            coverage=coverage,
            missing_telemetry=notes.missing[:MAX_NOTES],
            limitations=notes.limitations[:MAX_NOTES],
            truncated=dict(sorted(truncated.items())),
        )
        digest = context_input_hash(draft)
        return draft.model_copy(
            update={"input_hash": digest, "context_id": context_id(alert.alert_id, digest)}
        )

    # ── alert, rule, evidence ─────────────────────────────────────────
    def _load_alert(self, alert_id: str) -> DetectionAlert:
        rows = self.db.select(ALERT_SQL, {"alert_id": alert_id}).rows
        if not rows:
            raise AlertNotFound(f"alert {alert_id} not found")
        try:
            return DetectionAlert.model_validate_json(rows[0][0])
        except ValidationError as exc:
            raise ContextBuildError(
                f"stored alert {alert_id} failed contract validation ({exc.error_count()} errors)"
            ) from None

    def _load_rule(self, alert: DetectionAlert, notes: _Notes) -> RuleMetadata:
        given = self.rules.get(alert.rule_id)
        if given is not None and given.version == alert.rule_version:
            return given
        try:
            rows = self.db.select(
                RULE_BY_VERSION_SQL, {"rule_id": alert.rule_id, "version": alert.rule_version}
            ).dicts()
        except Exception as exc:  # noqa: BLE001 - fall back to the in-process registry
            log.warning(
                "rule_metadata_read_failed", rule_id=alert.rule_id, error=sanitize_error(exc)
            )
            rows = []
        rule: RuleMetadata | None = None
        if rows:
            try:
                rule = _rule_from_row(rows[0])
            except (ValidationError, ValueError, TypeError) as exc:
                log.warning(
                    "rule_metadata_invalid", rule_id=alert.rule_id, error=sanitize_error(exc)
                )
        if rule is None:
            rule = given or _rule_from_registry(alert.rule_id)
        if rule is None:
            raise ContextBuildError(f"rule metadata for {alert.rule_id} is not available")
        if rule.version != alert.rule_version:
            notes.limit(
                f"Rule metadata shown is version {rule.version}; the alert was last written by "
                f"version {alert.rule_version}."
            )
        return rule

    def _evidence(self, alert: DetectionAlert) -> tuple[list[EventRecord], int]:
        ids: list[str] = list(alert.evidence_event_ids)
        seen = set(ids)
        try:
            result = self.db.select(
                EVIDENCE_IDS_SQL, {"alert_id": alert.alert_id, "version_at": alert.updated_at}
            )
            stored = [str(r[0]) for r in result.rows]
        except Exception as exc:  # noqa: BLE001 - the alert array is still authoritative
            log.warning(
                "alert_evidence_read_failed", alert_id=alert.alert_id, error=sanitize_error(exc)
            )
            stored = []
        for eid in stored:
            if eid not in seen and _HEX32.match(eid):
                seen.add(eid)
                ids.append(eid)
        total = max(len(seen), alert.event_count)
        fetch = ids[: self.settings.max_evidence_fetch]
        return self._events_by_id(fetch), total

    def _events_by_id(self, ids: Sequence[str]) -> list[EventRecord]:
        records: list[EventRecord] = []
        for batch in chunked(ids, 500):
            records.extend(_records(self.db.select(EVENTS_BY_ID_SQL, {"ids": batch})))
        records.sort(key=lambda e: (e.event_time, e.event_id))
        return records

    # ── related events ────────────────────────────────────────────────
    def _related(
        self,
        alert: DetectionAlert,
        profile: EvidenceProfile,
        evidence: Sequence[EventRecord],
        ws: datetime,
        we: datetime,
    ) -> tuple[list[EventRecord], list[Relationship], bool]:
        evidence_ids = sorted({*profile.event_ids, *alert.evidence_event_ids})[:1000]
        names = {
            n
            for e in evidence
            if e.asset_id == alert.asset_id
            for n in (e.resource_name, e.k8s_object_name, e.unit_name())
            if n
        }
        paths = {
            p
            for e in evidence
            if e.asset_id == alert.asset_id
            for p in (e.resource_path, e.gh_workflow_path)
            if p
        }
        params = {
            "ws": ws,
            "we": we,
            "asset": alert.asset_id,
            "evidence": evidence_ids,
            "request_ids": sorted(profile.request_ids)[:200],
            "pod_uids": sorted({uid for _, uid in profile.pod_uids})[:200],
            "audit_ids": sorted({aid for _, aid in profile.audit_ids})[:200],
            "commit_shas": sorted({sha for _, sha in profile.commit_shas})[:200],
            "run_ids": sorted({rid for _, rid in profile.run_ids})[:200],
            "ips": sorted(profile.source_ips)[:100],
            "auth_principals": sorted(profile.authenticated_principals)[:50],
            "principals": sorted(profile.principals)[:100],
            "paths": sorted(paths)[:100],
            "names": sorted(names)[:100],
            "service_ids": sorted(profile.service_ids)[:50],
            "limit": self.settings.max_linked_rows + 1,
        }
        linked = _records(self.db.select(LINKED_SQL, params))
        linked_truncated = len(linked) > self.settings.max_linked_rows
        linked = linked[: self.settings.max_linked_rows]
        known = {e.event_id for e in linked} | set(evidence_ids)
        temporal: list[EventRecord] = []
        if self.settings.max_temporal:
            anchor_ms = int(alert.first_seen.timestamp() * 1000)
            rows = _records(
                self.db.select(
                    TEMPORAL_SQL,
                    {
                        "asset": alert.asset_id,
                        "ws": ws,
                        "we": we,
                        "evidence": evidence_ids,
                        "anchor_ms": anchor_ms,
                        "limit": self.settings.max_temporal + len(linked) + 1,
                    },
                )
            )
            temporal = [e for e in rows if e.event_id not in known][: self.settings.max_temporal]

        by_id: dict[str, EventRecord] = {}
        relationships: list[Relationship] = []
        for event in [*linked, *temporal]:
            if event.event_id in by_id:
                continue
            rel = classify(event, profile)
            if rel is None:
                continue
            by_id[event.event_id] = event
            relationships.append(rel)
        relationships.sort(key=rank_key)
        cap = self.settings.max_related
        truncated = linked_truncated or len(relationships) > cap
        kept = relationships[:cap]
        kept_ids = {r.event_id for r in kept}
        related = sorted(
            (e for eid, e in by_id.items() if eid in kept_ids),
            key=lambda e: (e.event_time, e.event_id),
        )
        return related, kept, truncated

    # ── services, assets, findings ────────────────────────────────────
    def _services(
        self,
        evidence: Sequence[EventRecord],
        related: Sequence[EventRecord],
        relationships: Sequence[Relationship],
        notes: _Notes,
    ) -> tuple[list[ServiceSummary], bool]:
        # Producing services and subject services (records ABOUT a service) both count.
        evidence_ids = sorted({sid for e in evidence for sid in e.all_service_ids})
        related_ids = sorted(
            {sid for e in related for sid in e.all_service_ids} - set(evidence_ids)
        )
        wanted = [*evidence_ids, *related_ids]
        if not wanted:
            if evidence:
                notes.limit(
                    "Evidence events carry no service attribution (no adapter attributed them)."
                )
            return [], False
        names = {e.service_id: e.service_name for e in [*evidence, *related] if e.service_id}
        assets: dict[str, str] = {}
        for e in [*evidence, *related]:
            for sid in e.all_service_ids:
                assets.setdefault(sid, e.asset_id)
        rows: list[dict[str, Any]] = []
        try:
            rows = self.db.select(SERVICES_SQL, {"ids": wanted[:200]}).dicts()
        except Exception as exc:  # noqa: BLE001 - service inventory is optional context
            log.warning("service_inventory_read_failed", error=sanitize_error(exc))
            notes.limit("Service inventory could not be read; service details are unknown.")
        # Only rows whose id recomputes from (asset, kind, key) count (F-IC-6), and only on
        # an asset related to the event that referenced the service.
        valid = valid_service_assets(rows)
        records: dict[str, dict[str, Any]] = {}
        for row in rows:
            sid, asset = str(row["service_id"]), str(row["asset_id"])
            trusted = asset in valid.get(sid, set())
            if trusted and sid in assets and assets_related(assets[sid], asset):
                records.setdefault(sid, row)
        out: list[ServiceSummary] = []
        missing = shadowed = 0
        for sid in wanted[:MAX_SERVICES]:
            role = "evidence" if sid in evidence_ids else "related"
            record = records.get(sid)
            if record is None:
                if not reference_allowed(sid, assets[sid], valid):
                    shadowed += 1
                else:
                    missing += 1
                out.append(
                    ServiceSummary(
                        service_id=sid,
                        asset_id=assets[sid],
                        name=sanitize(names.get(sid) or "unknown", 256),
                        service_kind="unknown",
                        category="unknown",
                        adapter_support="unknown",
                        monitoring_status="unknown",
                        role=role,
                    )
                )
                continue
            out.append(
                ServiceSummary(
                    service_id=sid,
                    asset_id=str(record["asset_id"]),
                    name=sanitize(str(record["s_name"]), 256) or "unknown",
                    service_kind=sanitize(str(record["service_kind"]), 64) or "unknown",
                    category=sanitize(str(record["s_category"]), 64) or "unknown",
                    adapter_support=sanitize(str(record["s_support"]), 64) or "unknown",
                    monitoring_status=sanitize(str(record["s_status"]), 64) or "unknown",
                    role=role,
                )
            )
        if missing:
            notes.limit(
                f"No service inventory record for {missing} attributed service(s); their kind, "
                "category and coverage are shown as unknown."
            )
        if shadowed:
            notes.limit(
                f"{shadowed} service reference(s) point to a service id registered for an "
                "unrelated asset; the reference is not trusted and details are shown as unknown."
            )
        return out, len(wanted) > MAX_SERVICES

    def _asset_rows(self, ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        if not ids:
            return {}
        rows = self.db.select(ASSETS_SQL, {"ids": list(ids)}).dicts()
        return {str(r["asset_id"]): r for r in rows}

    def _asset(self, alert: DetectionAlert, notes: _Notes) -> AssetSummary:
        try:
            row = self._asset_rows([alert.asset_id]).get(alert.asset_id)
        except Exception as exc:  # noqa: BLE001 - asset inventory is optional context
            log.warning("asset_read_failed", error=sanitize_error(exc))
            row = None
        if row is None:
            # The contract requires both values; the defaults are named, never presented as
            # observed inventory.
            notes.limit(
                "No asset inventory record for the alert asset: criticality and environment "
                "are unknown and shown as the contract defaults."
            )
            return AssetSummary(
                asset_id=alert.asset_id,
                asset_type=alert.asset_type,
                name=alert.asset_id,
                criticality=Criticality.MEDIUM,
                environment=Environment.LAB,
            )
        return _asset_summary(row, alert.asset_type)

    def _related_assets(
        self,
        alert: DetectionAlert,
        related: Sequence[EventRecord],
        relationships: Sequence[Relationship],
        notes: _Notes,
    ) -> tuple[list[AssetSummary], bool]:
        types: dict[str, str] = {}
        for event in related:
            if event.asset_id != alert.asset_id:
                types.setdefault(event.asset_id, event.asset_type)
        ids = sorted(types)
        if not ids:
            return [], False
        try:
            rows = self._asset_rows(ids[:MAX_RELATED_ASSETS])
        except Exception as exc:  # noqa: BLE001 - optional context
            log.warning("related_asset_read_failed", error=sanitize_error(exc))
            rows = {}
        out: list[AssetSummary] = []
        for asset_id in ids[:MAX_RELATED_ASSETS]:
            fallback = _enum_or(types[asset_id], AssetType, None)
            row = rows.get(asset_id)
            if row is not None:
                out.append(_asset_summary(row, fallback or alert.asset_type))
            elif fallback is not None:
                out.append(
                    AssetSummary(
                        asset_id=asset_id,
                        asset_type=fallback,
                        name=asset_id,
                        criticality=Criticality.MEDIUM,
                        environment=Environment.LAB,
                    )
                )
        if len(out) < len(ids[:MAX_RELATED_ASSETS]) or len(rows) < len(out):
            notes.limit(
                "Some related assets have no inventory record; contract defaults are shown."
            )
        return out, len(ids) > MAX_RELATED_ASSETS

    def _findings(
        self, asset_id: str, service_ids: Sequence[str], notes: _Notes
    ) -> tuple[list[FindingSummary], bool, int]:
        params = {"asset": asset_id, "limit": MAX_FINDINGS + 1}
        rows: list[dict[str, Any]] = []
        try:
            rows = self.db.select(
                FINDINGS_SERVICE_SQL, {**params, "services": list(service_ids)}
            ).dicts()
        except Exception as exc:  # noqa: BLE001 - view without service_id (before 0005)
            log.info("findings_service_view_unavailable", error=sanitize_error(exc))
            rows = []
            try:
                rows = self.db.select(FINDINGS_CURRENT_SQL, params).dicts()
            except Exception as exc2:  # noqa: BLE001 - C3's view may be absent: fallback below
                log.info("findings_view_unavailable", error=sanitize_error(exc2))
                raw = self._raw_findings(params, notes)
                if raw is None:
                    return [], False, 0
                rows = raw
        return self._finding_summaries(rows, service_ids)

    def _raw_findings(self, params: dict[str, Any], notes: _Notes) -> list[dict[str, Any]] | None:
        """Fallback without C3's lifecycle view: newest raw observation per finding."""
        try:
            rows = self.db.select(FINDINGS_RAW_SQL, params).dicts()
        except Exception as exc:  # noqa: BLE001 - findings are optional context
            log.warning("findings_read_failed", error=sanitize_error(exc))
            notes.limit("Posture findings could not be read.")
            return None
        if rows:
            notes.limit(
                "Findings lifecycle view unavailable: raw observations are shown as unverified."
            )
        return rows

    def _finding_summaries(
        self, rows: list[dict[str, Any]], service_ids: Sequence[str]
    ) -> tuple[list[FindingSummary], bool, int]:
        wanted = set(service_ids)
        on_services = 0
        out: list[FindingSummary] = []
        for row in rows[:MAX_FINDINGS]:
            severity = _enum_or(row.get("severity"), Severity, None)
            state = row.get("state")
            last = row.get("last_observed_at")
            if severity is None or state not in _STATE_RANK or not isinstance(last, datetime):
                continue
            if not isinstance(row.get("finding_id"), str) or not _HEX32.match(row["finding_id"]):
                continue
            if row.get("f_service") and row.get("f_service") in wanted:
                on_services += 1
            out.append(
                FindingSummary(
                    finding_id=row["finding_id"],
                    scanner=sanitize(str(row.get("scanner") or "unknown"), 256),
                    check_id=sanitize(str(row.get("check_id") or "unknown"), 256),
                    severity=severity,
                    title=sanitize(str(row.get("title") or ""), 256) or "untitled",
                    state=state,
                    last_observed_at=last,
                )
            )
        return out, len(rows) > MAX_FINDINGS, on_services

    # ── coverage and missing telemetry ────────────────────────────────
    def _coverage(
        self,
        rule: RuleMetadata,
        evidence: Sequence[EventRecord],
        alert: DetectionAlert,
        ws: datetime,
        we: datetime,
        now: datetime,
        notes: _Notes,
    ) -> list[SourceCoverage]:
        sources = sorted(
            {r.source_type.value for r in rule.requires}
            | {e.source_type for e in evidence if e.source_type in _SOURCE_TYPES}
        )
        scoped_assets = _coverage_assets(alert.asset_id, evidence)
        assets = sorted({alert.asset_id} | {a for group in scoped_assets.values() for a in group})
        scope = {"assets": assets, "sources": sources}
        try:
            collectors = self.db.select(COLLECTORS_SQL, scope).dicts()
        except Exception as exc:  # noqa: BLE001 - coverage is optional context
            log.warning("coverage_read_failed", error=sanitize_error(exc))
            notes.limit("Collector health could not be read; telemetry coverage is unknown.")
            return []
        check_end = min(we, now)
        chosen: list[tuple[str, dict[str, Any] | None]] = []
        for source in sources:
            source_assets = scoped_assets.get(source, {alert.asset_id})
            for asset in sorted(source_assets):
                matching = [
                    c
                    for c in collectors
                    if c.get("asset_id") == asset and source in (c.get("source_types") or [])
                ]
                if not matching:
                    chosen.append((source, None))
                chosen.extend((source, c) for c in matching[:4])
        ids = sorted({str(c["collector_id"]) for _, c in chosen if c is not None})
        window_stats: dict[tuple[str, str], tuple[int, int]] = {}
        gap_sources: set[tuple[str, str]] = set()
        try:
            if ids:
                for cid, asset, bad, reports in self.db.select(
                    COLLECTOR_WINDOW_SQL, {"ids": ids, "assets": assets, "ws": ws, "we": check_end}
                ).rows:
                    window_stats[(str(cid), str(asset))] = (int(bad), int(reports))
            gap_sources = {
                (str(asset), str(source))
                for asset, source in self.db.select(
                    GAP_EVENTS_SQL, {**scope, "ws": ws, "we": check_end}
                ).rows
            }
        except Exception as exc:  # noqa: BLE001 - partial coverage is still useful
            log.warning("coverage_window_read_failed", error=sanitize_error(exc))
            notes.limit("Collector health history for the window could not be read.")
        out: list[SourceCoverage] = []
        for source, collector in chosen:
            if collector is None:
                out.append(
                    SourceCoverage(
                        source_type=source,
                        collector_id=None,
                        status=HealthStatus.UNKNOWN,
                        stale=True,
                        gap_during_window=True,
                        note="No collector health report for this source and asset.",
                    )
                )
                continue
            entry = _coverage_entry(
                source, collector, ws, check_end, now, window_stats, gap_sources
            )
            out.append(entry)
        out.sort(key=lambda c: (c.source_type, c.collector_id or ""))
        return out[:MAX_COVERAGE]

    def _missing(
        self, rule: RuleMetadata, alert: DetectionAlert, ws: datetime, we: datetime, notes: _Notes
    ) -> None:
        sources = sorted({r.source_type.value for r in rule.requires})
        optional = {r.source_type.value for r in rule.requires if r.optional}
        try:
            present = {
                str(r[0])
                for r in self.db.select(
                    SOURCES_PRESENT_SQL,
                    {"asset": alert.asset_id, "sources": sources, "ws": ws, "we": we},
                ).rows
            }
            for source in sources:
                if source not in present:
                    kind = "optional" if source in optional else "required"
                    notes.miss(
                        f"No {source} events from {alert.asset_id} in the context window "
                        f"({kind} source of {rule.rule_id})."
                    )
        except Exception as exc:  # noqa: BLE001 - optional context
            log.warning("source_presence_read_failed", error=sanitize_error(exc))
            notes.limit("Telemetry presence in the context window could not be checked.")
        try:
            rows = self.db.select(
                RULE_RUN_MISSING_SQL,
                {
                    "rule_id": alert.rule_id,
                    "version": alert.rule_version,
                    "status": RuleRunStatus.SUCCEEDED.value,
                    "ws": alert.window_start,
                    "we": alert.window_end,
                },
            ).rows
            for source, runs in rows:
                if str(source) in _SOURCE_TYPES:
                    notes.miss(
                        f"{int(runs)} evaluation(s) of {rule.rule_id} overlapping the alert found "
                        f"no {source} events across monitored assets in their window."
                    )
        except Exception as exc:  # noqa: BLE001 - optional context
            log.warning("rule_run_read_failed", error=sanitize_error(exc))

    def _limitations(
        self,
        evidence: Sequence[EventRecord],
        evidence_total: int,
        shown: Sequence[EventRecord],
        profile: EvidenceProfile,
        coverage: Sequence[SourceCoverage],
        notes: _Notes,
    ) -> None:
        notes.limitations.insert(
            0,
            "Relationships show co-occurrence and shared attributes within the context window; "
            "they never establish causation.",
        )
        for ip in sorted(profile.source_ips & profile.nat_ips)[:3]:
            notes.limit(
                f"Evidence source IP {ip} is a shared NAT/gateway/loopback address: it does not "
                "identify one origin, and links through it stay unestablished."
            )
        if evidence_total > len(shown):
            notes.limit(
                f"Evidence list shows {len(shown)} of {evidence_total} evidence events "
                "(earliest and latest kept)."
            )
        if len(evidence) < min(evidence_total, self.settings.max_evidence_fetch):
            notes.limit(
                f"Only {len(evidence)} of {evidence_total} evidence events were readable; the "
                "rest may have expired (TTL) or not yet been written."
            )
        if any(c.stale or c.gap_during_window for c in coverage):
            notes.limit(
                "At least one telemetry source is stale or had a gap during the window: absence "
                "of related events is not evidence of absence."
            )


# ── helpers ──────────────────────────────────────────────────────────────────


class _Notes:
    """Trusted text only: fixed phrases plus validated identifiers (no telemetry text)."""

    def __init__(self) -> None:
        self.missing: list[str] = []
        self.limitations: list[str] = []

    def miss(self, text: str) -> None:
        if text not in self.missing:
            self.missing.append(text[:2048])

    def limit(self, text: str) -> None:
        if text not in self.limitations:
            self.limitations.append(text[:2048])


def _records(result: QueryRows) -> list[EventRecord]:
    out: list[EventRecord] = []
    for row in result.dicts():
        record = record_from_row(row)
        if record is not None:
            out.append(record)
    return out


def _head_tail(events: Sequence[EventRecord], cap: int) -> list[EventRecord]:
    ordered = sorted(events, key=lambda e: (e.event_time, e.event_id))
    if len(ordered) <= cap:
        return ordered
    head = (cap + 1) // 2
    return ordered[:head] + ordered[-(cap - head) :]


def _timeline(
    shown: Sequence[EventRecord],
    related: Sequence[EventRecord],
    relationships: Sequence[Relationship],
) -> tuple[list[TimelineEntry], bool]:
    types = {r.event_id: r.relationship_type for r in relationships}
    entries = [
        TimelineEntry(
            event_id=e.event_id,
            time=e.event_time,
            event_type=sanitize(e.event_type, 256),
            source_type=sanitize(e.source_type, 256),
            summary=sanitize(e.summary_text(), 2048),
            is_evidence=True,
        )
        for e in shown
    ]
    budget = max(0, MAX_TIMELINE - len(entries))
    order = {r.event_id: i for i, r in enumerate(relationships)}  # already ranked
    ranked = sorted(related, key=lambda e: order.get(e.event_id, len(order)))
    for e in ranked[:budget]:
        entries.append(
            TimelineEntry(
                event_id=e.event_id,
                time=e.event_time,
                event_type=sanitize(e.event_type, 256),
                source_type=sanitize(e.source_type, 256),
                summary=sanitize(e.summary_text(), 2048),
                is_evidence=False,
                relationship_type=types.get(e.event_id),
            )
        )
    entries.sort(key=lambda t: (t.time, t.event_id))
    return entries, len(related) > budget


def _coverage_assets(alert_asset: str, evidence: Sequence[EventRecord]) -> dict[str, set[str]]:
    """An OTel report covers only the node an event was observed on."""
    scopes: dict[str, set[str]] = {}
    for event in evidence:
        if event.source_type not in {"k8s.audit", "k8s.container_log"}:
            continue
        if not alert_asset.startswith("k8s:") or not assets_related(alert_asset, event.asset_id):
            continue
        scope = scopes.setdefault(event.source_type, set())
        node = event.k8s_node
        cluster = event.asset_id.split("/node/", 1)[0]
        if node and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", node):
            scope.add(f"{cluster}/node/{node}")
        else:
            scope.add(event.asset_id)
    return scopes


def _asset_summary(row: Mapping[str, Any], fallback_type: AssetType) -> AssetSummary:
    return AssetSummary(
        asset_id=str(row["asset_id"]),
        asset_type=_enum_or(row.get("a_type"), AssetType, fallback_type),
        name=sanitize(str(row.get("a_name") or row["asset_id"]), 256),
        criticality=_enum_or(row.get("a_criticality"), Criticality, Criticality.MEDIUM),
        environment=_enum_or(row.get("a_environment"), Environment, Environment.LAB),
    )


def _coverage_entry(
    source: str,
    collector: Mapping[str, Any],
    ws: datetime,
    check_end: datetime,
    now: datetime,
    window_stats: Mapping[tuple[str, str], tuple[int, int]],
    gap_sources: set[tuple[str, str]],
) -> SourceCoverage:
    cid = str(collector["collector_id"])
    asset = str(collector["asset_id"])
    interval = max(1, int(collector.get("interval_seconds") or 0))
    last_success = collector.get("last_success_at")
    if not isinstance(last_success, datetime):
        last_success = None
    stale = last_success is None or (now - last_success).total_seconds() > 3 * interval
    bad, reports = window_stats.get((cid, asset), (0, 0))
    span = (check_end - ws).total_seconds()
    no_reports = reports == 0 and span > 3 * interval
    reported_gap = (asset, source) in gap_sources
    gap = bad > 0 or reported_gap or no_reports
    reasons: list[str] = []
    if stale:
        reasons.append("stale: no successful collection within 3 x interval")
    if bad:
        reasons.append("collector reported failed/degraded status during the window")
    if reported_gap:
        reasons.append("a telemetry gap was reported during the window")
    if no_reports:
        reasons.append("no health report during the window")
    lag = collector.get("lag_seconds")
    return SourceCoverage(
        source_type=source,
        collector_id=sanitize(cid, 256),
        status=_enum_or(collector.get("status"), HealthStatus, HealthStatus.UNKNOWN),
        last_success_at=last_success,
        lag_seconds=float(lag) if isinstance(lag, int | float) and lag >= 0 else None,
        stale=stale,
        gap_during_window=gap,
        note="; ".join(reasons) + "." if reasons else None,
    )


def _rule_from_row(row: Mapping[str, Any]) -> RuleMetadata:
    return RuleMetadata.model_validate(
        {
            "rule_id": row["rule_id"],
            "version": row["version"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "status": row["status"],
            "mitre_techniques": list(row["mitre_techniques"]),
            "asset_types": list(row["asset_types"]),
            "requires": json.loads(row["requires"]),
            "schedule": json.loads(row["schedule"]),
            "dedup": json.loads(row["dedup"]),
            "group_by": list(row["group_by"]),
            "params": json.loads(row["params"]),
            "false_positives": list(row["false_positives"]),
            "blind_spots": list(row["blind_spots"]),
            "references": list(row["reference_urls"]),
            "query_sha256": row["query_sha256"],
        }
    )


def _rule_from_registry(rule_id: str) -> RuleMetadata | None:
    """Last resort: the rules directory shipped with the code (may be absent in images)."""
    try:
        from extorq.detection.registry import load_rules_report

        rules, _ = load_rules_report(None)
    except Exception:  # noqa: BLE001 - no rules directory in this deployment
        return None
    for rule in rules:
        if rule.rule_id == rule_id:
            return rule.metadata
    return None


__all__ = [
    "BUILDER_VERSION",
    "AlertNotFound",
    "ContextBuildError",
    "ContextBuilder",
    "compute_input_hash",
    "context_input_hash",
]

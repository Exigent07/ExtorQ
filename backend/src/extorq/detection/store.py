"""Persistence for the detection engine (tables defined in migration 0001).

Writes use the ``extorq_detect`` identity: alerts, alert_evidence, rule_runs,
detection_rules, pipeline_health. Reads of existing alerts are duplicate-safe
without ``FINAL``: ``ORDER BY updated_at DESC LIMIT 1 BY alert_id`` returns the
newest version of each alert even before ReplacingMergeTree merges.

Every alert row carries ``payload`` = canonical JSON of the validated
:class:`DetectionAlert`, so readers reconstruct the exact contract object.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from extorq.contracts.alert import AlertEvidence, DetectionAlert, RuleRun
from extorq.contracts.health import PipelineHealth
from extorq.contracts.identity import canonical_json
from extorq.detection.clients import DbClient, chunked

if TYPE_CHECKING:
    from extorq.detection.registry import LoadedRule

_ID_CHUNK = 500


def alert_to_row(alert: DetectionAlert) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "schema_version": alert.schema_version,
        "rule_id": alert.rule_id,
        "rule_version": alert.rule_version,
        "rule_title": alert.rule_title,
        "severity": alert.severity.value,
        "confidence": alert.confidence.value,
        "asset_id": alert.asset_id,
        "asset_type": alert.asset_type.value,
        "group_key": alert.group_key,
        "entities": dict(alert.entities),
        "summary": alert.summary,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "window_start": alert.window_start,
        "window_end": alert.window_end,
        "event_count": alert.event_count,
        "evidence_event_ids": list(alert.evidence_event_ids),
        "evidence_truncated": 1 if alert.evidence_truncated else 0,
        "features": canonical_json(alert.features),
        "mitre_techniques": list(alert.mitre_techniques),
        "simulation_run_ids": list(alert.simulation_run_ids),
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "detector_version": alert.detector_version,
        "payload": canonical_json(alert.model_dump(mode="json")),
    }


def evidence_to_row(evidence: AlertEvidence) -> dict[str, Any]:
    return {
        "alert_id": evidence.alert_id,
        "event_id": evidence.event_id,
        "role": evidence.role.value,
        "added_at": evidence.added_at,
    }


def rule_run_to_row(run: RuleRun, instance: str) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "rule_id": run.rule_id,
        "rule_version": run.rule_version,
        "started_at": run.started_at,
        "finished_at": run.finished_at,
        "window_start": run.window_start,
        "window_end": run.window_end,
        "status": run.status.value,
        "rows_matched": min(run.rows_matched, 2**32 - 1),
        "alerts_created": min(run.alerts_created, 2**32 - 1),
        "alerts_updated": min(run.alerts_updated, 2**32 - 1),
        "duration_ms": min(run.duration_ms, 2**32 - 1),
        "error": run.error,
        "missing_sources": list(run.missing_sources),
        "detector_instance": instance,
    }


def rule_to_row(rule: LoadedRule, loaded_at: datetime, *, enabled: bool) -> dict[str, Any]:
    meta = rule.metadata
    return {
        "rule_id": meta.rule_id,
        "version": meta.version,
        "title": meta.title,
        "description": meta.description,
        "severity": meta.severity.value,
        "status": meta.status.value,
        "mitre_techniques": list(meta.mitre_techniques),
        "asset_types": [a.value for a in meta.asset_types],
        "requires": canonical_json([r.model_dump(mode="json") for r in meta.requires]),
        "schedule": canonical_json(meta.schedule.model_dump(mode="json")),
        "dedup": canonical_json(meta.dedup.model_dump(mode="json")),
        "group_by": list(meta.group_by),
        "params": canonical_json(meta.params),
        "false_positives": list(meta.false_positives),
        "blind_spots": list(meta.blind_spots),
        "reference_urls": list(meta.references),
        "query_sha256": meta.query_sha256,
        "query_text": rule.query_text,
        "enabled": 1 if enabled else 0,
        "loaded_at": loaded_at,
    }


def health_to_row(health: PipelineHealth) -> dict[str, Any]:
    return {
        "component": health.component,
        "instance": health.instance,
        "reported_at": health.reported_at,
        "status": health.status.value,
        "queue_depth": health.queue_depth,
        "oldest_queued_age_seconds": health.oldest_queued_age_seconds,
        "accepted_total": health.accepted_total,
        "duplicate_total": health.duplicate_total,
        "rejected_total": health.rejected_total,
        "quarantined_total": health.quarantined_total,
        "written_total": health.written_total,
        "write_errors_total": health.write_errors_total,
        "dead_letter_total": health.dead_letter_total,
        "last_write_at": health.last_write_at,
        "details": canonical_json(health.details),
    }


class DetectionStore:
    """Reads/writes of detection tables through injected clients."""

    def __init__(self, read_client: DbClient, write_client: DbClient, *, instance: str) -> None:
        self.read = read_client
        self.write = write_client
        self.instance = instance

    # ── reads ────────────────────────────────────────────────────────
    def load_alerts(
        self,
        rule_id: str,
        alert_ids: Iterable[str] = (),
        group_keys: Iterable[str] = (),
        since: datetime | None = None,
    ) -> dict[str, DetectionAlert]:
        """Newest version of ``rule_id`` alerts by id, or by group key with last_seen >= since."""
        ids = sorted(set(alert_ids))
        keys = sorted(set(group_keys))
        if not ids and not keys:
            return {}
        params: dict[str, Any] = {
            "rule_id": rule_id,
            "ids": ids,
            "keys": keys,
            "since": since or datetime(1970, 1, 1, tzinfo=UTC),
        }
        sql = (
            "SELECT alert_id, payload FROM alerts WHERE rule_id = {rule_id:String} "
            "AND (alert_id IN {ids:Array(String)} OR (group_key IN {keys:Array(String)} "
            "AND last_seen >= {since:DateTime64(3, 'UTC')})) "
            "ORDER BY updated_at DESC LIMIT 1 BY alert_id"
        )
        result = self.read.select(sql, params)
        alerts: dict[str, DetectionAlert] = {}
        for alert_id, payload in result.rows:
            alerts[str(alert_id)] = DetectionAlert.model_validate_json(payload)
        return alerts

    def load_alert(self, alert_id: str) -> DetectionAlert | None:
        result = self.read.select(
            "SELECT payload FROM alerts WHERE alert_id = {id:String} "
            "ORDER BY updated_at DESC LIMIT 1",
            {"id": alert_id},
        )
        if not result.rows:
            return None
        return DetectionAlert.model_validate_json(result.rows[0][0])

    def load_evidence(self, alert_ids: Iterable[str]) -> dict[str, dict[str, str]]:
        """Full evidence set per alert: ``{alert_id: {event_id: role}}``."""
        evidence: dict[str, dict[str, str]] = defaultdict(dict)
        for batch in chunked(sorted(set(alert_ids)), _ID_CHUNK):
            result = self.read.select(
                "SELECT alert_id, event_id, any(role) FROM alert_evidence "
                "WHERE alert_id IN {ids:Array(String)} GROUP BY alert_id, event_id "
                "LIMIT 200000",
                {"ids": batch},
            )
            for alert_id, event_id, role in result.rows:
                evidence[str(alert_id)][str(event_id)] = str(role)
        return dict(evidence)

    def present_source_types(
        self, source_types: Sequence[str], start: datetime, end: datetime
    ) -> set[str]:
        """Which of ``source_types`` have at least one event in ``[start, end)``."""
        if not source_types:
            return set()
        result = self.read.select(
            "SELECT DISTINCT source_type FROM events "
            "WHERE event_time >= {start:DateTime64(3, 'UTC')} "
            "AND event_time < {end:DateTime64(3, 'UTC')} "
            "AND source_type IN {sources:Array(String)}",
            {"start": start, "end": end, "sources": list(source_types)},
        )
        return {str(row[0]) for row in result.rows}

    def registered_rule_ids(self) -> set[str]:
        result = self.read.select(
            "SELECT rule_id FROM detection_rules GROUP BY rule_id "
            "HAVING argMax(enabled, loaded_at) = 1"
        )
        return {str(row[0]) for row in result.rows}

    # ── writes ───────────────────────────────────────────────────────
    def write_alerts(self, alerts: Sequence[DetectionAlert]) -> None:
        self.write.insert_rows("alerts", [alert_to_row(a) for a in alerts])

    def write_evidence(self, evidence: Sequence[AlertEvidence]) -> None:
        for batch in chunked(evidence, 5000):
            self.write.insert_rows("alert_evidence", [evidence_to_row(e) for e in batch])

    def write_rule_runs(self, runs: Sequence[RuleRun]) -> None:
        self.write.insert_rows("rule_runs", [rule_run_to_row(r, self.instance) for r in runs])

    def write_rules(self, rows: Sequence[dict[str, Any]]) -> None:
        self.write.insert_rows("detection_rules", list(rows))

    def write_health(self, health: PipelineHealth) -> None:
        self.write.insert_rows("pipeline_health", [health_to_row(health)])

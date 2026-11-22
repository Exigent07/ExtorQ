"""SYNTHETIC test doubles for the analyst API unit tests.

Everything here is synthetic: identifiers and values are invented for tests and marked
with ``synthetic`` where a free-text field exists. Nothing is presented as telemetry.
``FakeRepository`` implements the ``extorq.api.repository.Repository`` protocol in
memory so route/derivation logic can be tested without ClickHouse (the SQL itself is
validated separately against a real ClickHouse in tests/integration/api).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from extorq.api.repository import (
    CLOSED_STATUSES,
    AlertFilters,
    EventFilters,
    FindingFilters,
    SeriesQuery,
    ServiceFilters,
    identity_matches,
)
from extorq.contracts import (
    AIAssessment,
    AIProvider,
    AIStatus,
    AITask,
    InvestigationContext,
)
from extorq.contracts.identity import service_id

Row = dict[str, Any]
NOW = datetime(2026, 11, 21, 12, 0, 0, tzinfo=UTC)
SYN = "synthetic"


def hexid(label: str) -> str:
    return hashlib.sha256(f"synthetic:{label}".encode()).hexdigest()[:32]


def sha(label: str) -> str:
    return hashlib.sha256(f"synthetic:{label}".encode()).hexdigest()


def asset_row(asset_id: str = "linux:lab-vm-01", **kw: Any) -> Row:
    row: Row = {
        "asset_id": asset_id,
        "asset_type": "linux_host",
        "name": f"{SYN}-{asset_id}",
        "display_name": None,
        "parent_asset_id": None,
        "environment": "lab",
        "criticality": "medium",
        "owner": None,
        "labels": {"origin": SYN},
        "attributes": '{"os_name":"synthetic"}',
        "first_seen": NOW - timedelta(days=2),
        "last_seen": NOW - timedelta(minutes=5),
        "observed_by": "synthetic-collector",
    }
    row.update(kw)
    return row


def collector_row(collector_id: str = "linux-ssh", **kw: Any) -> Row:
    row: Row = {
        "collector_id": collector_id,
        "collector_type": "linux_ssh",
        "asset_id": "linux:lab-vm-01",
        "source_types": ["linux.journald"],
        "status": "ok",
        "last_reported_at": NOW - timedelta(seconds=30),
        "last_attempt_at": NOW - timedelta(seconds=30),
        "last_success_at": NOW - timedelta(seconds=30),
        "last_error": None,
        "events_collected": 10,
        "records_buffered": 0,
        "lag_seconds": 1.5,
        "checkpoint_summary": None,
        "collector_version": "0.0.0-synthetic",
        "interval_seconds": 60,
        "details": "{}",
    }
    row.update(kw)
    return row


def alert_row(label: str = "a1", **kw: Any) -> Row:
    row: Row = {
        "alert_id": hexid(f"alert:{label}"),
        "schema_version": "1.0",
        "rule_id": "VM-001",
        "rule_version": "1.0.0",
        "rule_title": f"{SYN} failed SSH burst",
        "severity": "high",
        "confidence": "high",
        "asset_id": "linux:lab-vm-01",
        "asset_type": "linux_host",
        "group_key": "linux:lab-vm-01|10.0.2.2",
        "entities": {"src_ip": "10.0.2.2"},
        "summary": f"{SYN} summary",
        "first_seen": NOW - timedelta(hours=1),
        "last_seen": NOW - timedelta(minutes=50),
        "window_start": NOW - timedelta(hours=1),
        "window_end": NOW - timedelta(minutes=55),
        "event_count": 3,
        "evidence_event_ids": [],
        "evidence_truncated": 0,
        "features": '{"distinct_connections":6}',
        "mitre_techniques": ["T1110"],
        "simulation_run_ids": [],
        "created_at": NOW - timedelta(minutes=49),
        "updated_at": NOW - timedelta(minutes=49),
        "detector_version": "0.0.0-synthetic",
    }
    row.update(kw)
    return row


def event_row(label: str = "e1", **kw: Any) -> Row:
    row: Row = {
        "event_id": hexid(f"event:{label}"),
        "event_type": "auth.ssh.login_failed",
        "category": "authentication",
        "asset_id": "linux:lab-vm-01",
        "asset_type": "linux_host",
        "source_type": "linux.journald",
        "collector_id": "linux-ssh",
        "event_time": NOW - timedelta(hours=1),
        "observed_time": None,
        "ingested_time": NOW - timedelta(minutes=59),
        "action": None,
        "outcome": "failure",
        "severity_hint": None,
        "actor_type": "user",
        "actor_name": f"{SYN}-user",
        "actor_id": None,
        "src_ip": "10.0.2.2",
        "src_port": 50000,
        "dst_ip": None,
        "dst_port": None,
        "resource_type": None,
        "resource_name": None,
        "resource_namespace": None,
        "resource_path": None,
        "process_name": "sshd",
        "process_pid": 100,
        "http_method": None,
        "http_route": None,
        "http_status": None,
        "http_request_id": None,
        "k8s_namespace": None,
        "k8s_pod_name": None,
        "k8s_verb": None,
        "k8s_resource": None,
        "k8s_object_name": None,
        "k8s_response_code": None,
        "k8s_user": None,
        "k8s_audit_id": None,
        "gh_repository": None,
        "gh_commit_sha": None,
        "gh_workflow_path": None,
        "gh_workflow_run_id": None,
        "gh_actor_login": None,
        "simulation_run_id": None,
        "scenario_id": None,
        "message": "<b>synthetic</b> message",
        "attributes": '{"auth_method":"password"}',
    }
    row.update(kw)
    return row


def rule_row(rule_id: str = "VM-001", **kw: Any) -> Row:
    row: Row = {
        "rule_id": rule_id,
        "version": "1.0.0",
        "title": f"{SYN} rule {rule_id}",
        "description": f"{SYN} description",
        "severity": "high",
        "status": "stable",
        "enabled": 1,
        "mitre_techniques": ["T1110"],
        "asset_types": ["linux_host"],
        "requires": '[{"source_type":"linux.journald"}]',
        "schedule": '{"interval_seconds":60,"lookback_seconds":900}',
        "dedup": '{"strategy":"window_bucket","bucket_seconds":300}',
        "group_by": ["asset_id", "src_ip"],
        "params": "{}",
        "false_positives": [f"{SYN} fp"],
        "blind_spots": [f"{SYN} blind spot"],
        "reference_urls": [],
        "query_sha256": sha(f"query:{rule_id}"),
        "query_text": "SELECT 1",
        "loaded_at": NOW - timedelta(hours=3),
    }
    row.update(kw)
    return row


def latest_run_row(rule_id: str = "VM-001", **kw: Any) -> Row:
    row: Row = {
        "rule_id": rule_id,
        "rule_version": "1.0.0",
        "last_run_at": NOW - timedelta(seconds=30),
        "last_status": "succeeded",
        "last_error": None,
        "last_duration_ms": 12,
        "missing_sources": [],
        "runs_24h": 100,
        "failures_24h": 0,
    }
    row.update(kw)
    return row


def pipeline_row(component: str = "writer", instance: str = "w1", **kw: Any) -> Row:
    row: Row = {
        "component": component,
        "instance": instance,
        "status": "ok",
        "last_reported_at": NOW - timedelta(seconds=20),
        "queue_depth": 0,
        "oldest_queued_age_seconds": None,
        "accepted_total": 0,
        "duplicate_total": 0,
        "rejected_total": 0,
        "quarantined_total": 0,
        "written_total": 5,
        "write_errors_total": 0,
        "dead_letter_total": 0,
        "last_write_at": NOW - timedelta(seconds=25),
        "details": "{}",
    }
    row.update(kw)
    return row


def service_row(key: str = "ssh.service", **kw: Any) -> Row:
    """A SYNTHETIC ``v_services`` row (implemented ssh adapter, reported monitored)."""
    asset_id = kw.get("asset_id", "linux:lab-vm-01")
    kind = kw.get("service_kind", "host_service")
    row: Row = {
        "service_id": service_id(asset_id, kind, key),
        "asset_id": asset_id,
        "service_kind": kind,
        "service_key": key,
        "name": f"{SYN}-{key}",
        "category": "ssh",
        "product": "openssh",
        "version": None,
        "discovered_via": ["listening_socket", "systemd_unit"],
        "adapter_id": "ssh",
        "adapter_support": "implemented",
        "monitoring_status": "monitored",
        "coverage_note": "telemetry fresh",
        "telemetry_sources": ["linux.journald"],
        "endpoints": (
            '[{"address":"0.0.0.0","attribution":"confirmed","attribution_basis":"socket owner",'
            '"exposure":"any","port":22,"protocol":"tcp"}]'
        ),
        "config_refs": ["/etc/ssh/sshd_config"],
        "instance_count": 1,
        "last_telemetry_at": NOW - timedelta(minutes=2),
        "first_seen": NOW - timedelta(days=1),
        "last_seen": NOW - timedelta(minutes=1),
        "present": 1,
        "observed_by": "linux-ssh",
        "attributes": "{}",
    }
    row.update(kw)
    row["service_id"] = kw.get("service_id", service_id(asset_id, row["service_kind"], key))
    return row


def instance_row(service: Row, key: str = "pid:100", **kw: Any) -> Row:
    row: Row = {
        "instance_id": hexid(f"instance:{service['service_id']}:{key}"),
        "service_id": service["service_id"],
        "asset_id": service["asset_id"],
        "instance_kind": "process",
        "instance_key": key,
        "parent_instance_id": None,
        "state": "running",
        "pid": 100,
        "process_name": "sshd",
        "process_user": "root",
        "namespace": None,
        "pod_name": None,
        "pod_uid": None,
        "container_name": None,
        "container_id": None,
        "image": None,
        "node_name": None,
        "workload_kind": None,
        "workload_name": None,
        "started_at": NOW - timedelta(days=1),
        "observed_at": NOW - timedelta(minutes=1),
        "observed_by": "linux-ssh",
        "attributes": "{}",
    }
    row.update(kw)
    return row


def assessment(alert_id: str, **kw: Any) -> AIAssessment:
    data: dict[str, Any] = {
        "assessment_id": hexid(f"assessment:{alert_id}:{kw.get('status', 'ok')}"),
        "alert_id": alert_id,
        "context_id": hexid(f"context:{alert_id}"),
        "context_input_hash": sha(f"input:{alert_id}"),
        "provider": AIProvider.GEMINI,
        "model": "synthetic-model",
        "task": AITask.SUMMARY,
        "prompt_version": "summary-v1",
        "status": AIStatus.OK,
        "created_at": NOW,
        "requested_by": "analyst:alice",
    }
    data.update(kw)
    return AIAssessment(**data)


class FakeRepository:
    """In-memory Repository. ``writes`` records (table, row) in insertion order."""

    def __init__(self) -> None:
        self.assets: list[Row] = []
        self.collector_rows: list[Row] = []
        self.alerts: list[Row] = []
        self.states: dict[str, Row] = {}
        self.evidence: dict[str, list[Row]] = {}
        self.events: dict[str, Row] = {}
        self.payloads: dict[str, Row] = {}
        self.actions: list[Row] = []
        self.rules: list[Row] = []
        self.latest_runs: list[Row] = []
        self.runs: dict[str, list[Row]] = {}
        self.pipeline: list[Row] = []
        self.ai_counts: list[Row] = []
        self.ai_last: list[Row] = []
        self.quarantined = 0
        self.audit_decisions: list[Row] = []
        self.inventory: dict[str, list[Row]] = {}
        self.event_counts: dict[str, list[Row]] = {}
        self.findings: list[Row] = []
        self.finding_counts: list[Row] = []
        self.lifecycle = False
        self.alert_series_rows: list[Row] = []
        self.event_series_rows: list[Row] = []
        self.direct_assessments: list[Row] = []
        self.services: list[Row] = []
        self.instances: list[Row] = []
        self.auth_summary: dict[str, Row] = {}
        self.auth_sources: dict[str, list[Row]] = {}
        self.service_sources: dict[str, list[Row]] = {}
        self.writes: list[tuple[str, Row]] = []
        self.calls: list[tuple[str, Any]] = []
        self.fail_action_insert = False
        self.fail_state_insert = False
        self.ping_error: Exception | None = None

    # plumbing
    def read_client(self) -> Any:
        return "read-client"

    def write_client(self) -> Any:
        return "write-client"

    def ping(self) -> None:
        if self.ping_error is not None:
            raise self.ping_error

    # assets / coverage
    def all_assets(self) -> list[Row]:
        self.calls.append(("all_assets", None))
        return sorted(self.assets, key=lambda a: (a["asset_type"], a["asset_id"]))

    def get_asset(self, asset_id: str) -> Row | None:
        return next((a for a in self.assets if a["asset_id"] == asset_id), None)

    def asset_last_events(self, asset_ids: Sequence[str]) -> list[Row]:
        self.calls.append(("asset_last_events", tuple(asset_ids)))
        out: dict[str, Row] = {}
        for e in self.events.values():
            if asset_ids and e["asset_id"] not in asset_ids:
                continue
            cur = out.get(e["asset_id"])
            if cur is None or e["event_time"] > cur["last_event_at"]:
                out[e["asset_id"]] = {
                    "asset_id": e["asset_id"],
                    "asset_type": e["asset_type"],
                    "last_event_at": e["event_time"],
                    "last_ingested_at": e["ingested_time"],
                }
        return list(out.values())

    def collectors(self, asset_id: str) -> list[Row]:
        self.calls.append(("collectors", asset_id))
        return [c for c in self.collector_rows if not asset_id or c["asset_id"] == asset_id]

    def asset_children(self, asset_id: str) -> list[Row]:
        return [a for a in self.assets if a.get("parent_asset_id") == asset_id]

    def inventory_summary(self, asset_id: str) -> list[Row]:
        return self.inventory.get(asset_id, [])

    def event_counts_by_source(self, asset_id: str, since: datetime, until: datetime) -> list[Row]:
        self.calls.append(("event_counts_by_source", (asset_id, since, until)))
        return self.event_counts.get(asset_id, [])

    # findings
    def findings_lifecycle_available(self) -> bool:
        return self.lifecycle

    def list_findings(
        self, filters: FindingFilters, limit: int, offset: int
    ) -> tuple[list[Row], int, bool]:
        self.calls.append(("list_findings", filters))
        rows = [
            f
            for f in self.findings
            if (not filters.asset_id or f["asset_id"] == filters.asset_id)
            and (not filters.severities or f["severity"] in filters.severities)
            # Mirrors v_findings_current.service_id: the latest observation's attribution
            # (a row's ``service_id``), never an older one.
            and (not filters.service_id or f.get("service_id") == filters.service_id)
        ]
        return rows[offset : offset + limit], len(rows), self.lifecycle

    def finding_severity_counts(
        self, asset_id: str, exclude_assets: Sequence[str] = ()
    ) -> tuple[list[Row], bool]:
        # Rows may carry an ``asset_id`` (tests of the exclusion); the SQL groups them away.
        self.calls.append(("finding_severity_counts", (asset_id, tuple(exclude_assets))))
        rows = [
            r
            for r in self.finding_counts
            if (not asset_id or r.get("asset_id", asset_id) == asset_id)
            and r.get("asset_id") not in exclude_assets
        ]
        return rows, self.lifecycle

    # services
    def list_services(self, filters: ServiceFilters, max_rows: int) -> list[Row]:
        self.calls.append(("list_services", (filters, max_rows)))
        rows = [
            r
            for r in self.services
            if (not filters.asset_id or r["asset_id"] == filters.asset_id)
            and (not filters.service_kind or r["service_kind"] == filters.service_kind)
            and (not filters.category or r["category"] == filters.category)
            and (not filters.adapter_support or r["adapter_support"] == filters.adapter_support)
            and (
                not filters.monitoring_status or r["monitoring_status"] == filters.monitoring_status
            )
            and (filters.include_removed or r["present"] == 1)
        ]
        rows.sort(key=lambda r: (r["asset_id"], r["service_kind"], r["name"], r["service_id"]))
        return rows[:max_rows]

    @staticmethod
    def _in_scope(asset_id: str | None, scope: str) -> bool:
        """Mirror of the SQL scope predicate (F-19): the asset itself or a descendant."""
        return not scope or asset_id == scope or (asset_id or "").startswith(scope + "/")

    def get_service(self, service_id: str) -> Row | None:
        # Mirror of ClickHouseRepository.get_service: newest row whose id matches its key.
        rows = sorted(
            (r for r in self.services if r["service_id"] == service_id),
            key=lambda r: r["last_seen"],
            reverse=True,
        )
        return next((r for r in rows if identity_matches(r)), None)

    def service_instances(
        self, service_id: str, limit: int, scope_asset: str = ""
    ) -> tuple[list[Row], int]:
        rows = [
            i
            for i in self.instances
            if i["service_id"] == service_id and self._in_scope(i.get("asset_id"), scope_asset)
        ]
        return rows[:limit], len(rows)

    def instances_on_asset(self, asset_id: str, limit: int) -> list[Row]:
        rows = [i for i in self.instances if i.get("asset_id") == asset_id]
        rows.sort(key=lambda r: (r["service_id"], -r["observed_at"].timestamp(), r["instance_id"]))
        return rows[:limit]

    def services_by_id(self, service_ids: Sequence[str], max_rows: int) -> list[Row]:
        rows = [r for r in self.services if r["service_id"] in service_ids]
        rows.sort(key=lambda r: (r["asset_id"], r["service_kind"], r["name"], r["service_id"]))
        return rows[:max_rows]

    def service_event_sources(
        self, service_id: str, since: datetime, until: datetime, scope_asset: str = ""
    ) -> list[Row]:
        self.calls.append(("service_event_sources", (service_id, since, until)))
        self.calls.append(("service_scope", scope_asset))
        return self.service_sources.get(service_id, [])

    def service_auth_summary(
        self, service_id: str, since: datetime, until: datetime, scope_asset: str = ""
    ) -> Row:
        self.calls.append(("service_scope", scope_asset))
        return self.auth_summary.get(service_id, {})

    def service_auth_sources(
        self, service_id: str, since: datetime, until: datetime, limit: int, scope_asset: str = ""
    ) -> list[Row]:
        self.calls.append(("service_scope", scope_asset))
        return self.auth_sources.get(service_id, [])[:limit]

    # rules
    def rules_latest(self) -> list[Row]:
        return list(self.rules)

    def rule_latest_runs(self) -> list[Row]:
        return list(self.latest_runs)

    def rule_versions(self, rule_id: str) -> list[Row]:
        return [r for r in self.rules if r["rule_id"] == rule_id]

    def rule_runs(self, rule_id: str, status: str, limit: int, offset: int) -> list[Row]:
        self.calls.append(("rule_runs", (rule_id, status, limit, offset)))
        return self.runs.get(rule_id, [])[offset : offset + limit]

    def alert_counts_by_rule(self) -> list[Row]:
        counts: dict[str, Row] = {}
        for a in self.alerts:
            row = counts.setdefault(
                a["rule_id"], {"rule_id": a["rule_id"], "alerts_total": 0, "alerts_open": 0}
            )
            row["alerts_total"] += 1
            if self._status(a["alert_id"]) not in CLOSED_STATUSES:
                row["alerts_open"] += 1
        return list(counts.values())

    def alert_status_counts_for_rule(self, rule_id: str) -> list[Row]:
        counts: dict[str, int] = {}
        for a in self.alerts:
            if a["rule_id"] == rule_id:
                status = self._status(a["alert_id"])
                counts[status] = counts.get(status, 0) + 1
        return [{"analyst_status": k, "alerts": v} for k, v in counts.items()]

    # alerts
    def _status(self, alert_id: str) -> str:
        state = self.states.get(alert_id)
        return str(state["status"]) if state else "new"

    def _matching_alerts(self, f: AlertFilters) -> list[Row]:
        out = []
        for a in self.alerts:
            status = self._status(a["alert_id"])
            if a["last_seen"] < f.since or a["first_seen"] >= f.until:
                continue
            if f.asset_id and a["asset_id"] != f.asset_id:
                continue
            if f.rule_id and a["rule_id"] != f.rule_id:
                continue
            if f.severities and a["severity"] not in f.severities:
                continue
            if f.statuses and status not in f.statuses:
                continue
            if f.open_only and status in CLOSED_STATUSES:
                continue
            if f.simulation_run_id and f.simulation_run_id not in a["simulation_run_ids"]:
                continue
            if f.service_id and f.service_id not in a.get("service_ids", []):
                continue
            state = self.states.get(a["alert_id"])
            out.append(
                {
                    **a,
                    "analyst_status": status,
                    "analyst_state_recorded": 1 if state else 0,
                    "assignee": state.get("assignee") if state else None,
                }
            )
        return sorted(out, key=lambda r: r["last_seen"], reverse=True)

    def list_alerts(self, filters: AlertFilters, limit: int, offset: int) -> list[Row]:
        self.calls.append(("list_alerts", filters))
        return self._matching_alerts(filters)[offset : offset + limit]

    def count_alerts(self, filters: AlertFilters) -> int:
        return len(self._matching_alerts(filters))

    def get_alert(self, alert_id: str) -> Row | None:
        return next((a for a in self.alerts if a["alert_id"] == alert_id), None)

    def get_analyst_state(self, alert_id: str) -> Row | None:
        return self.states.get(alert_id)

    def open_alert_severity_counts(self, asset_id: str) -> list[Row]:
        counts: dict[str, int] = {}
        for a in self.alerts:
            if asset_id and a["asset_id"] != asset_id:
                continue
            if self._status(a["alert_id"]) in CLOSED_STATUSES:
                continue
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
        return [{"severity": k, "alerts": v} for k, v in counts.items()]

    def open_alerts_by_asset(self) -> list[Row]:
        counts: dict[str, int] = {}
        for a in self.alerts:
            if self._status(a["alert_id"]) not in CLOSED_STATUSES:
                counts[a["asset_id"]] = counts.get(a["asset_id"], 0) + 1
        return [{"asset_id": k, "open_alerts": v} for k, v in counts.items()]

    def evidence_refs(self, alert_id: str, limit: int) -> list[Row]:
        refs = sorted(
            self.evidence.get(alert_id, []),
            key=lambda r: (r["role"] != "trigger", r["added_at"], r["event_id"]),
        )
        return refs[:limit]

    def evidence_total(self, alert_id: str, array_ids: Sequence[str]) -> int:
        ids = {r["event_id"] for r in self.evidence.get(alert_id, [])} | set(array_ids)
        return len(ids)

    def events_by_ids(self, event_ids: Sequence[str]) -> list[Row]:
        return [self.events[i] for i in event_ids if i in self.events]

    def alert_actions(self, alert_id: str, limit: int) -> list[Row]:
        rows = [a for a in self.actions if a["alert_id"] == alert_id]
        return sorted(rows, key=lambda r: r["occurred_at"], reverse=True)[:limit]

    def assessments_direct(self, alert_id: str, limit: int) -> list[Row]:
        return [r for r in self.direct_assessments if r["alert_id"] == alert_id][:limit]

    # events
    def list_events(self, filters: EventFilters, limit: int, offset: int) -> list[Row]:
        self.calls.append(("list_events", filters))
        rows = [
            e
            for e in self.events.values()
            if filters.since <= e["event_time"] < filters.until
            and (not filters.asset_id or e["asset_id"] == filters.asset_id)
            and (not filters.src_ip or e["src_ip"] == filters.src_ip)
            and (not filters.service_id or e.get("service_id") == filters.service_id)
            and self._in_scope(e.get("asset_id"), filters.scope_asset)
        ]
        rows.sort(key=lambda r: r["event_time"], reverse=True)
        return rows[offset : offset + limit]

    def get_event(self, event_id: str) -> Row | None:
        return self.payloads.get(event_id)

    def alerts_citing_event(self, event_id: str, limit: int) -> list[str]:
        return sorted(
            alert_id
            for alert_id, refs in self.evidence.items()
            if any(r["event_id"] == event_id for r in refs)
        )[:limit]

    # health
    def pipeline_latest(self) -> list[Row]:
        return list(self.pipeline)

    def ai_status_counts(self, since: datetime) -> list[Row]:
        return list(self.ai_counts)

    def ai_latest(self) -> list[Row]:
        return list(self.ai_last)

    def ingest_quarantine_count(self, since: datetime) -> int:
        return self.quarantined

    def ingest_audit_decisions(self, since: datetime) -> list[Row]:
        return list(self.audit_decisions)

    # series
    def alert_series(self, query: SeriesQuery) -> list[Row]:
        self.calls.append(("alert_series", query))
        return list(self.alert_series_rows)

    def event_series(self, query: SeriesQuery) -> list[Row]:
        self.calls.append(("event_series", query))
        return list(self.event_series_rows)

    # writes
    def insert_analyst_action(self, row: Row) -> None:
        if self.fail_action_insert:
            raise ConnectionError("synthetic audit failure")
        self.writes.append(("analyst_actions", dict(row)))
        self.actions.append(dict(row))

    def insert_analyst_state(self, row: Row) -> None:
        if self.fail_state_insert:
            raise ConnectionError("synthetic state failure")
        self.writes.append(("analyst_state", dict(row)))
        self.states[row["alert_id"]] = dict(row)

    def last_call(self, name: str) -> Any:
        return next(args for method, args in reversed(self.calls) if method == name)


class FakeIntegrations:
    """Configurable stand-in for the C2/E adapters."""

    def __init__(self) -> None:
        self.stored: dict[str, InvestigationContext] = {}
        self.buildable: dict[str, InvestigationContext] = {}
        self.saved: list[InvestigationContext] = []
        self.assessments: dict[str, list[AIAssessment]] | None = {}
        self.summary_result: AIAssessment | None = None
        self.summary_error: Exception | None = None
        self.build_error: Exception | None = None
        self.load_error: Exception | None = None
        self.summary_calls: list[tuple[str, str]] = []
        self.config: dict[tuple[str, str], dict[str, bool | None]] = {
            ("typesafe-jev", "triage"): {"configured": False, "enabled": False},
            ("google-gemini", "summary"): {"configured": True, "enabled": False},
        }

    def load_context(self, repo: Any, alert_id: str) -> InvestigationContext | None:
        if self.load_error is not None:
            raise self.load_error
        return self.stored.get(alert_id)

    def build_context(self, repo: Any, alert_id: str) -> InvestigationContext:
        if self.build_error is not None:
            raise self.build_error
        return self.buildable[alert_id]

    def save_context(self, repo: Any, context: InvestigationContext) -> None:
        self.saved.append(context)

    def list_assessments(self, repo: Any, alert_id: str) -> list[AIAssessment] | None:
        if self.assessments is None:
            return None
        return self.assessments.get(alert_id, [])

    def request_summary(self, repo: Any, alert_id: str, requested_by: str) -> AIAssessment:
        self.summary_calls.append((alert_id, requested_by))
        if self.summary_error is not None:
            raise self.summary_error
        assert self.summary_result is not None
        return self.summary_result

    def ai_configuration(self) -> tuple[dict[tuple[str, str], dict[str, bool | None]], str]:
        return self.config, "fake"


def make_context(alert_id: str) -> InvestigationContext:
    """A minimal, contract-valid SYNTHETIC InvestigationContext."""
    from extorq.contracts import (
        AssetSummary,
        DetectionAlert,
        RuleDedup,
        RuleMetadata,
        RuleSchedule,
        TelemetryRequirement,
    )

    evidence_id = hexid(f"event:{alert_id}")
    alert = DetectionAlert(
        alert_id=alert_id,
        rule_id="VM-001",
        rule_version="1.0.0",
        rule_title=f"{SYN} rule",
        severity="high",
        confidence="high",
        asset_id="linux:lab-vm-01",
        asset_type="linux_host",
        group_key="synthetic",
        summary=f"{SYN} summary",
        first_seen=NOW - timedelta(hours=1),
        last_seen=NOW - timedelta(minutes=50),
        window_start=NOW - timedelta(hours=1),
        window_end=NOW - timedelta(minutes=55),
        event_count=1,
        evidence_event_ids=[evidence_id],
        created_at=NOW - timedelta(minutes=49),
        updated_at=NOW - timedelta(minutes=49),
        detector_version="0.0.0-synthetic",
    )
    rule = RuleMetadata(
        rule_id="VM-001",
        version="1.0.0",
        title=f"{SYN} rule",
        description=f"{SYN} description",
        severity="high",
        asset_types=["linux_host"],
        requires=[
            TelemetryRequirement(
                source_type="linux.journald", event_types=["auth.ssh.login_failed"]
            )
        ],
        schedule=RuleSchedule(interval_seconds=60, lookback_seconds=900),
        dedup=RuleDedup(strategy="window_bucket", bucket_seconds=300),
        group_by=["asset_id"],
        query_sha256=sha("query"),
    )
    return InvestigationContext(
        context_id=hexid(f"context:{alert_id}"),
        alert_id=alert_id,
        builder_version="0.0.0-synthetic",
        created_at=NOW,
        input_hash=sha(f"input:{alert_id}"),
        window_start=NOW - timedelta(hours=2),
        window_end=NOW,
        alert=alert,
        rule=rule,
        asset=AssetSummary(
            asset_id="linux:lab-vm-01",
            asset_type="linux_host",
            name=f"{SYN}-vm",
            criticality="medium",
            environment="lab",
        ),
        evidence=[],
        timeline=[],
        relationships=[],
    )

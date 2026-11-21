"""Mapping of validated contract models to ClickHouse rows (0001 column contract).

``to_row(kind, model, producer_id=..., batch_id=..., ingested_at=...)`` returns a
``dict`` whose keys are exactly the columns of ``TABLE_BY_KIND[kind]`` in
``infra/clickhouse/migrations/0001_core_tables.sql``. Values are Python objects
accepted by clickhouse-connect's typed insert (aware UTC ``datetime`` for
``DateTime64``, ``None`` for ``Nullable``, ``list`` for ``Array``, ``dict`` for
``Map``). Rules:

* Unknown stays unknown: absent optional values become ``NULL``; nothing is
  substituted.
* JSON-bearing columns hold :func:`extorq.contracts.identity.canonical_json`.
* ``payload`` (events) is the canonical JSON of the whole validated model.
* ``row_version`` formulas follow the DDL comments exactly.
* Integer columns are range-checked against their ClickHouse type, and every
  string must be encodable as UTF-8, so a record that passes ``to_row`` at the
  gateway can always be inserted by the writer.

Besides the seven ingest kinds, this module provides row builders for
``pipeline_health``, ``ingest_quarantine`` and ``ingest_audit``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from extorq.contracts.asset import Asset, InventoryItem
from extorq.contracts.event import SecurityEvent
from extorq.contracts.finding import PostureFinding
from extorq.contracts.health import CollectorHealth, PipelineHealth
from extorq.contracts.identity import canonical_json
from extorq.contracts.ingest import RecordKind
from extorq.contracts.scan import ScanRun, ScanStatus
from extorq.contracts.simulation import SimulationRun, SimulationStatus

#: Target table (in database ``extorq``) for every ingest record kind.
TABLE_BY_KIND: dict[RecordKind, str] = {
    RecordKind.EVENT: "events",
    RecordKind.ASSET: "assets",
    RecordKind.INVENTORY_ITEM: "inventory_items",
    RecordKind.FINDING: "finding_observations",
    RecordKind.SCAN_RUN: "scan_runs",
    RecordKind.COLLECTOR_HEALTH: "collector_health",
    RecordKind.SIMULATION_RUN: "simulation_runs",
}

#: Model class expected for each kind (to_row rejects mismatches).
MODEL_BY_KIND: dict[RecordKind, type[BaseModel]] = {
    RecordKind.EVENT: SecurityEvent,
    RecordKind.ASSET: Asset,
    RecordKind.INVENTORY_ITEM: InventoryItem,
    RecordKind.FINDING: PostureFinding,
    RecordKind.SCAN_RUN: ScanRun,
    RecordKind.COLLECTOR_HEALTH: CollectorHealth,
    RecordKind.SIMULATION_RUN: SimulationRun,
}

PIPELINE_HEALTH_TABLE = "pipeline_health"
QUARANTINE_TABLE = "ingest_quarantine"
AUDIT_TABLE = "ingest_audit"

_UINT_MAX = {8: 2**8 - 1, 16: 2**16 - 1, 32: 2**32 - 1, 64: 2**64 - 1}
#: DateTime64(3) supports 1900-01-01 .. 2299-12-31; ExtorQ restricts to the Unix era.
_MIN_TIME = datetime(1970, 1, 1, tzinfo=UTC)
_MAX_TIME = datetime(2262, 1, 1, tzinfo=UTC)

_SCAN_STATUS_RANK = {
    ScanStatus.RUNNING: 0,
    ScanStatus.PARTIAL: 1,
    ScanStatus.FAILED: 1,
    ScanStatus.SUCCEEDED: 1,
}
_SIM_STATUS_RANK = {
    SimulationStatus.STARTED: 1,
    SimulationStatus.COMPLETED: 2,
    SimulationStatus.FAILED: 2,
    SimulationStatus.CLEANED_UP: 3,
}


class RowError(ValueError):
    """A model cannot be represented in its ClickHouse table (permanent error)."""


# ── value helpers ─────────────────────────────────────────────────────


def _uint(value: int | None, bits: int, column: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise RowError(f"{column}: expected integer")
    if value < 0 or value > _UINT_MAX[bits]:
        raise RowError(f"{column}: {value} outside UInt{bits} range")
    return value


def _time(value: datetime | None, column: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise RowError(f"{column}: naive datetime")
    value = value.astimezone(UTC)
    if not (_MIN_TIME <= value < _MAX_TIME):
        raise RowError(f"{column}: {value.isoformat()} outside supported range")
    # DateTime64(3): keep millisecond precision deterministically (truncate, never round up).
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


def _req_time(value: datetime, column: str) -> datetime:
    result = _time(value, column)
    if result is None:  # pragma: no cover - guarded by the contract types
        raise RowError(f"{column}: required timestamp missing")
    return result


def _enum(value: Any) -> Any:
    return getattr(value, "value", value)


def epoch_ms(value: datetime) -> int:
    """Milliseconds since the Unix epoch for an aware datetime (truncated)."""
    if value.tzinfo is None:
        raise RowError("epoch_ms: naive datetime")
    delta = value.astimezone(UTC) - _MIN_TIME
    return (delta.days * 86_400 + delta.seconds) * 1000 + delta.microseconds // 1000


def scan_run_row_version(scan: ScanRun) -> int:
    """``epoch_ms(coalesce(finished_at, started_at)) * 10 + status_rank`` (0001 DDL)."""
    reference = scan.finished_at or scan.started_at
    return epoch_ms(reference) * 10 + _SCAN_STATUS_RANK[scan.status]


def simulation_run_row_version(run: SimulationRun) -> int:
    """``status_rank * 10^13 + epoch_ms(coalesce(finished_at, started_at))`` (0001 DDL)."""
    reference = run.finished_at or run.started_at
    return _SIM_STATUS_RANK[run.status] * 10**13 + epoch_ms(reference)


def _check_utf8(row: dict[str, Any]) -> None:
    """Reject strings that cannot be encoded (e.g. lone surrogates from JSON escapes)."""
    for column, value in row.items():
        values: list[Any]
        if isinstance(value, str):
            values = [value]
        elif isinstance(value, list):
            values = value
        elif isinstance(value, dict):
            values = [*value.keys(), *value.values()]
        else:
            continue
        for item in values:
            if isinstance(item, str):
                try:
                    item.encode("utf-8")
                except UnicodeEncodeError:
                    raise RowError(f"{column}: string is not valid UTF-8") from None


# ── per-kind mappers ──────────────────────────────────────────────────


def event_to_row(
    event: SecurityEvent, *, producer_id: str, batch_id: str, ingested_at: datetime
) -> dict[str, Any]:
    actor, resource, net = event.actor, event.resource, event.network
    proc, http, k8s, gh, sim = (
        event.process, event.http, event.kubernetes, event.github, event.simulation
    )
    prov = event.provenance
    return {
        "event_id": event.event_id,
        "schema_version": event.schema_version,
        "event_type": event.event_type,
        "category": _enum(event.category),
        "asset_id": event.asset_id,
        "asset_type": _enum(event.asset_type),
        "source_type": _enum(event.source.source_type),
        "collector_id": event.source.collector_id,
        "collector_version": event.source.collector_version,
        "collection_method": _enum(event.source.collection_method),
        "source_native_id": event.source.source_native_id,
        "event_time": _req_time(event.event_time, "event_time"),
        "observed_time": _time(event.observed_time, "observed_time"),
        "ingested_time": _req_time(ingested_at, "ingested_time"),
        "action": event.action,
        "outcome": _enum(event.outcome),
        "severity_hint": _enum(event.severity_hint) if event.severity_hint else None,
        "actor_type": _enum(actor.type) if actor else None,
        "actor_name": actor.name if actor else None,
        "actor_id": actor.id if actor else None,
        "resource_type": resource.type if resource else None,
        "resource_name": resource.name if resource else None,
        "resource_namespace": resource.namespace if resource else None,
        "resource_path": resource.path if resource else None,
        "src_ip": net.src_ip if net else None,
        "src_port": _uint(net.src_port, 16, "src_port") if net else None,
        "dst_ip": net.dst_ip if net else None,
        "dst_port": _uint(net.dst_port, 16, "dst_port") if net else None,
        "net_protocol": net.protocol if net else None,
        "process_name": proc.name if proc else None,
        "process_pid": _uint(proc.pid, 32, "process_pid") if proc else None,
        "process_executable": proc.executable if proc else None,
        "process_command_line": proc.command_line if proc else None,
        "http_method": http.method if http else None,
        "http_route": http.route if http else None,
        "http_status": _uint(http.status_code, 16, "http_status") if http else None,
        "http_request_id": http.request_id if http else None,
        "http_user_agent": http.user_agent if http else None,
        "k8s_cluster": k8s.cluster if k8s else None,
        "k8s_namespace": k8s.namespace if k8s else None,
        "k8s_pod_name": k8s.pod_name if k8s else None,
        "k8s_pod_uid": k8s.pod_uid if k8s else None,
        "k8s_container": k8s.container_name if k8s else None,
        "k8s_node": k8s.node_name if k8s else None,
        "k8s_verb": k8s.verb if k8s else None,
        "k8s_resource": k8s.resource if k8s else None,
        "k8s_subresource": k8s.subresource if k8s else None,
        "k8s_object_name": k8s.object_name if k8s else None,
        "k8s_audit_id": k8s.audit_id if k8s else None,
        "k8s_response_code": _uint(k8s.response_code, 16, "k8s_response_code") if k8s else None,
        "k8s_user": k8s.user if k8s else None,
        "k8s_user_groups": list(k8s.user_groups) if k8s else [],
        "k8s_source_ips": list(k8s.source_ips) if k8s else [],
        "gh_repository": gh.repository if gh else None,
        "gh_ref": gh.ref if gh else None,
        "gh_commit_sha": gh.commit_sha if gh else None,
        "gh_workflow_path": gh.workflow_path if gh else None,
        "gh_workflow_run_id": _uint(gh.workflow_run_id, 64, "gh_workflow_run_id") if gh else None,
        "gh_actor_login": gh.actor_login if gh else None,
        "gh_event_name": gh.event_name if gh else None,
        "gh_conclusion": gh.conclusion if gh else None,
        "simulation_run_id": sim.run_id if sim else None,
        "scenario_id": sim.scenario_id if sim else None,
        "message": event.message,
        "attributes": canonical_json(event.attributes),
        "labels": dict(event.labels),
        "raw": event.raw,
        "parser": prov.parser,
        "parser_version": prov.parser_version,
        "raw_sha256": prov.raw_sha256,
        "truncated": 1 if prov.truncated else 0,
        "redaction_count": _uint(prov.redaction_count, 32, "redaction_count"),
        "payload": canonical_json(event),
        "producer_id": producer_id,
        "batch_id": batch_id,
    }


def asset_to_row(asset: Asset, *, producer_id: str, ingested_at: datetime) -> dict[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "asset_type": _enum(asset.asset_type),
        "name": asset.name,
        "display_name": asset.display_name,
        "parent_asset_id": asset.parent_asset_id,
        "environment": _enum(asset.environment),
        "criticality": _enum(asset.criticality),
        "owner": asset.owner,
        "labels": dict(asset.labels),
        "attributes": canonical_json(asset.attributes),
        "first_seen": _req_time(asset.first_seen, "first_seen"),
        "last_seen": _req_time(asset.last_seen, "last_seen"),
        "observed_by": asset.observed_by,
        "producer_id": producer_id,
        "ingested_at": _req_time(ingested_at, "ingested_at"),
    }


def inventory_item_to_row(
    item: InventoryItem, *, producer_id: str, ingested_at: datetime
) -> dict[str, Any]:
    return {
        "asset_id": item.asset_id,
        "item_type": _enum(item.item_type),
        "item_key": item.item_key,
        "attributes": canonical_json(item.attributes),
        "snapshot_id": item.snapshot_id,
        "observed_at": _req_time(item.observed_at, "observed_at"),
        "present": 1 if item.present else 0,
        "collector_id": item.collector_id,
        "producer_id": producer_id,
        "ingested_at": _req_time(ingested_at, "ingested_at"),
    }


def finding_to_row(
    finding: PostureFinding, *, producer_id: str, ingested_at: datetime
) -> dict[str, Any]:
    res, pkg, risk = finding.resource, finding.package, finding.accepted_risk
    return {
        "finding_id": finding.finding_id,
        "scan_run_id": finding.scan_run_id,
        "asset_id": finding.asset_id,
        "scanner": finding.scanner,
        "check_id": finding.check_id,
        "category": _enum(finding.category),
        "severity": _enum(finding.severity),
        "title": finding.title,
        "description": finding.description,
        "resource_type": res.type if res else None,
        "resource_name": res.name if res else None,
        "resource_namespace": res.namespace if res else None,
        "resource_path": res.path if res else None,
        "package_name": pkg.name if pkg else None,
        "installed_version": pkg.installed_version if pkg else None,
        "fixed_version": pkg.fixed_version if pkg else None,
        "package_ecosystem": pkg.ecosystem if pkg else None,
        "cve_ids": list(finding.cve_ids),
        "cvss_score": finding.cvss_score,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "reference_urls": list(finding.references),
        "observed_at": _req_time(finding.observed_at, "observed_at"),
        "accepted_risk_reason": risk.reason if risk else None,
        "accepted_risk_source": risk.source if risk else None,
        "attributes": canonical_json(finding.attributes),
        "producer_id": producer_id,
        "ingested_at": _req_time(ingested_at, "ingested_at"),
    }


def scan_run_to_row(scan: ScanRun, *, producer_id: str, ingested_at: datetime) -> dict[str, Any]:
    cov = scan.coverage
    return {
        "scan_run_id": scan.scan_run_id,
        "scanner": scan.scanner,
        "scanner_version": scan.scanner_version,
        "asset_id": scan.asset_id,
        "scope_targets": list(scan.scope.targets),
        "scope_description": scan.scope.description,
        "scope_hash": scan.scope.scope_hash,
        "started_at": _req_time(scan.started_at, "started_at"),
        "finished_at": _time(scan.finished_at, "finished_at"),
        "status": _enum(scan.status),
        "checks_total": _uint(cov.checks_total, 32, "checks_total"),
        "checks_run": _uint(cov.checks_run, 32, "checks_run"),
        "coverage": canonical_json(cov),
        "findings_count": _uint(scan.findings_count, 32, "findings_count"),
        "error": scan.error,
        "producer_id": producer_id,
        "attributes": canonical_json(scan.attributes),
        "row_version": _uint(scan_run_row_version(scan), 64, "row_version"),
        "ingested_at": _req_time(ingested_at, "ingested_at"),
    }


def collector_health_to_row(
    health: CollectorHealth, *, producer_id: str, ingested_at: datetime
) -> dict[str, Any]:
    return {
        "collector_id": health.collector_id,
        "collector_type": health.collector_type,
        "asset_id": health.asset_id,
        "source_types": list(health.source_types),
        "status": _enum(health.status),
        "reported_at": _req_time(health.reported_at, "reported_at"),
        "last_attempt_at": _time(health.last_attempt_at, "last_attempt_at"),
        "last_success_at": _time(health.last_success_at, "last_success_at"),
        "last_error": health.last_error,
        "events_collected": _uint(health.events_collected, 32, "events_collected"),
        "records_buffered": _uint(health.records_buffered, 32, "records_buffered"),
        "lag_seconds": health.lag_seconds,
        "checkpoint_summary": health.checkpoint_summary,
        "collector_version": health.collector_version,
        "interval_seconds": _uint(health.interval_seconds, 32, "interval_seconds"),
        "details": canonical_json(health.details),
        "producer_id": producer_id,
        "ingested_at": _req_time(ingested_at, "ingested_at"),
    }


def simulation_run_to_row(
    run: SimulationRun, *, producer_id: str, ingested_at: datetime
) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "scenario_id": run.scenario_id,
        "asset_id": run.asset_id,
        "status": _enum(run.status),
        "started_at": _req_time(run.started_at, "started_at"),
        "finished_at": _time(run.finished_at, "finished_at"),
        "operator": run.operator,
        "description": run.description,
        "expected_rule_ids": list(run.expected_rule_ids),
        "notes": list(run.notes),
        "row_version": _uint(simulation_run_row_version(run), 64, "row_version"),
        "producer_id": producer_id,
        "ingested_at": _req_time(ingested_at, "ingested_at"),
    }


def to_row(
    kind: RecordKind | str,
    model: BaseModel,
    *,
    producer_id: str,
    batch_id: str,
    ingested_at: datetime,
) -> dict[str, Any]:
    """Map a validated contract model to its ClickHouse row (keys == table columns)."""
    try:
        record_kind = RecordKind(kind)
    except ValueError:
        raise RowError(f"unknown record kind {kind!r}") from None
    expected = MODEL_BY_KIND[record_kind]
    if not isinstance(model, expected):
        raise RowError(f"kind {record_kind.value} expects {expected.__name__}, "
                       f"got {type(model).__name__}")
    row: dict[str, Any]
    if isinstance(model, SecurityEvent):
        row = event_to_row(model, producer_id=producer_id, batch_id=batch_id,
                           ingested_at=ingested_at)
    elif isinstance(model, Asset):
        row = asset_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    elif isinstance(model, InventoryItem):
        row = inventory_item_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    elif isinstance(model, PostureFinding):
        row = finding_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    elif isinstance(model, ScanRun):
        row = scan_run_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    elif isinstance(model, CollectorHealth):
        row = collector_health_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    elif isinstance(model, SimulationRun):
        row = simulation_run_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    else:  # pragma: no cover - MODEL_BY_KIND covers every kind
        raise RowError(f"no row mapper for {type(model).__name__}")
    _check_utf8(row)
    return row


# ── pipeline-internal tables ──────────────────────────────────────────


def pipeline_health_to_row(health: PipelineHealth) -> dict[str, Any]:
    row = {
        "component": health.component,
        "instance": health.instance,
        "reported_at": _req_time(health.reported_at, "reported_at"),
        "status": _enum(health.status),
        "queue_depth": _uint(health.queue_depth, 64, "queue_depth"),
        "oldest_queued_age_seconds": health.oldest_queued_age_seconds,
        "accepted_total": _uint(health.accepted_total, 64, "accepted_total"),
        "duplicate_total": _uint(health.duplicate_total, 64, "duplicate_total"),
        "rejected_total": _uint(health.rejected_total, 64, "rejected_total"),
        "quarantined_total": _uint(health.quarantined_total, 64, "quarantined_total"),
        "written_total": _uint(health.written_total, 64, "written_total"),
        "write_errors_total": _uint(health.write_errors_total, 64, "write_errors_total"),
        "dead_letter_total": _uint(health.dead_letter_total, 64, "dead_letter_total"),
        "last_write_at": _time(health.last_write_at, "last_write_at"),
        "details": canonical_json(health.details),
    }
    _check_utf8(row)
    return row


def quarantine_row(
    *,
    quarantine_id: str,
    received_at: datetime,
    producer_id: str,
    batch_id: str,
    record_index: int,
    record_kind: str | None,
    reason: str,
    payload_excerpt: str,
    payload_sha256: str,
) -> dict[str, Any]:
    row = {
        "quarantine_id": quarantine_id,
        "received_at": _req_time(received_at, "received_at"),
        "producer_id": producer_id,
        "batch_id": batch_id,
        "record_index": _uint(record_index, 32, "record_index"),
        "record_kind": record_kind,
        "reason": reason,
        "payload_excerpt": payload_excerpt,
        "payload_sha256": payload_sha256,
    }
    _check_utf8(row)
    return row


def audit_row(
    *,
    audit_id: str,
    occurred_at: datetime,
    remote_addr: str | None,
    claimed_producer: str | None,
    authenticated_producer: str | None,
    decision: str,
    reason: str,
    path: str,
) -> dict[str, Any]:
    row = {
        "audit_id": audit_id,
        "occurred_at": _req_time(occurred_at, "occurred_at"),
        "remote_addr": remote_addr,
        "claimed_producer": claimed_producer,
        "authenticated_producer": authenticated_producer,
        "decision": decision,
        "reason": reason,
        "path": path,
    }
    _check_utf8(row)
    return row

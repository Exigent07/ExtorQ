"""Mapping of validated contract models to ClickHouse rows (contract schema 2.0).

``to_row(kind, model, producer_id=..., batch_id=..., ingested_at=...)`` returns a
``dict`` whose keys are exactly the columns of ``TABLE_BY_KIND[kind]`` after every
migration in ``infra/clickhouse/migrations/`` is applied (``0001`` core tables,
``0004`` service model, ``0008`` removal of the simulation columns).
``tests/unit/platform/test_platform_rows.py`` replays the DDL and fails on drift.
Values are Python objects accepted by clickhouse-connect's typed insert (aware UTC
``datetime`` for ``DateTime64``, ``None`` for ``Nullable``, ``list`` for ``Array``,
``dict`` for ``Map``). Rules:

* Unknown stays unknown: absent optional values become ``NULL``; nothing is
  substituted.
* JSON-bearing columns hold :func:`extorq.contracts.identity.canonical_json`.
* ``payload`` (events, alerts) is the canonical JSON of the whole validated model.
* ``row_version`` formulas follow the DDL comments exactly.
* Integer columns are range-checked against their ClickHouse type, and every
  string must be encodable as UTF-8, so a record that passes ``to_row`` at the
  gateway can always be inserted by the writer.

Besides the eight ingest record kinds, this module provides row builders for
``pipeline_health``, ``ingest_quarantine``, ``ingest_audit`` and ``alerts``
(:func:`alert_to_row`; the detector is the only writer of alerts).

Service model mapping (``0004_services.sql``):

* ``Service`` -> ``services`` (``endpoints`` = canonical JSON array of ServiceEndpoint);
* ``ServiceInstance`` -> ``service_instances`` (field ``user`` -> column ``process_user``);
* ``SecurityEvent.service.{service_id,name,instance_id,adapter_id}`` ->
  ``events.{service_id,service_name,service_instance_id,adapter_id}`` and
  ``SecurityEvent.kubernetes.container_id`` -> ``events.k8s_container_id``;
* ``PostureFinding.service_id`` -> ``finding_observations.service_id``;
* ``DetectionAlert.service_ids`` -> ``alerts.service_ids``.

Events without ``service`` map the service columns to NULL. Schema 2.0 has no
simulation category: rows never carry ``simulation_run_id``, ``scenario_id`` or
``simulation_run_ids``. Until migration 0008 drops those columns from an existing
database, ClickHouse fills them with their defaults (NULL / empty array).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

from extorq.contracts.alert import AlertEvidence, DetectionAlert
from extorq.contracts.asset import Asset, InventoryItem
from extorq.contracts.event import SecurityEvent
from extorq.contracts.finding import PostureFinding
from extorq.contracts.health import CollectorHealth, PipelineHealth
from extorq.contracts.identity import canonical_json
from extorq.contracts.ingest import RecordKind
from extorq.contracts.scan import ScanRun, ScanStatus
from extorq.contracts.service import Service, ServiceInstance

#: Target table (in database ``extorq``) for every ingest record kind.
TABLE_BY_KIND: dict[RecordKind, str] = {
    RecordKind.EVENT: "events",
    RecordKind.ASSET: "assets",
    RecordKind.INVENTORY_ITEM: "inventory_items",
    RecordKind.FINDING: "finding_observations",
    RecordKind.SCAN_RUN: "scan_runs",
    RecordKind.COLLECTOR_HEALTH: "collector_health",
    RecordKind.SERVICE: "services",
    RecordKind.SERVICE_INSTANCE: "service_instances",
}

#: Model class expected for each kind (to_row rejects mismatches).
MODEL_BY_KIND: dict[RecordKind, type[BaseModel]] = {
    RecordKind.EVENT: SecurityEvent,
    RecordKind.ASSET: Asset,
    RecordKind.INVENTORY_ITEM: InventoryItem,
    RecordKind.FINDING: PostureFinding,
    RecordKind.SCAN_RUN: ScanRun,
    RecordKind.COLLECTOR_HEALTH: CollectorHealth,
    RecordKind.SERVICE: Service,
    RecordKind.SERVICE_INSTANCE: ServiceInstance,
}

PIPELINE_HEALTH_TABLE = "pipeline_health"
QUARANTINE_TABLE = "ingest_quarantine"
AUDIT_TABLE = "ingest_audit"
ALERTS_TABLE = "alerts"

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
    """``SecurityEvent`` -> ``extorq.events`` (flattened nested objects + canonical payload)."""
    actor, resource, net = event.actor, event.resource, event.network
    proc, http, k8s, gh = event.process, event.http, event.kubernetes, event.github
    prov, svc = event.provenance, event.service
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
        "k8s_container_id": k8s.container_id if k8s else None,
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
        "service_id": svc.service_id if svc else None,
        "service_name": svc.name if svc else None,
        "service_instance_id": svc.instance_id if svc else None,
        "adapter_id": svc.adapter_id if svc else None,
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
    """``Asset`` -> ``extorq.assets`` (latest state per ``asset_id``: read ``v_assets``)."""
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
    """``InventoryItem`` -> ``extorq.inventory_items`` (``present`` 0 marks a tombstone)."""
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
    """``PostureFinding`` -> ``extorq.finding_observations`` (one row per scan observation)."""
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
        "service_id": finding.service_id,
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
    """``ScanRun`` -> ``extorq.scan_runs``; ``row_version`` lets a finished run replace RUNNING."""
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
    """``CollectorHealth`` -> ``extorq.collector_health`` (append-only; ``v_collector_latest``)."""
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


def service_to_row(service: Service, *, producer_id: str, ingested_at: datetime) -> dict[str, Any]:
    """``Service`` -> ``extorq.services`` (0004). Endpoints are a canonical JSON array."""
    return {
        "service_id": service.service_id,
        "asset_id": service.asset_id,
        "service_kind": _enum(service.service_kind),
        "service_key": service.service_key,
        "name": service.name,
        "category": _enum(service.category),
        "product": service.product,
        "version": service.version,
        "discovered_via": [_enum(e) for e in service.discovered_via],
        "adapter_id": service.adapter_id,
        "adapter_support": _enum(service.adapter_support),
        "monitoring_status": _enum(service.monitoring_status),
        "coverage_note": service.coverage_note,
        "telemetry_sources": [_enum(s) for s in service.telemetry_sources],
        "endpoints": canonical_json([e.model_dump(mode="json") for e in service.endpoints]),
        "config_refs": list(service.config_refs),
        "instance_count": _uint(service.instance_count, 32, "instance_count"),
        "last_telemetry_at": _time(service.last_telemetry_at, "last_telemetry_at"),
        "attributes": canonical_json(service.attributes),
        "first_seen": _req_time(service.first_seen, "first_seen"),
        "last_seen": _req_time(service.last_seen, "last_seen"),
        "present": 1 if service.present else 0,
        "observed_by": service.observed_by,
        "schema_version": service.schema_version,
        "producer_id": producer_id,
        "ingested_at": _req_time(ingested_at, "ingested_at"),
    }


def service_instance_to_row(
    instance: ServiceInstance, *, producer_id: str, ingested_at: datetime
) -> dict[str, Any]:
    """``ServiceInstance`` -> ``extorq.service_instances`` (0004); ``user`` -> ``process_user``."""
    return {
        "instance_id": instance.instance_id,
        "service_id": instance.service_id,
        "asset_id": instance.asset_id,
        "instance_kind": _enum(instance.instance_kind),
        "instance_key": instance.instance_key,
        "parent_instance_id": instance.parent_instance_id,
        "state": instance.state,
        "pid": _uint(instance.pid, 32, "pid"),
        "process_name": instance.process_name,
        "process_user": instance.user,
        "namespace": instance.namespace,
        "pod_name": instance.pod_name,
        "pod_uid": instance.pod_uid,
        "container_name": instance.container_name,
        "container_id": instance.container_id,
        "image": instance.image,
        "node_name": instance.node_name,
        "workload_kind": instance.workload_kind,
        "workload_name": instance.workload_name,
        "started_at": _time(instance.started_at, "started_at"),
        "observed_at": _req_time(instance.observed_at, "observed_at"),
        "present": 1 if instance.present else 0,
        "observed_by": instance.observed_by,
        "attributes": canonical_json(instance.attributes),
        "schema_version": instance.schema_version,
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
        raise RowError(
            f"kind {record_kind.value} expects {expected.__name__}, got {type(model).__name__}"
        )
    row: dict[str, Any]
    if isinstance(model, SecurityEvent):
        row = event_to_row(
            model, producer_id=producer_id, batch_id=batch_id, ingested_at=ingested_at
        )
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
    elif isinstance(model, Service):
        row = service_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    elif isinstance(model, ServiceInstance):
        row = service_instance_to_row(model, producer_id=producer_id, ingested_at=ingested_at)
    else:  # pragma: no cover - MODEL_BY_KIND covers every kind
        raise RowError(f"no row mapper for {type(model).__name__}")
    _check_utf8(row)
    return row


# ── pipeline-internal tables ──────────────────────────────────────────


def pipeline_health_to_row(health: PipelineHealth) -> dict[str, Any]:
    """``PipelineHealth`` of the gateway or writer -> ``extorq.pipeline_health``."""
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
    """One quarantined record -> ``extorq.ingest_quarantine`` (excerpt already redacted)."""
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
    """One refused request (401/403) -> ``extorq.ingest_audit`` (never the request body)."""
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


def alert_to_row(alert: DetectionAlert) -> dict[str, Any]:
    """``DetectionAlert`` -> ``extorq.alerts`` (0001 + ``service_ids`` from 0004, schema 2.0).

    Shared helper for the detector (the only writer of alerts, PLAN §3 invariant 4):
    ``payload`` is the canonical JSON of the validated model; ``service_ids`` lists the
    services whose telemetry is evidence for the alert (empty when not attributable).
    """
    row = {
        "alert_id": alert.alert_id,
        "schema_version": alert.schema_version,
        "rule_id": alert.rule_id,
        "rule_version": alert.rule_version,
        "rule_title": alert.rule_title,
        "severity": _enum(alert.severity),
        "confidence": _enum(alert.confidence),
        "asset_id": alert.asset_id,
        "asset_type": _enum(alert.asset_type),
        "group_key": alert.group_key,
        "entities": dict(alert.entities),
        "service_ids": list(alert.service_ids),
        "summary": alert.summary,
        "first_seen": _req_time(alert.first_seen, "first_seen"),
        "last_seen": _req_time(alert.last_seen, "last_seen"),
        "window_start": _req_time(alert.window_start, "window_start"),
        "window_end": _req_time(alert.window_end, "window_end"),
        "event_count": _uint(alert.event_count, 64, "event_count"),
        "evidence_event_ids": list(alert.evidence_event_ids),
        "evidence_truncated": 1 if alert.evidence_truncated else 0,
        "features": canonical_json(alert.features),
        "mitre_techniques": list(alert.mitre_techniques),
        "created_at": _req_time(alert.created_at, "created_at"),
        "updated_at": _req_time(alert.updated_at, "updated_at"),
        "detector_version": alert.detector_version,
        "payload": canonical_json(alert),
    }
    _check_utf8(row)
    return row


def alert_evidence_to_row(evidence: AlertEvidence) -> dict[str, Any]:
    """``AlertEvidence`` -> ``extorq.alert_evidence`` with optional source event time."""
    return {
        "alert_id": evidence.alert_id,
        "event_id": evidence.event_id,
        "role": evidence.role.value,
        "added_at": evidence.added_at,
        "event_time": evidence.event_time,
    }

"""SYNTHETIC contract records for platform unit tests (contract schema 2.0).

Every record built here is clearly synthetic test data (labels/attributes say so,
collector ids start with ``synthetic-``). Nothing here is real telemetry and none
of it is ever sent to the live stack by unit tests.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from extorq.contracts.alert import DetectionAlert
from extorq.contracts.identity import (
    alert_id,
    event_id,
    finding_id,
    instance_id,
    scope_hash,
    service_id,
    stable_id,
)

NOW = datetime(2026, 11, 21, 12, 0, 0, 123000, tzinfo=UTC)
LINUX_ASSET = "linux:lab-vm-01"
MACOS_ASSET = "macos:workstation-01"
SSH_SERVICE_ID = service_id(LINUX_ASSET, "host_service", "ssh.service")
SSH_INSTANCE_ID = instance_id(SSH_SERVICE_ID, "process", "812:2026-11-21T09:00:00Z")


def iso(value: datetime) -> str:
    return value.isoformat()


def event_data(
    marker: str = "1",
    *,
    asset_id: str = LINUX_ASSET,
    source_type: str = "linux.journald",
    event_type: str = "auth.ssh.login_failed",
    category: str = "authentication",
    asset_type: str = "linux_host",
    event_time: datetime | None = None,
    with_service: bool = False,
    **extra: Any,
) -> dict[str, Any]:
    when = event_time or NOW
    data: dict[str, Any] = {
        "event_id": event_id(source_type, asset_id, f"synthetic:{marker}"),
        "event_type": event_type,
        "category": category,
        "asset_id": asset_id,
        "asset_type": asset_type,
        "source": {
            "source_type": source_type,
            "collector_id": "synthetic-collector",
            "collector_version": "0.0.0",
            "collection_method": "ssh_pull",
            "source_native_id": f"synthetic:{marker}",
        },
        "event_time": iso(when),
        "observed_time": iso(when),
        "outcome": "failure",
        "actor": {"type": "user", "name": "synthetic-user"},
        "network": {"src_ip": "10.0.2.2", "src_port": 50000, "protocol": "tcp"},
        "message": "SYNTHETIC test event",
        "attributes": {"synthetic": True},
        "labels": {"synthetic": "true"},
        "provenance": {"parser": "synthetic-parser", "parser_version": "0.0.0"},
    }
    if with_service:
        data["service"] = {
            "service_id": SSH_SERVICE_ID,
            "name": "ssh",
            "instance_id": SSH_INSTANCE_ID,
            "adapter_id": "ssh",
        }
    data.update(extra)
    return data


def asset_data(asset_id: str = LINUX_ASSET) -> dict[str, Any]:
    return {
        "asset_id": asset_id,
        "asset_type": "linux_host",
        "name": "synthetic-vm",
        "labels": {"synthetic": "true"},
        "attributes": {"os_name": "synthetic"},
        "first_seen": iso(NOW - timedelta(days=1)),
        "last_seen": iso(NOW),
        "observed_by": "synthetic-collector",
    }


def inventory_data(asset_id: str = LINUX_ASSET) -> dict[str, Any]:
    return {
        "asset_id": asset_id,
        "item_type": "package",
        "item_key": "synthetic-package",
        "attributes": {"version": "1.0-synthetic"},
        "snapshot_id": "synthetic-snapshot-1",
        "observed_at": iso(NOW),
        "present": True,
        "collector_id": "synthetic-collector",
    }


def scan_run_data(
    asset_id: str = LINUX_ASSET, producer_id: str = "scanner-runner"
) -> dict[str, Any]:
    return {
        "scan_run_id": stable_id("synthetic.scan", asset_id),
        "scanner": "trivy",
        "scanner_version": "0.0.0-synthetic",
        "asset_id": asset_id,
        "scope": {
            "targets": ["synthetic"],
            "description": "synthetic scope",
            "scope_hash": scope_hash(["synthetic"], "synthetic scope"),
        },
        "started_at": iso(NOW - timedelta(minutes=5)),
        "finished_at": iso(NOW),
        "status": "succeeded",
        "coverage": {"checks_total": 10, "checks_run": 10},
        "findings_count": 1,
        "producer_id": producer_id,
    }


def finding_data(asset_id: str = LINUX_ASSET, *, with_service: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "finding_id": finding_id(asset_id, "trivy", "CVE-0000-0000", "synthetic-package"),
        "scan_run_id": stable_id("synthetic.scan", asset_id),
        "asset_id": asset_id,
        "scanner": "trivy",
        "check_id": "CVE-0000-0000",
        "category": "vulnerability",
        "severity": "high",
        "title": "SYNTHETIC finding",
        "package": {"name": "synthetic-package", "installed_version": "1.0"},
        "cve_ids": ["CVE-0000-0000"],
        "cvss_score": 7.5,
        "observed_at": iso(NOW),
    }
    if with_service:
        data["service_id"] = SSH_SERVICE_ID
    return data


def health_data(
    asset_id: str = LINUX_ASSET, source_types: list[str] | None = None
) -> dict[str, Any]:
    return {
        "collector_id": "synthetic-collector",
        "collector_type": "linux_ssh",
        "asset_id": asset_id,
        "source_types": source_types or ["linux.journald"],
        "status": "ok",
        "reported_at": iso(NOW),
        "last_attempt_at": iso(NOW),
        "last_success_at": iso(NOW),
        "events_collected": 3,
        "records_buffered": 0,
        "lag_seconds": 1.5,
        "collector_version": "0.0.0",
        "interval_seconds": 60,
        "details": {"synthetic": True},
    }


def service_data(asset_id: str = LINUX_ASSET) -> dict[str, Any]:
    return {
        "service_id": service_id(asset_id, "host_service", "ssh.service"),
        "asset_id": asset_id,
        "service_kind": "host_service",
        "service_key": "ssh.service",
        "name": "ssh",
        "category": "ssh",
        "product": "openssh",
        "discovered_via": ["systemd_unit", "listening_socket"],
        "adapter_id": "ssh",
        "adapter_support": "implemented",
        "monitoring_status": "monitored",
        "coverage_note": "telemetry fresh",
        "telemetry_sources": ["linux.journald"],
        "endpoints": [
            {
                "protocol": "tcp",
                "address": "0.0.0.0",  # noqa: S104 - synthetic observed bind address
                "port": 22,
                "exposure": "any",
                "attribution": "confirmed",
                "attribution_basis": "socket owner pid 812",
            },
        ],
        "config_refs": ["/etc/ssh/sshd_config"],
        "instance_count": 1,
        "last_telemetry_at": iso(NOW),
        "attributes": {"synthetic": True},
        "first_seen": iso(NOW - timedelta(days=1)),
        "last_seen": iso(NOW),
        "observed_by": "synthetic-collector",
    }


def service_instance_data(asset_id: str | None = LINUX_ASSET) -> dict[str, Any]:
    return {
        "instance_id": SSH_INSTANCE_ID,
        "service_id": SSH_SERVICE_ID,
        "asset_id": asset_id,
        "instance_kind": "process",
        "instance_key": "812:2026-11-21T09:00:00Z",
        "state": "running",
        "pid": 812,
        "process_name": "sshd",
        "user": "root",
        "started_at": iso(NOW - timedelta(hours=3)),
        "observed_at": iso(NOW),
        "observed_by": "synthetic-collector",
        "attributes": {"synthetic": True},
    }


def record(kind: str, data: dict[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "data": data}


def all_kind_records(asset_id: str = LINUX_ASSET) -> list[dict[str, Any]]:
    """One valid record of every RecordKind (for mapping/authorization tests)."""
    return [
        record("event", event_data(asset_id=asset_id, with_service=True)),
        record("asset", asset_data(asset_id)),
        record("inventory_item", inventory_data(asset_id)),
        record("finding", finding_data(asset_id)),
        record("scan_run", scan_run_data(asset_id)),
        record("collector_health", health_data(asset_id)),
        record("service", service_data(asset_id)),
        record("service_instance", service_instance_data(asset_id)),
    ]


def alert(service_ids: list[str] | None = None) -> DetectionAlert:
    return DetectionAlert(
        alert_id=alert_id("VM-001", "linux:lab-vm-01|10.0.2.2", NOW),
        rule_id="VM-001",
        rule_version="1.0.0",
        rule_title="SYNTHETIC alert",
        severity="high",
        confidence="high",
        asset_id=LINUX_ASSET,
        asset_type="linux_host",
        group_key="linux:lab-vm-01|10.0.2.2",
        entities={"src_ip": "10.0.2.2"},
        service_ids=service_ids if service_ids is not None else [SSH_SERVICE_ID],
        summary="SYNTHETIC alert summary",
        first_seen=NOW - timedelta(minutes=3),
        last_seen=NOW,
        window_start=NOW - timedelta(minutes=5),
        window_end=NOW,
        event_count=6,
        evidence_event_ids=[event_data()["event_id"]],
        features={"distinct_connections": 6},
        created_at=NOW,
        updated_at=NOW,
        detector_version="0.0.0-synthetic",
    )

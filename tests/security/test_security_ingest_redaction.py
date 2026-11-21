"""Gateway redaction coverage across every record kind (owner: agent F).

Invariant (AGENTS.md security invariant 1, PLAN section 3 invariant 6): a secret
that a producer places in any free-text field of any record kind never reaches
the spool payload, and never appears in a quarantine excerpt.

The test drives the gateway's documented processing entry point
(``extorq.ingest.processing.prepare_batch``) in-process, without the stack. The
canary secrets are generated at runtime (``secrets.token_hex``) so no
secret-shaped literal is committed, and they are never printed: assertions
report only field names.

All records here are SYNTHETIC test inputs (collector id ``f-security-test``),
never presented as telemetry.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from typing import Any

import pytest

processing = pytest.importorskip("extorq.ingest.processing")
registry = pytest.importorskip("extorq.ingest.registry")

from extorq.contracts.identity import (  # noqa: E402
    event_id,
    finding_id,
    instance_id,
    scope_hash,
    service_id,
)
from extorq.contracts.ingest import RecordKind  # noqa: E402

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
NOW_ISO = NOW.isoformat()
HOST = "linux:lab-vm-01"
CLUSTER = "k8s:extorq-lab"
PRODUCER_ID = "f-security-test"
COLLECTOR = "f-security-test"


class Canary:
    """Runtime-generated secret values embedded in free text with a redactable prefix."""

    def __init__(self) -> None:
        self.values: list[str] = []

    def password(self) -> str:
        value = "Fc" + secrets.token_hex(12)
        self.values.append(value)
        return f"password={value}"

    def bearer(self) -> str:
        value = "Fb" + secrets.token_hex(16)
        self.values.append(value)
        return f"Authorization: Bearer {value}"

    def leaked_in(self, text: str) -> bool:
        return any(value in text for value in self.values)


def _producer() -> Any:
    return registry.ProducerEntry(
        producer_id=PRODUCER_ID,
        token_sha256=registry.token_digest(secrets.token_hex(16)),
        allowed_kinds=list(RecordKind),
        allowed_source_types=["linux.*", "k8s.*", "scanner.*", "extorq.*"],
        allowed_asset_patterns=[HOST, f"{CLUSTER}*"],
    )


def _source(source_type: str) -> dict[str, Any]:
    return {
        "source_type": source_type,
        "collector_id": COLLECTOR,
        "collector_version": "0.0.0",
        "collection_method": "ssh_pull",
    }


def _records(c: Canary) -> dict[str, dict[str, Any]]:
    """One record per (kind, field group); every free-text field carries a canary."""
    svc = service_id(HOST, "host_service", "f-test.service")
    scan = "0" * 31 + "f"
    return {
        "event:text": {
            "kind": "event",
            "data": {
                "event_id": event_id("linux.journald", HOST, "f-security-test-1"),
                "event_type": "system.log.notable",
                "category": "other",
                "asset_id": HOST,
                "asset_type": "linux_host",
                "source": _source("linux.journald"),
                "event_time": NOW_ISO,
                "provenance": {"parser": "f-security-test", "parser_version": "1"},
                "message": f"note {c.password()}",
                "raw": f"raw {c.bearer()}",
                "process": {"command_line": f"app {c.password()}"},
                "attributes": {"note": f"x {c.password()}", "items": [f"y {c.bearer()}"]},
                "labels": {"note": f"z {c.password()}"},
            },
        },
        "event:http": {
            "kind": "event",
            "data": {
                "event_id": event_id("linux.nginx", HOST, "f-security-test-2"),
                "event_type": "http.request",
                "category": "http",
                "asset_id": HOST,
                "asset_type": "linux_host",
                "source": _source("linux.nginx"),
                "event_time": NOW_ISO,
                "provenance": {"parser": "f-security-test", "parser_version": "1"},
                "http": {
                    "method": "GET",
                    "route": f"/login?{c.password()}",
                    "user_agent": f"curl {c.bearer()}",
                },
            },
        },
        "event:kubernetes": {
            "kind": "event",
            "data": {
                "event_id": event_id("k8s.audit", CLUSTER, "f-security-test-3"),
                "event_type": "k8s.api.request",
                "category": "kubernetes_api",
                "asset_id": CLUSTER,
                "asset_type": "kubernetes_cluster",
                "source": _source("k8s.audit"),
                "event_time": NOW_ISO,
                "provenance": {"parser": "f-security-test", "parser_version": "1"},
                "kubernetes": {"cluster": "extorq-lab", "user_agent": f"kubectl {c.bearer()}"},
            },
        },
        "asset": {
            "kind": "asset",
            "data": {
                "asset_id": HOST,
                "asset_type": "linux_host",
                "name": "lab-vm-01",
                "first_seen": NOW_ISO,
                "last_seen": NOW_ISO,
                "observed_by": COLLECTOR,
                "attributes": {"note": c.password()},
                "labels": {"note": c.password()},
            },
        },
        "inventory_item": {
            "kind": "inventory_item",
            "data": {
                "asset_id": HOST,
                "item_type": "process",
                "item_key": "4242:1",
                "snapshot_id": "f-security-test",
                "observed_at": NOW_ISO,
                "collector_id": COLLECTOR,
                "attributes": {"args": f"server {c.password()}", "argv": [c.bearer()]},
            },
        },
        "finding": {
            "kind": "finding",
            "data": {
                "finding_id": finding_id(HOST, "f-security-test", "F-TEST-1", "resource"),
                "scan_run_id": scan,
                "asset_id": HOST,
                "scanner": "f-security-test",
                "check_id": "F-TEST-1",
                "category": "misconfiguration",
                "severity": "low",
                "title": f"title {c.password()}",
                "description": f"description {c.bearer()}",
                "evidence": f"evidence {c.password()}",
                "remediation": f"remediation {c.password()}",
                "observed_at": NOW_ISO,
                "attributes": {"note": c.password()},
            },
        },
        "scan_run": {
            "kind": "scan_run",
            "data": {
                "scan_run_id": scan,
                "scanner": "f-security-test",
                "scanner_version": "1",
                "asset_id": HOST,
                "scope": {"targets": ["t"], "scope_hash": scope_hash(["t"])},
                "started_at": NOW_ISO,
                "status": "failed",
                "producer_id": PRODUCER_ID,
                "error": f"failed {c.password()}",
                "attributes": {"note": c.password()},
                "coverage": {
                    "notes": [f"note {c.bearer()}"],
                    "skipped": [{"check": "x", "reason": f"reason {c.password()}"}],
                },
            },
        },
        "collector_health": {
            "kind": "collector_health",
            "data": {
                "collector_id": COLLECTOR,
                "collector_type": "f-security-test",
                "asset_id": HOST,
                "source_types": ["linux.journald"],
                "status": "degraded",
                "reported_at": NOW_ISO,
                "collector_version": "0.0.0",
                "interval_seconds": 60,
                "last_error": f"error {c.password()}",
                "checkpoint_summary": f"cursor {c.password()}",
                "details": {"note": c.bearer()},
            },
        },
        "simulation_run": {
            "kind": "simulation_run",
            "data": {
                "run_id": "fsectest01",
                "scenario_id": "VM-001",
                "asset_id": HOST,
                "status": "started",
                "started_at": NOW_ISO,
                "operator": "f-security-test",
                "description": f"description {c.password()}",
                "notes": [f"note {c.bearer()}"],
            },
        },
        "service": {
            "kind": "service",
            "data": {
                "service_id": svc,
                "asset_id": HOST,
                "service_kind": "host_service",
                "service_key": "f-test.service",
                "name": "f-test",
                "category": "unknown",
                "discovered_via": ["systemd_unit"],
                "adapter_support": "none",
                "monitoring_status": "unmonitored",
                "coverage_note": f"note {c.password()}",
                "config_refs": [f"/etc/f-test.conf?{c.password()}"],
                "endpoints": [
                    {
                        "protocol": "tcp",
                        "port": 8080,
                        "attribution": "inferred",
                        "attribution_basis": f"config {c.password()}",
                    }
                ],
                "attributes": {"args": f"server {c.bearer()}"},
                "first_seen": NOW_ISO,
                "last_seen": NOW_ISO,
                "observed_by": COLLECTOR,
            },
        },
        "service_instance": {
            "kind": "service_instance",
            "data": {
                "instance_id": instance_id(svc, "process", "4242:1"),
                "service_id": svc,
                "asset_id": HOST,
                "instance_kind": "process",
                "instance_key": "4242:1",
                "observed_at": NOW_ISO,
                "observed_by": COLLECTOR,
                "attributes": {"args": f"server {c.password()}"},
            },
        },
    }


def _canary_records() -> tuple[Canary, dict[str, dict[str, Any]]]:
    canary = Canary()
    return canary, _records(canary)


def test_every_record_kind_is_exercised() -> None:
    _, records = _canary_records()
    covered = {record["kind"] for record in records.values()}
    assert covered == {kind.value for kind in RecordKind}, (
        "record kinds without a redaction-coverage case (add one): "
        f"{sorted({kind.value for kind in RecordKind} - covered)}"
    )


@pytest.mark.parametrize("case", sorted(_canary_records()[1]))
def test_secrets_in_free_text_never_reach_the_spool(case: str) -> None:
    canary, records = _canary_records()
    record = records[case]
    batch = processing.prepare_batch([record], _producer(), batch_id="f" * 32, now=NOW)
    assert not batch.denials, f"{case}: unexpectedly denied: {batch.denials}"
    reasons = [q.reason for q in batch.quarantined]
    assert not reasons, f"{case}: synthetic record quarantined: {reasons}"
    assert len(batch.candidates) == 1
    payload = batch.candidates[0].payload
    leaked = [
        path for path, value in _string_leaves(json.loads(payload)) if canary.leaked_in(value)
    ]
    assert not leaked, f"{case}: secret survived redaction in field(s) {leaked}"
    assert batch.redactions >= 1, f"{case}: no redaction was counted"


def test_quarantine_excerpt_is_redacted() -> None:
    canary, records = _canary_records()
    record = json.loads(json.dumps(records["event:text"]))
    record["data"]["unexpected_field"] = f"x {canary.password()}"  # extra field -> quarantine
    batch = processing.prepare_batch([record], _producer(), batch_id="e" * 32, now=NOW)
    assert len(batch.quarantined) == 1
    entry = batch.quarantined[0]
    # Booleans only: pytest must never echo the (synthetic) secret on failure.
    excerpt_leak = canary.leaked_in(entry.excerpt)
    reason_leak = canary.leaked_in(entry.reason)
    assert excerpt_leak is False, "secret survived in the quarantine excerpt"
    assert reason_leak is False, "secret survived in the quarantine reason"


def _string_leaves(value: Any, path: str = "") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path or "<root>", value)]
    if isinstance(value, dict):
        out: list[tuple[str, str]] = []
        for key, item in value.items():
            out.extend(_string_leaves(item, f"{path}.{key}" if path else str(key)))
        return out
    if isinstance(value, list):
        out = []
        for index, item in enumerate(value):
            out.extend(_string_leaves(item, f"{path}[{index}]"))
        return out
    return []

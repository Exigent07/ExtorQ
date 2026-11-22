"""Synthetic Collector samples and gateway acknowledgements on disposable SQLite."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from extorq.api.service import collector_status
from extorq.common.config import Settings
from extorq.contracts.common import utc_now
from extorq.ingest.app import OTLP_LOGS_PATH, OTLP_METRICS_PATH, create_app
from extorq.ingest.otlp_health import PRODUCER_ID, DeliveryHealth, parse_observation
from extorq.ingest.registry import ProducerEntry, ProducerRegistry, token_digest
from extorq.pipeline.spool import Spool

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=UTC)
NODE = "extorq-lab-control-plane"
ASSET = f"k8s:extorq-lab/node/{NODE}"
TEST_TOKEN = "synthetic-otel-credential-for-local-tests"
OTHER_TOKEN = "synthetic-other-credential-for-local-tests"


def attrs(**pairs: str) -> list[dict[str, Any]]:
    return [{"key": key, "value": {"stringValue": value}} for key, value in pairs.items()]


def metric(name: str, value: int, at: datetime, **labels: str) -> dict[str, Any]:
    return {
        "name": f"otelcol_{name}",
        "gauge": {
            "dataPoints": [
                {
                    "asInt": str(value),
                    "timeUnixNano": str(int(at.timestamp() * 1000) * 1_000_000),
                    "attributes": attrs(**labels),
                }
            ]
        },
    }


def resource(**attributes: str) -> dict[str, Any]:
    return {
        "attributes": attrs(
            **{"k8s.cluster.name": "extorq-lab", "k8s.node.name": NODE, **attributes}
        )
    }


def sample(*metrics: dict[str, Any]) -> dict[str, Any]:
    return {
        "resourceMetrics": [{"resource": resource(), "scopeMetrics": [{"metrics": list(metrics)}]}]
    }


def metric_state(payload: dict[str, Any]) -> list[dict[str, Any]]:
    parsed = parse_observation(payload, NOW)
    assert parsed is not None
    return [report.model_dump(mode="json") for report in DeliveryHealth().reports(parsed)]


def test_metrics_scope_and_delivery_states() -> None:
    exporter = "otlp_http/extorq"
    accepted = metric("receiver_accepted_log_records_total", 17, NOW, receiver="file_log/audit")
    queue = metric("exporter_queue_size", 4, NOW, exporter=exporter)
    capacity = metric("exporter_queue_capacity", 4, NOW, exporter=exporter)
    foreign = metric(
        "exporter_send_failed_log_records",
        999,
        NOW,
        exporter="otlp_http/health",
        error_permanent="true",
    )
    audit, containers = metric_state(sample(accepted, queue, capacity, foreign))
    assert audit["asset_id"] == ASSET
    assert audit["events_collected"] == 17
    assert audit["details"] == {
        "accepted_records": 17,
        "queue_capacity_requests": 4,
        "queue_requests": 4,
        "delivery_state": "backlogged",
        "exporter_scope": "node",
    }
    assert containers["source_types"] == ["k8s.container_log"]
    assert containers["records_buffered"] == 0
    assert containers["last_success_at"] is None
    assert audit["collector_id"] != containers["collector_id"]
    assert parse_observation(sample(queue), NOW + timedelta(minutes=2)) is None
    transient = metric("exporter_send_failed_log_records", 2, NOW, exporter=exporter)
    permanent = metric(
        "exporter_send_failed_log_records", 1, NOW, exporter=exporter, error_permanent="true"
    )
    assert metric_state(sample(transient))[0]["details"]["delivery_state"] == "degraded"
    assert metric_state(sample(transient, permanent))[0]["details"]["delivery_state"] == (
        "dropping_records"
    )
    assert metric_state(sample(capacity))[0]["details"]["delivery_state"] == (
        "running_not_delivering"
    )


def test_gateway_acknowledgement_and_health_expiry(tmp_path: Path) -> None:
    spool = Spool(tmp_path / "otel-test.sqlite")
    registry = ProducerRegistry.from_entries(
        [
            ProducerEntry(
                producer_id=PRODUCER_ID,
                token_sha256=token_digest(TEST_TOKEN),
                allowed_kinds=["event", "collector_health"],
                allowed_source_types=["k8s.audit", "k8s.container_log"],
                allowed_asset_patterns=["k8s:extorq-lab", ASSET],
            ),
            ProducerEntry(
                producer_id="other-collector",
                token_sha256=token_digest(OTHER_TOKEN),
                allowed_kinds=["collector_health"],
                allowed_source_types=["k8s.*"],
                allowed_asset_patterns=["k8s:*"],
            ),
        ]
    )
    app = create_app(
        Settings(home=tmp_path), spool=spool, registry=registry, background_tasks=False
    )
    headers = {"Authorization": f"Bearer {TEST_TOKEN}"}
    now = utc_now()
    logs = {
        "resourceLogs": [
            {
                "resource": resource(
                    **{
                        "extorq.source": "container",
                        "k8s.pod.uid": "00000000-0000-4000-8000-0000000000d1",
                        "k8s.container.name": "acceptance-marker",
                    }
                ),
                "scopeLogs": [
                    {
                        "logRecords": [
                            {
                                "timeUnixNano": str(int(now.timestamp() * 1000) * 1_000_000),
                                "body": {"stringValue": "synthetic retained pod test line"},
                            }
                        ]
                    }
                ],
            }
        ]
    }
    health = sample(
        metric("exporter_queue_size", 0, now, exporter="otlp_http/extorq"),
        metric("receiver_accepted_log_records", 1, now, receiver="file_log/containers"),
    )
    try:
        with TestClient(app) as client:
            denied = client.post(
                OTLP_METRICS_PATH, json=health, headers={"Authorization": f"Bearer {OTHER_TOKEN}"}
            )
            assert denied.status_code == 403
            accepted = client.post(OTLP_LOGS_PATH, json=logs, headers=headers)
            assert accepted.status_code == 200 and accepted.json() == {}
            for _ in range(2):
                report = client.post(OTLP_METRICS_PATH, json=health, headers=headers)
                assert report.status_code == 200 and report.json() == {}
            with spool._lock:
                stored = spool._conn.execute(
                    "SELECT payload FROM records WHERE kind = 'collector_health'"
                ).fetchall()
            assert len(stored) == 1
            row = json.loads(stored[0][0])["data"]
            assert row["details"]["delivery_state"] == "delivering"
            assert row["source_types"] == ["k8s.container_log"]
            api_row = {
                **row,
                "details": json.dumps(row["details"]),
                "last_reported_at": datetime.fromisoformat(row["reported_at"]),
                "last_success_at": datetime.fromisoformat(row["last_success_at"]),
            }
            current = collector_status(api_row, now)
            assert not current.stale and current.details["delivery_state"] == "delivering"
            expired = collector_status(api_row, now + timedelta(minutes=2))
            assert expired.stale and expired.details["delivery_state"] == "unavailable"
    finally:
        spool.close()

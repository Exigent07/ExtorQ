"""Helpers for platform tests against the RUNNING stack (agent A).

Every record these tests send is SYNTHETIC: ``labels.synthetic = "true"``, event type
``system.log.notable`` (no detection rule consumes it), collector id
``extorq-platform-test`` and a per-run marker. Tokens and passwords are read from
``var/secrets`` by path and never printed.
"""

from __future__ import annotations

import ssl
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from extorq.common.config import Settings
from extorq.contracts.common import utc_now
from extorq.contracts.identity import event_id
from extorq.storage.clickhouse import get_client

REPO = Path(__file__).resolve().parents[3]
GATEWAY = "https://127.0.0.1:8443"
CA = REPO / "var" / "tls" / "ca.crt"
TOKENS = REPO / "var" / "secrets" / "tokens"
PRODUCER = "macos-workstation-01"
ASSET = "macos:workstation-01"
SOURCE = "macos.unified_log"


def tls() -> ssl.SSLContext:
    """TLS context trusting only the ExtorQ CA (as collectors do)."""
    return ssl.create_default_context(cafile=str(CA))


def settings() -> Settings:
    return Settings(home=REPO)


def token(producer: str = PRODUCER) -> str:
    return (TOKENS / f"{producer}.token").read_text(encoding="utf-8").strip()


def client(role: str) -> Any:
    return get_client(role, settings=settings())  # type: ignore[arg-type]


def require_stack() -> None:
    """Skip unless the gateway (8443) and the ClickHouse debug proxy (18123) answer."""
    if not CA.is_file() or not (TOKENS / f"{PRODUCER}.token").is_file():
        pytest.skip("var/ secrets not bootstrapped (make bootstrap)")
    try:
        health = httpx.get(f"{GATEWAY}/healthz", verify=tls(), timeout=5)
    except httpx.HTTPError:
        pytest.skip("ingest gateway not reachable on 127.0.0.1:8443 (make up)")
    if health.status_code != 200:
        pytest.skip(f"ingest gateway unhealthy: HTTP {health.status_code}")
    try:
        client("api_ro").query("SELECT 1")
    except Exception as exc:  # noqa: BLE001 - any failure means "not available here"
        pytest.skip(f"ClickHouse debug proxy not reachable (make up-debug): {type(exc).__name__}")


def synthetic_event(marker: str, index: int = 0) -> dict[str, Any]:
    now = utc_now()
    native = f"platform-test:{marker}:{index}"
    return {
        "event_id": event_id(SOURCE, ASSET, native),
        "event_type": "system.log.notable",
        "category": "other",
        "asset_id": ASSET,
        "asset_type": "macos_host",
        "source": {
            "source_type": SOURCE,
            "collector_id": "extorq-platform-test",
            "collector_version": "0.1.0",
            "collection_method": "native_command",
            "source_native_id": native,
        },
        "event_time": now.isoformat(),
        "observed_time": now.isoformat(),
        "outcome": "unknown",
        "message": "SYNTHETIC platform integration test event (agent A); not real telemetry",
        "attributes": {"synthetic": True, "test_marker": marker},
        "labels": {"synthetic": "true", "purpose": "platform-integration-test"},
        "provenance": {"parser": "extorq-platform-test", "parser_version": "0.1.0"},
    }


def batch(
    records: list[dict[str, Any]], producer: str = PRODUCER, batch_id: str | None = None
) -> dict[str, Any]:
    return {
        "schema_version": "1.1",
        "batch_id": batch_id or uuid.uuid4().hex,
        "producer_id": producer,
        "sent_at": utc_now().isoformat(),
        "records": records,
    }


def post(
    body: dict[str, Any] | bytes,
    *,
    bearer: str | None = None,
    path: str = "/v1/ingest",
    timeout: float = 15.0,
) -> httpx.Response:
    import json

    content = body if isinstance(body, bytes) else json.dumps(body).encode()
    headers = {"Content-Type": "application/json"}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    return httpx.post(
        f"{GATEWAY}{path}", content=content, headers=headers, verify=tls(), timeout=timeout
    )


def wait_for(
    fetch: Callable[[], Any],
    ok: Callable[[Any], bool],
    *,
    timeout: float = 60.0,
    interval: float = 0.5,
) -> Any:
    """Poll ``fetch`` until ``ok(result)``; return the last result (callers assert)."""
    deadline = time.monotonic() + timeout
    result = fetch()
    while not ok(result) and time.monotonic() < deadline:
        time.sleep(interval)
        result = fetch()
    return result


def event_counts(ids: list[str]) -> tuple[int, int]:
    """``(uniqExact(event_id), count())`` in ClickHouse for the given ids (api_ro)."""
    rows = (
        client("api_ro")
        .query(
            "SELECT uniqExact(event_id), count() FROM extorq.events "
            "WHERE event_id IN {ids:Array(String)}",
            parameters={"ids": ids},
        )
        .result_rows
    )
    return int(rows[0][0]), int(rows[0][1])

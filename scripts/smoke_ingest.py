#!/usr/bin/env python3
"""End-to-end smoke test: HTTPS ingest -> spool -> writer -> ClickHouse (scoped read).

Sends ONE clearly labelled SYNTHETIC SecurityEvent (``labels.synthetic = "true"``,
event type ``system.log.notable``, which no detection rule consumes) with the
``macos-workstation-01`` producer token, then polls ClickHouse through the
loopback debug proxy (compose profile ``debug``) as ``extorq_api_ro`` until the
event is visible. Prints only ids, counts and timings; never secrets.

    uv run python scripts/smoke_ingest.py [--gateway https://127.0.0.1:8443]
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path

import httpx

from extorq.common.config import Settings
from extorq.contracts.common import utc_now
from extorq.contracts.identity import event_id
from extorq.contracts.ingest import IngestBatch
from extorq.storage.clickhouse import get_client

REPO = Path(__file__).resolve().parents[1]
PRODUCER = "macos-workstation-01"
ASSET = "macos:workstation-01"


def synthetic_event(marker: str) -> dict[str, object]:
    now = utc_now()
    return {
        "event_id": event_id("macos.unified_log", ASSET, f"platform-smoke:{marker}"),
        "event_type": "system.log.notable",
        "category": "other",
        "asset_id": ASSET,
        "asset_type": "macos_host",
        "source": {
            "source_type": "macos.unified_log",
            "collector_id": "extorq-platform-smoke",
            "collector_version": "0.1.0",
            "collection_method": "native_command",
            "source_native_id": f"platform-smoke:{marker}",
        },
        "event_time": now.isoformat(),
        "observed_time": now.isoformat(),
        "outcome": "unknown",
        "message": "SYNTHETIC platform smoke test event (agent A); not real telemetry",
        "attributes": {"synthetic": True, "smoke_marker": marker},
        "labels": {"synthetic": "true", "purpose": "platform-smoke-test"},
        "provenance": {"parser": "extorq-platform-smoke", "parser_version": "0.1.0"},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--gateway", default="https://127.0.0.1:8443")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    token = (REPO / "var/secrets/tokens" / f"{PRODUCER}.token").read_text().strip()
    marker = uuid.uuid4().hex
    event = synthetic_event(marker)
    batch = IngestBatch(
        batch_id=uuid.uuid4().hex,
        producer_id=PRODUCER,
        sent_at=utc_now(),
        records=[{"kind": "event", "data": event}],
    )
    started = time.monotonic()
    with httpx.Client(verify=str(REPO / "var/tls/ca.crt"), timeout=15.0) as client:
        response = client.post(
            f"{args.gateway}/v1/ingest",
            content=batch.model_dump_json(),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
    print(f"gateway: HTTP {response.status_code} {response.json()}")
    if response.status_code != 202 or response.json().get("accepted") != 1:
        return 1

    settings = Settings(home=REPO)
    ch = get_client("api_ro", settings=settings)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        rows = ch.query(
            "SELECT event_id, producer_id, batch_id, labels['synthetic'], ingested_time "
            "FROM extorq.events WHERE event_id = {id:String}",
            parameters={"id": event["event_id"]},
        ).result_rows
        if rows:
            row = rows[0]
            print(
                f"clickhouse (extorq_api_ro): event_id={row[0]} producer={row[1]} "
                f"batch={row[2]} synthetic={row[3]} ingested_time={row[4].isoformat()}"
            )
            print(f"round trip: {time.monotonic() - started:.2f}s")
            return 0
        time.sleep(0.5)
    print("event not visible in ClickHouse before timeout", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

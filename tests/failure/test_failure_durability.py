"""Failure injection against the SHARED stack (``-m failure``; agent A only, PLAN §7).

These tests stop/restart shared services. Announce them in docs/team/status/A.md
before running and keep outages short. Every record sent is SYNTHETIC (see
tests/integration/platform/platform_live.py). Services are always brought back,
even when an assertion fails.

1. ClickHouse down: the gateway keeps answering 202, the spool grows, and after
   ClickHouse returns every accepted record arrives (no loss).
2. Gateway and writer restarted while a collector outbox is sending: every record
   arrives (at-least-once; logical duplicates collapse by event_id).
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration" / "platform"))

from platform_live import (
    GATEWAY,
    PRODUCER,
    REPO,
    batch,
    event_counts,
    post,
    require_stack,
    synthetic_event,
    tls,
    token,
    wait_for,
)

pytestmark = [pytest.mark.failure, pytest.mark.timeout(600)]


def compose(*args: str, timeout: float = 120) -> str:
    proc = subprocess.run(
        ["docker", "compose", *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"docker compose {' '.join(args)} failed: {proc.stderr[-400:]}")
    return proc.stdout


def health(service: str) -> str:
    out = compose("ps", "--format", "json", service)
    for line in out.splitlines():
        line = line.strip()
        if line:
            data = json.loads(line)
            return str(data.get("Health") or data.get("State") or "")
    return "missing"


def wait_healthy(service: str, timeout: float = 180) -> None:
    status = wait_for(
        lambda: health(service), lambda s: s == "healthy", timeout=timeout, interval=1.0
    )
    assert status == "healthy", f"{service} not healthy after restart: {status}"


def spool_depth() -> int:
    response = httpx.get(
        f"{GATEWAY}/v1/status",
        verify=tls(),
        timeout=10,
        headers={"Authorization": f"Bearer {token('extorq-selftest')}"},
    )
    response.raise_for_status()
    return int(response.json()["spool"]["depth"])


@pytest.fixture(scope="module", autouse=True)
def _stack() -> None:
    require_stack()


def test_clickhouse_outage_loses_nothing() -> None:
    marker = uuid.uuid4().hex
    events = [synthetic_event(marker, i) for i in range(100)]
    ids = [e["event_id"] for e in events]
    stopped_at = time.monotonic()
    compose("stop", "clickhouse", timeout=90)
    try:
        assert health("clickhouse") != "healthy"
        depth_before = spool_depth()
        for start in range(0, len(events), 20):
            chunk = events[start : start + 20]
            response = post(batch([{"kind": "event", "data": e} for e in chunk]), bearer=token())
            assert response.status_code == 202, response.text  # gateway does not need CH
            assert response.json()["accepted"] == len(chunk)
        assert spool_depth() >= depth_before + 100  # buffered durably, nothing written
    finally:
        compose("start", "clickhouse", timeout=90)
        wait_healthy("clickhouse")
    outage = time.monotonic() - stopped_at
    counts = wait_for(lambda: _safe_counts(ids), lambda c: c[0] == 100, timeout=240, interval=2.0)
    assert counts[0] == 100, f"only {counts[0]}/100 events arrived after the outage"
    assert counts[1] == 100  # each accepted once by the gateway; no replays happened
    print(f"clickhouse outage {outage:.1f}s; 100/100 events delivered")


def _safe_counts(ids: list[str]) -> tuple[int, int]:
    try:
        return event_counts(ids)
    except Exception:  # noqa: BLE001 - ClickHouse may still be warming up
        return (0, 0)


def test_gateway_and_writer_restart_mid_stream_loses_nothing(tmp_path: Path) -> None:
    from extorq_collectors.sdk.client import GatewayClient
    from extorq_collectors.sdk.sender import Sender
    from extorq_collectors.sdk.state import StateStore

    marker = uuid.uuid4().hex
    total = 800  # 32 batches of 25, paced ~0.5 s apart: the stream spans both restarts
    store = StateStore(tmp_path / "state.db")
    records = [
        json.dumps({"kind": "event", "data": synthetic_event(marker, i)}, sort_keys=True)
        for i in range(total)
    ]
    store.commit([("event", r) for r in records])
    ids = [json.loads(r)["data"]["event_id"] for r in records]
    client = GatewayClient(GATEWAY, token(), REPO / "var" / "tls" / "ca.crt", timeout=10)
    sender = Sender(store, client, PRODUCER, max_records=25)
    done = threading.Event()
    errors: list[str] = []

    def pump() -> None:
        deadline = time.monotonic() + 240
        while store.outbox_depth() and time.monotonic() < deadline:
            report = sender.send_pending(deadline=time.monotonic() + 5, max_batches=1)
            if report.error:
                errors.append(report.error)
                time.sleep(min(2.0, max(0.1, sender.state.next_attempt_at - time.monotonic())))
            else:
                time.sleep(0.5)  # pace the stream so it spans the restarts
        done.set()

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    try:
        time.sleep(1.0)
        compose("restart", "ingest", timeout=120)
        wait_healthy("ingest")
        time.sleep(0.5)
        compose("restart", "writer", timeout=120)
        wait_healthy("writer")
    finally:
        done.wait(timeout=260)
        thread.join(timeout=5)
        client.close()
    assert store.outbox_depth() == 0, f"outbox not drained: {store.outbox_depth()} left"
    assert store.dead_count() == 0
    store.close()
    counts = wait_for(lambda: _safe_counts(ids), lambda c: c[0] == total, timeout=180, interval=2.0)
    assert counts[0] == total, f"only {counts[0]}/{total} events arrived"
    # At-least-once: a writer crash between insert and spool delete may re-insert rows;
    # uniqExact(event_id) stays exact, count() may exceed it.
    assert counts[1] >= total
    print(
        f"restart test: {counts[0]}/{total} unique, {counts[1]} rows, "
        f"{len(errors)} transient send errors observed: {sorted(set(errors))[:3]}"
    )

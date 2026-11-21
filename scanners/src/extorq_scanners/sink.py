"""Where scan records go: A's collector SDK (gateway + durable outbox) or a JSONL file.

``GatewaySink`` reuses the collector SDK unchanged: records are validated with
``extorq_collectors.sdk.base.to_record_json`` and committed to a durable SQLite
outbox (``extorq_collectors.sdk.state.StateStore``, WAL, synchronous=FULL);
``extorq_collectors.sdk.sender.Sender`` delivers them in outbox order through
``GatewayClient`` (TLS pinned to the ExtorQ CA, producer token read from a file,
bounded jittered backoff, 403 bisection, dead letters). Records that cannot be
delivered before the drain deadline stay buffered and are sent by the next run.

Ordering contract (relied upon by the lifecycle view): for every scan the
``running`` ScanRun is submitted first, then all findings, and the terminal
ScanRun **last**, so a terminal ``succeeded`` record can never reach storage
before the observations it vouches for (when the transport preserves order).
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from extorq.contracts.ingest import CollectorHealthRecord, FindingRecord, ScanRunRecord

ScannerRecord = ScanRunRecord | FindingRecord | CollectorHealthRecord


@dataclass
class SinkReport:
    submitted: int = 0
    delivered: int = 0
    buffered: int = 0
    errors: list[str] = field(default_factory=list)


class RecordSink(Protocol):
    def submit(self, records: Sequence[ScannerRecord]) -> None:
        """Durably accept records in order (raise on failure)."""

    def flush(self, timeout_seconds: float) -> SinkReport:
        """Try to deliver what is buffered (bounded by ``timeout_seconds``)."""

    def close(self, timeout_seconds: float = 120.0) -> SinkReport:
        """Flush what can be flushed and report delivery state."""


class JsonlSink:
    """Writes one ``{"kind": ..., "data": ...}`` JSON object per line (0600 file)."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self._fh = os.fdopen(fd, "a", encoding="utf-8")
        self.report = SinkReport()

    def submit(self, records: Sequence[ScannerRecord]) -> None:
        for record in records:
            self._fh.write(json.dumps(record.model_dump(mode="json"), sort_keys=True) + "\n")
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self.report.submitted += len(records)

    def flush(self, timeout_seconds: float) -> SinkReport:
        return self.report

    def close(self, timeout_seconds: float = 0.0) -> SinkReport:
        self._fh.close()
        self.report.delivered = self.report.submitted
        return self.report


class MemorySink:
    """In-memory sink (tests and dry runs)."""

    def __init__(self) -> None:
        self.records: list[ScannerRecord] = []
        self.report = SinkReport()

    def submit(self, records: Sequence[ScannerRecord]) -> None:
        self.records.extend(records)
        self.report.submitted += len(records)

    def flush(self, timeout_seconds: float) -> SinkReport:
        return self.report

    def close(self, timeout_seconds: float = 0.0) -> SinkReport:
        return self.report


class GatewaySink:
    """A's collector SDK outbox + sender (see module docstring)."""

    def __init__(
        self,
        *,
        state_path: Path,
        producer_id: str,
        base_url: str = "https://127.0.0.1:8443",
        token_file: Path | None = None,
        ca_file: Path | None = None,
        timeout_seconds: float = 30.0,
        client: Any = None,
    ) -> None:
        """``client`` (tests) replaces the HTTPS GatewayClient built from the token file."""
        from extorq.common.config import read_secret_file
        from extorq_collectors.sdk.client import GatewayClient
        from extorq_collectors.sdk.sender import Sender
        from extorq_collectors.sdk.state import StateStore

        if client is None:
            if token_file is None or ca_file is None:
                raise ValueError("token_file and ca_file are required without a client")
            token = read_secret_file(token_file)  # never logged; errors name the file only
            client = GatewayClient(base_url, token, ca_file, timeout=timeout_seconds)
        self.client = client
        self.store = StateStore(state_path)
        self.sender = Sender(self.store, self.client, producer_id)
        self.report = SinkReport()

    def submit(self, records: Sequence[ScannerRecord]) -> None:
        from extorq_collectors.sdk.base import to_record_json

        prepared = [to_record_json(record) for record in records]  # validate all first
        self.store.commit(prepared)
        self.report.submitted += len(prepared)

    def flush(self, timeout_seconds: float) -> SinkReport:
        """Deliver buffered records until drained or the deadline passes (backoff honoured)."""
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        while True:
            result = self.sender.send_pending(deadline=deadline)
            self.report.delivered += result.accepted + result.duplicates
            if result.dead_lettered:
                self.report.errors.append(f"{result.dead_lettered} records dead-lettered")
            if result.drained or time.monotonic() >= deadline:
                break
            if result.error:
                self.report.errors.append(result.error)
            wait = self.sender.state.next_attempt_at - time.monotonic()
            if wait > 0:
                time.sleep(min(wait, max(0.0, deadline - time.monotonic()), 30.0))
        self.report.buffered = self.store.outbox_depth()
        self.report.errors = self.report.errors[-10:]
        return self.report

    def dead_letters(self) -> int:
        return self.store.dead_count()

    def close(self, timeout_seconds: float = 120.0) -> SinkReport:
        try:
            self.flush(timeout_seconds)
        finally:
            self.client.close()
            self.store.close()
        return self.report

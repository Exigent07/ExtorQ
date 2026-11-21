"""Where scan records go: A's collector SDK (gateway + durable outbox) or a JSONL file.

Ordering contract (relied upon by the lifecycle view): for every scan the
``running`` ScanRun is submitted first, then all findings, and the terminal
ScanRun **last**, so a terminal ``succeeded`` record can never reach storage
before the observations it vouches for (when the transport preserves order).
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

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

    def close(self) -> SinkReport:
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

    def close(self) -> SinkReport:
        self._fh.close()
        self.report.buffered = self.report.submitted
        return self.report


class MemorySink:
    """In-memory sink (tests and dry runs)."""

    def __init__(self) -> None:
        self.records: list[ScannerRecord] = []
        self.report = SinkReport()

    def submit(self, records: Sequence[ScannerRecord]) -> None:
        self.records.extend(records)
        self.report.submitted += len(records)

    def close(self) -> SinkReport:
        return self.report

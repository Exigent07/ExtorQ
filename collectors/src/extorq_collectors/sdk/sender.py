"""Outbox sender: deliver buffered records to the gateway, at least once.

Rules:

* Batches hold at most 500 records and ~3.5 MB of JSON (the gateway limit is
  4 MiB after decompression), gzip on the wire.
* A batch keeps its ``batch_id`` across retries; rows are deleted from the
  outbox only after a 202 (a replayed 202 counts as delivered).
* Retryable failures (timeouts, 5xx, 429, 503) back off exponentially with
  jitter, honouring ``Retry-After``; nothing is dropped.
* 401 keeps everything buffered (token problem) with a long backoff.
* 403 (unauthorized records) bisects the batch so authorized records still
  flow; a single unauthorized record moves to ``outbox_dead``. 413 splits the
  batch. 409 (batch id clash) re-issues ids. 400/415/422 move the batch to
  ``outbox_dead`` (the SDK validated the records, so this is a bug to inspect).
"""

from __future__ import annotations

import json
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts.common import utc_now
from extorq.contracts.ingest import IngestBatch
from extorq_collectors.sdk.client import AuthError, GatewayClient, RejectedError, RetryableError
from extorq_collectors.sdk.state import StateStore

MAX_BATCH_RECORDS = 500
MAX_BATCH_BYTES = 3_500_000
BACKOFF_INITIAL = 1.0
BACKOFF_MAX = 60.0
AUTH_BACKOFF = 60.0


def sanitize(text: str, limit: int = 1024) -> str:
    return sanitize_untrusted(redact_text(text)[0], limit)


@dataclass
class SendReport:
    batches: int = 0
    accepted: int = 0
    duplicates: int = 0
    quarantined: int = 0
    replayed: int = 0
    dead_lettered: int = 0
    error: str | None = None
    drained: bool = False


@dataclass
class SenderState:
    consecutive_failures: int = 0
    next_attempt_at: float = 0.0
    last_success_at: float | None = None
    last_error: str | None = None
    totals: dict[str, int] = field(default_factory=lambda: {
        "accepted": 0, "duplicates": 0, "quarantined": 0, "dead_lettered": 0})


class Sender:
    def __init__(
        self,
        store: StateStore,
        client: GatewayClient,
        producer_id: str,
        *,
        max_records: int = MAX_BATCH_RECORDS,
        max_bytes: int = MAX_BATCH_BYTES,
        clock: Callable[[], float] = time.monotonic,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.store = store
        self.client = client
        self.producer_id = producer_id
        self.max_records = max(1, min(max_records, MAX_BATCH_RECORDS))
        self.max_bytes = max_bytes
        self.clock = clock
        self.rng = rng
        self.state = SenderState()

    def backoff(self, retry_after: float | None = None) -> float:
        failures = max(1, self.state.consecutive_failures)
        delay = min(BACKOFF_MAX, BACKOFF_INITIAL * (2 ** (failures - 1)))
        delay = delay * (0.5 + 0.5 * self.rng())
        if retry_after is not None:
            delay = max(delay, retry_after)
        return delay

    def ready(self) -> bool:
        return self.clock() >= self.state.next_attempt_at

    def send_pending(self, *, deadline: float | None = None, max_batches: int | None = None
                     ) -> SendReport:
        """Send batches until the outbox is empty, an error occurs or the deadline passes."""
        report = SendReport()
        if not self.ready():
            report.error = self.state.last_error
            return report
        while True:
            if deadline is not None and self.clock() >= deadline:
                break
            if max_batches is not None and report.batches >= max_batches:
                break
            claimed = self.store.next_batch(self.max_records, self.max_bytes)
            if claimed is None:
                report.drained = True
                break
            batch_id, rows = claimed
            batch = IngestBatch(
                batch_id=batch_id,
                producer_id=self.producer_id,
                sent_at=utc_now(),
                records=[json.loads(row.record) for row in rows],
            )
            report.batches += 1
            try:
                result = self.client.send(batch)
            except RetryableError as exc:
                self._fail(str(exc), exc.retry_after)
                report.error = self.state.last_error
                break
            except AuthError as exc:
                self._fail(str(exc), AUTH_BACKOFF)
                report.error = self.state.last_error
                break
            except RejectedError as exc:
                self._handle_rejection(batch_id, len(rows), exc, report)
                continue
            self.store.ack(batch_id)
            report.accepted += result.accepted
            report.duplicates += result.duplicates
            report.quarantined += len(result.quarantined)
            report.replayed += 1 if result.replayed else 0
            self.state.consecutive_failures = 0
            self.state.next_attempt_at = 0.0
            self.state.last_success_at = time.time()
            self.state.last_error = None
            self.state.totals["accepted"] += result.accepted
            self.state.totals["duplicates"] += result.duplicates
            self.state.totals["quarantined"] += len(result.quarantined)
        return report

    def _fail(self, error: str, retry_after: float | None) -> None:
        self.state.consecutive_failures += 1
        self.state.last_error = sanitize(error)
        self.state.next_attempt_at = self.clock() + self.backoff(retry_after)

    def _handle_rejection(self, batch_id: str, size: int, exc: RejectedError,
                          report: SendReport) -> None:
        status = exc.status_code
        if status == 403 and size > 1:
            self.store.reassign(batch_id, split=True)
            return
        if status == 413 and size > 1:
            self.store.reassign(batch_id, split=True)
            return
        if status == 409:
            self.store.reassign(batch_id, split=False)
            return
        moved = self.store.dead_letter(batch_id, status, sanitize(str(exc)))
        report.dead_lettered += moved
        self.state.totals["dead_lettered"] += moved
        self.state.last_error = sanitize(str(exc))

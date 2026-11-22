"""``extorq writer``: drain the SQLite spool into ClickHouse (identity ``extorq_ingest``).

Guarantees (docs/data-flow.md):

* **At-least-once** into ClickHouse. A record is deleted from the spool only
  after ClickHouse acknowledged the INSERT containing it. A crash between the
  acknowledgement and the delete re-sends the record; deterministic identities
  plus ReplacingMergeTree and duplicate-safe queries collapse the duplicate.
  ExtorQ does **not** claim exactly-once delivery.
* **No loss while ClickHouse is unavailable**: transient errors (connection
  refused, timeouts, memory/parts pressure, auth/config errors) never consume
  attempts. The writer backs off exponentially with jitter (bounded per
  attempt by the client timeout) and keeps everything in the spool.
* **Poison records are isolated**: a data error makes the writer bisect the
  batch; only the records that fail on their own consume attempts and, after
  ``EXTORQ_WRITER_MAX_ATTEMPTS``, move to the spool's ``dead_letter`` table with
  a sanitised error. Dead letters are counted in PipelineHealth.
* Records are inserted grouped by target table, in spool order per fetch.
"""

from __future__ import annotations

import json
import random
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from types import FrameType
from typing import Any

from pydantic import ValidationError

from extorq.common.config import Settings, get_settings
from extorq.common.logging import get_logger
from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts.common import HealthStatus, utc_now
from extorq.contracts.health import PipelineHealth
from extorq.contracts.identity import canonical_json, iso_utc, stable_id
from extorq.contracts.ingest import INGEST_RECORD_ADAPTER, RecordKind
from extorq.ingest.event_identity import stored_event
from extorq.pipeline.spool import NewRecord, Spool, SpoolRow, SpoolUnavailable
from extorq.storage.clickhouse import is_transient_error
from extorq.storage.rows import (
    AUDIT_TABLE,
    PIPELINE_HEALTH_TABLE,
    QUARANTINE_TABLE,
    TABLE_BY_KIND,
    RowError,
    audit_row,
    pipeline_health_to_row,
    quarantine_row,
    to_row,
)

log = get_logger("extorq.writer")

_KINDS = {k.value for k in RecordKind}
FAILED_AFTER_SECONDS = 120.0


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise RowError("naive timestamp in spool row")
    return parsed.astimezone(UTC)


def decode_row(row: SpoolRow) -> tuple[str, dict[str, Any]]:
    """Convert a spool row into ``(table, clickhouse_row)``; raises on permanent errors."""
    if row.kind in _KINDS:
        payload = json.loads(row.payload)
        if row.kind == "event" and isinstance(payload, dict) and payload.get("kind") == "event":
            data = payload.get("data")
            if isinstance(data, dict) and data.get("schema_version") in {"1.0", "1.1"}:
                event = stored_event(data)
                if event is None or event.event_id != row.record_key:
                    raise RowError("historical event cannot be converted without changing evidence")
                payload["data"] = event
        record = INGEST_RECORD_ADAPTER.validate_python(payload)
        if record.kind != row.kind:
            raise RowError(f"spool kind {row.kind} does not match payload kind {record.kind}")
        if record.kind == "event" and record.data.event_id != row.record_key:
            raise RowError("spool event key does not match its payload identity")
        return TABLE_BY_KIND[RecordKind(row.kind)], to_row(
            row.kind,
            record.data,
            producer_id=row.producer_id,
            batch_id=row.batch_id,
            ingested_at=_parse_time(row.ingested_at),
        )
    if row.kind == "pipeline_health":
        return PIPELINE_HEALTH_TABLE, pipeline_health_to_row(
            PipelineHealth.model_validate_json(row.payload)
        )
    if row.kind == "quarantine":
        data = json.loads(row.payload)
        data["received_at"] = _parse_time(data["received_at"])
        return QUARANTINE_TABLE, quarantine_row(**data)
    if row.kind == "ingest_audit":
        data = json.loads(row.payload)
        data["occurred_at"] = _parse_time(data["occurred_at"])
        return AUDIT_TABLE, audit_row(**data)
    raise RowError(f"unknown spool kind {row.kind!r}")


def sanitize_error(exc: BaseException, limit: int = 1024) -> str:
    text = f"{type(exc).__name__}: {exc}"
    return sanitize_untrusted(redact_text(text)[0], limit)


@dataclass
class WriterStats:
    consecutive_failures: int = 0
    failing_since: float | None = None
    last_error: str | None = None
    last_write_at: datetime | None = None
    batches_written: int = 0
    dead_lettered_session: int = 0
    _last_health: float = field(default=0.0)
    _last_heartbeat: float = field(default=0.0)


class Writer:
    def __init__(
        self,
        settings: Settings,
        spool: Spool,
        client_factory: Callable[[], Any],
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        rng: Callable[[], float] = random.random,
    ) -> None:
        self.settings = settings
        self.spool = spool
        self.client_factory = client_factory
        self.sleep = sleep
        self.clock = clock
        self.rng = rng
        self.stats = WriterStats()
        self._client: Any | None = None
        self.stop_event = threading.Event()
        self.heartbeat_path: Path = settings.resolve(settings.writer_heartbeat_file)

    # ── ClickHouse plumbing ───────────────────────────────────────────

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = self.client_factory()
        return self._client

    def _drop_client(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001 - best effort on a broken connection
                log.debug("client_close_failed")

    def _insert(self, table: str, rows: list[dict[str, Any]]) -> None:
        columns = list(rows[0].keys())
        data = [[row[column] for column in columns] for row in rows]
        self._get_client().insert(
            table, data, column_names=columns, database=self.settings.clickhouse_database
        )

    def backoff_seconds(self) -> float:
        failures = max(1, self.stats.consecutive_failures)
        ceiling = min(
            self.settings.writer_backoff_max_seconds,
            self.settings.writer_backoff_initial_seconds * (2 ** (failures - 1)),
        )
        return ceiling * (0.5 + 0.5 * self.rng())  # "equal jitter"

    # ── batch processing ──────────────────────────────────────────────

    def _insert_isolating(
        self, table: str, items: list[tuple[SpoolRow, dict[str, Any]]]
    ) -> tuple[list[SpoolRow], list[tuple[SpoolRow, str]], BaseException | None]:
        """Insert ``items``; bisect on data errors. Returns (written, poisoned, transient_exc)."""
        try:
            self._insert(table, [row for _, row in items])
            return [spool_row for spool_row, _ in items], [], None
        except Exception as exc:  # noqa: BLE001 - classified right here
            if is_transient_error(exc):
                return [], [], exc
            if len(items) == 1:
                return [], [(items[0][0], sanitize_error(exc))], None
            middle = len(items) // 2
            written, poisoned, transient = self._insert_isolating(table, items[:middle])
            if transient is not None:
                return written, poisoned, transient
            written_r, poisoned_r, transient_r = self._insert_isolating(table, items[middle:])
            return written + written_r, poisoned + poisoned_r, transient_r

    def process_once(self) -> int:
        """Deliver one fetch of ready records. Returns the number of records written."""
        rows = self.spool.fetch_ready(self.settings.writer_batch_size, now=self.clock())
        if not rows:
            return 0
        groups: dict[str, list[tuple[SpoolRow, dict[str, Any]]]] = {}
        poisoned: list[tuple[SpoolRow, str]] = []
        for row in rows:
            try:
                table, ch_row = decode_row(row)
            except (RowError, ValidationError, ValueError, KeyError, TypeError) as exc:
                poisoned.append((row, sanitize_error(exc)))
                continue
            groups.setdefault(table, []).append((row, ch_row))
        written_total = 0
        transient: BaseException | None = None
        for table, items in groups.items():
            written, bad, transient = self._insert_isolating(table, items)
            if written:
                now_ms = int(self.clock() * 1000)
                self.spool.delete([r.seq for r in written], last_write_ms=now_ms)
                written_total += len(written)
                self.stats.last_write_at = utc_now()
            poisoned.extend(bad)
            if transient is not None:
                break
        if poisoned:
            self._handle_poisoned(poisoned)
        if transient is not None:
            self._on_transient(transient)
        elif written_total or not poisoned:
            self._on_success(written_total)
        return written_total

    def _handle_poisoned(self, poisoned: list[tuple[SpoolRow, str]]) -> None:
        retry_at = self.clock() + self.settings.writer_backoff_max_seconds
        by_error: dict[str, list[SpoolRow]] = {}
        for row, error in poisoned:
            by_error.setdefault(error, []).append(row)
        for error, rows in by_error.items():
            moved = self.spool.fail(rows, retry_at, error, self.settings.writer_max_attempts)
            self.stats.dead_lettered_session += moved
            log.error(
                "records_failed_permanently",
                count=len(rows),
                dead_lettered=moved,
                kinds=sorted({r.kind for r in rows}),
                error=error,
            )

    def _on_transient(self, exc: BaseException) -> None:
        self.stats.consecutive_failures += 1
        if self.stats.failing_since is None:
            self.stats.failing_since = self.clock()
        self.stats.last_error = sanitize_error(exc, 512)
        self._drop_client()
        try:
            self.spool.incr({"write_errors_total": 1})
        except SpoolUnavailable:
            log.error("counter_write_failed")
        delay = self.backoff_seconds()
        log.warning(
            "clickhouse_unavailable",
            consecutive_failures=self.stats.consecutive_failures,
            retry_in_seconds=round(delay, 2),
            error=self.stats.last_error,
        )
        self._interruptible_sleep(delay)

    def _on_success(self, written: int) -> None:
        if self.stats.consecutive_failures:
            log.info("clickhouse_recovered", after_failures=self.stats.consecutive_failures)
        self.stats.consecutive_failures = 0
        self.stats.failing_since = None
        if written:
            self.stats.batches_written += 1

    # ── health / heartbeat ────────────────────────────────────────────

    def status(self) -> HealthStatus:
        if self.stats.failing_since is not None:
            outage = self.clock() - self.stats.failing_since
            return HealthStatus.FAILED if outage >= FAILED_AFTER_SECONDS else HealthStatus.DEGRADED
        if self.stats.dead_lettered_session:
            return HealthStatus.DEGRADED
        return HealthStatus.OK

    def health(self) -> PipelineHealth:
        counters = self.spool.counters()
        last_write_ms = counters.get("last_write_ms")
        last_write = datetime.fromtimestamp(last_write_ms / 1000, tz=UTC) if last_write_ms else None
        return PipelineHealth(
            component="writer",
            instance=self.settings.instance_name[:256],
            reported_at=utc_now(),
            status=self.status(),
            queue_depth=self.spool.depth(max_age_seconds=0),
            oldest_queued_age_seconds=self.spool.oldest_age_seconds(),
            written_total=counters.get("written_total", 0),
            write_errors_total=counters.get("write_errors_total", 0),
            dead_letter_total=counters.get("dead_letter_total", 0),
            last_write_at=last_write,
            details={
                "consecutive_failures": self.stats.consecutive_failures,
                "last_error": self.stats.last_error,
                "dead_letter_rows": self.spool.dead_letter_count(),
                "batch_size": self.settings.writer_batch_size,
                "max_attempts": self.settings.writer_max_attempts,
            },
        )

    def emit_health(self) -> None:
        health = self.health()
        key = stable_id("health.v1", "writer", health.instance, iso_utc(health.reported_at))
        self.spool.append(
            [
                NewRecord(
                    kind="pipeline_health",
                    record_key=key,
                    payload=canonical_json(health),
                    dedup=False,
                )
            ],
            producer_id="writer",
            batch_id="health",
            ingested_at=iso_utc(utc_now()),
        )
        log.info(
            "writer_health",
            status=health.status.value,
            queue_depth=health.queue_depth,
            written_total=health.written_total,
            dead_letter_total=health.dead_letter_total,
        )

    def _maybe_periodic(self) -> None:
        now = time.monotonic()
        if now - self.stats._last_heartbeat >= 5:
            self.stats._last_heartbeat = now
            try:
                self.heartbeat_path.parent.mkdir(parents=True, exist_ok=True)
                self.heartbeat_path.write_text(f"{time.time():.0f}\n", encoding="utf-8")
            except OSError:
                log.warning("heartbeat_write_failed")
        if now - self.stats._last_health >= self.settings.health_interval_seconds:
            self.stats._last_health = now
            try:
                self.emit_health()
            except Exception as exc:  # noqa: BLE001 - health must never stop delivery
                log.error("writer_health_failed", error_type=type(exc).__name__)

    def _interruptible_sleep(self, seconds: float) -> None:
        if self.sleep is time.sleep:
            self.stop_event.wait(seconds)
        else:
            self.sleep(seconds)

    def run(self) -> None:
        log.info(
            "writer_started",
            batch_size=self.settings.writer_batch_size,
            max_attempts=self.settings.writer_max_attempts,
        )
        while not self.stop_event.is_set():
            self._maybe_periodic()
            try:
                written = self.process_once()
            except SpoolUnavailable as exc:
                log.error("spool_unavailable", error=sanitize_error(exc, 256))
                self._interruptible_sleep(1.0)
                continue
            if written == 0 and self.stats.consecutive_failures == 0:
                self._interruptible_sleep(self.settings.writer_poll_interval_seconds)
        self._drop_client()
        log.info("writer_stopped")


def main() -> int:
    from extorq.common.config import check_startup
    from extorq.common.logging import configure_logging
    from extorq.storage.clickhouse import get_client

    configure_logging("writer")
    settings = get_settings()
    if check_startup("writer", settings, clickhouse_roles=("ingest",)):
        return 2
    spool = Spool(
        settings.resolve(settings.spool_path), busy_timeout_ms=settings.spool_busy_timeout_ms
    )
    writer = Writer(settings, spool, lambda: get_client("ingest", settings=settings))

    def _stop(signum: int, _frame: FrameType | None) -> None:
        log.info("writer_stop_requested", signal=signum)
        writer.stop_event.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        writer.run()
    finally:
        spool.close()
    return 0


def healthcheck(max_age_seconds: float = 60.0) -> int:
    """Container healthcheck: the writer loop refreshed its heartbeat recently."""
    settings = get_settings()
    path = settings.resolve(settings.writer_heartbeat_file)
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return 1
    return 0 if age <= max_age_seconds else 1

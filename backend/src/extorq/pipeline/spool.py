"""Durable SQLite spool between the ingest gateway and the ClickHouse writer.

Durability contract (docs/data-flow.md):

* WAL journal + ``synchronous=FULL``: a committed transaction survives process
  crash and power loss of the container host (fsync of the WAL on commit).
* The gateway commits accepted records, quarantine rows, its dedup index entries
  and the batch idempotency result in ONE transaction before answering 202.
* The writer deletes records only after ClickHouse acknowledged the insert.
  Transient failures defer records without consuming attempts; permanent
  failures consume attempts and finally move records to ``dead_letter``.

Both processes open the same file (shared Docker volume); every access is a
short transaction (never held across network I/O) with ``busy_timeout``.
Internally each :class:`Spool` serialises access to its connection with a lock,
so one instance may be shared by threads.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

#: Spool kinds besides the seven ingest RecordKinds.
INTERNAL_KINDS = ("pipeline_health", "quarantine", "ingest_audit")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT    NOT NULL,
    record_key      TEXT    NOT NULL,
    producer_id     TEXT    NOT NULL,
    batch_id        TEXT    NOT NULL,
    ingested_at     TEXT    NOT NULL,
    enqueued_at     REAL    NOT NULL,
    payload         TEXT    NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL    NOT NULL DEFAULT 0,
    last_error      TEXT
);
CREATE INDEX IF NOT EXISTS records_ready ON records (next_attempt_at, seq);
CREATE TABLE IF NOT EXISTS batches (
    producer_id     TEXT NOT NULL,
    batch_id        TEXT NOT NULL,
    content_sha256  TEXT NOT NULL,
    received_ts     REAL NOT NULL,
    result          TEXT NOT NULL,
    PRIMARY KEY (producer_id, batch_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS batches_received ON batches (received_ts);
CREATE TABLE IF NOT EXISTS dedup (
    kind        TEXT NOT NULL,
    record_key  TEXT NOT NULL,
    first_seen  REAL NOT NULL,
    PRIMARY KEY (kind, record_key)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS dedup_first_seen ON dedup (first_seen);
CREATE TABLE IF NOT EXISTS dead_letter (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    seq          INTEGER NOT NULL,
    kind         TEXT    NOT NULL,
    record_key   TEXT    NOT NULL,
    producer_id  TEXT    NOT NULL,
    batch_id     TEXT    NOT NULL,
    ingested_at  TEXT    NOT NULL,
    payload      TEXT    NOT NULL,
    attempts     INTEGER NOT NULL,
    error        TEXT    NOT NULL,
    failed_ts    REAL    NOT NULL
);
CREATE TABLE IF NOT EXISTS counters (
    name   TEXT PRIMARY KEY,
    value  INTEGER NOT NULL
) WITHOUT ROWID;
"""


@dataclass(frozen=True)
class NewRecord:
    """A record to enqueue (payload is canonical JSON text)."""

    kind: str
    record_key: str
    payload: str
    dedup: bool = True


@dataclass(frozen=True)
class SpoolRow:
    seq: int
    kind: str
    record_key: str
    producer_id: str
    batch_id: str
    ingested_at: str
    enqueued_at: float
    payload: str
    attempts: int


@dataclass(frozen=True)
class CommitOutcome:
    replayed: bool
    result: dict[str, Any]
    conflict: bool = False


class SpoolUnavailable(RuntimeError):
    """The spool cannot accept writes (disk full, I/O error, locked too long)."""


class Spool:
    def __init__(self, path: Path, *, busy_timeout_ms: int = 10_000) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path),
            timeout=busy_timeout_ms / 1000,
            isolation_level=None,  # explicit BEGIN/COMMIT only
            check_same_thread=False,
        )
        self._conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        mode = self._conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise SpoolUnavailable(f"could not enable WAL journal mode (got {mode})")
        self._conn.execute("PRAGMA synchronous = FULL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA temp_store = MEMORY")
        with self._tx():
            for statement in filter(None, (s.strip() for s in _SCHEMA.split(";"))):
                self._conn.execute(statement)
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._depth_cache: tuple[float, int] = (0.0, 0)

    # ── plumbing ──────────────────────────────────────────────────────

    @contextmanager
    def _tx(self, immediate: bool = True) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            except sqlite3.OperationalError as exc:
                raise SpoolUnavailable(f"spool busy: {exc}") from exc
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                try:
                    self._conn.execute("COMMIT")
                except sqlite3.OperationalError as exc:
                    self._conn.execute("ROLLBACK")
                    raise SpoolUnavailable(f"spool commit failed: {exc}") from exc

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def pragma(self, name: str) -> Any:
        if not name.isidentifier():
            raise ValueError("invalid pragma name")
        with self._lock:
            return self._conn.execute(f"PRAGMA {name}").fetchone()[0]

    @staticmethod
    def _incr(conn: sqlite3.Connection, name: str, amount: int) -> None:
        if amount:
            conn.execute(
                "INSERT INTO counters(name, value) VALUES (?, ?) "
                "ON CONFLICT(name) DO UPDATE SET value = value + excluded.value",
                (name, amount),
            )

    @staticmethod
    def _set_counter(conn: sqlite3.Connection, name: str, value: int) -> None:
        conn.execute(
            "INSERT INTO counters(name, value) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            (name, value),
        )

    # ── gateway side ──────────────────────────────────────────────────

    def lookup_batch(self, producer_id: str, batch_id: str) -> tuple[str, dict[str, Any]] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT content_sha256, result FROM batches WHERE producer_id = ? AND batch_id = ?",
                (producer_id, batch_id),
            ).fetchone()
        if row is None:
            return None
        return str(row[0]), json.loads(row[1])

    def commit_batch(
        self,
        *,
        producer_id: str,
        batch_id: str,
        content_sha256: str,
        ingested_at: str,
        records: Sequence[NewRecord],
        extra: Sequence[NewRecord],
        build_result: Callable[[int, int], dict[str, Any]],
        counters: dict[str, int] | None = None,
    ) -> CommitOutcome:
        """Atomically enqueue a batch. ``build_result(accepted, duplicates)`` makes the result.

        ``records`` are deduplicated by (kind, record_key); ``extra`` rows
        (quarantine, audit) are always enqueued. A previously committed
        ``(producer_id, batch_id)`` returns the stored result with ``replayed``.
        """
        now = time.time()
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT content_sha256, result FROM batches WHERE producer_id = ? AND batch_id = ?",
                (producer_id, batch_id),
            ).fetchone()
            if existing is not None:
                if existing[0] != content_sha256:
                    return CommitOutcome(replayed=True, result=json.loads(existing[1]),
                                         conflict=True)
                self._incr(conn, "replayed_batches_total", 1)
                return CommitOutcome(replayed=True, result=json.loads(existing[1]))
            accepted = duplicates = 0
            for rec in records:
                if rec.dedup:
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO dedup(kind, record_key, first_seen) VALUES (?, ?, ?)",
                        (rec.kind, rec.record_key, now),
                    )
                    if cur.rowcount == 0:
                        duplicates += 1
                        continue
                self._insert_record(conn, rec, producer_id, batch_id, ingested_at, now)
                accepted += 1
            for rec in extra:
                self._insert_record(conn, rec, producer_id, batch_id, ingested_at, now)
            result = build_result(accepted, duplicates)
            conn.execute(
                "INSERT INTO batches(producer_id, batch_id, content_sha256, received_ts, result) "
                "VALUES (?, ?, ?, ?, ?)",
                (producer_id, batch_id, content_sha256, now,
                 json.dumps(result, sort_keys=True, separators=(",", ":"))),
            )
            self._incr(conn, "accepted_total", accepted)
            self._incr(conn, "duplicate_total", duplicates)
            for name, amount in (counters or {}).items():
                self._incr(conn, name, amount)
        self._depth_cache = (0.0, 0)
        return CommitOutcome(replayed=False, result=result)

    @staticmethod
    def _insert_record(
        conn: sqlite3.Connection, rec: NewRecord, producer_id: str, batch_id: str,
        ingested_at: str, now: float,
    ) -> None:
        conn.execute(
            "INSERT INTO records(kind, record_key, producer_id, batch_id, ingested_at, "
            "enqueued_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rec.kind, rec.record_key, producer_id, batch_id, ingested_at, now, rec.payload),
        )

    def append(
        self,
        records: Iterable[NewRecord],
        *,
        producer_id: str,
        batch_id: str,
        ingested_at: str,
        counters: dict[str, int] | None = None,
    ) -> int:
        """Enqueue internal rows (audit, health) without dedup or batch bookkeeping."""
        now = time.time()
        count = 0
        with self._tx() as conn:
            for rec in records:
                self._insert_record(conn, rec, producer_id, batch_id, ingested_at, now)
                count += 1
            for name, amount in (counters or {}).items():
                self._incr(conn, name, amount)
        self._depth_cache = (0.0, 0)
        return count

    def incr(self, counters: dict[str, int]) -> None:
        with self._tx() as conn:
            for name, amount in counters.items():
                self._incr(conn, name, amount)

    # ── observability ─────────────────────────────────────────────────

    def depth(self, max_age_seconds: float = 1.0) -> int:
        """Number of queued records (cached for ``max_age_seconds``)."""
        cached_at, value = self._depth_cache
        if time.monotonic() - cached_at <= max_age_seconds and cached_at:
            return value
        with self._lock:
            value = int(self._conn.execute("SELECT count(*) FROM records").fetchone()[0])
        self._depth_cache = (time.monotonic(), value)
        return value

    def oldest_age_seconds(self) -> float | None:
        with self._lock:
            row = self._conn.execute("SELECT min(enqueued_at) FROM records").fetchone()
        if row is None or row[0] is None:
            return None
        return max(0.0, time.time() - float(row[0]))

    def counters(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute("SELECT name, value FROM counters").fetchall()
        return {str(name): int(value) for name, value in rows}

    def dead_letter_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT count(*) FROM dead_letter").fetchone()[0])

    def free_bytes(self) -> int:
        return shutil.disk_usage(self.path.parent).free

    def healthy(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    # ── writer side ───────────────────────────────────────────────────

    def fetch_ready(self, limit: int, now: float | None = None,
                    max_bytes: int = 16 * 1024 * 1024) -> list[SpoolRow]:
        """Oldest ready records: at most ``limit`` rows and ~``max_bytes`` of payload."""
        now = time.time() if now is None else now
        rows: list[SpoolRow] = []
        budget = 0
        with self._lock:
            cursor = self._conn.execute(
                "SELECT seq, kind, record_key, producer_id, batch_id, ingested_at, enqueued_at, "
                "payload, attempts FROM records WHERE next_attempt_at <= ? ORDER BY seq LIMIT ?",
                (now, int(limit)),
            )
            for raw in cursor:
                row = SpoolRow(*raw)
                budget += len(row.payload)
                if rows and budget > max_bytes:
                    break
                rows.append(row)
            cursor.close()
        return rows

    def next_ready_at(self) -> float | None:
        with self._lock:
            row = self._conn.execute("SELECT min(next_attempt_at) FROM records").fetchone()
        return None if row is None or row[0] is None else float(row[0])

    def delete(self, seqs: Sequence[int], *, written: int | None = None,
               last_write_ms: int | None = None) -> None:
        """Delete delivered records (call only after ClickHouse acknowledged them)."""
        if not seqs:
            return
        with self._tx() as conn:
            conn.executemany("DELETE FROM records WHERE seq = ?", [(s,) for s in seqs])
            self._incr(conn, "written_total", len(seqs) if written is None else written)
            if last_write_ms is not None:
                self._set_counter(conn, "last_write_ms", last_write_ms)
        self._depth_cache = (0.0, 0)

    def defer(self, seqs: Sequence[int], next_attempt_at: float, error: str) -> None:
        """Transient failure: retry later without consuming an attempt."""
        if not seqs:
            return
        with self._tx() as conn:
            conn.executemany(
                "UPDATE records SET next_attempt_at = ?, last_error = ? WHERE seq = ?",
                [(next_attempt_at, error, s) for s in seqs],
            )
            self._incr(conn, "write_errors_total", 1)

    def fail(self, rows: Sequence[SpoolRow], next_attempt_at: float, error: str,
             max_attempts: int) -> int:
        """Permanent-looking failure: consume an attempt; dead-letter when exhausted.

        Returns the number of records moved to the dead-letter table.
        """
        if not rows:
            return 0
        moved = 0
        now = time.time()
        with self._tx() as conn:
            for row in rows:
                attempts = row.attempts + 1
                if attempts >= max_attempts:
                    conn.execute(
                        "INSERT INTO dead_letter(seq, kind, record_key, producer_id, batch_id, "
                        "ingested_at, payload, attempts, error, failed_ts) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (row.seq, row.kind, row.record_key, row.producer_id, row.batch_id,
                         row.ingested_at, row.payload, attempts, error, now),
                    )
                    conn.execute("DELETE FROM records WHERE seq = ?", (row.seq,))
                    moved += 1
                else:
                    conn.execute(
                        "UPDATE records SET attempts = ?, next_attempt_at = ?, last_error = ? "
                        "WHERE seq = ?",
                        (attempts, next_attempt_at, error, row.seq),
                    )
            self._incr(conn, "write_errors_total", 1)
            self._incr(conn, "dead_letter_total", moved)
        self._depth_cache = (0.0, 0)
        return moved

    # ── maintenance ───────────────────────────────────────────────────

    def prune(self, *, dedup_older_than: float, batches_older_than: float) -> tuple[int, int]:
        with self._tx() as conn:
            d = conn.execute("DELETE FROM dedup WHERE first_seen < ?", (dedup_older_than,))
            b = conn.execute("DELETE FROM batches WHERE received_ts < ?", (batches_older_than,))
            return d.rowcount, b.rowcount

    def checkpoint(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()

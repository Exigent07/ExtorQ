"""Per-collector durable state: ``var/collectors/<collector_id>/state.db`` (SQLite, WAL).

Tables:

* ``outbox``       records waiting for a 202 from the gateway. ``batch_id`` is
                   assigned on the first send attempt and reused for every retry,
                   so a 202 lost in transit is answered with ``replayed=true``
                   instead of a duplicate batch.
* ``outbox_dead``  records the gateway permanently refused (403/422 ...), kept for
                   inspection; counted in CollectorHealth.
* ``checkpoints``  source cursors/offsets; written ONLY together with the records
                   they cover (one transaction, see :meth:`StateStore.commit`).
* ``kv``           small JSON state (asset first_seen, last health, ...).
* ``snapshots``    last observed item set per snapshot name (inventory diffs);
                   replaced in the same transaction as the emitted diff records.

Each :class:`StateStore` owns one connection guarded by a lock; the collector
thread and anything else touching the same file use separate instances.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS outbox (
        seq        INTEGER PRIMARY KEY AUTOINCREMENT,
        kind       TEXT    NOT NULL,
        record     TEXT    NOT NULL,
        size       INTEGER NOT NULL,
        created_at REAL    NOT NULL,
        batch_id   TEXT
    )""",
    "CREATE INDEX IF NOT EXISTS outbox_batch ON outbox (batch_id, seq)",
    """CREATE TABLE IF NOT EXISTS outbox_dead (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        seq         INTEGER NOT NULL,
        kind        TEXT    NOT NULL,
        record      TEXT    NOT NULL,
        batch_id    TEXT,
        status_code INTEGER,
        error       TEXT    NOT NULL,
        failed_at   REAL    NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS checkpoints (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at REAL NOT NULL
    ) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS kv (
        key        TEXT PRIMARY KEY,
        value      TEXT NOT NULL,
        updated_at REAL NOT NULL
    ) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS snapshots (
        name      TEXT NOT NULL,
        item_key  TEXT NOT NULL,
        item      TEXT NOT NULL,
        item_hash TEXT NOT NULL,
        PRIMARY KEY (name, item_key)
    ) WITHOUT ROWID""",
    """CREATE TABLE IF NOT EXISTS snapshot_names (
        name       TEXT PRIMARY KEY,
        updated_at REAL NOT NULL
    ) WITHOUT ROWID""",
)


@dataclass(frozen=True)
class OutboxRow:
    seq: int
    kind: str
    record: str
    size: int
    created_at: float
    batch_id: str | None


@dataclass(frozen=True)
class StagedSnapshot:
    """A snapshot replacement staged by ``diff_snapshot`` and applied by ``commit``."""

    name: str
    items: dict[str, tuple[str, str]]  # item_key -> (canonical item JSON, sha256)


class StateStore:
    def __init__(self, path: Path, *, busy_timeout_ms: int = 10_000) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass
        self._lock = threading.RLock()
        new_file = not path.exists()
        self._conn = sqlite3.connect(str(path), timeout=busy_timeout_ms / 1000,
                                     isolation_level=None, check_same_thread=False)
        if new_file:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        self._conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)}")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = FULL")
        with self.transaction() as conn:
            for statement in _SCHEMA:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── atomic emit ───────────────────────────────────────────────────

    def commit(
        self,
        records: Sequence[tuple[str, str]],
        checkpoints: Mapping[str, str] | None = None,
        snapshots: Sequence[StagedSnapshot] = (),
    ) -> int:
        """Insert outbox ``(kind, record_json)`` rows, checkpoints and snapshots atomically."""
        now = time.time()
        with self.transaction() as conn:
            for kind, record in records:
                conn.execute(
                    "INSERT INTO outbox(kind, record, size, created_at) VALUES (?, ?, ?, ?)",
                    (kind, record, len(record.encode("utf-8")), now),
                )
            for key, value in (checkpoints or {}).items():
                conn.execute(
                    "INSERT INTO checkpoints(key, value, updated_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                    "updated_at = excluded.updated_at",
                    (key, value, now),
                )
            for snapshot in snapshots:
                conn.execute("DELETE FROM snapshots WHERE name = ?", (snapshot.name,))
                conn.executemany(
                    "INSERT INTO snapshots(name, item_key, item, item_hash) VALUES (?, ?, ?, ?)",
                    [(snapshot.name, key, item, digest)
                     for key, (item, digest) in snapshot.items.items()],
                )
                conn.execute(
                    "INSERT INTO snapshot_names(name, updated_at) VALUES (?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at",
                    (snapshot.name, now),
                )
        return len(records)

    # ── checkpoints / kv / snapshots ──────────────────────────────────

    def checkpoint(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM checkpoints WHERE key = ?",
                                     (key,)).fetchone()
        return None if row is None else str(row[0])

    def checkpoints(self) -> dict[str, str]:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM checkpoints").fetchall()
        return {str(k): str(v) for k, v in rows}

    def kv_get(self, key: str) -> Any:
        with self._lock:
            row = self._conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return None if row is None else json.loads(row[0])

    def kv_set(self, key: str, value: Any) -> None:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO kv(key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated_at = excluded.updated_at",
                (key, encoded, time.time()),
            )

    def kv_delete(self, key: str) -> None:
        with self.transaction() as conn:
            conn.execute("DELETE FROM kv WHERE key = ?", (key,))

    def snapshot(self, name: str) -> dict[str, tuple[str, str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT item_key, item, item_hash FROM snapshots WHERE name = ?", (name,)
            ).fetchall()
        return {str(k): (str(item), str(digest)) for k, item, digest in rows}

    def has_snapshot(self, name: str) -> bool:
        with self._lock:
            row = self._conn.execute("SELECT 1 FROM snapshot_names WHERE name = ?",
                                     (name,)).fetchone()
        return row is not None

    # ── outbox (sender side) ──────────────────────────────────────────

    def outbox_depth(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT count(*) FROM outbox").fetchone()[0])

    def dead_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT count(*) FROM outbox_dead").fetchone()[0])

    def oldest_outbox_age(self) -> float | None:
        with self._lock:
            row = self._conn.execute("SELECT min(created_at) FROM outbox").fetchone()
        return None if row is None or row[0] is None else max(0.0, time.time() - float(row[0]))

    def next_batch(self, max_records: int, max_bytes: int) -> tuple[str, list[OutboxRow]] | None:
        """Return the in-flight batch (same id as before) or assign a new one."""
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT batch_id FROM outbox WHERE batch_id IS NOT NULL ORDER BY seq LIMIT 1"
            ).fetchone()
            if row is not None:
                batch_id = str(row[0])
                rows = conn.execute(
                    "SELECT seq, kind, record, size, created_at, batch_id FROM outbox "
                    "WHERE batch_id = ? ORDER BY seq", (batch_id,)
                ).fetchall()
                return batch_id, [OutboxRow(*r) for r in rows]
            candidates = conn.execute(
                "SELECT seq, kind, record, size, created_at, batch_id FROM outbox "
                "ORDER BY seq LIMIT ?", (int(max_records),)
            ).fetchall()
            if not candidates:
                return None
            chosen: list[OutboxRow] = []
            total = 0
            for candidate in candidates:
                outbox_row = OutboxRow(*candidate)
                if chosen and total + outbox_row.size > max_bytes:
                    break
                chosen.append(outbox_row)
                total += outbox_row.size
            batch_id = uuid.uuid4().hex
            conn.executemany("UPDATE outbox SET batch_id = ? WHERE seq = ?",
                             [(batch_id, r.seq) for r in chosen])
            return batch_id, [OutboxRow(r.seq, r.kind, r.record, r.size, r.created_at, batch_id)
                              for r in chosen]

    def ack(self, batch_id: str) -> int:
        """Delete a batch after the gateway answered 202."""
        with self.transaction() as conn:
            cur = conn.execute("DELETE FROM outbox WHERE batch_id = ?", (batch_id,))
            return cur.rowcount

    def reassign(self, batch_id: str, *, split: bool) -> None:
        """Give the rows of ``batch_id`` fresh batch ids (halves when ``split``)."""
        with self.transaction() as conn:
            seqs = [int(r[0]) for r in conn.execute(
                "SELECT seq FROM outbox WHERE batch_id = ? ORDER BY seq", (batch_id,))]
            if not seqs:
                return
            groups = [seqs[: len(seqs) // 2], seqs[len(seqs) // 2:]] if split and len(seqs) > 1 \
                else [seqs]
            for group in groups:
                new_id = uuid.uuid4().hex
                conn.executemany("UPDATE outbox SET batch_id = ? WHERE seq = ?",
                                 [(new_id, s) for s in group])

    def dead_letter(self, batch_id: str, status_code: int | None, error: str) -> int:
        now = time.time()
        with self.transaction() as conn:
            rows = conn.execute(
                "SELECT seq, kind, record FROM outbox WHERE batch_id = ?", (batch_id,)
            ).fetchall()
            conn.executemany(
                "INSERT INTO outbox_dead(seq, kind, record, batch_id, status_code, error, "
                "failed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(seq, kind, record, batch_id, status_code, error, now)
                 for seq, kind, record in rows],
            )
            conn.execute("DELETE FROM outbox WHERE batch_id = ?", (batch_id,))
            return len(rows)

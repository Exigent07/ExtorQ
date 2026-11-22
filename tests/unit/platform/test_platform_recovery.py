"""Local recovery checks use synthetic SQLite state and a fake ClickHouse protocol."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from extorq.storage.recovery import native_archive, snapshot_sqlite
from extorq.storage.reset import ResetError

ARCHIVE = "extorq-" + "7" * 32 + ".zip"


class ArchiveClient:
    def __init__(self) -> None:
        self.exists = False
        self.commands: list[str] = []
        self.status = "BACKUP_CREATED"
        self.rows = 17

    def query(self, sql: str, *, parameters: dict[str, Any] | None = None) -> SimpleNamespace:
        if "system.databases" in sql:
            assert parameters == {"database": "extorq"}
            rows: list[tuple[Any, ...]] = [(int(self.exists),)]
        elif "extorq.schema_migrations" in sql:
            rows = [("0009", "7" * 64)]
        else:
            assert "system.tables" in sql
            rows = [("events", self.rows), ("schema_migrations", 1)]
        return SimpleNamespace(result_rows=rows)

    def command(self, sql: str) -> list[str]:
        self.commands.append(sql)
        return ["synthetic-query-id", self.status]


def test_native_backup_and_disposable_restore_reports_match() -> None:
    client = ArchiveClient()
    report = native_archive(client, ARCHIVE, restore=False)
    assert report == {
        "archive": ARCHIVE,
        "status": "BACKUP_CREATED",
        "migrations": {"0009": "7" * 64},
        "tables": {"events": 17, "schema_migrations": 1},
        "schema_sha256": report["schema_sha256"],
    }
    client.status = "RESTORED"
    restored = native_archive(client, ARCHIVE, restore=True)
    assert restored == {**report, "status": "RESTORED"}
    assert client.commands == [
        f"BACKUP DATABASE extorq TO Disk('extorq_backups', '{ARCHIVE}')",
        f"RESTORE DATABASE extorq FROM Disk('extorq_backups', '{ARCHIVE}')",
    ]


def test_native_restore_refuses_existing_database_and_invalid_archive() -> None:
    client = ArchiveClient()
    client.exists = True
    with pytest.raises(ResetError, match="fresh ClickHouse"):
        native_archive(client, ARCHIVE, restore=True)
    with pytest.raises(ResetError, match="archive name"):
        native_archive(client, "../outside.zip", restore=False)
    assert client.commands == []


def test_prepared_restore_requires_empty_data_and_matching_schema() -> None:
    client = ArchiveClient()
    backup = native_archive(client, ARCHIVE, restore=False)
    client.exists = True
    client.status = "RESTORED"
    with pytest.raises(ResetError, match="checksum mismatch"):
        native_archive(client, ARCHIVE, restore=True, expected_schema="f" * 64)
    with pytest.raises(ResetError, match="empty recovery database"):
        native_archive(client, ARCHIVE, restore=True, expected_schema=backup["schema_sha256"])
    assert len(client.commands) == 1
    client.rows = 0
    native_archive(client, ARCHIVE, restore=True, expected_schema=backup["schema_sha256"])
    assert client.commands[-1].startswith("RESTORE DATABASE extorq EXCEPT TABLES schema_migrations")


def test_native_backup_rejects_incomplete_status() -> None:
    client = ArchiveClient()
    client.status = "CREATING_BACKUP"
    with pytest.raises(ResetError, match="completed archive"):
        native_archive(client, ARCHIVE, restore=False)


def test_sqlite_restore_keeps_committed_wal_queue_and_checkpoint(tmp_path: Path) -> None:
    source = tmp_path / "state.db"
    backup = tmp_path / "backup.sqlite3"
    restored = tmp_path / "restored.db"
    with closing(sqlite3.connect(source)) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE outbox (id INTEGER)")
        db.execute("CREATE TABLE checkpoints (marker TEXT)")
        db.execute("INSERT INTO outbox VALUES (1)")
        db.execute("INSERT INTO checkpoints VALUES ('synthetic-cursor')")
        db.commit()
        db.execute("INSERT INTO outbox VALUES (2)")
        assert source.with_name("state.db-wal").is_file()
        snapshot_sqlite(source, backup)
    snapshot_sqlite(backup, restored)
    with closing(sqlite3.connect(restored)) as db:
        assert db.execute("SELECT id FROM outbox").fetchall() == [(1,)]
        assert db.execute("SELECT marker FROM checkpoints").fetchall() == [("synthetic-cursor",)]
    with pytest.raises(FileExistsError):
        snapshot_sqlite(backup, restored)

"""Native backups of the ExtorQ database, excluding ClickHouse access entities."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from extorq.common.config import get_settings
from extorq.storage.clickhouse import get_client
from extorq.storage.reset import DATABASE, ResetError, table_rows

_ARCHIVE_NAME = re.compile(r"extorq-[a-f0-9]{32}\.zip")


def check_sqlite(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise ResetError("SQLite integrity check failed")


def snapshot_sqlite(source: Path, target: Path) -> None:
    """Back up the complete SQLite transaction, including committed WAL data."""
    if source.is_symlink() or not source.is_file():
        raise ResetError("SQLite source must be a regular file")
    with closing(sqlite3.connect(source.absolute().as_uri() + "?mode=ro", uri=True)) as original:
        # Create exclusively so a restore cannot overwrite an existing database.
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            with closing(sqlite3.connect(target)) as copy:
                original.backup(copy)
                check_sqlite(copy)
        except (OSError, sqlite3.Error, ResetError):
            target.unlink(missing_ok=True)
            raise


def archive_report(client: Any) -> dict[str, Any]:
    """Counts and the migration ledger identify the data generation without row contents."""
    ledger = client.query(
        "SELECT version, argMax(checksum, applied_at) FROM extorq.schema_migrations "
        "GROUP BY version ORDER BY version"
    )
    migrations = {str(version): str(checksum) for version, checksum in ledger.result_rows}
    return {
        "tables": table_rows(client),
        "migrations": migrations,
        "schema_sha256": hashlib.sha256(
            json.dumps(migrations, sort_keys=True).encode()
        ).hexdigest(),
    }


def native_archive(
    client: Any, archive: str, *, restore: bool, expected_schema: str | None = None
) -> dict[str, Any]:
    if not _ARCHIVE_NAME.fullmatch(archive):
        raise ResetError("archive name must be extorq-<32 lowercase hex digits>.zip")
    if restore:
        exists = client.query(
            "SELECT count() FROM system.databases WHERE name = {database:String}",
            parameters={"database": DATABASE},
        )
        database_exists = int(exists.result_rows[0][0]) != 0
        if expected_schema is not None:
            if not database_exists:
                raise ResetError("migrate the disposable recovery database before restoring")
            current = archive_report(client)
            if current["schema_sha256"] != expected_schema:
                raise ResetError("recovery database migration checksum mismatch")
            if any(
                rows for table, rows in current["tables"].items() if table != "schema_migrations"
            ):
                raise ResetError("restore requires an empty recovery database")
            statement = (
                "RESTORE DATABASE extorq EXCEPT TABLES schema_migrations "
                f"FROM Disk('extorq_backups', '{archive}')"
            )
        else:
            if database_exists:
                raise ResetError(
                    "restore requires a fresh ClickHouse server without an extorq database"
                )
            statement = f"RESTORE DATABASE extorq FROM Disk('extorq_backups', '{archive}')"
        expected = "RESTORED"
    else:
        statement = f"BACKUP DATABASE extorq TO Disk('extorq_backups', '{archive}')"
        expected = "BACKUP_CREATED"
    status = client.command(statement)  # extorq: sql-reviewed strict generated archive basename
    if not isinstance(status, list | tuple) or expected not in status:
        raise ResetError("ClickHouse did not report a completed archive operation")
    return {"archive": archive, "status": expected, **archive_report(client)}


def main(*, archive: str, restore: bool = False, expected_schema: str | None = None) -> int:
    from clickhouse_connect.driver.exceptions import Error

    settings = get_settings().model_copy(update={"clickhouse_send_receive_timeout": 590.0})
    try:
        client = get_client("admin", settings=settings, database="default")
        try:
            result = native_archive(
                client, archive, restore=restore, expected_schema=expected_schema
            )
        finally:
            client.close()
    except ResetError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    except (Error, OSError) as exc:
        print(json.dumps({"error": f"ClickHouse archive operation failed ({type(exc).__name__})"}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0

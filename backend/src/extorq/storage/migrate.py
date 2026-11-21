"""ClickHouse migration runner (``extorq migrate``).

Behaviour:

1. Connects as ``extorq_admin`` (bounded retries while ClickHouse starts).
2. Creates ``extorq`` and ``extorq.schema_migrations`` if needed.
3. Discovers ``infra/clickhouse/migrations/NNNN_name.sql`` in version order.
4. **Refuses to continue** if any already-applied migration's SHA-256 checksum
   differs from the file on disk (applied migrations are immutable).
5. Applies pending migrations statement by statement and records
   ``(version, name, checksum, applied_at, duration_ms, applied_by)``.
6. Re-syncs every service user's password hash from
   ``var/secrets/clickhouse/<user>_password`` (``ALTER USER ... IDENTIFIED WITH
   sha256_hash ... SALT ...``), so ``bootstrap --rotate`` + ``migrate`` rotates
   credentials without editing SQL.

ClickHouse DDL is not transactional: a migration that fails midway is not
recorded and is re-run from its first statement next time, so every statement
must be idempotent (``IF NOT EXISTS``; GRANT is additive). Placeholders
``{{password_sha256:<user>}}`` / ``{{password_salt:<user>}}`` are rendered from
secret files with strict hex validation; rendered SQL is never logged.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from extorq.common.config import CLICKHOUSE_USERS, Settings, get_settings, read_secret_file
from extorq.common.logging import get_logger

log = get_logger("extorq.migrate")

MIGRATION_FILE_RE = re.compile(r"^(?P<version>\d{4})_(?P<name>[a-z0-9_]+)\.sql$")
PLACEHOLDER_RE = re.compile(r"\{\{\s*(password_sha256|password_salt)\s*:\s*([a-z0-9_]+)\s*\}\}")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")

SERVICE_USERS: tuple[str, ...] = tuple(
    user for role, user in CLICKHOUSE_USERS.items() if role != "admin"
)

SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS extorq.schema_migrations
(
    version      String,
    name         String,
    checksum     String,
    applied_at   DateTime64(3, 'UTC'),
    duration_ms  UInt32,
    applied_by   String
)
ENGINE = ReplacingMergeTree(applied_at)
ORDER BY version
""".strip()


class MigrationError(RuntimeError):
    """Migration problem. Messages never include rendered SQL or secrets."""


@dataclass(frozen=True)
class Migration:
    version: str
    name: str
    path: Path
    checksum: str
    text: str

    @property
    def label(self) -> str:
        return f"{self.version}_{self.name}"


# ── discovery and parsing ─────────────────────────────────────────────


def discover_migrations(directory: Path) -> list[Migration]:
    if not directory.is_dir():
        raise MigrationError(f"migrations directory not found: {directory}")
    found: dict[str, Migration] = {}
    for path in sorted(directory.iterdir()):
        if path.suffix != ".sql":
            continue
        match = MIGRATION_FILE_RE.match(path.name)
        if not match:
            raise MigrationError(f"unexpected migration file name: {path.name}")
        data = path.read_bytes()
        migration = Migration(
            version=match["version"],
            name=match["name"],
            path=path,
            checksum=hashlib.sha256(data).hexdigest(),
            text=data.decode("utf-8"),
        )
        if migration.version in found:
            raise MigrationError(f"duplicate migration version {migration.version}")
        found[migration.version] = migration
    return [found[v] for v in sorted(found)]


def split_statements(sql: str) -> list[str]:
    """Split SQL text into statements on ``;`` outside quotes and comments."""
    statements: list[str] = []
    buf: list[str] = []
    i, n = 0, len(sql)
    quote: str | None = None
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if quote:
            buf.append(ch)
            if ch == "\\" and quote in ("'", '"'):
                if nxt:
                    buf.append(nxt)
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == "-" and nxt == "-":
            end = sql.find("\n", i)
            i = n if end == -1 else end
            continue
        if ch == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            if end == -1:
                raise MigrationError("unterminated block comment")
            i = end + 2
            buf.append(" ")
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == ";":
            statement = "".join(buf).strip()
            if statement:
                statements.append(statement)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if quote:
        raise MigrationError("unterminated quoted string")
    tail = "".join(buf).strip()
    if tail:
        statements.append(tail)
    return statements


@dataclass(frozen=True)
class PasswordHash:
    sha256: str
    salt: str


def password_hash(password: str, salt: str | None = None) -> PasswordHash:
    """Salted SHA-256 as ClickHouse expects for ``sha256_hash ... SALT``: sha256(password+salt)."""
    salt = salt or secrets.token_hex(16)
    digest = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    return PasswordHash(sha256=digest, salt=salt)


def render(text: str, hashes: dict[str, PasswordHash]) -> str:
    """Substitute password placeholders with strictly validated hex values."""

    def replace(match: re.Match[str]) -> str:
        field, user = match.group(1), match.group(2)
        if user not in hashes:
            raise MigrationError(f"placeholder references unknown user {user!r}")
        value = hashes[user].sha256 if field == "password_sha256" else hashes[user].salt
        pattern = _HEX64 if field == "password_sha256" else _HEX32
        if not pattern.fullmatch(value):
            raise MigrationError(f"invalid {field} for {user}")
        return value

    return PLACEHOLDER_RE.sub(replace, text)


def first_words(statement: str, count: int = 4) -> str:
    """Safe statement description for logs (keywords + object name, never values)."""
    words = statement.split()
    return " ".join(words[:count])


# ── runner ────────────────────────────────────────────────────────────


@dataclass
class MigrationReport:
    applied: list[str]
    already_applied: list[str]
    passwords_synced: int


class Migrator:
    def __init__(
        self,
        client: Any,
        migrations_dir: Path,
        password_dir: Path,
        *,
        applied_by: str = "extorq-migrate",
    ) -> None:
        self.client = client
        self.migrations_dir = migrations_dir
        self.password_dir = password_dir
        self.applied_by = applied_by

    def _hashes(self) -> dict[str, PasswordHash]:
        return {
            user: password_hash(read_secret_file(self.password_dir / f"{user}_password"))
            for user in SERVICE_USERS
        }

    def ensure_bookkeeping(self) -> None:
        self.client.command("CREATE DATABASE IF NOT EXISTS extorq")
        self.client.command(SCHEMA_MIGRATIONS_DDL)

    def applied_checksums(self) -> dict[str, str]:
        result = self.client.query(
            "SELECT version, argMax(checksum, applied_at) FROM extorq.schema_migrations "
            "GROUP BY version ORDER BY version"
        )
        return {str(row[0]): str(row[1]) for row in result.result_rows}

    def verify(self, migrations: list[Migration], applied: dict[str, str]) -> None:
        on_disk = {m.version: m for m in migrations}
        for version, checksum in applied.items():
            migration = on_disk.get(version)
            if migration is None:
                log.warning("migration_applied_but_missing_on_disk", version=version)
                continue
            if migration.checksum != checksum:
                raise MigrationError(
                    f"checksum mismatch for applied migration {migration.label}: the file "
                    "changed after it was applied; add a new migration instead"
                )

    def apply(self, migration: Migration, hashes: dict[str, PasswordHash]) -> None:
        rendered = render(migration.text, hashes)
        statements = split_statements(rendered)
        started = time.monotonic()
        for index, statement in enumerate(statements, start=1):
            try:
                self.client.command(statement)
            except Exception as exc:  # noqa: BLE001 - re-raised as MigrationError below
                # Error text from ClickHouse may echo the statement: log only its class/code.
                code = getattr(exc, "code", None)
                raise MigrationError(
                    f"{migration.label}: statement {index}/{len(statements)} "
                    f"({first_words(statement)} ...) failed: {type(exc).__name__}"
                    f"{f' code={code}' if code else ''}"
                ) from None
        duration_ms = int((time.monotonic() - started) * 1000)
        self.client.insert(
            "extorq.schema_migrations",
            [
                [
                    migration.version,
                    migration.name,
                    migration.checksum,
                    datetime.now(UTC),
                    duration_ms,
                    self.applied_by,
                ]
            ],
            column_names=["version", "name", "checksum", "applied_at", "duration_ms", "applied_by"],
        )
        log.info(
            "migration_applied",
            migration=migration.label,
            statements=len(statements),
            duration_ms=duration_ms,
        )

    def sync_passwords(self, hashes: dict[str, PasswordHash]) -> int:
        existing = {
            str(row[0])
            for row in self.client.query(
                "SELECT name FROM system.users WHERE name IN {names:Array(String)}",
                parameters={"names": list(SERVICE_USERS)},
            ).result_rows
        }
        synced = 0
        for user in SERVICE_USERS:
            if user not in existing:
                log.warning("service_user_missing", user=user)
                continue
            value = hashes[user]
            if not (
                _HEX64.fullmatch(value.sha256)
                and _HEX32.fullmatch(value.salt)
                and user in SERVICE_USERS
            ):
                raise MigrationError(f"invalid password hash for {user}")
            # ClickHouse cannot bind parameters in ALTER USER: the identifier comes from the
            # fixed SERVICE_USERS allow-list and hash/salt are fullmatch-validated hex (F-04).
            self.client.command(  # extorq: sql-reviewed allow-listed user + fullmatch-validated hex
                f"ALTER USER {user} IDENTIFIED WITH sha256_hash "
                f"BY '{value.sha256}' SALT '{value.salt}'"
            )
            synced += 1
        return synced

    def run(self) -> MigrationReport:
        migrations = discover_migrations(self.migrations_dir)
        self.ensure_bookkeeping()
        applied = self.applied_checksums()
        self.verify(migrations, applied)
        hashes = self._hashes()
        newly_applied: list[str] = []
        highest_applied = max(applied) if applied else ""
        for migration in migrations:
            if migration.version in applied:
                continue
            if migration.version < highest_applied:
                log.warning(
                    "migration_out_of_order",
                    migration=migration.label,
                    highest_applied=highest_applied,
                )
            self.apply(migration, hashes)
            newly_applied.append(migration.label)
        synced = self.sync_passwords(hashes)
        return MigrationReport(
            applied=newly_applied,
            already_applied=sorted(applied),
            passwords_synced=synced,
        )


def connect_admin(
    settings: Settings,
    *,
    attempts: int = 30,
    delay: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
) -> Any:
    """Connect as extorq_admin with bounded retries (ClickHouse may still be starting)."""
    from extorq.common.config import ConfigError
    from extorq.storage.clickhouse import get_client, is_transient_error

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            client = get_client("admin", settings=settings, database="default")
            client.command("SELECT 1")
            return client
        except ConfigError as exc:
            raise MigrationError(str(exc)) from None
        except Exception as exc:  # noqa: BLE001 - classified below
            last = exc
            if not is_transient_error(exc):
                raise MigrationError(
                    f"ClickHouse admin connection failed: {type(exc).__name__}"
                    f" code={getattr(exc, 'code', None)}"
                ) from None
            log.info(
                "clickhouse_not_ready",
                attempt=attempt,
                attempts=attempts,
                error=type(exc).__name__,
                code=getattr(exc, "code", None),
            )
            sleep(delay)
    raise MigrationError(
        f"ClickHouse not reachable after {attempts} attempts: "
        f"{type(last).__name__ if last else 'unknown'}"
    )


def main(*, status_only: bool = False) -> int:
    from extorq.common.logging import configure_logging

    configure_logging("migrate")
    settings = get_settings()
    password_dir = settings.resolve(settings.clickhouse_password_dir)
    migrations_dir = settings.resolve(settings.migrations_dir)
    try:
        client = connect_admin(settings)
        migrator = Migrator(
            client,
            migrations_dir,
            password_dir,
            applied_by=f"extorq-migrate@{settings.instance_name}",
        )
        if status_only:
            migrator.ensure_bookkeeping()
            applied = migrator.applied_checksums()
            migrations = discover_migrations(migrations_dir)
            migrator.verify(migrations, applied)
            pending = [m.label for m in migrations if m.version not in applied]
            log.info("migration_status", applied=sorted(applied), pending=pending)
            return 0
        report = migrator.run()
    except MigrationError as exc:
        log.error("migration_failed", error=str(exc))
        return 1
    log.info(
        "migrations_complete",
        applied=report.applied,
        already_applied=report.already_applied,
        passwords_synced=report.passwords_synced,
    )
    return 0

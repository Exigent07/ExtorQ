"""ClickHouse client factory with per-service least-privilege identities.

``get_client(role)`` returns a clickhouse-connect HTTP client authenticated as
the ClickHouse user for ``role`` (PLAN §4.4), reading the password from
``<EXTORQ_CLICKHOUSE_PASSWORD_DIR>/<user>_password``. Passwords are read from
files only, never from environment variables, and never logged.

Always use server-side parameters for values::

    client.query("SELECT count() FROM events WHERE asset_id = {asset:String}",
                 parameters={"asset": asset_id})
"""

from __future__ import annotations

from typing import Any, Literal, get_args

import clickhouse_connect
from clickhouse_connect.driver.client import Client
from clickhouse_connect.driver.exceptions import DatabaseError, Error, OperationalError

from extorq.common.config import (
    CLICKHOUSE_USERS,
    ConfigError,
    Settings,
    get_settings,
    read_secret_file,
)

Role = Literal["admin", "ingest", "detect", "rules_ro", "ai", "api_ro", "api_writer", "grafana"]
ROLES: tuple[str, ...] = get_args(Role)

#: ClickHouse error codes that indicate a transient condition (retry, never dead-letter).
TRANSIENT_ERROR_CODES = frozenset(
    {
        3,  # UNEXPECTED_END_OF_FILE
        8,  # THERE_IS_NO_COLUMN (schema not migrated yet: deployment issue, not data)
        16,  # NO_SUCH_COLUMN_IN_TABLE (same)
        60,  # UNKNOWN_TABLE (writer started before `extorq migrate`)
        81,  # UNKNOWN_DATABASE (same)
        159,  # TIMEOUT_EXCEEDED
        160,  # TOO_SLOW
        164,  # READONLY (e.g. disk/replica read-only mode)
        201,  # QUOTA_EXCEEDED
        202,  # TOO_MANY_SIMULTANEOUS_QUERIES
        203,  # NO_FREE_CONNECTION
        209,  # SOCKET_TIMEOUT
        210,  # NETWORK_ERROR
        236,  # ABORTED
        241,  # MEMORY_LIMIT_EXCEEDED
        242,  # TABLE_IS_READ_ONLY
        243,  # NOT_ENOUGH_SPACE
        252,  # TOO_MANY_PARTS
        285,  # TOO_FEW_LIVE_REPLICAS
        394,  # QUERY_WAS_CANCELLED
        425,  # SYSTEM_ERROR
        439,  # CANNOT_SCHEDULE_TASK
        497,  # ACCESS_DENIED (configuration problem: never blame the records)
        516,  # AUTHENTICATION_FAILED (configuration problem)
        999,  # KEEPER_EXCEPTION
    }
)


def user_for_role(role: str) -> str:
    try:
        return CLICKHOUSE_USERS[role]
    except KeyError:
        raise ConfigError(f"unknown ClickHouse role {role!r}; expected one of {ROLES}") from None


def get_client(
    role: Role,
    *,
    settings: Settings | None = None,
    database: str | None = None,
    query_settings: dict[str, Any] | None = None,
    **kwargs: Any,
) -> Client:
    """Return a ClickHouse client for ``role`` with timeouts and the role's password file."""
    cfg = settings or get_settings()
    user = user_for_role(role)
    password = read_secret_file(cfg.clickhouse_password_file(role))
    return clickhouse_connect.get_client(
        host=cfg.clickhouse_host,
        port=cfg.clickhouse_port,
        username=user,
        password=password,
        database=database if database is not None else cfg.clickhouse_database,
        secure=cfg.clickhouse_secure,
        connect_timeout=cfg.clickhouse_connect_timeout,
        send_receive_timeout=cfg.clickhouse_send_receive_timeout,
        # No per-client session: services are stateless and may share connections.
        autogenerate_session_id=False,
        settings=query_settings or {},
        **kwargs,
    )


def is_transient_error(exc: BaseException) -> bool:
    """True when an insert/query failure says nothing about the data itself."""
    if isinstance(exc, OperationalError):
        return True  # connection refused/reset, DNS failure, HTTP-level timeouts
    if isinstance(exc, Error):
        code = getattr(exc, "code", None)
        if code is None:
            # Transport problems without a server error code (proxy 502/503, resets).
            return not isinstance(exc, DatabaseError) or "Code:" not in str(exc)
        return int(code) in TRANSIENT_ERROR_CODES
    return isinstance(exc, ConnectionError | TimeoutError | OSError)

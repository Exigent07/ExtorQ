"""ClickHouse access for detection and correlation.

The engine talks to a minimal :class:`DbClient` protocol so it can be unit-tested
with an in-memory fake and run in production on top of A's
``extorq.storage.clickhouse.get_client(role)``.

:class:`ClickHouseConnectClient` adapts a ``clickhouse_connect`` client:

* bounded retries with exponential backoff + full jitter for *transient* failures
  only (connection errors, timeouts, overload codes); privilege/syntax errors fail
  fast so they surface in ``rule_runs.error``
* timestamps: ClickHouse returns ``DateTime64(3, 'UTC')`` as naive UTC datetimes,
  which are made aware here; inserts *refuse* naive datetimes because
  clickhouse-connect would interpret them in the host's local time zone
* server-side parameters only (``{name:Type}``); no client-side settings are sent
  (the readonly rules identity may not change settings)
"""

from __future__ import annotations

import random
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from extorq.detection._compat import get_logger

log = get_logger(__name__)

#: ClickHouse error codes worth retrying (overload, network, read-only replica, keeper).
TRANSIENT_CODES = frozenset({3, 159, 202, 209, 210, 241, 242, 252, 319, 425, 999, 1000, 1002})
_CODE_RE = re.compile(r"Code:\s*(\d+)")


class ClickHouseUnavailable(RuntimeError):
    """ClickHouse could not be reached after the bounded retries."""


@dataclass
class QueryRows:
    columns: list[str]
    types: list[str]
    rows: list[tuple[Any, ...]] = field(default_factory=list)

    def dicts(self) -> list[dict[str, Any]]:
        return [dict(zip(self.columns, row, strict=True)) for row in self.rows]


class DbClient(Protocol):
    """What detection/correlation need from a database connection."""

    def select(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryRows: ...

    def insert_rows(self, table: str, rows: Sequence[dict[str, Any]]) -> None: ...


def error_code(exc: BaseException) -> int | None:
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return code
    match = _CODE_RE.search(str(exc))
    return int(match.group(1)) if match else None


def is_transient(exc: BaseException) -> bool:
    """True for failures that may succeed on retry (network, overload)."""
    if isinstance(exc, ConnectionError | TimeoutError):
        return True
    try:
        from clickhouse_connect.driver import exceptions as ch_exc
    except ImportError:  # pragma: no cover - dependency is always installed
        return False
    if isinstance(exc, ch_exc.OperationalError):
        return True
    if isinstance(exc, ch_exc.DatabaseError):
        return error_code(exc) in TRANSIENT_CODES
    return isinstance(exc, OSError)


def _to_utc(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    if isinstance(value, list):
        return [_to_utc(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_to_utc(v) for v in value)
    return value


def ch_datetime(value: datetime) -> str:
    """Render an aware datetime as a ClickHouse ``DateTime64(3)`` literal in UTC."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("naive datetimes are not accepted as query parameters")
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%d %H:%M:%S.") + f"{utc.microsecond // 1000:03d}"


def _bind_value(value: Any) -> Any:
    """Parameters are rendered explicitly so no driver time-zone conversion applies."""
    if isinstance(value, datetime):
        return ch_datetime(value)
    if isinstance(value, list | tuple):
        return [_bind_value(v) for v in value]
    return value


def _check_aware(value: Any, column: str) -> None:
    if isinstance(value, datetime) and (value.tzinfo is None or value.utcoffset() is None):
        raise ValueError(
            f"naive datetime for column {column}: refusing to insert (would be shifted)"
        )


class ClickHouseConnectClient:
    """Retrying, timezone-safe adapter over a ``clickhouse_connect`` client."""

    def __init__(
        self,
        client: Any,
        *,
        database: str = "extorq",
        attempts: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self._database = database
        self._attempts = max(1, attempts)
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._sleep = sleep

    @property
    def raw(self) -> Any:
        return self._client

    def _retry(self, operation: str, func: Callable[[], Any]) -> Any:
        for attempt in range(1, self._attempts + 1):
            try:
                return func()
            except Exception as exc:
                if not is_transient(exc):
                    raise
                if attempt == self._attempts:
                    raise ClickHouseUnavailable(
                        f"{operation} failed after {attempt} attempts: {type(exc).__name__}"
                    ) from exc
                cap = min(self._max_delay, self._base_delay * 2 ** (attempt - 1))
                delay = random.uniform(0, cap)  # noqa: S311 - jitter, not cryptography
                log.warning(
                    "clickhouse_retry",
                    operation=operation,
                    attempt=attempt,
                    delay_s=round(delay, 3),
                    error_type=type(exc).__name__,
                )
                self._sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover

    def select(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryRows:
        bound = {k: _bind_value(v) for k, v in (parameters or {}).items()}

        def run() -> QueryRows:
            result = self._client.query(sql, parameters=bound or None)
            types = [getattr(t, "name", str(t)) for t in result.column_types]
            rows = [tuple(_to_utc(v) for v in row) for row in result.result_rows]
            return QueryRows(columns=list(result.column_names), types=types, rows=rows)

        return self._retry("select", run)  # type: ignore[no-any-return,unused-ignore]

    def insert_rows(self, table: str, rows: Sequence[dict[str, Any]]) -> None:
        if not rows:
            return
        columns = list(rows[0].keys())
        data: list[list[Any]] = []
        for row in rows:
            if list(row.keys()) != columns:
                raise ValueError(f"inconsistent columns for {table}")
            for column, value in row.items():
                _check_aware(value, column)
            data.append([row[c] for c in columns])
        self._retry(
            f"insert:{table}",
            lambda: self._client.insert(table, data, column_names=columns, database=self._database),
        )


def wrap(client: Any) -> DbClient:
    """Return ``client`` if it already speaks :class:`DbClient`, else adapt it."""
    if hasattr(client, "select") and hasattr(client, "insert_rows"):
        return client  # type: ignore[no-any-return,unused-ignore]
    return ClickHouseConnectClient(client)


def connect(role: str) -> DbClient:
    """Open a client for a ClickHouse identity via A's storage layer."""
    from extorq.storage.clickhouse import get_client

    return wrap(get_client(role))  # type: ignore[arg-type]


def chunked(items: Iterable[Any], size: int) -> Iterable[list[Any]]:
    batch: list[Any] = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch

"""Read-only client of the ExtorQ analyst API (the runner's only view of detections).

Why the API and not ClickHouse: it is the product path an analyst uses (``FINAL`` reads,
evidence resolution, rule-run summaries), it needs no debug proxy, and its read-only
``viewer`` role cannot change anything.

Security properties:

* The service token is read from a file (``var/secrets/api_service_token`` by default) at
  first use and kept only in memory; it is never logged, printed or put in an exception.
* Plain HTTP is accepted only to a loopback address (the compose API binds 127.0.0.1:8000),
  so the token never crosses a network unencrypted.
* Every request has a timeout and bounded retries with jittered backoff (connection errors,
  429 and 5xx); 4xx answers other than 404/429 fail immediately.
"""

from __future__ import annotations

import ipaddress
import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from detection_tests.windows import format_time

DEFAULT_API_URL = "http://127.0.0.1:8000"
DEFAULT_TOKEN_FILE = "var/secrets/api_service_token"  # noqa: S105 - a path, not a secret
#: Identity sent in ``X-ExtorQ-User`` (shows up in API access logs; read-only role).
API_USER = "detection-tests"
API_ROLE = "viewer"
MAX_PAGE = 200
MAX_EVENT_PAGE = 500
_LOOPBACK_NAMES = {"localhost"}


class ApiError(RuntimeError):
    """The analyst API could not answer (message never contains the token)."""


def validate_base_url(url: str) -> str:
    """Return the normalised base URL; refuse plain HTTP to anything but loopback."""
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ApiError(f"invalid API URL {url!r} (expected http(s)://host:port)")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ApiError("the API URL must not contain credentials, a query or a fragment")
    if parsed.scheme == "http" and not _is_loopback(parsed.hostname):
        raise ApiError(
            "refusing plain HTTP to a non-loopback host: the service token would cross the "
            "network unencrypted (use https or the local API on 127.0.0.1)"
        )
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", ""))


def _is_loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class AnalystApi:
    """Minimal typed-by-convention client: returns the API's JSON objects as dicts."""

    def __init__(
        self,
        base_url: str = DEFAULT_API_URL,
        token_file: Path | str = DEFAULT_TOKEN_FILE,
        *,
        timeout: float = 20.0,
        retries: int = 3,
        sleep: Callable[[float], None] = time.sleep,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self._token_file = Path(token_file)
        self._token: str | None = None
        self._timeout = timeout
        self._retries = max(0, retries)
        self._sleep = sleep
        self._open = opener or urllib.request.urlopen

    # ── transport ──

    def _token_value(self) -> str:
        if self._token is None:
            try:
                token = self._token_file.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise ApiError(
                    f"cannot read the API service token file {self._token_file} "
                    f"({type(exc).__name__}); run `make bootstrap`"
                ) from None
            if not token:
                raise ApiError(f"the API service token file {self._token_file} is empty")
            self._token = token
        return self._token

    def get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        """GET ``/api/v1/<path>`` and decode JSON; ``None`` for 404."""
        query = urllib.parse.urlencode(
            [(k, _param(v)) for k, v in (params or {}).items() if v is not None], doseq=True
        )
        url = f"{self.base_url}/api/v1/{path.lstrip('/')}" + (f"?{query}" if query else "")
        attempt = 0
        while True:
            attempt += 1
            request = urllib.request.Request(  # noqa: S310 - scheme validated in __init__
                url,
                headers={
                    "Authorization": f"Bearer {self._token_value()}",
                    "X-ExtorQ-User": API_USER,
                    "X-ExtorQ-Role": API_ROLE,
                    "Accept": "application/json",
                },
                method="GET",
            )
            try:
                with self._open(request, timeout=self._timeout) as response:
                    body = response.read(32 * 1024 * 1024)
                return json.loads(body.decode("utf-8"))
            except urllib.error.HTTPError as exc:
                status = exc.code
                exc.close()
                if status == 404:
                    return None
                retryable = status == 429 or status >= 500
                if not retryable or attempt > self._retries:
                    raise ApiError(f"GET {path} -> HTTP {status}") from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                if attempt > self._retries:
                    reason = getattr(exc, "reason", exc)
                    raise ApiError(
                        f"GET {path}: analyst API at {self.base_url} unreachable "
                        f"({type(reason).__name__})"
                    ) from None
            except json.JSONDecodeError:
                raise ApiError(f"GET {path}: response is not JSON") from None
            # Jittered exponential backoff: 1, 2, 4 s (x 0.5-1.0).
            self._sleep(min(8.0, 2 ** (attempt - 1)) * random.uniform(0.5, 1.0))  # noqa: S311

    # ── endpoints ──

    def alerts(
        self,
        *,
        asset_id: str,
        since: datetime,
        until: datetime,
        rule_id: str | None = None,
        max_pages: int = 5,
    ) -> list[dict[str, Any]]:
        """Alerts with ``last_seen >= since`` and ``first_seen < until`` (newest first)."""
        items: list[dict[str, Any]] = []
        for page in range(max_pages):
            data = self.get(
                "alerts",
                {
                    "asset_id": asset_id,
                    "rule_id": rule_id,
                    "since": since,
                    "until": until,
                    "sort": "first_seen",
                    "limit": MAX_PAGE,
                    "offset": page * MAX_PAGE,
                },
            )
            batch = _items(data)
            items.extend(batch)
            if len(batch) < MAX_PAGE:
                break
        return items

    def alert_detail(self, alert_id: str) -> dict[str, Any] | None:
        data = self.get(f"alerts/{alert_id}")
        return data if isinstance(data, dict) else None

    def event_detail(self, event_id: str) -> dict[str, Any] | None:
        data = self.get(f"events/{urllib.parse.quote(event_id, safe='')}")
        return data if isinstance(data, dict) else None

    def events(
        self,
        *,
        asset_id: str,
        event_type: str,
        since: datetime,
        until: datetime,
        actor: str | None = None,
        src_ip: str | None = None,
        source_type: str | None = None,
        limit: int = MAX_EVENT_PAGE,
    ) -> list[dict[str, Any]]:
        data = self.get(
            "events",
            {
                "asset_id": asset_id,
                "event_type": event_type,
                "since": since,
                "until": until,
                "actor": actor,
                "src_ip": src_ip,
                "source_type": source_type,
                "limit": max(1, min(limit, MAX_EVENT_PAGE)),
            },
        )
        return _items(data)

    def rule(self, rule_id: str, *, runs_limit: int = 20) -> dict[str, Any] | None:
        """``GET /rules/{id}`` (record, interval, staleness, recent runs) or ``None``."""
        data = self.get(f"rules/{rule_id}", {"runs_limit": runs_limit})
        return data if isinstance(data, dict) else None

    def health(self) -> dict[str, Any]:
        data = self.get("health")
        if not isinstance(data, dict):
            raise ApiError("GET health returned no document")
        return data


def _param(value: Any) -> str:
    if isinstance(value, datetime):
        return format_time(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _items(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, dict):
        return []
    items = data.get("items")
    if not isinstance(items, list):
        return []
    return [item for item in items if isinstance(item, dict)]

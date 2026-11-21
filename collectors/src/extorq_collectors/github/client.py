"""Defensive, read-only GitHub REST API client.

Properties (see docs/telemetry/github.md):

* every request is a GET with explicit connect/read/write/pool timeouts;
* headers ``Accept: application/vnd.github+json`` and ``X-GitHub-Api-Version: 2022-11-28``;
* conditional requests (``If-None-Match``) with 304 handling; GitHub does not charge
  authenticated 304 responses against the primary rate limit;
* ``Link`` header pagination; next links must stay on the configured API origin so a
  hostile or broken response can never redirect the token to another host;
* primary rate limit (``X-RateLimit-Remaining``/``X-RateLimit-Reset``) and secondary
  rate limits (``Retry-After``, 403/429 "secondary rate limit") with bounded waits:
  a wait longer than ``max_rate_limit_wait`` raises :class:`GitHubRateLimited` instead
  of blocking the poll; requests known to be over the primary limit are not sent;
* bounded retries with jittered exponential backoff for network errors and 5xx;
* response bodies are streamed and capped (decoded size) before parsing.

The token is held only in the ``Authorization`` header of the underlying httpx client.
It is never logged, never included in exceptions and never part of ``repr()``.
"""

from __future__ import annotations

import json
import random
import re
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import httpx

from extorq_collectors import __version__

API_VERSION = "2022-11-28"
DEFAULT_BASE_URL = "https://api.github.com"
JSON_ACCEPT = "application/vnd.github+json"
RAW_ACCEPT = "application/vnd.github.raw+json"
DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

_LINK_RE = re.compile(r'<([^>]+)>\s*;\s*rel="([^"]+)"')
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")
_SECONDARY_RE = re.compile(
    r"secondary rate limit|abuse detection|temporarily blocked", re.IGNORECASE
)

QueryParams = Mapping[str, str | int | bool]


def _clean(text: str, limit: int = 200) -> str:
    text = " ".join(_CONTROL_RE.sub(" ", text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


class GitHubApiError(Exception):
    """A GitHub API call failed. Messages never contain credentials."""

    def __init__(
        self,
        status: int | None,
        endpoint: str,
        message: str,
        *,
        accepted_permissions: str | None = None,
        retry_at: float | None = None,
    ) -> None:
        self.status = status
        self.endpoint = endpoint
        self.message = _clean(message)
        self.accepted_permissions = (
            _clean(accepted_permissions, 120) if accepted_permissions else None
        )
        self.retry_at = retry_at
        label = f"HTTP {status}" if status is not None else "request"
        super().__init__(f"GitHub API {label} on {endpoint}: {self.message}")

    @property
    def gap_reason(self) -> str:
        """Short reason suitable for data-gap records."""
        reason = f"HTTP {self.status}: {self.message}" if self.status else self.message
        if self.accepted_permissions:
            reason += f" (token needs: {self.accepted_permissions})"
        return _clean(reason, 300)


class GitHubUnauthorized(GitHubApiError):
    """401: token missing, invalid, expired or revoked."""


class GitHubForbidden(GitHubApiError):
    """403 that is not a rate limit: feature unavailable or token not authorised."""


class GitHubNotFound(GitHubApiError):
    """404/410: resource absent, or hidden from this token."""


class GitHubConflict(GitHubApiError):
    """409: e.g. 'Git Repository is empty.'"""


class GitHubRateLimited(GitHubApiError):
    """Rate limited and the required wait exceeds the per-request budget."""


class GitHubTransientError(GitHubApiError):
    """Network error, timeout or 5xx after bounded retries."""


class GitHubResponseError(GitHubApiError):
    """Malformed, oversized or otherwise unusable response."""


@dataclass
class RateLimitState:
    limit: int | None = None
    remaining: int | None = None
    reset_at: float | None = None
    used: int | None = None
    resource: str | None = None
    secondary_hits: int = 0
    waits_seconds: float = 0.0


@dataclass(frozen=True)
class ApiResponse:
    status: int
    data: Any
    etag: str | None
    not_modified: bool
    links: Mapping[str, str] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PageResult:
    items: list[Any]
    etag: str | None
    not_modified: bool
    pages: int
    #: True when more pages existed beyond ``max_pages`` (results are incomplete).
    truncated: bool
    #: Parsed body of the first page (useful when the items sit inside an object).
    first: Any = None


def parse_link_header(value: str | None) -> dict[str, str]:
    links: dict[str, str] = {}
    if not value:
        return links
    for url, rels in _LINK_RE.findall(value):
        for rel in rels.split():
            links.setdefault(rel, url)
    return links


class GitHubClient:
    """Synchronous GitHub REST client for read-only polling."""

    def __init__(
        self,
        token: str | None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: httpx.Timeout | None = None,
        max_attempts: int = 3,
        backoff_base: float = 1.0,
        backoff_cap: float = 30.0,
        max_rate_limit_wait: float = 60.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
        rng: Callable[[], float] = random.random,
        user_agent: str | None = None,
    ) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https" or not parts.netloc or parts.query or parts.fragment:
            raise ValueError("GitHub API base URL must be an absolute https:// URL without query")
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._base_url = base_url.rstrip("/")
        self._origin = (parts.scheme, parts.netloc.lower())
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._backoff_cap = backoff_cap
        self._max_wait = max_rate_limit_wait
        self._max_bytes = max_response_bytes
        self._sleep = sleep
        self._clock = clock
        self._rng = rng
        self.rate_limit = RateLimitState()
        self.request_count = 0
        self.not_modified_count = 0
        #: Scope names granted to a classic/OAuth token (``X-OAuth-Scopes``); not secret.
        self.token_scopes: tuple[str, ...] | None = None
        #: ``GitHub-Authentication-Token-Expiration`` header value, if sent.
        self.token_expiration: str | None = None
        headers = {
            "Accept": JSON_ACCEPT,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": user_agent or f"extorq-github-collector/{__version__}",
        }
        if token:
            if any(ch in token for ch in "\r\n\t ") or not token.isprintable():
                raise ValueError("GitHub token contains whitespace or control characters")
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(
            base_url=self._base_url,
            headers=headers,
            timeout=timeout or httpx.Timeout(20.0, connect=5.0, pool=5.0),
            transport=transport,
            follow_redirects=True,  # httpx drops Authorization on cross-origin redirects
            max_redirects=3,
        )

    def __repr__(self) -> str:
        return f"GitHubClient(base_url={self._base_url!r})"

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ── public API ──────────────────────────────────────────────────────────

    def get(
        self,
        path: str,
        *,
        params: QueryParams | None = None,
        etag: str | None = None,
        raw: bool = False,
        max_bytes: int | None = None,
    ) -> ApiResponse:
        """GET ``path`` (relative to the API base) and parse the JSON body."""
        if not path.startswith("/") or "://" in path:
            raise ValueError("path must be an API-relative path starting with '/'")
        return self._request(path, params=params, etag=etag, raw=raw, max_bytes=max_bytes)

    def get_text(self, path: str, *, params: QueryParams | None = None, max_bytes: int) -> str:
        """GET raw file content (``application/vnd.github.raw+json``) as text, size-capped."""
        response = self.get(path, params=params, raw=True, max_bytes=max_bytes)
        return str(response.data)

    def paginate(
        self,
        path: str,
        *,
        params: QueryParams | None = None,
        etag: str | None = None,
        max_pages: int = 10,
        items_key: str | None = None,
        stop: Callable[[Any], bool] | None = None,
    ) -> PageResult:
        """Collect items across ``Link: rel="next"`` pages.

        ``etag`` applies to the first page only; a 304 there means the whole listing is
        unchanged. ``stop(item)`` returning True ends pagination after the current page
        (e.g. when a checkpoint item was reached).
        """
        items: list[Any] = []
        first = self.get(path, params=params, etag=etag)
        if first.not_modified:
            return PageResult(
                items=[], etag=first.etag or etag, not_modified=True, pages=1, truncated=False
            )
        response = first
        pages = 1
        while True:
            page_items = self._extract_items(response.data, items_key, path)
            items.extend(page_items)
            next_url = response.links.get("next")
            done = next_url is None or (stop is not None and any(stop(item) for item in page_items))
            if done or pages >= max_pages:
                return PageResult(
                    items=items,
                    etag=first.etag,
                    not_modified=False,
                    pages=pages,
                    truncated=not done,
                    first=first.data,
                )
            response = self.follow(str(next_url), endpoint=path)
            pages += 1

    def follow(self, url: str, *, endpoint: str = "pagination") -> ApiResponse:
        """GET an absolute ``Link`` URL after checking it stays on the API origin."""
        return self._request(self._validated_next(url, endpoint), params=None, etag=None)

    def iter_pages(
        self,
        path: str,
        *,
        params: QueryParams | None = None,
        max_pages: int = 10,
        items_key: str | None = None,
    ) -> Iterator[list[Any]]:
        """Yield item lists page by page (no conditional request)."""
        response = self.get(path, params=params)
        pages = 1
        while True:
            yield self._extract_items(response.data, items_key, path)
            next_url = response.links.get("next")
            if next_url is None or pages >= max_pages:
                return
            response = self.follow(next_url, endpoint=path)
            pages += 1

    # ── internals ───────────────────────────────────────────────────────────

    @staticmethod
    def _extract_items(data: Any, items_key: str | None, endpoint: str) -> list[Any]:
        if items_key is not None:
            data = data.get(items_key) if isinstance(data, dict) else None
        if not isinstance(data, list):
            raise GitHubResponseError(None, endpoint, "expected a JSON array in paginated response")
        return data

    def _validated_next(self, url: str, endpoint: str) -> str:
        parts = urlsplit(url)
        if (parts.scheme, parts.netloc.lower()) != self._origin:
            raise GitHubResponseError(
                None, endpoint, "pagination link points outside the API origin"
            )
        return url

    def _backoff(self, attempt: int) -> float:
        delay = min(self._backoff_cap, self._backoff_base * (2 ** (attempt - 1)))
        return delay * (0.5 + self._rng() / 2)

    def _wait_or_raise(self, wait: float, endpoint: str, status: int | None, message: str) -> None:
        if wait > self._max_wait:
            raise GitHubRateLimited(status, endpoint, message, retry_at=self._clock() + wait)
        self.rate_limit.waits_seconds += wait
        self._sleep(wait)

    def _respect_known_exhaustion(self, endpoint: str) -> None:
        state = self.rate_limit
        if state.remaining == 0 and state.reset_at is not None:
            wait = state.reset_at - self._clock()
            if wait > 0:
                self._wait_or_raise(
                    wait + 1, endpoint, None, "primary rate limit exhausted (not sent)"
                )
                state.remaining = None

    def _update_rate_limit(self, headers: httpx.Headers) -> None:
        state = self.rate_limit

        def as_int(name: str) -> int | None:
            value = headers.get(name)
            try:
                return int(value) if value is not None else None
            except ValueError:
                return None

        remaining = as_int("x-ratelimit-remaining")
        if remaining is not None:
            state.remaining = remaining
            state.limit = as_int("x-ratelimit-limit")
            reset = as_int("x-ratelimit-reset")
            state.reset_at = float(reset) if reset is not None else None
            state.used = as_int("x-ratelimit-used")
            resource = headers.get("x-ratelimit-resource")
            state.resource = _clean(resource, 40) if resource else None
        scopes = headers.get("x-oauth-scopes")
        if scopes is not None:
            self.token_scopes = tuple(s.strip() for s in scopes.split(",") if s.strip())
        expiration = headers.get("github-authentication-token-expiration")
        if expiration:
            self.token_expiration = _clean(expiration, 64)

    def _rate_limit_wait(self, response: httpx.Response, message: str) -> float | None:
        """Seconds to wait if the error response is a rate limit, else None."""
        retry_after = response.headers.get("retry-after")
        if retry_after is not None:
            try:
                self.rate_limit.secondary_hits += 1
                return max(1.0, float(retry_after))
            except ValueError:
                pass
        if response.headers.get("x-ratelimit-remaining") == "0":
            reset = self.rate_limit.reset_at
            return max(1.0, (reset - self._clock()) + 1) if reset is not None else 60.0
        if _SECONDARY_RE.search(message) or response.status_code == 429:
            self.rate_limit.secondary_hits += 1
            # GitHub: wait at least one minute, then back off exponentially.
            return min(900.0, 60.0 * (2 ** min(self.rate_limit.secondary_hits - 1, 4)))
        return None

    def _read_body(self, response: httpx.Response, endpoint: str, limit: int) -> bytes:
        declared = response.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            raise GitHubResponseError(
                response.status_code, endpoint, f"response exceeds {limit} bytes"
            )
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > limit:
                raise GitHubResponseError(
                    response.status_code, endpoint, f"response exceeds {limit} bytes"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    @staticmethod
    def _error_message(body: bytes) -> str:
        try:
            data = json.loads(body.decode("utf-8", errors="replace")) if body else None
        except ValueError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("message"), str):
            return data["message"]
        return "no error message"

    def _request(
        self,
        url: str,
        *,
        params: QueryParams | None,
        etag: str | None,
        raw: bool = False,
        max_bytes: int | None = None,
    ) -> ApiResponse:
        endpoint = urlsplit(url).path or url
        headers: dict[str, str] = {}
        if etag:
            headers["If-None-Match"] = etag
        if raw:
            headers["Accept"] = RAW_ACCEPT
        limit = max_bytes or self._max_bytes
        query = {
            k: (str(v).lower() if isinstance(v, bool) else str(v))
            for k, v in (params or {}).items()
        }
        attempt = 0
        while True:
            attempt += 1
            self._respect_known_exhaustion(endpoint)
            try:
                self.request_count += 1
                with self._http.stream(
                    "GET", url, params=query or None, headers=headers
                ) as response:
                    body = self._read_body(response, endpoint, limit)
            except httpx.TransportError as exc:  # timeouts, connection errors, protocol errors
                if attempt < self._max_attempts:
                    self._sleep(self._backoff(attempt))
                    continue
                raise GitHubTransientError(
                    None, endpoint, f"network error ({type(exc).__name__})"
                ) from None
            except httpx.TooManyRedirects:
                raise GitHubResponseError(None, endpoint, "too many redirects") from None
            self._update_rate_limit(response.headers)
            status = response.status_code
            response_etag = response.headers.get("etag")
            links = parse_link_header(response.headers.get("link"))
            if status == 304:
                self.not_modified_count += 1
                return ApiResponse(304, None, response_etag or etag, True, links)
            if 200 <= status < 300:
                return ApiResponse(
                    status,
                    self._parse_body(body, raw=raw, endpoint=endpoint, status=status),
                    response_etag,
                    False,
                    links,
                    {"content-type": response.headers.get("content-type", "")},
                )
            message = self._error_message(body)
            accepted = response.headers.get("x-accepted-github-permissions")
            if status in (403, 429):
                wait = self._rate_limit_wait(response, message)
                if wait is not None:
                    if attempt < self._max_attempts:
                        self._wait_or_raise(wait, endpoint, status, f"rate limited: {message}")
                        continue
                    raise GitHubRateLimited(
                        status, endpoint, message, retry_at=self._clock() + wait
                    )
                raise GitHubForbidden(status, endpoint, message, accepted_permissions=accepted)
            if status == 401:
                raise GitHubUnauthorized(status, endpoint, message)
            if status in (404, 410):
                raise GitHubNotFound(status, endpoint, message, accepted_permissions=accepted)
            if status == 409:
                raise GitHubConflict(status, endpoint, message)
            if status >= 500 or status == 408:
                if attempt < self._max_attempts:
                    self._sleep(self._backoff(attempt))
                    continue
                raise GitHubTransientError(status, endpoint, message)
            raise GitHubApiError(status, endpoint, message, accepted_permissions=accepted)

    @staticmethod
    def _parse_body(body: bytes, *, raw: bool, endpoint: str, status: int) -> Any:
        if status == 204 or not body:
            return None
        text = body.decode("utf-8", errors="replace")
        if raw:
            return text
        try:
            return json.loads(text)
        except ValueError:
            raise GitHubResponseError(status, endpoint, "response body is not valid JSON") from None

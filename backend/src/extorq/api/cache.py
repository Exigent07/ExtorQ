"""Short-TTL in-process cache for the analyst API's aggregate responses.

Why: every console page costs the API 10-20 ClickHouse queries, and one ClickHouse quota is
shared by every process using the ``extorq_api_ro`` identity. Overview, health, asset and
service coverage and rules change slowly compared with how often consoles render them, so
their computed responses are reused for ``EXTORQ_API_CACHE_TTL_SECONDS`` (default 15 s).

Properties:

* Keys are built by the route from its name and its validated query/path parameters only.
  Responses of these GET endpoints do not depend on the caller's role, and authentication
  runs before the cache is consulted.
* Single flight: concurrent misses of one key compute once; the others wait and reuse it.
* Exceptions are never cached (a failed computation is retried by the next request).
* ``clear()`` (called after every successful analyst mutation) drops every entry and
  bumps a generation counter, so a computation that started before the mutation is not
  stored afterwards.
* Bounded: at most ``max_entries`` responses (oldest evicted first).

A cached response is exactly what was computed at its ``generated_at``; the route adds
``X-ExtorQ-Cache: hit|miss|off`` and, on hits, ``X-ExtorQ-Cache-Age`` (seconds).
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Hashable
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request, Response

CACHE_HEADER = "X-ExtorQ-Cache"
CACHE_AGE_HEADER = "X-ExtorQ-Cache-Age"


@dataclass
class _Flight:
    lock: threading.Lock = field(default_factory=threading.Lock)
    users: int = 0


@dataclass(frozen=True)
class CacheResult:
    hit: bool
    age_seconds: float


class ResponseCache:
    """Thread-safe TTL cache with per-key single flight (sync FastAPI routes run in threads)."""

    def __init__(
        self,
        ttl_seconds: float,
        max_entries: int = 128,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ttl = float(ttl_seconds)
        self._max_entries = max(1, int(max_entries))
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[Hashable, tuple[float, Any]] = OrderedDict()
        self._flights: dict[Hashable, _Flight] = {}
        self._generation = 0
        self.hits = 0
        self.misses = 0

    @property
    def enabled(self) -> bool:
        return self._ttl > 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def _lookup(self, key: Hashable) -> tuple[bool, Any, float]:
        """Caller holds ``_lock``. Expired entries are dropped."""
        entry = self._entries.get(key)
        if entry is None:
            return False, None, 0.0
        stored_at, value = entry
        age = self._clock() - stored_at
        if age < 0 or age >= self._ttl:
            del self._entries[key]
            return False, None, 0.0
        return True, value, age

    def get_or_compute[T](self, key: Hashable, compute: Callable[[], T]) -> tuple[T, CacheResult]:
        if not self.enabled:
            return compute(), CacheResult(hit=False, age_seconds=0.0)
        with self._lock:
            hit, value, age = self._lookup(key)
            if hit:
                self.hits += 1
                return value, CacheResult(hit=True, age_seconds=age)
            flight = self._flights.setdefault(key, _Flight())
            flight.users += 1
        try:
            with flight.lock:
                with self._lock:
                    hit, value, age = self._lookup(key)
                    if hit:
                        self.hits += 1
                        return value, CacheResult(hit=True, age_seconds=age)
                    generation = self._generation
                computed = compute()
                with self._lock:
                    self.misses += 1
                    if generation == self._generation:
                        self._entries[key] = (self._clock(), computed)
                        self._entries.move_to_end(key)
                        while len(self._entries) > self._max_entries:
                            self._entries.popitem(last=False)
                return computed, CacheResult(hit=False, age_seconds=0.0)
        finally:
            with self._lock:
                flight.users -= 1
                if flight.users == 0 and self._flights.get(key) is flight:
                    del self._flights[key]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._generation += 1


def response_cache(request: Request) -> ResponseCache:
    cache: ResponseCache = request.app.state.response_cache
    return cache


def cached[T](
    request: Request, response: Response, key: tuple[Any, ...], compute: Callable[[], T]
) -> T:
    """Serve ``compute()`` through the app's response cache and label the response."""
    cache = response_cache(request)
    value, result = cache.get_or_compute(key, compute)
    if not cache.enabled:
        response.headers[CACHE_HEADER] = "off"
    elif result.hit:
        response.headers[CACHE_HEADER] = "hit"
        response.headers[CACHE_AGE_HEADER] = str(int(result.age_seconds))
    else:
        response.headers[CACHE_HEADER] = "miss"
    return value


def invalidate(request: Request) -> None:
    """Drop every cached response (after an analyst mutation changed stored state)."""
    response_cache(request).clear()

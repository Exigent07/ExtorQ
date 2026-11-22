"""Daily cap for paid Jev calls.

Accounting is persisted: the number of provider attempts recorded today (UTC day) in
``ai_assessments`` is the shared source of truth across processes. An in-process guard
adds calls that are in flight (reserved, not yet stored) and calls whose storage failed,
so a ClickHouse write outage cannot turn into unbounded spending. If the persisted count
cannot be read the guard fails closed (no call).

Concurrency note: two *processes* may each pass the check for the last slot at the same
moment, so the cap can be exceeded by at most the number of concurrently running
processes minus one. Within a process the check and the reservation are atomic.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from extorq.contracts.ai import AIProvider
from extorq.contracts.common import utc_now


class BudgetExceeded(Exception):
    def __init__(self, provider: AIProvider, used: int, cap: int) -> None:
        super().__init__(f"daily_cap_reached ({used}/{cap} {provider.value} calls today, UTC)")
        self.used = used
        self.cap = cap


class BudgetUnavailable(Exception):
    """The persisted usage count could not be read (fail closed)."""


def utc_day_start(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


@dataclass
class Reservation:
    """One reserved call slot; :meth:`finish` must be called once the attempt is over."""

    guard: BudgetGuard
    #: UTC day the slot was reserved on.
    day: datetime | None = None
    _done: bool = False
    _counted_unsaved: bool = False

    def finish(self, *, persisted: bool) -> None:
        """Release the in-flight slot; unpersisted attempts keep counting today."""
        if not self._done:
            self._done = True
            self._counted_unsaved = not persisted
            self.guard._release(persisted=persisted)

    def persisted_later(self) -> None:
        """The attempt was finished unsaved and stored by a later write retry.

        The stored row now counts in the persisted total, so the in-process count drops it
        (same UTC day only; a new day already reset the in-process count).
        """
        if self._counted_unsaved:
            self._counted_unsaved = False
            self.guard._persisted_later(self.day)


class BudgetGuard:
    """Per-provider daily cap with persisted counting and an in-process guard."""

    def __init__(
        self, provider: AIProvider, daily_cap: int, *, clock: Callable[[], datetime] = utc_now
    ) -> None:
        self.provider = provider
        self.daily_cap = daily_cap
        self._clock = clock
        self._lock = threading.Lock()
        self._day: datetime | None = None
        self._inflight = 0
        self._unsaved = 0

    def _roll_day(self, now: datetime) -> datetime:
        day = utc_day_start(now)
        if self._day != day:
            self._day = day
            self._unsaved = 0
        return day

    def try_reserve(self, count_persisted: Callable[[datetime], int]) -> Reservation:
        """Reserve one call or raise BudgetExceeded / BudgetUnavailable."""
        with self._lock:
            day = self._roll_day(self._clock())
            try:
                persisted = int(count_persisted(day))
            except Exception as exc:  # noqa: BLE001 - any storage failure means "cannot verify"
                raise BudgetUnavailable(
                    f"budget_check_unavailable ({type(exc).__name__})"
                ) from None
            used = persisted + self._inflight + self._unsaved
            if used >= self.daily_cap:
                raise BudgetExceeded(self.provider, used, self.daily_cap)
            self._inflight += 1
            return Reservation(self, day)

    def _release(self, *, persisted: bool) -> None:
        with self._lock:
            self._inflight = max(0, self._inflight - 1)
            if not persisted:
                self._unsaved += 1

    def _persisted_later(self, day: datetime | None) -> None:
        with self._lock:
            if day is not None and self._day == day and self._unsaved > 0:
                self._unsaved -= 1

    def used_estimate(self, persisted: int) -> int:
        with self._lock:
            return persisted + self._inflight + self._unsaved


_registry_lock = threading.Lock()
_guards: dict[AIProvider, BudgetGuard] = {}


def shared_guard(provider: AIProvider, daily_cap: int) -> BudgetGuard:
    """Process-wide guard per provider, so short-lived service objects share one counter."""
    with _registry_lock:
        guard = _guards.get(provider)
        if guard is None or guard.daily_cap != daily_cap:
            guard = BudgetGuard(provider, daily_cap)
            _guards[provider] = guard
        return guard

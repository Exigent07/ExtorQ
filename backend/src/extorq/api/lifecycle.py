"""Asset and collector lifecycle at request time: ``active`` / ``stale`` / ``retired``.

Pure logic (no ClickHouse), unit-tested with synthetic rows. One :class:`Estate` is built
per request from the asset rows, every collector's latest health report and the newest
event time per asset. Every endpoint that reports asset coverage or lifecycle goes through
it, so an asset has the same state in every view at the same instant.

Rules (also in ``docs/api/README.md``):

* A collector is **reporting** while its latest health report (``last_reported_at``) is no
  older than the retirement window, or 3 x its interval when that is longer. The collector
  runner reports health every cycle for every enabled collector, failed cycles included; a
  collector that is removed from or disabled in ``config/collectors`` (or a one-off test
  run) stops reporting. The API cannot read the host's collector configuration (it runs in
  a container without it), so "no reporting collector" is the observable form of "no
  enabled collector configured".
* **Self-tests** (collector type ``heartbeat`` or only ``extorq.*`` pipeline sources: the
  SDK heartbeat, A-IC-1) collect no telemetry of their asset: they never count toward its
  coverage and never keep it configured.
* An asset is **retired** when no telemetry collector covering it (its own or an
  ancestor's: a cluster covers its nodes) is reporting AND it was not observed (newer of the
  asset record's ``last_seen`` and its newest event) within the retirement window.
* Otherwise it is **stale** when not observed for longer than the stale threshold
  (``asset_stale_seconds``, or 3 x the shortest interval of its reporting collectors when
  that is longer, so an asset refreshed by a daily scan is not stale between scans); else
  **active**.
* A collector is **retired** when it reports for a retired asset, or is a self-test that
  stopped reporting; otherwise **stale** when its ``stale`` flag is set, else **active**.

Nothing is deleted. Retired assets and collectors stay available (``include_retired=true``,
asset detail) with their history; the rollups (asset coverage per class, findings KPI,
collection health, service coverage) leave them out by default. Open alerts are never
filtered by lifecycle: silencing an asset's collectors must not hide its detections.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime

from extorq.api import schemas as s
from extorq.api import service
from extorq.api.repository import Row
from extorq.api.settings import EXPECTED_ASSET_TYPES


@dataclass(frozen=True)
class AssetLifecycle:
    state: s.LifecycleState
    #: Newer of the asset record's ``last_seen`` and its newest event (``None``: neither).
    last_observed_at: datetime | None
    #: API-derived explanation for ``stale`` / ``retired`` (never telemetry text).
    reason: str | None = None


def reporting_window_seconds(collector: s.CollectorStatus, retire_seconds: int) -> int:
    """How long a collector counts as configured after its latest health report."""
    return max(retire_seconds, service.STALE_FACTOR * max(collector.interval_seconds, 0))


def is_reporting(collector: s.CollectorStatus, now: datetime, retire_seconds: int) -> bool:
    age = (now - collector.last_reported_at).total_seconds()
    return age <= reporting_window_seconds(collector, retire_seconds)


def _newest(*values: datetime | None) -> datetime | None:
    present = [value for value in values if value is not None]
    return max(present) if present else None


def last_event_map(rows: Iterable[Row]) -> dict[str, datetime | None]:
    """``asset_id -> newest event_time`` from ``Repository.asset_last_events`` rows."""
    return {str(row["asset_id"]): row.get("last_event_at") for row in rows}


class Estate:
    """Lifecycle of every asset and collector at ``now`` (build one per request)."""

    def __init__(
        self,
        assets: Iterable[Row],
        collectors: Sequence[s.CollectorStatus],
        last_event_at: Mapping[str, datetime | None],
        now: datetime,
        *,
        stale_seconds: int,
        retire_seconds: int,
    ) -> None:
        self._now = now
        self._stale_seconds = stale_seconds
        self._retire_seconds = retire_seconds
        self._last_event_at = dict(last_event_at)
        self._telemetry = [c for c in collectors if not c.self_test]
        self._assets: dict[str, AssetLifecycle] = {}
        for row in assets:
            asset_id = str(row["asset_id"])
            self._assets[asset_id] = self.evaluate(
                asset_id, row.get("last_seen"), self._last_event_at.get(asset_id)
            )
        self._retired = frozenset(
            asset_id for asset_id, lc in self._assets.items() if lc.state == "retired"
        )
        self._collectors = [self._with_lifecycle(c) for c in collectors]

    # -- assets --

    def evaluate(
        self, asset_id: str, last_seen: datetime | None, last_event_at: datetime | None
    ) -> AssetLifecycle:
        """Lifecycle of one asset from its observation times and covering collectors."""
        observed = _newest(last_seen, last_event_at)
        age = None if observed is None else (self._now - observed).total_seconds()
        covering = service.collectors_for_asset(asset_id, self._telemetry)
        reporting = [c for c in covering if is_reporting(c, self._now, self._retire_seconds)]
        if not reporting and (age is None or age > self._retire_seconds):
            seen = "was never observed" if age is None else f"was last observed {int(age)}s ago"
            return AssetLifecycle(
                "retired",
                observed,
                f"no collector covering it has reported within {self._retire_seconds}s and it "
                f"{seen}",
            )
        intervals = [c.interval_seconds for c in reporting if c.interval_seconds > 0]
        threshold = self._stale_seconds
        if intervals:
            threshold = max(threshold, service.STALE_FACTOR * min(intervals))
        if age is not None and age > threshold:
            tail = (
                "a collector covering it reported within the retirement window"
                if reporting
                else "no collector covering it reports; retired once unobserved for "
                f"{self._retire_seconds}s"
            )
            return AssetLifecycle(
                "stale", observed, f"last observed {int(age)}s ago (threshold {threshold}s); {tail}"
            )
        return AssetLifecycle("active", observed)

    def lifecycle(self, asset_id: str) -> AssetLifecycle | None:
        return self._assets.get(asset_id)

    def is_retired(self, asset_id: str) -> bool:
        return asset_id in self._retired

    @property
    def retired_asset_ids(self) -> frozenset[str]:
        return self._retired

    def asset_item(self, row: Row, open_alerts: int) -> s.AssetListItem:
        """``AssetListItem`` with coverage (telemetry collectors) and lifecycle."""
        asset_id = str(row["asset_id"])
        last_event_at = self._last_event_at.get(asset_id)
        lifecycle = self.lifecycle(asset_id) or self.evaluate(
            asset_id, row.get("last_seen"), last_event_at
        )
        return service.asset_item(
            row,
            self.coverage_collectors(asset_id),
            last_event_at,
            open_alerts,
            lifecycle_state=lifecycle.state,
            last_observed_at=lifecycle.last_observed_at,
            lifecycle_reason=lifecycle.reason,
        )

    def summary(self, *, include_retired: bool) -> s.AssetLifecycleSummary:
        states = [lc.state for lc in self._assets.values()]
        return s.AssetLifecycleSummary(
            stale_after_seconds=self._stale_seconds,
            retire_after_seconds=self._retire_seconds,
            active=states.count("active"),
            stale=states.count("stale"),
            retired=states.count("retired"),
            retired_asset_ids=sorted(self._retired),
            include_retired=include_retired,
        )

    def class_coverage(
        self, assets: Sequence[Row], event_rows: Iterable[Row], *, include_retired: bool
    ) -> list[s.AssetClassCoverage]:
        """Coverage per asset class; retired assets only counted in ``assets_retired``
        unless ``include_retired`` (then they are part of every count as well)."""
        by_type: dict[str, list[Row]] = defaultdict(list)
        for asset in assets:
            by_type[str(asset["asset_type"])].append(asset)
        last_by_type: dict[str, datetime] = {}
        for row in event_rows:
            event_time = row.get("last_event_at")
            asset_type = str(row.get("asset_type") or "")
            if event_time is None or not asset_type:
                continue
            if not include_retired and self.is_retired(str(row["asset_id"])):
                continue
            if asset_type not in last_by_type or event_time > last_by_type[asset_type]:
                last_by_type[asset_type] = event_time
        ordered = list(EXPECTED_ASSET_TYPES) + sorted(
            t for t in by_type if t not in EXPECTED_ASSET_TYPES
        )
        result: list[s.AssetClassCoverage] = []
        for asset_type in ordered:
            members = by_type.get(asset_type, [])
            retired = sum(1 for a in members if self.is_retired(str(a["asset_id"])))
            counted = (
                members
                if include_retired
                else [a for a in members if not self.is_retired(str(a["asset_id"]))]
            )
            statuses = [
                service.coverage_status(self.coverage_collectors(str(a["asset_id"])))
                for a in counted
            ]
            result.append(
                s.AssetClassCoverage(
                    asset_type=asset_type,
                    expected=asset_type in EXPECTED_ASSET_TYPES,
                    assets_total=len(counted),
                    assets_ok=statuses.count("ok"),
                    assets_degraded=statuses.count("degraded"),
                    assets_stale=statuses.count("stale"),
                    assets_without_collector=statuses.count("missing"),
                    status=service.class_status(statuses),
                    last_event_at=last_by_type.get(asset_type),
                    assets_retired=retired,
                )
            )
        return result

    # -- collectors --

    def _with_lifecycle(self, collector: s.CollectorStatus) -> s.CollectorStatus:
        state: s.LifecycleState
        if collector.asset_id in self._retired or (
            collector.self_test and not is_reporting(collector, self._now, self._retire_seconds)
        ):
            state = "retired"
        elif collector.stale:
            state = "stale"
        else:
            state = "active"
        if collector.lifecycle_state == state:
            return collector
        return collector.model_copy(update={"lifecycle_state": state})

    def collectors(self, *, include_retired: bool) -> list[s.CollectorStatus]:
        """Every collector with its lifecycle; retired ones only with ``include_retired``."""
        return [c for c in self._collectors if include_retired or c.lifecycle_state != "retired"]

    @property
    def retired_collectors(self) -> int:
        return sum(1 for c in self._collectors if c.lifecycle_state == "retired")

    def coverage_collectors(self, asset_id: str) -> list[s.CollectorStatus]:
        """Telemetry collectors covering ``asset_id`` (own + ancestors), with lifecycle.

        Self-tests are left out (A-IC-1). Retired collectors stay: they only exist on a
        retired asset (whose coverage then shows what stopped) or on its descendants.
        """
        return [
            c for c in service.collectors_for_asset(asset_id, self._collectors) if not c.self_test
        ]

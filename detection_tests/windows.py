"""Pure time-window logic: bounds, alert selection, quiet periods, conclusive negatives.

No I/O here, so every decision the runner makes about time is unit-tested
(``tests/unit/detection_tests/test_detection_tests_windows.py``).

Why each rule exists:

* **Bounded waits.** A positive test waits at most one detection latency for its alert:
  the evidence source's interval (times the cycles the action may need), the collector loop
  tick, the pipeline, the rule's own interval, the detector's ingest delay and a margin.
  Waiting longer would only hide a broken collector or rule.
* **first_seen in the window.** The alert must be about this activity: its earliest
  evidence lies between the start of the action (minus a small clock-skew tolerance for the
  VM's clock) and the end of the wait, and it did not exist before the action started.
* **Quiet periods.** Threshold rules (dedup ``window_bucket``) extend an open alert of the
  same group when new activity follows within ``bucket_seconds``; a positive test then sees
  an *extended* alert, not a new one. The runner waits until the previous alert of the rule
  on the asset is older than that gap before acting.
* **Separation.** A threshold rule's negative control must not share a sliding window with
  the positive action (one failed login after six failed logins would legitimately extend
  the burst), so it starts at least the rule's window after the positive action ended.
* **Conclusive negatives.** "No alert" means something only once the control's own events
  are stored and a successful rule run started after they were ingested and covered their
  event time; until then the runner keeps waiting (bounded).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from detection_tests.model import TelemetryExpectation

#: Detector default (``EXTORQ_DETECTOR_INGEST_DELAY_SECONDS``): window end lag behind "now".
DEFAULT_INGEST_DELAY_SECONDS = 10


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_time(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp from the API into an aware UTC datetime (or ``None``)."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        # The API always sends aware timestamps; a naive one is treated as UTC rather than
        # local time so a misbehaving server cannot shift windows by the Mac's UTC offset.
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def format_time(value: datetime) -> str:
    """``2026-11-23T09:15:00.123Z``: millisecond precision, matching storage."""
    value = value.astimezone(UTC)
    return value.strftime("%Y-%m-%dT%H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"


# ── bounds ───────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Timing:
    """Inputs of one test's detection latency, kept for the report."""

    source_seconds: int
    loop_seconds: int
    cycles: int
    pipeline_seconds: int
    rule_interval_seconds: int
    ingest_delay_seconds: int
    margin_seconds: int

    @property
    def base_seconds(self) -> int:
        return (
            self.cycles * self.source_seconds
            + self.loop_seconds
            + self.pipeline_seconds
            + self.rule_interval_seconds
            + self.ingest_delay_seconds
        )

    @property
    def bound_seconds(self) -> int:
        return self.base_seconds + self.margin_seconds

    def describe(self) -> str:
        cycles = f"{self.cycles} x " if self.cycles != 1 else ""
        return (
            f"{self.bound_seconds}s = source {cycles}{self.source_seconds}s"
            f" + collector loop {self.loop_seconds}s + pipeline {self.pipeline_seconds}s"
            f" + rule interval {self.rule_interval_seconds}s"
            f" + ingest delay {self.ingest_delay_seconds}s + margin {self.margin_seconds}s"
        )


def detection_timing(
    *,
    source_seconds: int,
    loop_seconds: int,
    cycles: int,
    pipeline_seconds: int,
    rule_interval_seconds: int,
    ingest_delay_seconds: int = DEFAULT_INGEST_DELAY_SECONDS,
    min_margin_seconds: int = 60,
    margin_fraction: float = 0.2,
) -> Timing:
    """Detection latency with a margin of ``max(min_margin, fraction * base)``.

    The proportional part keeps slow sources (a 5-minute inventory, a 2-minute GitHub
    poll) from timing out on ordinary jitter; the floor covers fast ones.
    """
    for name, value in (
        ("source_seconds", source_seconds),
        ("loop_seconds", loop_seconds),
        ("pipeline_seconds", pipeline_seconds),
        ("rule_interval_seconds", rule_interval_seconds),
        ("ingest_delay_seconds", ingest_delay_seconds),
        ("min_margin_seconds", min_margin_seconds),
    ):
        if value < 0:
            raise ValueError(f"{name} must be >= 0")
    if cycles < 1:
        raise ValueError("cycles must be >= 1")
    base = cycles * source_seconds + loop_seconds + pipeline_seconds
    base += rule_interval_seconds + ingest_delay_seconds
    margin = max(min_margin_seconds, math.ceil(base * max(0.0, margin_fraction)))
    return Timing(
        source_seconds=source_seconds,
        loop_seconds=loop_seconds,
        cycles=cycles,
        pipeline_seconds=pipeline_seconds,
        rule_interval_seconds=rule_interval_seconds,
        ingest_delay_seconds=ingest_delay_seconds,
        margin_seconds=margin,
    )


# ── alert selection ──────────────────────────────────────────────────────────────────


def in_window(when: datetime, start: datetime, end: datetime, *, skew_seconds: float = 0.0) -> bool:
    """``start - skew <= when <= end``."""
    return start - timedelta(seconds=skew_seconds) <= when <= end


def select_new_alerts(
    alerts: Iterable[Mapping[str, Any]],
    *,
    rule_id: str | None,
    asset_id: str,
    start: datetime,
    end: datetime,
    baseline_ids: frozenset[str] | set[str],
    skew_seconds: float,
) -> list[Mapping[str, Any]]:
    """Alerts (API list items) that are new and whose ``first_seen`` lies in the window.

    ``rule_id=None`` selects every rule (used to report overlaps). Alerts that already
    existed when the phase started (``baseline_ids``) never count, even if new activity
    extended them: that activity is then not what the alert is about.
    """
    selected: list[Mapping[str, Any]] = []
    for alert in alerts:
        if alert.get("asset_id") != asset_id:
            continue
        if rule_id is not None and alert.get("rule_id") != rule_id:
            continue
        if str(alert.get("alert_id")) in baseline_ids:
            continue
        first_seen = parse_time(alert.get("first_seen"))
        if first_seen is None or not in_window(first_seen, start, end, skew_seconds=skew_seconds):
            continue
        selected.append(alert)
    selected.sort(key=lambda a: (str(a.get("first_seen")), str(a.get("alert_id"))))
    return selected


def joined_alerts(
    alerts: Iterable[Mapping[str, Any]],
    *,
    rule_id: str,
    asset_id: str,
    start: datetime,
    baseline_ids: frozenset[str] | set[str],
    skew_seconds: float,
) -> list[Mapping[str, Any]]:
    """Alerts created after the phase began whose ``first_seen`` precedes it (batch mode).

    Window-bucket rules cite ALL activity of the bucket, so when a test runs negative-first the
    alert raised by the positive also cites the benign control's events and starts at the
    control. Such an alert only counts if it is new (not in the baseline), still active inside
    the window, and the caller then verifies that its evidence contains the positive's telemetry.
    """
    selected: list[Mapping[str, Any]] = []
    for alert in alerts:
        if alert.get("asset_id") != asset_id or alert.get("rule_id") != rule_id:
            continue
        if str(alert.get("alert_id")) in baseline_ids:
            continue
        last_seen = parse_time(alert.get("last_seen"))
        if last_seen is None or last_seen < start - timedelta(seconds=skew_seconds):
            continue
        selected.append(alert)
    selected.sort(key=lambda a: (str(a.get("first_seen")), str(a.get("alert_id"))))
    return selected


def extended_alerts(
    alerts: Iterable[Mapping[str, Any]],
    *,
    rule_id: str,
    asset_id: str,
    start: datetime,
    baseline_last_seen: Mapping[str, datetime],
) -> list[str]:
    """Pre-existing alerts whose ``last_seen`` moved into the window.

    A threshold rule extends an open alert of the same group instead of opening a new one,
    so after a negative control this is a false positive just like a new alert; after a
    positive action it explains a missing new alert (quiet period too short).
    """
    extended: list[str] = []
    for alert in alerts:
        alert_id = str(alert.get("alert_id"))
        if alert.get("rule_id") != rule_id or alert.get("asset_id") != asset_id:
            continue
        before = baseline_last_seen.get(alert_id)
        last_seen = parse_time(alert.get("last_seen"))
        if before is None or last_seen is None:
            continue
        if last_seen > before and last_seen >= start:
            extended.append(alert_id)
    return sorted(extended)


# ── waiting rules ────────────────────────────────────────────────────────────────────


def quiet_period_remaining(
    latest_last_seen: datetime | None, *, gap_seconds: int, margin_seconds: int, now: datetime
) -> float:
    """Seconds to wait so new activity cannot extend the latest alert of the rule.

    The engine extends an open ``window_bucket`` alert when the new activity starts at most
    ``gap_seconds`` after the alert's ``last_seen``; after ``gap + margin`` a new alert opens.
    """
    if latest_last_seen is None or gap_seconds <= 0:
        return 0.0
    ready_at = latest_last_seen + timedelta(seconds=gap_seconds + margin_seconds)
    return max(0.0, (ready_at - now).total_seconds())


def separation_remaining(
    previous_action_end: datetime | None,
    *,
    window_seconds: int,
    margin_seconds: int,
    now: datetime,
) -> float:
    """Seconds until a threshold rule's sliding window no longer reaches the previous action."""
    if previous_action_end is None or window_seconds <= 0:
        return 0.0
    ready_at = previous_action_end + timedelta(seconds=window_seconds + margin_seconds)
    return max(0.0, (ready_at - now).total_seconds())


def rule_window_seconds(rule: Mapping[str, Any]) -> int:
    """Longest sliding window over which a deployed rule COUNTS events (0 if it does not).

    Reads the rule record from ``GET /api/v1/rules/{id}``: ``params.window_seconds`` (VM-001,
    HTTP-001, APP-001, MAC-004, K8S-004) and ``params.sequence_seconds`` (CORR-002). The
    continuation gap (``dedup.bucket_seconds``) is deliberately not part of it: activity
    that extends an existing alert is caught by the negative check itself
    (:func:`extended_alerts`), it does not need a wait.
    """
    params = rule.get("params") if isinstance(rule.get("params"), Mapping) else {}
    candidates: list[int] = []
    for key in ("window_seconds", "sequence_seconds"):
        value = params.get(key) if isinstance(params, Mapping) else None
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            candidates.append(value)
    return max(candidates, default=0)


def continuation_gap_seconds(rule: Mapping[str, Any]) -> int:
    """``bucket_seconds`` of a ``window_bucket`` rule (the engine's continuation gap), else 0."""
    dedup = rule.get("dedup") if isinstance(rule.get("dedup"), Mapping) else {}
    if not isinstance(dedup, Mapping) or dedup.get("strategy") != "window_bucket":
        return 0
    bucket = dedup.get("bucket_seconds")
    return bucket if isinstance(bucket, int) and not isinstance(bucket, bool) else 0


# ── telemetry matching ───────────────────────────────────────────────────────────────


def event_matches(event: Mapping[str, Any], expectation: TelemetryExpectation) -> bool:
    if event.get("event_type") != expectation.event_type:
        return False
    for key, value in expectation.equals:
        if event.get(key) != value:
            return False
    for key, needle in expectation.contains:
        field_value = event.get(key)
        if not isinstance(field_value, str) or needle not in field_value:
            return False
    return all(event.get(key) in (None, "") for key in expectation.is_null)


@dataclass(frozen=True)
class TelemetryMatch:
    matched: int
    latest_event_time: datetime | None
    latest_ingested_time: datetime | None
    earliest_event_time: datetime | None


def match_telemetry(
    events: Sequence[Mapping[str, Any]], expectation: TelemetryExpectation
) -> TelemetryMatch:
    """Count matching events (duplicates by ``event_id`` collapse) and their latest times."""
    seen: set[str] = set()
    latest_event: datetime | None = None
    latest_ingested: datetime | None = None
    earliest_event: datetime | None = None
    for event in events:
        if not event_matches(event, expectation):
            continue
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            continue
        if event_id in seen:
            continue
        seen.add(event_id)
        event_time = parse_time(event.get("event_time"))
        ingested = parse_time(event.get("ingested_time"))
        if event_time is not None and (latest_event is None or event_time > latest_event):
            latest_event = event_time
        if event_time is not None and (earliest_event is None or event_time < earliest_event):
            earliest_event = event_time
        if ingested is not None and (latest_ingested is None or ingested > latest_ingested):
            latest_ingested = ingested
    return TelemetryMatch(len(seen), latest_event, latest_ingested, earliest_event)


def conclusive_run(
    runs: Iterable[Mapping[str, Any]],
    *,
    ingested_after: datetime,
    event_time: datetime,
    earliest_event_time: datetime | None = None,
    ingest_delay_seconds: int = DEFAULT_INGEST_DELAY_SECONDS,
) -> Mapping[str, Any] | None:
    """The earliest successful rule run that must have seen the given telemetry.

    A run evaluates ``[now - lookback, now - ingest_delay)`` when it starts. It has seen an
    event when it started after the event was ingested (plus the ingest delay, because the
    window end lags) and its window end lies after the event time.
    """
    threshold = ingested_after + timedelta(seconds=ingest_delay_seconds)
    best: Mapping[str, Any] | None = None
    best_started: datetime | None = None
    for run in runs:
        if run.get("status") != "succeeded":
            continue
        started = parse_time(run.get("started_at"))
        window_start = parse_time(run.get("window_start"))
        window_end = parse_time(run.get("window_end"))
        finished = parse_time(run.get("finished_at"))
        if started is None or window_start is None or window_end is None or finished is None:
            continue
        if started < threshold or window_start > (earliest_event_time or event_time):
            continue
        if event_time >= window_end:
            continue
        if best_started is None or started < best_started:
            best, best_started = run, started
    return best

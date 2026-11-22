"""Test runner: preconditions, real actions, bounded waits, negative controls, cleanup.

Life of one test (``Runner.run_test``)::

    preconditions   rule deployed and running, asset reachable, collector fresh, test checks
    quiet period    threshold rules only: the previous alert of the rule must be old enough
                    that new activity opens a NEW alert instead of extending it
    setup           shared fixtures (e.g. a namespace), removed after both phases
    positive        baseline of existing alerts -> REAL action -> wait (bounded) for a new
                    alert of the rule on the asset with first_seen in the window -> cleanup
    separation      threshold rules only: the negative control starts outside the positive
                    action's sliding window
    negative        baseline -> benign control action -> watch until conclusive (its own
                    telemetry stored and evaluated by a later rule run) or the bound -> no
                    new alert of the rule allowed -> cleanup

Cleanup always runs (``try``/``finally`` per phase, undo steps registered before each
change). The first Ctrl-C (or SIGTERM) stops at the next wait, finishes cleanup and still
writes the report; a second one aborts immediately (``python -m detection_tests cleanup``
then removes leftovers).

The runner matches new alerts by asset, rule and time window, then verifies their cited
events against the action's telemetry expectations and authenticated producers.
"""

from __future__ import annotations

import re
import secrets
import sys
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, TextIO

from detection_tests.api import ApiError
from detection_tests.model import (
    ARTEFACT_PREFIX,
    ActionFailed,
    ActionRecord,
    AlertObservation,
    AssetRef,
    Cancelled,
    CleanupStack,
    DetectionTest,
    OtherAlert,
    PhaseKind,
    PhaseOutcome,
    PhaseResult,
    PreconditionFailed,
    StepResult,
    TelemetryExpectation,
    TelemetryObservation,
    TestResult,
    TestSpec,
    TestStatus,
    Window,
)
from detection_tests.proc import CommandError, display
from detection_tests.settings import evidence_producer, source_interval
from detection_tests.windows import (
    DEFAULT_INGEST_DELAY_SECONDS,
    Timing,
    conclusive_run,
    continuation_gap_seconds,
    detection_timing,
    event_matches,
    extended_alerts,
    format_time,
    match_telemetry,
    parse_time,
    quiet_period_remaining,
    rule_window_seconds,
    select_new_alerts,
    separation_remaining,
    utc_now,
)

#: ``TestResult.message`` / ``PhaseResult.message`` of a phase stopped by Ctrl-C or SIGTERM.
INTERRUPTED = "interrupted"


class ApiLike(Protocol):
    """The subset of :class:`detection_tests.api.AnalystApi` the runner uses (fakeable)."""

    def alerts(
        self,
        *,
        asset_id: str,
        since: datetime,
        until: datetime,
        rule_id: str | None = None,
        max_pages: int = 5,
    ) -> list[dict[str, Any]]: ...

    def alert_detail(self, alert_id: str) -> dict[str, Any] | None: ...

    def event_detail(self, event_id: str) -> dict[str, Any] | None: ...

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
        limit: int = 500,
    ) -> list[dict[str, Any]]: ...

    def rule(self, rule_id: str, *, runs_limit: int = 20) -> dict[str, Any] | None: ...

    def health(self) -> dict[str, Any]: ...


@dataclass(frozen=True)
class RunOptions:
    skip_negatives: bool = False
    #: Seconds between two API polls while waiting.
    poll_seconds: float = 10.0
    #: Tolerated clock difference between the Mac and an asset (the VM's journald clock).
    clock_skew_seconds: int = 30
    #: Minimum margin added to every detection bound (20 % of the base when larger).
    min_margin_seconds: int = 60
    #: Longest the runner waits for a quiet period before declaring the test blocked
    #: (covers the 15-minute episodes of K8S-003/K8S-004; CORR-002's 30 minutes do not fit).
    max_quiet_wait_seconds: int = 1200
    #: Detector window lag (``EXTORQ_DETECTOR_INGEST_DELAY_SECONDS``).
    ingest_delay_seconds: int = DEFAULT_INGEST_DELAY_SECONDS
    #: How far back the baseline of existing alerts is read at the start of each phase.
    baseline_lookback_seconds: int = 6 * 3600


class Clock:
    """Wall clock whose sleeps end early (raising :class:`Cancelled`) on cancellation."""

    def __init__(self, cancel: threading.Event | None = None) -> None:
        self.cancel = cancel or threading.Event()

    def now(self) -> datetime:
        return utc_now()

    def sleep(self, seconds: float) -> None:
        if seconds > 0 and self.cancel.wait(seconds):
            raise Cancelled(INTERRUPTED)
        self.check()

    def check(self) -> None:
        if self.cancel.is_set():
            raise Cancelled(INTERRUPTED)


class Output:
    """Thread-safe console lines: ``<UTC time> [<scope>] <message>`` (sanitised)."""

    def __init__(self, stream: TextIO | None = None, clock: Callable[[], datetime] = utc_now):
        self._stream = stream or sys.stdout
        self._lock = threading.Lock()
        self._clock = clock

    def line(self, scope: str, message: str) -> None:
        stamp = self._clock().strftime("%H:%M:%SZ")
        text = display(message, 600)
        with self._lock:
            print(f"{stamp} [{scope}] {text}", file=self._stream, flush=True)

    def scoped(self, scope: str) -> Callable[[str], None]:
        return lambda message: self.line(scope, message)


@dataclass
class TestContext:
    """What an action may use: paths, the API, the clock, options and output."""

    __test__ = False  # not a pytest test class

    root: Path
    api: ApiLike
    clock: Clock
    options: RunOptions
    out: Callable[[str], None]
    #: Detection bound of the current test (set by the runner before the phases run), so an
    #: action that must outlive the wait (MAC-003's listener) can size its own lifetime.
    bound_seconds: int | None = None

    def new_name(self) -> str:
        """A fresh artefact name: ``extorq-test-`` + 6 hex characters (CSPRNG)."""
        return f"{ARTEFACT_PREFIX}{secrets.token_hex(3)}"

    def wait(self, seconds: float, why: str) -> None:
        """Interruptible, announced wait (never used by cleanup steps)."""
        if seconds <= 0:
            return
        self.out(f"waiting {seconds:.0f}s: {why}")
        self.clock.sleep(seconds)

    def check_cancelled(self) -> None:
        self.clock.check()


@dataclass
class AssetSuite:
    """All tests of one asset plus its asset-wide checks and leftover sweep."""

    asset: AssetRef
    tests: list[DetectionTest]
    #: Asset-wide preconditions (reachability, credentials, files); raise to block.
    check: Callable[[TestContext], list[StepResult]]
    #: Removes leftovers of interrupted runs (``python -m detection_tests cleanup``).
    sweep: Callable[[TestContext], list[StepResult]]
    #: Collectors whose health (``GET /api/v1/health``) must be fresh for this asset.
    collector_ids: tuple[str, ...] = ()
    #: Extra run-only checks that telemetry of the asset flows (needs the analyst API);
    #: ``cleanup`` skips them so leftovers can be removed while the stack is down.
    telemetry_check: Callable[[TestContext], list[StepResult]] | None = None


@dataclass
class _Baseline:
    rule_ids: frozenset[str] = frozenset()
    all_ids: frozenset[str] = frozenset()
    rule_last_seen: dict[str, datetime] = field(default_factory=dict)


class Runner:
    """Executes suites and returns one :class:`TestResult` per selected test."""

    def __init__(
        self,
        *,
        root: Path,
        api: ApiLike,
        clock: Clock,
        options: RunOptions,
        output: Output,
    ) -> None:
        self.root = root
        self.api = api
        self.clock = clock
        self.options = options
        self.output = output

    # ── suites ──

    def run_suites(
        self, suites: Sequence[AssetSuite], *, parallel: bool = False
    ) -> list[TestResult]:
        """Run suites one after another, or one thread per asset with ``parallel``.

        Assets are independent (no rule correlates across them), so running them in parallel
        only shortens the wall-clock time; within an asset the order is fixed because some
        tests depend on it (see the Linux module's ordering note).
        """
        if not parallel or len(suites) <= 1:
            results: list[TestResult] = []
            for suite in suites:
                results.extend(self.run_suite(suite))
            return results
        with ThreadPoolExecutor(max_workers=len(suites), thread_name_prefix="suite") as pool:
            futures = [pool.submit(self.run_suite, suite) for suite in suites]
            ordered: list[TestResult] = []
            for future in futures:
                ordered.extend(future.result())
            return ordered

    def run_suite(self, suite: AssetSuite) -> list[TestResult]:
        out = self.output.scoped(suite.asset.key)
        ctx = TestContext(self.root, self.api, self.clock, self.options, out)
        results: list[TestResult] = []
        out(f"{len(suite.tests)} test(s) on {suite.asset.asset_id} ({suite.asset.label})")
        try:
            asset_checks = self._asset_checks(suite, ctx)
        except PreconditionFailed as exc:
            out(f"BLOCKED: {exc}")
            now = self.clock.now()
            for test in suite.tests:
                results.append(
                    TestResult(
                        spec=test.spec,
                        status=TestStatus.BLOCKED,
                        started_at=now,
                        finished_at=now,
                        message=f"asset precondition failed: {exc}",
                    )
                )
            return results
        cancelled = False
        for test in suite.tests:
            if cancelled or self.clock.cancel.is_set():
                cancelled = True
                now = self.clock.now()
                results.append(
                    TestResult(
                        spec=test.spec,
                        status=TestStatus.ERROR,
                        started_at=now,
                        finished_at=now,
                        message="not run: the run was interrupted",
                    )
                )
                continue
            result = self.run_test(test, asset_checks)
            results.append(result)
            if result.message == INTERRUPTED:
                cancelled = True
        return results

    def _asset_checks(self, suite: AssetSuite, ctx: TestContext) -> list[StepResult]:
        checks = list(suite.check(ctx))
        if all(c.ok for c in checks):
            checks.extend(self._collector_checks(suite))
            if suite.telemetry_check is not None:
                checks.extend(suite.telemetry_check(ctx))
        failed = [c for c in checks if not c.ok]
        if failed:
            raise PreconditionFailed("; ".join(f"{c.description}: {c.detail}" for c in failed))
        return checks

    def _collector_checks(self, suite: AssetSuite) -> list[StepResult]:
        if not suite.collector_ids:
            return []
        try:
            health = self.api.health()
        except ApiError as exc:
            return [StepResult("collector health", False, str(exc))]
        collectors = health.get("collectors") if isinstance(health, Mapping) else None
        by_id = {
            str(c.get("collector_id")): c
            for c in (collectors if isinstance(collectors, list) else [])
            if isinstance(c, Mapping)
        }
        results: list[StepResult] = []
        for collector_id in suite.collector_ids:
            entry = by_id.get(collector_id)
            if entry is None:
                results.append(
                    StepResult(
                        f"collector {collector_id}",
                        False,
                        "no health report: start it with `make collectors-start`",
                    )
                )
                continue
            status = str(entry.get("status"))
            if entry.get("stale") or status not in ("ok", "degraded"):
                since = entry.get("seconds_since_success")
                age = f"{float(since):.0f}s ago" if isinstance(since, int | float) else "never"
                results.append(
                    StepResult(
                        f"collector {collector_id}",
                        False,
                        f"status {status}, last success {age}: telemetry would not arrive",
                    )
                )
            else:
                results.append(StepResult(f"collector {collector_id}", True, f"status {status}"))
        return results

    # ── one test ──

    def run_test(self, test: DetectionTest, asset_checks: Sequence[StepResult] = ()) -> TestResult:
        spec = test.spec
        out = self.output.scoped(f"{spec.asset.key} {spec.rule_id}")
        ctx = TestContext(self.root, self.api, self.clock, self.options, out)
        result = TestResult(spec=spec, status=TestStatus.ERROR, started_at=self.clock.now())
        result.preconditions.extend(asset_checks)
        out(f"start: {spec.title}")
        try:
            rule, timing = self._rule_preconditions(spec, result)
            result.preconditions.extend(test.preconditions(ctx))
            self._quiet_period(spec, rule, ctx)
        except PreconditionFailed as exc:
            result.status = TestStatus.BLOCKED
            result.message = str(exc)
            result.finished_at = self.clock.now()
            out(f"BLOCKED: {exc}")
            return result
        except Cancelled:
            result.message = INTERRUPTED
            result.finished_at = self.clock.now()
            return result
        except (ApiError, CommandError) as exc:
            result.status = TestStatus.BLOCKED
            result.message = f"precondition check failed: {exc}"
            result.finished_at = self.clock.now()
            out(f"BLOCKED: {result.message}")
            return result
        except Exception as exc:  # noqa: BLE001 - a broken check must not stop the suite
            result.status = TestStatus.ERROR
            result.message = f"precondition check crashed: {type(exc).__name__}: {_describe(exc)}"
            result.finished_at = self.clock.now()
            out(f"ERROR: {result.message}")
            return result
        result.bound_seconds = ctx.bound_seconds = timing.bound_seconds
        out(f"detection bound {timing.describe()}")

        fixtures = CleanupStack(notify=out)
        interrupted = False
        try:
            try:
                result.fixtures = list(test.setup(ctx, fixtures))
            except Cancelled:
                raise
            except Exception as exc:  # noqa: BLE001 - recorded, fixtures are still removed
                result.message = f"setup failed: {_describe(exc)}"
                out(result.message)
                return result
            phases = (
                (PhaseKind.NEGATIVE, PhaseKind.POSITIVE)
                if spec.negative_first
                else (PhaseKind.POSITIVE, PhaseKind.NEGATIVE)
            )
            previous_end: datetime | None = None
            for kind in phases:
                if kind is PhaseKind.NEGATIVE and self.options.skip_negatives:
                    result.negative = PhaseResult(
                        kind, PhaseOutcome.SKIPPED, "skipped (--skip-negatives)"
                    )
                    continue
                if previous_end is not None:
                    ctx.wait(
                        self._phase_gap(spec, rule, kind, previous_end),
                        f"{spec.rule_id}: the {kind.value} phase must not share a detection "
                        "window with the previous phase",
                    )
                phase = self._run_phase(kind, test, ctx, timing, result.rule_version)
                if kind is PhaseKind.POSITIVE:
                    result.positive = phase
                else:
                    result.negative = phase
                if phase.window is not None:
                    previous_end = phase.window.action_end or previous_end
                if phase.message == INTERRUPTED:
                    interrupted = True
                    break
        except Cancelled:
            interrupted = True
        finally:
            if len(fixtures):
                result.fixture_cleanup = fixtures.run()
            result.finished_at = self.clock.now()
        if interrupted:
            result.status = TestStatus.ERROR
            result.message = INTERRUPTED
            return result
        result.status, summary = _verdict(result)
        result.message = result.message or summary
        out(f"{result.status.value.upper()}: {result.message}")
        return result

    def _rule_preconditions(
        self, spec: TestSpec, result: TestResult
    ) -> tuple[dict[str, Any], Timing]:
        rule = self.api.rule(spec.rule_id, runs_limit=5)
        if rule is None:
            raise PreconditionFailed(
                f"rule {spec.rule_id} is not deployed (GET /api/v1/rules/{spec.rule_id} -> 404): "
                "add it under rules/ and restart the detector"
            )
        record = rule.get("rule") if isinstance(rule.get("rule"), Mapping) else {}
        if not isinstance(record, Mapping) or record.get("enabled") is False:
            raise PreconditionFailed(f"rule {spec.rule_id} is disabled")
        if rule.get("run_stale") is True:
            raise PreconditionFailed(
                f"the detector has not run {spec.rule_id} recently (run_stale): is the "
                "detector service up?"
            )
        result.rule_version = str(record.get("version") or "") or None
        if result.rule_version is None:
            raise PreconditionFailed(f"rule {spec.rule_id} has no deployed version")
        result.preconditions.append(
            StepResult(f"rule {spec.rule_id}", True, f"deployed v{result.rule_version}")
        )
        interval = rule.get("interval_seconds")
        if not isinstance(interval, int) or interval <= 0:
            schedule = record.get("schedule") if isinstance(record.get("schedule"), Mapping) else {}
            interval = schedule.get("interval_seconds") if isinstance(schedule, Mapping) else None
        if not isinstance(interval, int) or interval <= 0:
            raise PreconditionFailed(f"rule {spec.rule_id} has no schedule interval")
        resolved = source_interval(self.root, spec.source)
        timing = detection_timing(
            source_seconds=resolved.source_seconds,
            loop_seconds=resolved.loop_seconds,
            cycles=spec.source.cycles,
            pipeline_seconds=spec.source.pipeline_seconds,
            rule_interval_seconds=interval,
            ingest_delay_seconds=self.options.ingest_delay_seconds,
            min_margin_seconds=self.options.min_margin_seconds,
        )
        result.preconditions.append(
            StepResult("evidence source", True, f"{spec.source.description} ({resolved.origin})")
        )
        return rule, timing

    def _phase_gap(
        self, spec: TestSpec, rule: Mapping[str, Any], kind: PhaseKind, previous_end: datetime
    ) -> float:
        """Seconds to wait before the second phase (see ``TestSpec.phase_gap_seconds``)."""
        if spec.phase_gap_seconds is not None:
            window_seconds = spec.phase_gap_seconds
        elif kind is PhaseKind.NEGATIVE:
            record = rule.get("rule")
            window_seconds = rule_window_seconds(record if isinstance(record, Mapping) else {})
        else:
            window_seconds = 0
        return separation_remaining(
            previous_end,
            window_seconds=window_seconds,
            margin_seconds=self.options.clock_skew_seconds,
            now=self.clock.now(),
        )

    def _quiet_period(self, spec: TestSpec, rule: Mapping[str, Any], ctx: TestContext) -> None:
        if spec.fresh_group:
            return
        record = rule.get("rule") if isinstance(rule.get("rule"), Mapping) else {}
        gap = continuation_gap_seconds(record if isinstance(record, Mapping) else {})
        if gap <= 0:
            return
        now = self.clock.now()
        alerts = self.api.alerts(
            asset_id=spec.asset.asset_id,
            rule_id=spec.rule_id,
            since=now - timedelta(seconds=gap + self.options.max_quiet_wait_seconds + 3600),
            until=now + timedelta(days=1),
        )
        latest = max(
            (t for t in (parse_time(a.get("last_seen")) for a in alerts) if t is not None),
            default=None,
        )
        remaining = quiet_period_remaining(
            latest, gap_seconds=gap, margin_seconds=self.options.clock_skew_seconds, now=now
        )
        if remaining > self.options.max_quiet_wait_seconds:
            raise PreconditionFailed(
                f"the latest {spec.rule_id} alert on {spec.asset.asset_id} was active until "
                f"{format_time(latest) if latest else '?'}; new activity within {gap}s would "
                f"extend it instead of opening a new alert. Retry in {remaining:.0f}s."
            )
        ctx.wait(remaining, f"quiet period: the previous {spec.rule_id} alert must close first")

    # ── phases ──

    def _baseline(self, spec: TestSpec) -> _Baseline:
        now = self.clock.now()
        alerts = self.api.alerts(
            asset_id=spec.asset.asset_id,
            since=now - timedelta(seconds=self.options.baseline_lookback_seconds),
            until=now + timedelta(days=1),
        )
        rule_alerts = [a for a in alerts if a.get("rule_id") == spec.rule_id]
        last_seen: dict[str, datetime] = {}
        for alert in rule_alerts:
            seen = parse_time(alert.get("last_seen"))
            if seen is not None:
                last_seen[str(alert.get("alert_id"))] = seen
        return _Baseline(
            rule_ids=frozenset(str(a.get("alert_id")) for a in rule_alerts),
            all_ids=frozenset(str(a.get("alert_id")) for a in alerts),
            rule_last_seen=last_seen,
        )

    def _run_phase(
        self,
        kind: PhaseKind,
        test: DetectionTest,
        ctx: TestContext,
        timing: Timing,
        rule_version: str | None,
    ) -> PhaseResult:
        spec = test.spec
        phase = PhaseResult(kind, PhaseOutcome.ERROR, bound_seconds=timing.bound_seconds)
        try:
            baseline = self._baseline(spec)
        except ApiError as exc:
            phase.message = f"could not read existing alerts: {exc}"
            return phase
        window = Window(start=self.clock.now())
        phase.window = window
        cleanup = CleanupStack(notify=ctx.out)
        action: ActionRecord | None = None
        ctx.out(f"{kind.value}: {spec.positive if kind is PhaseKind.POSITIVE else spec.negative}")
        try:
            if kind is PhaseKind.POSITIVE:
                action = test.positive(ctx, cleanup)
            else:
                action = test.negative(ctx, cleanup)
            window.action_end = self.clock.now()
            phase.action = action.summary
            phase.details = list(action.details)
            phase.artefacts = list(action.artefacts)
            ctx.out(f"{kind.value} action done: {action.summary}")
            if kind is PhaseKind.POSITIVE:
                self._await_alert(phase, spec, action, timing, baseline, rule_version)
            else:
                self._observe_negative(phase, spec, action, timing, baseline, rule_version)
        except Cancelled:
            phase.outcome = PhaseOutcome.ERROR
            phase.message = INTERRUPTED
        except ActionFailed as exc:
            phase.outcome = PhaseOutcome.ERROR
            phase.message = f"action failed: {_describe(exc)}"
        except Exception as exc:  # noqa: BLE001 - recorded in the report, cleanup still runs
            phase.outcome = PhaseOutcome.ERROR
            phase.message = f"{type(exc).__name__}: {_describe(exc)}"
        finally:
            phase.cleanup = cleanup.run()
            window.end = window.end or self.clock.now()
        if phase.message != INTERRUPTED:
            self._record_overlaps(phase, spec, baseline)
        ctx.out(f"{kind.value}: {phase.outcome.value}: {phase.message}")
        return phase

    def _await_alert(
        self,
        phase: PhaseResult,
        spec: TestSpec,
        action: ActionRecord,
        timing: Timing,
        baseline: _Baseline,
        rule_version: str | None,
    ) -> None:
        window, action_end = _action_window(phase)
        deadline = action_end + timedelta(seconds=timing.bound_seconds)
        last_error: str | None = None
        while True:
            now = self.clock.now()
            try:
                alerts = self.api.alerts(
                    asset_id=spec.asset.asset_id,
                    rule_id=spec.rule_id,
                    since=window.start - timedelta(seconds=self.options.clock_skew_seconds + 60),
                    until=now + timedelta(minutes=10),
                )
                found = select_new_alerts(
                    alerts,
                    rule_id=spec.rule_id,
                    asset_id=spec.asset.asset_id,
                    start=window.start,
                    end=now,
                    baseline_ids=baseline.rule_ids,
                    skew_seconds=self.options.clock_skew_seconds,
                )
                last_error = None
            except ApiError as exc:
                found, alerts, last_error = [], [], str(exc)
            if found:
                verified = [
                    self._observe_alert(
                        a, action, since=window.start, until=now, rule_version=rule_version
                    )
                    for a in found
                ]
                phase.alerts = [item for item in verified if item.verified_evidence]
            if phase.alerts:
                window.end = now
                phase.outcome = PhaseOutcome.PASSED
                first = phase.alerts[0]
                waited = (now - action_end).total_seconds()
                phase.message = (
                    f"alert {first.alert_id} ({first.severity}, confidence {first.confidence}) "
                    f"first_seen {format_time(first.first_seen)}, "
                    f"found {waited:.0f}s after the action"
                )
                return
            if now >= deadline:
                window.end = now
                phase.outcome = PhaseOutcome.FAILED
                phase.telemetry = self._telemetry(spec, action.telemetry, window.start, now)
                extended = extended_alerts(
                    alerts,
                    rule_id=spec.rule_id,
                    asset_id=spec.asset.asset_id,
                    start=window.start,
                    baseline_last_seen=baseline.rule_last_seen,
                )
                phase.message = _missing_alert_message(
                    spec, timing, phase.telemetry, extended, last_error
                )
                if found:
                    phase.message += (
                        " Candidate alerts did not resolve the expected evidence "
                        "for this action and rule version."
                    )
                return
            self.clock.sleep(min(self.options.poll_seconds, (deadline - now).total_seconds()))

    def _observe_negative(
        self,
        phase: PhaseResult,
        spec: TestSpec,
        action: ActionRecord,
        timing: Timing,
        baseline: _Baseline,
        rule_version: str | None,
    ) -> None:
        window, action_end = _action_window(phase)
        deadline = action_end + timedelta(seconds=timing.bound_seconds)
        expectations = list(action.telemetry)
        observations: list[TelemetryObservation] = []
        last_error: str | None = None
        ambiguous = False
        while True:
            now = self.clock.now()
            try:
                alerts = self.api.alerts(
                    asset_id=spec.asset.asset_id,
                    rule_id=spec.rule_id,
                    since=window.start - timedelta(seconds=self.options.clock_skew_seconds + 60),
                    until=now + timedelta(minutes=10),
                )
                last_error = None
            except ApiError as exc:
                # Never conclude "no alert" from a failed query: keep polling until the bound.
                alerts, last_error = [], str(exc)
            found = select_new_alerts(
                alerts,
                rule_id=spec.rule_id,
                asset_id=spec.asset.asset_id,
                start=window.start,
                end=now,
                baseline_ids=baseline.rule_ids,
                skew_seconds=self.options.clock_skew_seconds,
            )
            extended = extended_alerts(
                alerts,
                rule_id=spec.rule_id,
                asset_id=spec.asset.asset_id,
                start=window.start,
                baseline_last_seen=baseline.rule_last_seen,
            )
            candidates = {a["alert_id"]: a for a in found}
            candidates.update({a["alert_id"]: a for a in alerts if a.get("alert_id") in extended})
            matched = [
                self._observe_alert(
                    a, action, since=window.start, until=now, rule_version=rule_version
                )
                for a in candidates.values()
            ]
            ambiguous = ambiguous or any(not a.verified_evidence for a in matched)
            phase.alerts = [a for a in matched if a.verified_evidence]
            if phase.alerts:
                window.end = now
                phase.outcome = PhaseOutcome.FAILED
                phase.message = (
                    f"FALSE POSITIVE: {spec.rule_id} matched the negative control "
                    f"({', '.join(a.alert_id for a in phase.alerts)})"
                )
                return
            if expectations and last_error is None:
                observations = self._telemetry(spec, expectations, window.start, now)
                phase.telemetry = observations
                try:
                    run = self._conclusive_run(spec, observations, now, rule_version)
                except ApiError as exc:
                    run, last_error = None, str(exc)
                if run is not None and not ambiguous:
                    window.end = now
                    phase.outcome = PhaseOutcome.PASSED
                    phase.conclusive_run = str(run.get("run_id") or "") or None
                    phase.message = (
                        f"no {spec.rule_id} alert; rule run {phase.conclusive_run} "
                        f"(started {run.get('started_at')}) evaluated the control's telemetry"
                    )
                    return
            if now >= deadline:
                window.end = now
                if last_error is not None:
                    phase.outcome = PhaseOutcome.INCONCLUSIVE
                    phase.message = f"the analyst API failed at the end of the bound: {last_error}"
                elif ambiguous:
                    phase.outcome = PhaseOutcome.INCONCLUSIVE
                    phase.message = (
                        "A candidate alert could not be linked to the control's evidence"
                    )
                elif not expectations:
                    phase.outcome = PhaseOutcome.INCONCLUSIVE
                    phase.message = (
                        f"no {spec.rule_id} alert within the full detection bound "
                        f"({timing.bound_seconds}s), but no control telemetry was available "
                        "to verify rule evaluation"
                    )
                elif not all(o.satisfied for o in observations):
                    phase.outcome = PhaseOutcome.INCONCLUSIVE
                    missing = [o.description for o in observations if not o.satisfied]
                    phase.message = (
                        "no alert, but the control's own telemetry was not observed within "
                        f"{timing.bound_seconds}s ({'; '.join(missing)}): nothing was proven"
                    )
                else:
                    phase.outcome = PhaseOutcome.INCONCLUSIVE
                    phase.message = (
                        "no alert and the telemetry arrived, but no completed rule run covered it "
                        "within the bound (detector lagging?)"
                    )
                return
            self.clock.sleep(min(self.options.poll_seconds, (deadline - now).total_seconds()))

    def _conclusive_run(
        self,
        spec: TestSpec,
        observations: Sequence[TelemetryObservation],
        now: datetime,
        rule_version: str | None,
    ) -> Mapping[str, Any] | None:
        if not observations or not all(o.satisfied for o in observations):
            return None
        ingested = [o.latest_ingested_time for o in observations if o.latest_ingested_time]
        event_times = [o.latest_event_time for o in observations if o.latest_event_time]
        earliest_times = [o.earliest_event_time for o in observations if o.earliest_event_time]
        if min(len(ingested), len(event_times), len(earliest_times)) != len(observations):
            return None
        detail = self.api.rule(spec.rule_id, runs_limit=20)
        runs = detail.get("recent_runs") if isinstance(detail, Mapping) else None
        if not isinstance(runs, list):
            return None
        run = conclusive_run(
            [r for r in runs if isinstance(r, Mapping) and r.get("rule_version") == rule_version],
            ingested_after=max(ingested),
            event_time=max(event_times),
            earliest_event_time=min(earliest_times),
            ingest_delay_seconds=self.options.ingest_delay_seconds,
        )
        if run is None:
            return None
        finished = parse_time(run.get("finished_at"))
        return run if finished is not None and finished <= now else None

    def _telemetry(
        self,
        spec: TestSpec,
        expectations: Iterable[TelemetryExpectation],
        start: datetime,
        now: datetime,
    ) -> list[TelemetryObservation]:
        observations: list[TelemetryObservation] = []
        since = start - timedelta(seconds=self.options.clock_skew_seconds)
        for expectation in expectations:
            try:
                events = self.api.events(
                    asset_id=spec.asset.asset_id,
                    event_type=expectation.event_type,
                    since=since,
                    until=now + timedelta(minutes=5),
                    actor=expectation.actor,
                    src_ip=expectation.src_ip,
                    source_type=expectation.source_type,
                )
            except ApiError as exc:
                observations.append(
                    TelemetryObservation(
                        expectation.description,
                        expectation.event_type,
                        0,
                        expectation.min_count,
                        error=str(exc),
                    )
                )
                continue
            match = match_telemetry(events, expectation)
            observations.append(
                TelemetryObservation(
                    expectation.description,
                    expectation.event_type,
                    match.matched,
                    expectation.min_count,
                    match.latest_event_time,
                    match.latest_ingested_time,
                    earliest_event_time=match.earliest_event_time,
                )
            )
        return observations

    def _observe_alert(
        self,
        alert: Mapping[str, Any],
        action: ActionRecord,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        rule_version: str | None = None,
    ) -> AlertObservation:
        observation = AlertObservation(
            alert_id=str(alert.get("alert_id")),
            rule_id=str(alert.get("rule_id")),
            asset_id=str(alert.get("asset_id")),
            severity=display(str(alert.get("severity") or ""), 16),
            confidence=display(str(alert.get("confidence") or ""), 16),
            first_seen=parse_time(alert.get("first_seen")) or self.clock.now(),
            last_seen=parse_time(alert.get("last_seen")) or self.clock.now(),
            event_count=_int(alert.get("event_count")),
            summary=display(str(alert.get("summary") or ""), 400),
            created_at=parse_time(alert.get("created_at")),
        )
        texts = [str(alert.get("summary") or "")]
        entities = alert.get("entities")
        if isinstance(entities, Mapping):
            texts.extend(str(v) for v in entities.values())
        try:
            detail = self.api.alert_detail(observation.alert_id)
        except ApiError:
            detail = None
        if isinstance(detail, Mapping):
            total = detail.get("evidence_total")
            observation.evidence_total = total if isinstance(total, int) else None
            sources: dict[str, int] = {}
            for event in detail.get("evidence") or []:
                if isinstance(event, Mapping):
                    key = display(str(event.get("source_type") or "unknown"), 40)
                    sources[key] = sources.get(key, 0) + 1
            observation.evidence_sources = dict(sorted(sources.items()))
            if since is not None and until is not None and rule_version is not None:
                observation.verified_evidence = self._verify_evidence(
                    detail, action.telemetry, observation, since, until, rule_version
                )
        if action.artefact_hint:
            observation.references_artefact = any(action.artefact_hint in t for t in texts)
        return observation

    def _verify_evidence(
        self,
        detail: Mapping[str, Any],
        expectations: Sequence[TelemetryExpectation],
        alert: AlertObservation,
        since: datetime,
        until: datetime,
        rule_version: str,
    ) -> dict[str, dict[str, str]]:
        stored_alert = detail.get("alert")
        if (
            not isinstance(stored_alert, Mapping)
            or stored_alert.get("alert_id") != alert.alert_id
            or stored_alert.get("rule_id") != alert.rule_id
            or stored_alert.get("asset_id") != alert.asset_id
            or stored_alert.get("rule_version") != rule_version
        ):
            return {}
        resolved: dict[str, dict[str, str] | None] = {}
        verified: dict[str, dict[str, str]] = {}
        earliest = since - timedelta(seconds=self.options.clock_skew_seconds)
        for expectation in expectations:
            matches: set[str] = set()
            for row in detail.get("evidence") or []:
                if not isinstance(row, Mapping) or not event_matches(row, expectation):
                    continue
                event_id = row.get("event_id")
                source = row.get("source_type")
                event_time = parse_time(row.get("event_time"))
                ingested_time = parse_time(row.get("ingested_time"))
                if (
                    not isinstance(event_id, str)
                    or re.fullmatch(r"[0-9a-f]{32}", event_id) is None
                    or not isinstance(source, str)
                    or row.get("asset_id") != alert.asset_id
                    or event_time is None
                    or not earliest <= event_time <= until
                    or ingested_time is None
                    or not since <= ingested_time <= until
                    or (expectation.source_type is not None and expectation.source_type != source)
                    or (
                        expectation.actor is not None
                        and expectation.actor
                        not in (
                            row.get("actor_name"),
                            row.get("k8s_user"),
                            row.get("gh_actor_login"),
                        )
                    )
                    or (expectation.src_ip is not None and expectation.src_ip != row.get("src_ip"))
                ):
                    continue
                expected = evidence_producer(self.root, source)
                if expected is None:
                    continue
                if event_id not in resolved:
                    resolved[event_id] = self._event_provenance(event_id, alert.asset_id, source)
                provenance = resolved[event_id]
                if provenance is None or provenance["producer_id"] != expected:
                    continue
                matches.add(event_id)
                verified[event_id] = provenance
                if len(matches) >= expectation.min_count:
                    break
            if len(matches) < expectation.min_count:
                return {}
        return verified

    def _event_provenance(
        self, event_id: str, asset_id: str, source_type: str
    ) -> dict[str, str] | None:
        try:
            detail = self.api.event_detail(event_id)
        except ApiError:
            return None
        if detail is None:
            return None
        native, ingest = detail.get("event"), detail.get("ingest")
        if not isinstance(native, Mapping) or not isinstance(ingest, Mapping):
            return None
        source = native.get("source")
        labels = native.get("labels") or {}
        if (
            native.get("event_id") != event_id
            or native.get("asset_id") != asset_id
            or not isinstance(source, Mapping)
            or source.get("source_type") != source_type
            or not isinstance(labels, Mapping)
            or labels.get("synthetic") in ("true", True)
        ):
            return None
        producer = ingest.get("producer_id")
        native_id = source.get("source_native_id")
        if not isinstance(producer, str) or not producer:
            return None
        info = {"producer_id": producer, "source_type": source_type}
        if isinstance(native_id, str) and native_id:
            info["source_native_id"] = display(native_id, 256)
        else:
            info["reference_kind"] = "derived_event_id"
        return info

    def _record_overlaps(self, phase: PhaseResult, spec: TestSpec, baseline: _Baseline) -> None:
        window = phase.window
        if window is None or window.end is None:
            return
        expected = (
            spec.positive_overlaps if phase.kind is PhaseKind.POSITIVE else spec.negative_overlaps
        )
        try:
            alerts = self.api.alerts(
                asset_id=spec.asset.asset_id,
                since=window.start - timedelta(seconds=self.options.clock_skew_seconds + 60),
                until=window.end + timedelta(minutes=10),
            )
        except ApiError:
            return
        others = select_new_alerts(
            alerts,
            rule_id=None,
            asset_id=spec.asset.asset_id,
            start=window.start,
            end=window.end,
            baseline_ids=baseline.all_ids,
            skew_seconds=self.options.clock_skew_seconds,
        )
        phase.other_alerts = [
            OtherAlert(
                rule_id=str(a.get("rule_id")),
                alert_id=str(a.get("alert_id")),
                first_seen=parse_time(a.get("first_seen")) or window.start,
                expected=str(a.get("rule_id")) in expected,
            )
            for a in others
            if a.get("rule_id") != spec.rule_id
        ]


def _action_window(phase: PhaseResult) -> tuple[Window, datetime]:
    """The phase window and its action end (set by ``_run_phase`` before any wait)."""
    window = phase.window
    if window is None or window.action_end is None:
        raise RuntimeError("phase window not initialised before waiting")
    return window, window.action_end


def _verdict(result: TestResult) -> tuple[TestStatus, str]:
    positive, negative = result.positive, result.negative
    phases = [p for p in (positive, negative) if p is not None]
    if any(p.outcome is PhaseOutcome.ERROR for p in phases):
        failed = next(p for p in phases if p.outcome is PhaseOutcome.ERROR)
        return TestStatus.ERROR, f"{failed.kind.value}: {failed.message}"
    problems: list[str] = []
    if positive is None or positive.outcome is not PhaseOutcome.PASSED:
        problems.append(f"positive: {positive.message if positive else 'not run'}")
    if negative is not None and negative.outcome in (
        PhaseOutcome.FAILED,
        PhaseOutcome.INCONCLUSIVE,
    ):
        problems.append(f"negative: {negative.message}")
    if not result.cleanup_ok:
        problems.append(
            "cleanup incomplete: run `uv run python -m detection_tests cleanup "
            f"--asset {result.spec.asset.key}`"
        )
    if problems:
        return TestStatus.FAILED, "; ".join(problems)
    alerts = ", ".join(positive.alert_ids) if positive else ""
    negative_text = negative.outcome.value if negative is not None else "not run"
    return TestStatus.PASSED, f"alert {alerts}; negative control {negative_text}; cleanup ok"


def _missing_alert_message(
    spec: TestSpec,
    timing: Timing,
    telemetry: Sequence[TelemetryObservation],
    extended: Sequence[str],
    last_error: str | None,
) -> str:
    parts = [f"no new {spec.rule_id} alert on {spec.asset.asset_id} within {timing.bound_seconds}s"]
    if extended:
        parts.append(
            f"the activity extended pre-existing alert(s) {', '.join(extended)} instead "
            "(quiet period too short?)"
        )
    if telemetry:
        seen = all(o.satisfied for o in telemetry)
        detail = "; ".join(f"{o.description}: {o.matched}/{o.required}" for o in telemetry)
        if seen:
            parts.append(f"the evidence WAS stored ({detail}): check the rule and the detector")
        else:
            parts.append(f"evidence missing ({detail}): check the collector and the pipeline")
    if last_error:
        parts.append(f"last API error: {last_error}")
    return "; ".join(parts)


def _describe(exc: BaseException) -> str:
    return display(str(exc) or type(exc).__name__, 500)


def _int(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def install_signal_handlers(clock: Clock, output: Output) -> None:
    """First SIGINT/SIGTERM: stop at the next wait and clean up; second: abort now."""
    import signal

    def handler(signum: int, _frame: object) -> None:
        if clock.cancel.is_set():
            raise KeyboardInterrupt
        clock.cancel.set()
        output.line(
            "runner",
            f"signal {signum}: finishing the current cleanup and writing the report "
            "(send it again to abort immediately; then run `python -m detection_tests cleanup`)",
        )

    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

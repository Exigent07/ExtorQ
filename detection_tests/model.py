"""Data model shared by the runner, the per-asset modules and the report writer.

Plain dataclasses and enums only; nothing in this module performs I/O. The vocabulary:

* a :class:`TestSpec` is the static description of one matrix row (rule, asset, what the
  positive action and the negative control do, how the artefacts are removed, where the
  evidence comes from);
* a :class:`DetectionTest` implements the row: preconditions, the positive action and the
  negative control, each registering its undo steps on a :class:`CleanupStack`;
* the runner turns every executed phase into a :class:`PhaseResult` and every test into a
  :class:`TestResult`; :mod:`detection_tests.report` renders them.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # imported for annotations only (runner imports this module)
    from detection_tests.runner import TestContext

#: Prefix of every artefact a test creates (unit, account, pod, workflow file ...): realistic
#: enough to look like ordinary engineering activity, unique enough to be swept after an
#: interrupted run. Verification never relies on it.
ARTEFACT_PREFIX = "extorq-test-"
#: Reverse-DNS prefix used where a platform requires that form (launchd labels, bundle ids).
REVERSE_DNS_PREFIX = "com.extorq.test."
#: Exact form of a generated artefact name: the prefix plus 6 lower-case hex characters.
ARTEFACT_NAME_RE = re.compile(r"^extorq-test-[0-9a-f]{6}$")
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,15}-[0-9]{3}$")


def validate_artefact_name(name: str) -> str:
    """Return ``name`` if it is a generated artefact name, else raise ``ValueError``.

    Every name that ends up in a remote shell script, a Kubernetes object or a file path
    passes through here first, so a malformed value can never reach those places.
    """
    if not ARTEFACT_NAME_RE.fullmatch(name):
        raise ValueError(f"not a detection-test artefact name: {name!r}")
    return name


@dataclass(frozen=True)
class AssetRef:
    """One monitored asset: the CLI key, the ExtorQ asset id and a readable name."""

    key: str
    asset_id: str
    label: str


@dataclass(frozen=True)
class LatencySource:
    """Where a test's evidence comes from and how often that source is read.

    The runner derives its bounded wait from this and from the deployed rule's schedule:
    ``cycles * source interval + collector loop interval + pipeline + rule interval +
    detector ingest delay + margin`` (see :func:`detection_tests.windows.detection_bound`).
    """

    #: Human description, e.g. "Linux inventory diff (units, accounts, cron)".
    description: str
    #: Repository-relative collector config (``None`` for push sources such as OTel).
    config_file: str | None
    #: ``collector_id`` of the entry inside ``config_file``.
    collector_id: str | None
    #: Key path below the collector entry holding the source interval; ``()`` means the
    #: collector's own ``interval_seconds``.
    interval_keys: tuple[str, ...]
    #: Interval used when the config file or key is absent.
    default_seconds: int
    #: Add the collector loop interval: sources that "run when due" inside a loop can start
    #: up to one loop interval late.
    loop_tick: bool = True
    #: Gateway, spool and writer latency (plus OTel batching for in-cluster sources).
    pipeline_seconds: int = 15
    #: Source cycles the evidence may need (e.g. a settle deferral or "up to 3 inventory
    #: cycles" for a short-lived listener).
    cycles: int = 1


@dataclass(frozen=True)
class TelemetryExpectation:
    """Events an action must produce on the test's asset.

    Used to link cited evidence to the action and to verify telemetry reached the platform
    for a negative control. Matching is exact on fields of the analyst API's event items.
    """

    #: What the events prove, for the report.
    description: str
    event_type: str
    #: ``(field, value)`` pairs that must be equal on the event item.
    equals: tuple[tuple[str, str | int], ...] = ()
    #: ``(field, substring)`` pairs that must be contained in the (string) field.
    contains: tuple[tuple[str, str], ...] = ()
    #: Fields that must be null/absent (e.g. ``k8s_namespace`` for a cluster-wide list).
    is_null: tuple[str, ...] = ()
    min_count: int = 1
    #: Server-side filters of ``GET /api/v1/events``.
    actor: str | None = None
    src_ip: str | None = None
    source_type: str | None = None


@dataclass
class ActionRecord:
    """What one positive action or negative control did (report text; never secrets)."""

    summary: str
    details: list[str] = field(default_factory=list)
    artefacts: list[str] = field(default_factory=list)
    telemetry: list[TelemetryExpectation] = field(default_factory=list)
    #: Text an alert summary or entity is expected to contain when the alert is about this
    #: action's artefact. Informational only: verification is by asset + rule + window.
    artefact_hint: str | None = None


@dataclass(frozen=True)
class TestSpec:
    """Static description of one matrix row (``docs/team/PLAN.md`` section 12)."""

    __test__ = False  # not a pytest test class

    #: Stable id, e.g. ``linux.vm-001`` or ``kubernetes.app-001``.
    test_id: str
    asset: AssetRef
    rule_id: str
    title: str
    #: What the positive action does (real activity that must raise ``rule_id``).
    positive: str
    #: What the negative control does (similar, benign activity that must not).
    negative: str
    #: How every artefact is removed.
    cleanup: str
    #: The alert the positive action is expected to raise.
    expected_alert: str
    #: Why the test is safe to run against the monitored asset.
    safety: str
    #: Evidence source of the expected alert (drives the bounded wait).
    source: LatencySource
    #: Other rules the positive action legitimately raises too (documented overlaps). Any
    #: other rule alerting on the asset inside the window is reported as unexpected.
    positive_overlaps: frozenset[str] = frozenset()
    negative_overlaps: frozenset[str] = frozenset()
    #: Run the negative control before the positive action (CORR-002: the burst alone must
    #: happen before the probing that would make it a valid second stage).
    negative_first: bool = False
    #: Minimum seconds between the end of the first phase's action and the start of the
    #: second phase. ``None``: the deployed rule's sliding window before a negative control
    #: (see :func:`detection_tests.windows.rule_window_seconds`), nothing before a positive.
    #: ``0`` when the control can never count toward the rule's threshold (e.g. successful
    #: logins for a failed-login rule), so no wait is needed.
    phase_gap_seconds: int | None = None
    #: The positive action's alert group is new on every run (a fresh namespace or port), so
    #: it cannot extend an earlier alert and no quiet period is needed before it.
    fresh_group: bool = False

    def __post_init__(self) -> None:
        if not RULE_ID_RE.fullmatch(self.rule_id):
            raise ValueError(f"invalid rule id {self.rule_id!r}")


class PreconditionFailed(Exception):
    """A test (or a whole asset) cannot run; the message says what is missing."""


class ActionFailed(RuntimeError):
    """An action did not have the intended real effect (e.g. admission did not deny)."""


class Cancelled(Exception):
    """The operator interrupted the run; cleanup still runs."""


@dataclass
class StepResult:
    """Outcome of one precondition check or one cleanup step."""

    description: str
    ok: bool
    detail: str = ""


class CleanupStack:
    """Undo steps, registered BEFORE the change they undo and run in reverse order.

    Registering first means a half-done action (the unit file was written but enabling it
    failed) is still undone. Every step runs even if an earlier one failed; a step reports
    success by returning (optionally a short detail such as "verified absent") and failure
    by raising. :meth:`run` is idempotent: steps already executed are not run twice.
    """

    def __init__(self, notify: Callable[[str], None] | None = None) -> None:
        self._steps: list[tuple[str, Callable[[], str | None]]] = []
        self._notify = notify

    def push(self, description: str, undo: Callable[[], str | None]) -> None:
        self._steps.append((description, undo))

    def __len__(self) -> int:
        return len(self._steps)

    def run(self) -> list[StepResult]:
        results: list[StepResult] = []
        while self._steps:
            description, undo = self._steps.pop()
            try:
                detail = undo() or ""
                results.append(StepResult(description, True, detail))
            except Exception as exc:  # noqa: BLE001 - every undo step must be attempted
                results.append(StepResult(description, False, _short_error(exc)))
            if self._notify is not None:
                last = results[-1]
                self._notify(f"cleanup: {last.description}: {'ok' if last.ok else 'FAILED'}")
        return results


def _short_error(exc: BaseException) -> str:
    text = str(exc).strip() or type(exc).__name__
    return text if len(text) <= 500 else text[:497] + "..."


class DetectionTest(ABC):
    """One row of the detection-test matrix.

    Subclasses perform REAL activity. ``positive`` and ``negative`` must register an undo
    step on ``cleanup`` before creating anything, must never print or return secrets, and
    raise :class:`ActionFailed` when the action did not have its intended effect.
    """

    spec: TestSpec

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        """Test-specific checks (the asset-wide ones run once per asset); raise on failure."""
        return []

    def setup(self, ctx: TestContext, cleanup: CleanupStack) -> list[str]:
        """Fixtures shared by both phases (e.g. a namespace), removed after the test."""
        return []

    @abstractmethod
    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        """Perform the real activity that must raise ``spec.rule_id``."""

    @abstractmethod
    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        """Perform the benign control activity that must NOT raise ``spec.rule_id``."""


# ── results ──────────────────────────────────────────────────────────────────────────


class PhaseKind(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class PhaseOutcome(StrEnum):
    #: Positive: the deployed rule's new alert cites matching action evidence.
    #: Negative: a completed rule run covered the control telemetry without an alert.
    PASSED = "passed"
    #: Positive: no alert within the bound. Negative: the rule alerted (false positive).
    FAILED = "failed"
    #: Negative only: control telemetry, rule coverage or alert attribution is uncertain.
    INCONCLUSIVE = "inconclusive"
    #: The action itself failed or the run was interrupted.
    ERROR = "error"
    #: ``--skip-negatives``.
    SKIPPED = "skipped"
    #: Not executed (an earlier error or cancellation).
    NOT_RUN = "not_run"


class TestStatus(StrEnum):
    __test__ = False  # not a pytest test class

    PASSED = "passed"
    FAILED = "failed"
    #: A precondition was not met; nothing was changed on the asset.
    BLOCKED = "blocked"
    ERROR = "error"


@dataclass
class Window:
    """Time window of one phase (aware UTC). ``end`` is when the runner stopped looking."""

    start: datetime
    action_end: datetime | None = None
    end: datetime | None = None


@dataclass
class AlertObservation:
    """One alert the runner matched (sanitised values from the analyst API)."""

    alert_id: str
    rule_id: str
    asset_id: str
    severity: str
    confidence: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    summary: str = ""
    created_at: datetime | None = None
    evidence_total: int | None = None
    evidence_sources: dict[str, int] = field(default_factory=dict)
    verified_evidence: dict[str, dict[str, str]] = field(default_factory=dict)
    references_artefact: bool | None = None


@dataclass
class OtherAlert:
    """An alert of a different rule on the same asset inside the window."""

    rule_id: str
    alert_id: str
    first_seen: datetime
    expected: bool


@dataclass
class TelemetryObservation:
    """How many events matched one :class:`TelemetryExpectation` inside the window."""

    description: str
    event_type: str
    matched: int
    required: int
    latest_event_time: datetime | None = None
    latest_ingested_time: datetime | None = None
    error: str | None = None
    earliest_event_time: datetime | None = None

    @property
    def satisfied(self) -> bool:
        return self.error is None and self.matched >= self.required


@dataclass
class PhaseResult:
    kind: PhaseKind
    outcome: PhaseOutcome
    message: str = ""
    action: str = ""
    details: list[str] = field(default_factory=list)
    artefacts: list[str] = field(default_factory=list)
    window: Window | None = None
    bound_seconds: int | None = None
    alerts: list[AlertObservation] = field(default_factory=list)
    other_alerts: list[OtherAlert] = field(default_factory=list)
    telemetry: list[TelemetryObservation] = field(default_factory=list)
    #: Negative only: the rule ran over the control's stored telemetry (rule run id).
    conclusive_run: str | None = None
    cleanup: list[StepResult] = field(default_factory=list)

    @property
    def cleanup_ok(self) -> bool:
        return all(step.ok for step in self.cleanup)

    @property
    def alert_ids(self) -> list[str]:
        return [alert.alert_id for alert in self.alerts]

    @property
    def evidence_count(self) -> int | None:
        counts = [
            a.evidence_total if a.evidence_total is not None else a.event_count for a in self.alerts
        ]
        return sum(counts) if counts else None


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class

    spec: TestSpec
    status: TestStatus
    started_at: datetime
    finished_at: datetime | None = None
    message: str = ""
    preconditions: list[StepResult] = field(default_factory=list)
    fixtures: list[str] = field(default_factory=list)
    fixture_cleanup: list[StepResult] = field(default_factory=list)
    positive: PhaseResult | None = None
    negative: PhaseResult | None = None
    bound_seconds: int | None = None
    rule_version: str | None = None

    @property
    def cleanup_ok(self) -> bool:
        steps = list(self.fixture_cleanup)
        for phase in (self.positive, self.negative):
            if phase is not None:
                steps.extend(phase.cleanup)
        return all(step.ok for step in steps)

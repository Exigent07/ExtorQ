"""Run reports: ``var/reports/detection-tests-<UTC>.json`` and ``.md``.

The JSON document (schema :data:`REPORT_SCHEMA`) is the machine-readable record (``make
demo-check`` and the VERIFY stage read the newest one); the Markdown file is the same data
for people. Per test both carry: rule, asset, the action performed, the time windows, the
alert ids and their evidence counts, the positive verdict, the negative-control outcome and
whether every cleanup step succeeded.

Every value that originates outside the runner (alert summaries, API messages, command
output) was sanitised when it was recorded; the Markdown renderer additionally escapes HTML
and table syntax so a hostile string cannot change the document's structure. Files are
written atomically with mode 0600 into a 0700 directory.
"""

from __future__ import annotations

import html
import json
import os
import tempfile
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from detection_tests import __version__
from detection_tests.model import (
    AlertObservation,
    PhaseOutcome,
    PhaseResult,
    StepResult,
    TestResult,
    TestStatus,
    Window,
)
from detection_tests.proc import display
from detection_tests.windows import format_time

REPORT_SCHEMA = "extorq.detection-tests.report.v2"
REPORT_PREFIX = "detection-tests-"


@dataclass
class RunReport:
    started_at: datetime
    finished_at: datetime
    command: str
    api_url: str
    options: dict[str, Any]
    results: list[TestResult] = field(default_factory=list)
    interrupted: bool = False


def report_stem(started_at: datetime) -> str:
    """``detection-tests-20261123T091500Z`` (UTC, sortable)."""
    return REPORT_PREFIX + started_at.strftime("%Y%m%dT%H%M%SZ")


# ── JSON ─────────────────────────────────────────────────────────────────────────────────


def _time(value: datetime | None) -> str | None:
    return format_time(value) if value is not None else None


def _steps(steps: Sequence[StepResult]) -> list[dict[str, Any]]:
    return [{"description": s.description, "ok": s.ok, "detail": s.detail} for s in steps]


def _window(window: Window | None) -> dict[str, Any] | None:
    if window is None:
        return None
    return {
        "start": _time(window.start),
        "action_end": _time(window.action_end),
        "end": _time(window.end),
    }


def _alert(alert: AlertObservation) -> dict[str, Any]:
    return {
        "alert_id": alert.alert_id,
        "rule_id": alert.rule_id,
        "asset_id": alert.asset_id,
        "severity": alert.severity,
        "confidence": alert.confidence,
        "first_seen": _time(alert.first_seen),
        "last_seen": _time(alert.last_seen),
        "created_at": _time(alert.created_at),
        "event_count": alert.event_count,
        "evidence_total": alert.evidence_total,
        "evidence_sources": alert.evidence_sources,
        "verified_evidence": alert.verified_evidence,
        "summary": alert.summary,
        "references_artefact": alert.references_artefact,
    }


def _phase(phase: PhaseResult | None) -> dict[str, Any] | None:
    if phase is None:
        return None
    return {
        "outcome": phase.outcome.value,
        "message": phase.message,
        "action": phase.action,
        "details": phase.details,
        "artefacts": phase.artefacts,
        "window": _window(phase.window),
        "bound_seconds": phase.bound_seconds,
        "alerts": [_alert(a) for a in phase.alerts],
        "alert_ids": phase.alert_ids,
        "evidence_count": phase.evidence_count,
        "other_alerts": [
            {
                "rule_id": o.rule_id,
                "alert_id": o.alert_id,
                "first_seen": _time(o.first_seen),
                "expected": o.expected,
            }
            for o in phase.other_alerts
        ],
        "telemetry": [
            {
                "description": t.description,
                "event_type": t.event_type,
                "matched": t.matched,
                "required": t.required,
                "satisfied": t.satisfied,
                "latest_event_time": _time(t.latest_event_time),
                "latest_ingested_time": _time(t.latest_ingested_time),
                "error": t.error,
            }
            for t in phase.telemetry
        ],
        "conclusive_run": phase.conclusive_run,
        "cleanup": _steps(phase.cleanup),
        "cleanup_ok": phase.cleanup_ok,
    }


def _negative_outcome(result: TestResult) -> str:
    return result.negative.outcome.value if result.negative else PhaseOutcome.NOT_RUN.value


def result_json(result: TestResult) -> dict[str, Any]:
    spec = result.spec
    positive = result.positive
    return {
        "test_id": spec.test_id,
        "rule_id": spec.rule_id,
        "rule_version": result.rule_version,
        "asset": spec.asset.key,
        "asset_id": spec.asset.asset_id,
        "title": spec.title,
        "status": result.status.value,
        "message": result.message,
        "started_at": _time(result.started_at),
        "finished_at": _time(result.finished_at),
        "bound_seconds": result.bound_seconds,
        "evidence_source": spec.source.description,
        "spec": {
            "positive": spec.positive,
            "negative": spec.negative,
            "cleanup": spec.cleanup,
            "expected_alert": spec.expected_alert,
            "safety": spec.safety,
            "negative_first": spec.negative_first,
        },
        "preconditions": _steps(result.preconditions),
        "fixtures": result.fixtures,
        "fixture_cleanup": _steps(result.fixture_cleanup),
        "positive": _phase(positive),
        "negative": _phase(result.negative),
        # Flat verdict fields (what the matrix asks for per test).
        "alert_ids": positive.alert_ids if positive else [],
        "evidence_count": positive.evidence_count if positive else None,
        "positive_passed": bool(positive and positive.outcome is PhaseOutcome.PASSED),
        "negative_outcome": _negative_outcome(result),
        "cleanup_ok": result.cleanup_ok,
    }


def summary(results: Sequence[TestResult]) -> dict[str, Any]:
    counts = Counter(r.status.value for r in results)
    by_asset: dict[str, dict[str, int]] = {}
    for result in results:
        bucket = by_asset.setdefault(result.spec.asset.asset_id, {})
        bucket[result.status.value] = bucket.get(result.status.value, 0) + 1
    return {
        "total": len(results),
        **{status.value: counts.get(status.value, 0) for status in TestStatus},
        "by_asset": by_asset,
    }


def to_json(report: RunReport) -> dict[str, Any]:
    return {
        "schema": REPORT_SCHEMA,
        "runner_version": __version__,
        "started_at": _time(report.started_at),
        "finished_at": _time(report.finished_at),
        "command": report.command,
        "api_url": report.api_url,
        "options": report.options,
        "interrupted": report.interrupted,
        "summary": summary(report.results),
        "tests": [result_json(r) for r in report.results],
    }


# ── Markdown ─────────────────────────────────────────────────────────────────────────────


def md(text: object, limit: int = 400) -> str:
    """Inline text safe for a Markdown table cell (sanitised, HTML and pipes escaped)."""
    cleaned = display(str(text), limit) if text not in (None, "") else "-"
    return html.escape(cleaned, quote=False).replace("|", "\\|").replace("`", "'")


def md_code(text: object, limit: int = 120) -> str:
    """Untrusted value as an inline code span (backticks removed, pipes escaped)."""
    if text in (None, ""):
        return "-"
    cleaned = display(str(text), limit).replace("`", "'").replace("|", "\\|")
    return f"`{cleaned}`"


def _ok(step: StepResult) -> str:
    return "ok" if step.ok else "FAILED"


def _duration(start: datetime | None, end: datetime | None) -> str:
    if start is None or end is None:
        return "-"
    seconds = int((end - start).total_seconds())
    minutes, secs = divmod(max(0, seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if hours else f"{minutes} min {secs} s"


def _phase_cell(phase: PhaseResult | None) -> str:
    if phase is None:
        return "not run"
    if phase.outcome is PhaseOutcome.PASSED and phase.window and phase.window.action_end:
        end = phase.window.end or phase.window.action_end
        waited = int((end - phase.window.action_end).total_seconds())
        suffix = " (conclusive)" if phase.conclusive_run else ""
        return f"passed after {waited} s{suffix}"
    return phase.outcome.value


def _alert_line(alert: AlertObservation) -> str:
    sources = ", ".join(f"{k} x{v}" for k, v in alert.evidence_sources.items()) or "-"
    evidence = alert.evidence_total if alert.evidence_total is not None else alert.event_count
    refers = {True: "yes", False: "no", None: "n/a"}[alert.references_artefact]
    return (
        f"alert {md_code(alert.alert_id, 40)} {md(alert.severity)}/{md(alert.confidence)}, "
        f"first_seen {format_time(alert.first_seen)}, evidence {evidence} ({md(sources)}), "
        f"names the artefact: {refers}; summary {md_code(alert.summary, 300)}"
    )


def _phase_section(title: str, phase: PhaseResult | None) -> list[str]:
    if phase is None:
        return [f"- **{title}:** not run"]
    lines = [f"- **{title}:** {md(phase.outcome.value)}: {md(phase.message, 600)}"]
    if phase.action:
        lines.append(f"  - action: {md(phase.action, 300)}")
    lines.extend(f"  - {md(detail, 300)}" for detail in phase.details)
    if phase.window is not None:
        lines.append(
            f"  - window: {_time(phase.window.start)} .. {_time(phase.window.end)} "
            f"(action ended {_time(phase.window.action_end)}, bound {phase.bound_seconds} s)"
        )
    lines.extend(f"  - {_alert_line(alert)}" for alert in phase.alerts)
    for alert in phase.alerts:
        for event_id, provenance in sorted(alert.verified_evidence.items()):
            lines.append(
                f"  - Verified event {md_code(event_id, 32)} via "
                f"{md_code(provenance['producer_id'], 80)} "
                f"({md_code(provenance['source_type'], 80)})"
            )
    for other in phase.other_alerts:
        kind = "expected overlap" if other.expected else "UNEXPECTED (review as a false positive)"
        lines.append(
            f"  - other alert in the window: {md(other.rule_id)} "
            f"{md_code(other.alert_id, 40)} ({kind})"
        )
    for obs in phase.telemetry:
        state = "ok" if obs.satisfied else "MISSING"
        error = f", error {md(obs.error)}" if obs.error else ""
        lines.append(
            f"  - telemetry {md_code(obs.event_type, 60)}: {obs.matched}/{obs.required} {state} "
            f"({md(obs.description)}){error}"
        )
    for step in phase.cleanup:
        lines.append(f"  - cleanup: {md(step.description)}: {_ok(step)} {md(step.detail)}")
    return lines


def render_markdown(report: RunReport) -> str:
    counts = summary(report.results)
    head = [
        f"# Detection test report {format_time(report.started_at)}",
        "",
        f"Command: {md_code(report.command, 300)} · runner {__version__} · analyst API "
        f"{md_code(report.api_url, 80)} · "
        f"duration {_duration(report.started_at, report.finished_at)}",
        "",
        f"**Result: {counts['passed']} passed, {counts['failed']} failed, {counts['blocked']} "
        f"blocked, {counts['error']} error, of {counts['total']} tests"
        f"{' (run interrupted)' if report.interrupted else ''}.**",
        "",
        "A positive result requires a new alert for the deployed rule version and resolved "
        "evidence matching the test action, asset, source and authenticated producer. "
        "A conclusive negative result requires a completed rule run covering the observed "
        "control telemetry. The report records test attribution and cleanup separately.",
        "",
        "| Asset | Rule | Test | Positive | Alert ids | Evidence | Negative | Cleanup | Status |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for result in report.results:
        positive = result.positive
        ids = ", ".join(md_code(a, 40) for a in (positive.alert_ids if positive else [])) or "-"
        evidence = (
            positive.evidence_count if positive and positive.evidence_count is not None else "-"
        )
        head.append(
            f"| {md(result.spec.asset.asset_id)} | {md(result.spec.rule_id)} "
            f"| {md(result.spec.title)} | {md(_phase_cell(positive))} | {ids} | {evidence} "
            f"| {md(_phase_cell(result.negative))} "
            f"| {'ok' if result.cleanup_ok else 'FAILED'} | **{result.status.value.upper()}** |"
        )
    body: list[str] = []
    for result in report.results:
        spec = result.spec
        body += [
            "",
            f"## {md(spec.asset.asset_id)} {md(spec.rule_id)}: {md(spec.title)}",
            "",
            f"- **Status:** {result.status.value.upper()}: {md(result.message, 800)}",
            f"- **Rule version:** {md(result.rule_version)}; **detection bound:** "
            f"{result.bound_seconds if result.bound_seconds is not None else '-'} s; "
            f"**evidence source:** {md(spec.source.description)}",
            f"- **Expected alert:** {md(spec.expected_alert)}",
            f"- **Safety:** {md(spec.safety)}",
        ]
        failed_checks = [c for c in result.preconditions if not c.ok]
        if failed_checks:
            body += [
                f"- **Precondition failed:** {md(c.description)}: {md(c.detail)}"
                for c in failed_checks
            ]
        body += [f"- **Fixture:** {md(f)}" for f in result.fixtures]
        phases = (
            (("Negative control (runs first)", result.negative), ("Positive", result.positive))
            if spec.negative_first
            else (("Positive", result.positive), ("Negative control", result.negative))
        )
        for title, phase in phases:
            body += _phase_section(title, phase)
        for step in result.fixture_cleanup:
            body.append(
                f"- **Fixture cleanup:** {md(step.description)}: {_ok(step)} {md(step.detail)}"
            )
    return "\n".join(head + body) + "\n"


# ── files ────────────────────────────────────────────────────────────────────────────────


def _write_private(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_reports(report: RunReport, directory: Path) -> tuple[Path, Path]:
    """Write ``<stem>.json`` and ``<stem>.md`` (a ``-<n>`` suffix avoids overwriting)."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    stem = report_stem(report.started_at)
    candidate, counter = stem, 1
    while (directory / f"{candidate}.json").exists() or (directory / f"{candidate}.md").exists():
        counter += 1
        candidate = f"{stem}-{counter}"
    json_path = directory / f"{candidate}.json"
    md_path = directory / f"{candidate}.md"
    _write_private(json_path, json.dumps(to_json(report), indent=2, sort_keys=False) + "\n")
    _write_private(md_path, render_markdown(report))
    return json_path, md_path

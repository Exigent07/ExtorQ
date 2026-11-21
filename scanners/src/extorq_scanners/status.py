"""Scan status decision (pure). The lifecycle view trusts this completely.

A scan is ``succeeded`` only when ALL of the following hold; otherwise it is
``failed`` (no trustworthy result) or ``partial`` (result usable but coverage
reduced). PARTIAL and FAILED scans never resolve findings.

failed when
  * the tool could not be started (docker/image missing, mount invalid),
  * it timed out or was killed,
  * its output exceeded the size limit (truncated output is never parsed),
  * its output is missing or unusable (malformed JSON, wrong shape, unsupported schema),
  * the tool reports that it scanned nothing although errors were logged;
partial when
  * the exit code is not a documented success code but the output is usable,
  * the tool reported errors (files not parsed, rules failed, git errors ...),
  * checks/rulesets/targets were skipped,
  * findings had to be dropped because they could not be represented validly.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from extorq.contracts import ScanStatus


@dataclass(frozen=True)
class ProcessOutcome:
    """What happened to the tool process (independent of its output)."""

    exit_code: int | None
    timed_out: bool = False
    output_truncated: bool = False
    start_error: str | None = None
    duration_seconds: float = 0.0


@dataclass(frozen=True)
class Verdict:
    status: ScanStatus
    error: str | None
    reasons: tuple[str, ...] = ()


def decide(
    process: ProcessOutcome,
    *,
    success_exit_codes: Collection[int],
    parse_error: str | None,
    tool_errors: Collection[str] = (),
    skipped: Collection[str] = (),
    dropped_findings: int = 0,
    nothing_scanned: bool = False,
    timeout_seconds: float | None = None,
) -> Verdict:
    if process.start_error:
        return Verdict(ScanStatus.FAILED, f"tool could not be started: {process.start_error}")
    if process.timed_out:
        limit = f" after {timeout_seconds:.0f}s" if timeout_seconds else ""
        return Verdict(ScanStatus.FAILED, f"tool timed out{limit}; output discarded")
    if process.output_truncated:
        return Verdict(
            ScanStatus.FAILED, "tool output exceeded the size limit; truncated output discarded"
        )
    if parse_error is not None:
        code = f" (exit code {process.exit_code})" if process.exit_code is not None else ""
        return Verdict(ScanStatus.FAILED, f"unusable tool output{code}: {parse_error}")
    if process.exit_code is None:
        return Verdict(ScanStatus.FAILED, "tool exit status unknown")
    if nothing_scanned:
        detail = f": {next(iter(tool_errors))}" if tool_errors else ""
        return Verdict(ScanStatus.FAILED, f"tool reported that nothing was scanned{detail}")

    reasons: list[str] = []
    if process.exit_code not in success_exit_codes:
        reasons.append(f"unexpected exit code {process.exit_code}")
    if tool_errors:
        reasons.append(f"{len(tool_errors)} tool errors")
    if skipped:
        reasons.append(f"{len(skipped)} checks skipped")
    if dropped_findings:
        reasons.append(f"{dropped_findings} findings dropped")
    if reasons:
        first = next(iter(tool_errors), None)
        error = "; ".join(reasons) + (f" (first error: {first})" if first else "")
        return Verdict(ScanStatus.PARTIAL, error[:2000], tuple(reasons))
    return Verdict(ScanStatus.SUCCEEDED, None)

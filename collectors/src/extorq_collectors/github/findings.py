"""ScanRun + PostureFinding assembly shared by the posture and security-alert scans.

Lifecycle contract (contracts/scan.py): a finding is only resolved by a later
SUCCEEDED scan with the same scope hash. Therefore:

* checks that are *permanently* unavailable for this token/plan (HTTP 403/404:
  feature unavailable or not authorised) are excluded from the scope and listed in
  ``coverage.skipped`` - the scan never claims "no findings" for them;
* checks that failed *transiently* (network, 5xx, rate limit) stay in scope and
  make the scan PARTIAL, so nothing is resolved by an incomplete scan;
* a scan in which no check could run is PARTIAL with ``findings_count=None``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.contracts import (
    FindingCategory,
    PackageRef,
    PostureFinding,
    Resource,
    ScanCoverage,
    ScanRun,
    ScanScope,
    ScanStatus,
    Severity,
    SkippedCheck,
)
from extorq.contracts.identity import finding_id, iso_utc, scope_hash, stable_id
from extorq_collectors.github.records import clean_text


@dataclass(frozen=True)
class FindingDraft:
    check_id: str
    severity: Severity
    title: str
    resource_key: str
    category: FindingCategory = FindingCategory.POSTURE
    description: str | None = None
    resource: Resource | None = None
    package: PackageRef | None = None
    cve_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    evidence: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckOutcome:
    """Result of one check: evaluated (with 0..n findings) or skipped with a reason."""

    check_id: str
    evaluated: bool
    findings: tuple[FindingDraft, ...] = ()
    skip_reason: str | None = None
    transient: bool = False

    @classmethod
    def ok(cls, check_id: str, findings: Sequence[FindingDraft] = ()) -> CheckOutcome:
        return cls(check_id, True, tuple(findings))

    @classmethod
    def skip(cls, check_id: str, reason: str, *, transient: bool = False) -> CheckOutcome:
        return cls(check_id, False, (), clean_text(reason, 500), transient)


@dataclass(frozen=True)
class ScanRecords:
    scan_run: ScanRun
    findings: tuple[PostureFinding, ...]


def build_scan_records(
    *,
    scanner: str,
    scanner_version: str,
    asset_id: str,
    repo_target: str,
    description: str,
    producer_id: str,
    started_at: datetime,
    finished_at: datetime,
    outcomes: Sequence[CheckOutcome],
    attributes: dict[str, Any] | None = None,
    error: str | None = None,
) -> ScanRecords:
    in_scope = sorted(o.check_id for o in outcomes if o.evaluated or o.transient)
    targets = [repo_target] + [f"check:{check}" for check in in_scope]
    scope = ScanScope(
        targets=targets, description=description, scope_hash=scope_hash(targets, description)
    )
    scan_run_id = stable_id("github.scan.v1", scanner, asset_id, iso_utc(started_at))
    evaluated = [o for o in outcomes if o.evaluated]
    transient = [o for o in outcomes if o.transient]
    skipped = [
        SkippedCheck(check=o.check_id, reason=o.skip_reason or "not evaluated")
        for o in outcomes
        if not o.evaluated
    ]
    status = ScanStatus.SUCCEEDED if evaluated and not transient else ScanStatus.PARTIAL
    if not evaluated and error is None:
        error = "no check could be evaluated (see coverage.skipped)"
    elif transient and error is None:
        error = f"{len(transient)} check(s) failed transiently; scan is partial"
    findings: list[PostureFinding] = []
    for outcome in evaluated:
        for draft in outcome.findings:
            findings.append(
                PostureFinding(
                    finding_id=finding_id(asset_id, scanner, draft.check_id, draft.resource_key),
                    scan_run_id=scan_run_id,
                    asset_id=asset_id,
                    scanner=scanner,
                    check_id=clean_text(draft.check_id, 256),
                    category=draft.category,
                    severity=draft.severity,
                    title=clean_text(draft.title, 256),
                    description=clean_text(draft.description, 2000) if draft.description else None,
                    resource=draft.resource,
                    package=draft.package,
                    cve_ids=list(draft.cve_ids)[:32],
                    cvss_score=draft.cvss_score,
                    evidence=clean_text(draft.evidence, 2000) if draft.evidence else None,
                    remediation=clean_text(draft.remediation, 2000) if draft.remediation else None,
                    references=[clean_text(r, 2000) for r in draft.references][:10],
                    observed_at=finished_at,
                    attributes=draft.attributes,
                )
            )
    scan_run = ScanRun(
        scan_run_id=scan_run_id,
        scanner=scanner,
        scanner_version=scanner_version,
        asset_id=asset_id,
        scope=scope,
        started_at=started_at,
        finished_at=finished_at,
        status=status,
        coverage=ScanCoverage(
            checks_total=len(outcomes),
            checks_run=len(evaluated),
            skipped=skipped[:256],
            notes=[],
        ),
        findings_count=len(findings) if evaluated else None,
        error=clean_text(error, 2000) if error else None,
        producer_id=producer_id,
        attributes=attributes or {},
    )
    return ScanRecords(scan_run=scan_run, findings=tuple(findings))

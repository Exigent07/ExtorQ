"""ScanRun contract (schema 1.0).

Finding lifecycle depends on scan *success, scope and coverage*:
a finding is only ``resolved`` when a later SUCCEEDED scan with the SAME scope
hash completed without observing it. PARTIAL or FAILED scans never resolve
findings (see docs/data-model.md, "Findings lifecycle").
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from extorq.contracts.common import (
    SCHEMA_VERSION,
    AssetId,
    Attributes,
    ContractModel,
    HexId,
    Identifier,
    MediumStr,
    SchemaVersion,
    ShortStr,
    UtcDatetime,
)


class ScanStatus(StrEnum):
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"


class SkippedCheck(ContractModel):
    check: ShortStr
    reason: MediumStr


class ScanScope(ContractModel):
    #: What was scanned: paths, image refs, namespaces, repo@sha, check groups.
    targets: list[MediumStr] = Field(min_length=1, max_length=256)
    description: ShortStr = ""
    #: :func:`extorq.contracts.identity.scope_hash` of (targets, description).
    scope_hash: HexId


class ScanCoverage(ContractModel):
    checks_total: int | None = Field(default=None, ge=0)
    checks_run: int | None = Field(default=None, ge=0)
    skipped: list[SkippedCheck] = Field(default_factory=list, max_length=256)
    notes: list[MediumStr] = Field(default_factory=list, max_length=32)


class ScanRun(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    scan_run_id: HexId
    #: trivy | gitleaks | semgrep | extorq-posture-macos | extorq-posture-linux |
    #: extorq-posture-k8s | extorq-posture-github
    scanner: Identifier
    scanner_version: ShortStr
    asset_id: AssetId
    scope: ScanScope
    started_at: UtcDatetime
    finished_at: UtcDatetime | None = None
    status: ScanStatus
    coverage: ScanCoverage = Field(default_factory=ScanCoverage)
    findings_count: int | None = Field(default=None, ge=0)
    #: Sanitized error summary (no secrets, no raw stack traces with tokens).
    error: MediumStr | None = None
    producer_id: Identifier
    attributes: Attributes = Field(default_factory=dict)

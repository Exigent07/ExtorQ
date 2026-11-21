"""PostureFinding contract (schema 1.0).

A PostureFinding row is an *observation* of a finding during one ScanRun.
``finding_id`` is a stable fingerprint (see identity.finding_id) so the same
issue observed by successive scans shares one identity; lifecycle state
(open / resolved / unverified) is derived from scan history, never asserted by
a scanner (see v_findings_current in the ClickHouse schema).
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
    Severity,
    ShortStr,
    UtcDatetime,
)
from extorq.contracts.event import Resource


class FindingCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    SECRET = "secret"  # noqa: S105 - finding category name, not a credential
    CODE = "code"
    POSTURE = "posture"
    EXPOSURE = "exposure"


class PackageRef(ContractModel):
    name: ShortStr
    installed_version: ShortStr | None = None
    fixed_version: ShortStr | None = None
    ecosystem: ShortStr | None = None


class AcceptedRisk(ContractModel):
    """A documented, deliberate exception (e.g. node log collector hostPath)."""

    reason: MediumStr
    #: Where the acceptance is declared, e.g. "annotation:extorq.io/accepted-risk".
    source: ShortStr


class PostureFinding(ContractModel):
    schema_version: SchemaVersion = SCHEMA_VERSION
    finding_id: HexId
    scan_run_id: HexId
    asset_id: AssetId
    scanner: Identifier
    #: e.g. CVE-2024-1234, KSV-0017, gitleaks:generic-api-key, linux.ssh.password_auth
    check_id: ShortStr
    category: FindingCategory
    severity: Severity
    title: ShortStr
    description: MediumStr | None = None
    resource: Resource | None = None
    #: Service the finding applies to, when attributable (e.g. sshd config → ssh service) (1.1).
    service_id: HexId | None = None
    package: PackageRef | None = None
    cve_ids: list[ShortStr] = Field(default_factory=list, max_length=32)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    #: Sanitized evidence. Secrets are NEVER stored: only redacted match + location.
    evidence: MediumStr | None = None
    remediation: MediumStr | None = None
    references: list[MediumStr] = Field(default_factory=list, max_length=10)
    observed_at: UtcDatetime
    accepted_risk: AcceptedRisk | None = None
    attributes: Attributes = Field(default_factory=dict)

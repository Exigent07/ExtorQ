"""Internal data structures shared by the scanner runner and the normalisers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from extorq.contracts import PostureFinding, Severity, SkippedCheck

from extorq_scanners.k8s_index import K8sIndex


class ReportFormatError(ValueError):
    """Tool output is not a usable report (malformed, wrong shape, unsupported schema)."""


@dataclass(frozen=True)
class NormalizeContext:
    """Everything a pure normaliser needs besides the tool output itself."""

    asset_id: str
    scanner: str
    scan_run_id: str
    observed_at: datetime
    #: Container path the scan target was mounted at (stripped from reported paths).
    mount_point: str = "/src"
    #: Tool mode: trivy fs|config|image|sbom, gitleaks dir|git, semgrep scan.
    mode: str = ""
    #: Per-rule severity overrides (gitleaks rule id -> severity).
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)
    default_secret_severity: Severity = Severity.HIGH
    #: Kubernetes object line index of the scanned manifests (Trivy misconfig enrichment).
    k8s_index: K8sIndex | None = None
    #: Semgrep: prefixes Semgrep may prepend to rule ids (derived from config paths).
    rule_id_prefixes: tuple[str, ...] = ()
    #: Semgrep: number of rules supplied (coverage); label of the rulesets used.
    rules_total: int | None = None
    ruleset_label: str | None = None


@dataclass
class NormalizedScan:
    """Normaliser output: findings plus the coverage facts needed for the ScanRun."""

    findings: list[PostureFinding] = field(default_factory=list)
    scanner_version: str | None = None
    checks_total: int | None = None
    checks_run: int | None = None
    skipped: list[SkippedCheck] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    #: Problems reported by the tool that reduce coverage (=> scan is at best partial).
    tool_errors: list[str] = field(default_factory=list)
    #: The tool reports that it scanned nothing (=> scan failed).
    nothing_scanned: bool = False
    #: Findings that could not be represented as valid contract records.
    dropped: int = 0
    duplicates: int = 0
    redactions: int = 0
    #: Scan-level facts for ScanRun.attributes (bounded scalars/lists).
    attributes: dict[str, str | int | float | bool | list[str]] = field(default_factory=dict)

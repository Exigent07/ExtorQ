"""Mapping of scanner-native severities onto the contract :class:`Severity`.

The original value is always preserved in ``attributes.source_severity`` so the
mapping is auditable. When a scanner reports no usable severity, the CVSS v3
qualitative rating scale (FIRST CVSS v3.1 specification, section 5) is used if
a base score is available; otherwise the finding is ``info`` and
``attributes.severity_basis`` says so (never silently promoted).
"""

from __future__ import annotations

from extorq.contracts import Severity

TRIVY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

#: Semgrep rule severities: legacy ERROR/WARNING/INFO plus the newer levels.
SEMGREP = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
    "INVENTORY": Severity.INFO,
    "EXPERIMENT": Severity.INFO,
}


def from_cvss(score: float | None) -> Severity | None:
    """CVSS v3.x qualitative severity rating scale."""
    if score is None:
        return None
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def map_trivy(raw: object, cvss: float | None = None) -> tuple[Severity, str]:
    """Return (severity, basis) for a Trivy severity string."""
    key = raw.upper() if isinstance(raw, str) else ""
    if key in TRIVY:
        return TRIVY[key], "scanner"
    derived = from_cvss(cvss)
    if derived is not None:
        return derived, "cvss_v3"
    return Severity.INFO, "unknown"


def map_semgrep(raw: object) -> tuple[Severity, str]:
    key = raw.upper() if isinstance(raw, str) else ""
    if key in SEMGREP:
        return SEMGREP[key], "scanner"
    return Severity.INFO, "unknown"


def parse_severity(raw: object, default: Severity) -> Severity:
    """Parse a configured severity override (case-insensitive)."""
    if isinstance(raw, Severity):
        return raw
    if isinstance(raw, str):
        try:
            return Severity(raw.strip().lower())
        except ValueError:
            return default
    return default

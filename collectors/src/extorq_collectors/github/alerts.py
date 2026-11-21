"""GitHub security alerts (Dependabot, code scanning, secret scanning) -> findings.

Scanner id ``github-security-alerts``. Only *open* alerts are fetched; each scan
re-observes every open alert so the lifecycle view can resolve alerts that GitHub
closed (fixed/dismissed) when a later SUCCEEDED scan with the same scope no longer
reports them.

Access is frequently unavailable (GitHub Advanced Security / Secret Protection not
enabled on private repositories, missing fine-grained permissions, plan limits).
A 403/404 is recorded as a data gap "feature unavailable or not authorised" and the
feature is excluded from the scan scope - it is never reported as "no alerts".

Secret values are never requested (``hide_secret=true``) and never stored.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from extorq.contracts import FindingCategory, PackageRef, Resource, Severity
from extorq_collectors.github.findings import FindingDraft
from extorq_collectors.github.records import as_dict, clean_text

SCANNER = "github-security-alerts"
SCANNER_VERSION = "1.0.0"
SCOPE_DESCRIPTION = (
    "github-security-alerts v1: open Dependabot, code scanning and secret scanning alerts"
)

#: feature -> (API path suffix, extra query parameters)
FEATURES: dict[str, tuple[str, dict[str, str | int | bool]]] = {
    "dependabot_alerts": ("/dependabot/alerts", {"state": "open"}),
    "code_scanning_alerts": ("/code-scanning/alerts", {"state": "open"}),
    "secret_scanning_alerts": ("/secret-scanning/alerts", {"state": "open", "hide_secret": True}),
}

_SEVERITIES = {s.value: s for s in Severity}
_CODE_SCANNING_LEVELS = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


def _str(value: object, limit: int = 256) -> str | None:
    return clean_text(value, limit) if isinstance(value, str) and value else None


def _severity(value: object, default: Severity = Severity.MEDIUM) -> Severity:
    if isinstance(value, str):
        return _SEVERITIES.get(value.lower(), default)
    return default


def _valid_cvss(value: object) -> bool:
    """A usable CVSS base score: a real number in (0, 10] (bool excluded)."""
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and value == value  # not NaN
        and 0 < value <= 10
    )


def _number(alert: Mapping[str, Any]) -> int | None:
    number = alert.get("number")
    return number if isinstance(number, int) and number >= 0 else None


def dependabot_finding(alert: Mapping[str, Any]) -> FindingDraft | None:
    number = _number(alert)
    if number is None:
        return None
    advisory = as_dict(alert.get("security_advisory"))
    vuln = as_dict(alert.get("security_vulnerability"))
    dependency = as_dict(alert.get("dependency"))
    package = as_dict(dependency.get("package"))
    ghsa = _str(advisory.get("ghsa_id"), 64)
    cve = _str(advisory.get("cve_id"), 64)
    name = _str(package.get("name"), 200)
    ecosystem = _str(package.get("ecosystem"), 40)
    manifest = _str(dependency.get("manifest_path"), 500)
    patched = as_dict(vuln.get("first_patched_version"))
    cvss: float | None = None
    severities = as_dict(advisory.get("cvss_severities"))
    for key in ("cvss_v4", "cvss_v3"):
        entry = severities.get(key)
        if isinstance(entry, Mapping) and _valid_cvss(entry.get("score")):
            cvss = float(entry["score"])
            break
    if cvss is None:
        legacy = advisory.get("cvss")
        if isinstance(legacy, Mapping) and _valid_cvss(legacy.get("score")):
            cvss = float(legacy["score"])
    summary = _str(advisory.get("summary"), 200) or "Dependabot alert"
    return FindingDraft(
        check_id=f"dependabot:{ghsa or cve or number}",
        severity=_severity(advisory.get("severity") or vuln.get("severity")),
        title=f"{name or 'dependency'}: {summary}",
        resource_key=f"dependabot-alert:{number}",
        category=FindingCategory.VULNERABILITY,
        description=_str(advisory.get("description"), 1500),
        resource=Resource(type="manifest", path=manifest, name=name),
        package=PackageRef(
            name=name or "unknown",
            installed_version=None,
            fixed_version=_str(patched.get("identifier"), 100),
            ecosystem=ecosystem,
        )
        if name
        else None,
        cve_ids=(cve,) if cve else (),
        cvss_score=cvss,
        evidence=_str(
            f"vulnerable range {vuln.get('vulnerable_version_range')}"
            if vuln.get("vulnerable_version_range")
            else None,
            500,
        ),
        remediation=f"Upgrade {name} to {patched.get('identifier')} or later."
        if name and patched.get("identifier")
        else None,
        references=tuple(r for r in (_str(alert.get("html_url"), 500),) if r),
        attributes={"alert_number": number, "ghsa_id": ghsa, "manifest_path": manifest},
    )


def code_scanning_finding(alert: Mapping[str, Any]) -> FindingDraft | None:
    number = _number(alert)
    if number is None:
        return None
    rule = as_dict(alert.get("rule"))
    tool = as_dict(alert.get("tool"))
    instance = as_dict(alert.get("most_recent_instance"))
    location = as_dict(instance.get("location"))
    security_level = rule.get("security_severity_level")
    if isinstance(security_level, str) and security_level.lower() in _SEVERITIES:
        severity = _SEVERITIES[security_level.lower()]
    else:
        severity = _CODE_SCANNING_LEVELS.get(str(rule.get("severity")).lower(), Severity.MEDIUM)
    rule_id = _str(rule.get("id"), 128) or "unknown-rule"
    path = _str(location.get("path"), 500)
    line = location.get("start_line") if isinstance(location.get("start_line"), int) else None
    return FindingDraft(
        check_id=f"code-scanning:{_str(tool.get('name'), 40) or 'tool'}:{rule_id}",
        severity=severity,
        title=_str(rule.get("description"), 200) or _str(rule.get("name"), 200) or rule_id,
        resource_key=f"code-scanning-alert:{number}",
        category=FindingCategory.CODE,
        resource=Resource(type="file", path=path),
        evidence=f"{path}:{line}" if path and line else path,
        references=tuple(r for r in (_str(alert.get("html_url"), 500),) if r),
        attributes={"alert_number": number, "tool": _str(tool.get("name"), 40), "rule_id": rule_id},
    )


def secret_scanning_finding(alert: Mapping[str, Any]) -> FindingDraft | None:
    """Secret scanning alert -> finding. The secret value is never read or stored."""
    number = _number(alert)
    if number is None:
        return None
    secret_type = _str(alert.get("secret_type"), 128) or "unknown"
    display = _str(alert.get("secret_type_display_name"), 128) or secret_type
    validity = _str(alert.get("validity"), 20)
    bypassed = alert.get("push_protection_bypassed") is True
    return FindingDraft(
        check_id=f"secret-scanning:{secret_type}",
        severity=Severity.CRITICAL if validity == "active" else Severity.HIGH,
        title=f"Secret detected: {display}",
        resource_key=f"secret-scanning-alert:{number}",
        category=FindingCategory.SECRET,
        evidence=f"secret value withheld; validity={validity or 'unknown'}; "
        f"push_protection_bypassed={'true' if bypassed else 'false'}",
        remediation="Revoke and rotate the credential, then close the alert.",
        references=tuple(r for r in (_str(alert.get("html_url"), 500),) if r),
        attributes={"alert_number": number, "secret_type": secret_type, "validity": validity},
    )


BUILDERS = {
    "dependabot_alerts": dependabot_finding,
    "code_scanning_alerts": code_scanning_finding,
    "secret_scanning_alerts": secret_scanning_finding,
}

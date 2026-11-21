"""Trivy JSON report (SchemaVersion 2) -> PostureFindings.

Handles ``fs``, ``config``, ``image`` and ``sbom`` reports: ``Vulnerabilities``
become ``vulnerability`` findings, failed ``Misconfigurations`` become
``misconfiguration`` findings. Secret results are ignored on purpose (secrets
are Gitleaks' job and Trivy is run without its secret scanner) and code
snippets (``CauseMetadata.Code``) are never stored.

Finding identity (``identity.finding_id``):

* vulnerability: (check=VulnerabilityID, resource=class|location|package|installed|pkg_path)
  where location is ``os`` for OS packages and the lock/manifest path otherwise;
* misconfiguration: (check=ID, resource=target|sha256(message)[:16]) which is stable
  across unrelated edits that only shift line numbers.
"""

from __future__ import annotations

import hashlib
from typing import Any

from extorq.contracts import FindingCategory, PackageRef, Resource

from extorq_scanners import severity as sev
from extorq_scanners.k8s_index import lookup
from extorq_scanners.models import NormalizeContext, NormalizedScan, ReportFormatError
from extorq_scanners.normalize.common import FindingBuilder, references
from extorq_scanners.sanitize import (
    MEDIUM,
    SHORT,
    RedactionCounter,
    bounded_int,
    clean,
    clean_list,
    is_cve,
    safe_identifier,
)

_CVSS_VENDOR_ORDER = ("nvd", "ghsa", "redhat", "ubuntu", "debian")


def _pick_cvss(vuln: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    """(score, vector, source) preferring the severity source, then NVD, then others; v3 first."""
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, dict) or not cvss:
        return None, None, None
    preferred = vuln.get("SeveritySource")
    order: list[str] = []
    if isinstance(preferred, str) and preferred in cvss:
        order.append(preferred)
    order += [v for v in _CVSS_VENDOR_ORDER if v in cvss and v not in order]
    order += sorted(v for v in cvss if isinstance(v, str) and v not in order)
    for score_key, vector_key in (("V3Score", "V3Vector"), ("V40Score", "V40Vector")):
        for vendor in order:
            data = cvss.get(vendor)
            if not isinstance(data, dict):
                continue
            score = data.get(score_key)
            if isinstance(score, int | float) and not isinstance(score, bool) and 0 <= score <= 10:
                vector = data.get(vector_key)
                return float(score), vector if isinstance(vector, str) else None, vendor
    return None, None, None


def _vulnerability(
    vuln: dict[str, Any], result: dict[str, Any], b: FindingBuilder, counter: RedactionCounter
) -> None:
    vid = safe_identifier(vuln.get("VulnerabilityID"))
    pkg_name = clean(vuln.get("PkgName"), SHORT, counter)
    if vid is None or pkg_name is None:
        b.result.dropped += 1
        return
    installed = clean(vuln.get("InstalledVersion"), SHORT, counter)
    fixed = clean(vuln.get("FixedVersion"), SHORT, counter)
    pkg_path = clean(vuln.get("PkgPath"), MEDIUM, counter)
    klass = clean(result.get("Class"), 64) or "unknown"
    pkg_type = clean(result.get("Type"), 64)
    target = clean(result.get("Target"), MEDIUM, counter)
    is_os = klass == "os-pkgs"
    location = "os" if is_os else (target or "")
    resource_key = "|".join([klass, location, pkg_name, installed or "", pkg_path or ""])

    score, vector, cvss_source = _pick_cvss(vuln)
    severity, basis = sev.map_trivy(vuln.get("Severity"), score)
    trivy_title = clean(vuln.get("Title"), SHORT, counter)
    title = f"{vid} in {pkg_name} {installed or ''}".strip()
    if trivy_title:
        title = f"{title}: {trivy_title}"
    status = clean(vuln.get("Status"), 64)
    if fixed:
        remediation = f"Upgrade {pkg_name} to {fixed} or later."
    elif status in {"affected", "fix_deferred", "will_not_fix", "end_of_life"}:
        remediation = f"No fixed version available (vendor status: {status})."
    else:
        remediation = None
    ident = vuln.get("PkgIdentifier") if isinstance(vuln.get("PkgIdentifier"), dict) else {}
    data_source = vuln.get("DataSource") if isinstance(vuln.get("DataSource"), dict) else {}
    b.add(
        check_id=vid,
        resource_key=resource_key,
        category=FindingCategory.VULNERABILITY,
        severity=severity,
        title=clean(title, SHORT, counter) or vid,
        description=clean(vuln.get("Description"), MEDIUM, counter),
        resource=Resource(
            type="package", name=pkg_name, path=pkg_path if is_os else (pkg_path or target)
        ),
        package=PackageRef(
            name=pkg_name, installed_version=installed, fixed_version=fixed, ecosystem=pkg_type
        ),
        cve_ids=[vid] if is_cve(vid) else [],
        cvss_score=score,
        remediation=remediation,
        refs=references(vuln.get("PrimaryURL"), vuln.get("References"), counter),
        attributes={
            "source_severity": vuln.get("Severity"),
            "severity_basis": basis,
            "severity_source": vuln.get("SeveritySource"),
            "vuln_status": status,
            "target": target,
            "class": klass,
            "pkg_type": pkg_type,
            "pkg_id": vuln.get("PkgID"),
            "purl": ident.get("PURL"),
            "pkg_path": pkg_path,
            "vendor_ids": clean_list(vuln.get("VendorIDs"), max_items=16, item_limit=128),
            "cwe_ids": clean_list(vuln.get("CweIDs"), max_items=16, item_limit=64),
            "published_date": vuln.get("PublishedDate"),
            "last_modified_date": vuln.get("LastModifiedDate"),
            "data_source": data_source.get("ID"),
            "cvss_vector": vector,
            "cvss_source": cvss_source,
        },
    )


def _misconfiguration(
    mis: dict[str, Any], result: dict[str, Any], b: FindingBuilder, counter: RedactionCounter
) -> None:
    check = safe_identifier(mis.get("ID"))
    if check is None:
        b.result.dropped += 1
        return
    target = clean(result.get("Target"), MEDIUM, counter)
    config_type = clean(result.get("Type"), 64)
    message = clean(mis.get("Message"), MEDIUM, counter)
    cause = mis.get("CauseMetadata") if isinstance(mis.get("CauseMetadata"), dict) else {}
    start = bounded_int(cause.get("StartLine"))
    end = bounded_int(cause.get("EndLine"))
    obj = lookup(b.ctx.k8s_index, target, start)
    if obj is not None:
        resource = Resource(type=obj.kind, name=obj.name, namespace=obj.namespace, path=target)
    else:
        resource = Resource(type=config_type, path=target)
    location = target or ""
    if start is not None:
        location += f":{start}" + (f"-{end}" if end is not None and end != start else "")
    digest = hashlib.sha256((message or "").encode("utf-8")).hexdigest()[:16]
    severity, basis = sev.map_trivy(mis.get("Severity"))
    evidence = f"{message} ({location})" if message else location or None
    b.add(
        check_id=check,
        resource_key=f"{target or ''}|{digest}",
        category=FindingCategory.MISCONFIGURATION,
        severity=severity,
        title=clean(mis.get("Title"), SHORT, counter) or check,
        description=clean(mis.get("Description"), MEDIUM, counter),
        resource=resource,
        evidence=clean(evidence, MEDIUM, counter),
        remediation=clean(mis.get("Resolution"), MEDIUM, counter),
        refs=references(mis.get("PrimaryURL"), mis.get("References"), counter),
        attributes={
            "source_severity": mis.get("Severity"),
            "severity_basis": basis,
            "target": target,
            "config_type": config_type,
            "check_type": mis.get("Type"),
            "check_namespace": mis.get("Namespace"),
            "start_line": start,
            "end_line": end,
            "provider": cause.get("Provider"),
            "service": cause.get("Service"),
            "message": message,
        },
    )


def normalize_trivy(report: object, ctx: NormalizeContext) -> NormalizedScan:
    """Normalise a parsed Trivy JSON report. Raises ReportFormatError if unusable."""
    if not isinstance(report, dict):
        raise ReportFormatError("trivy report is not a JSON object")
    if report.get("SchemaVersion") != 2:
        raise ReportFormatError(f"unsupported trivy SchemaVersion {report.get('SchemaVersion')!r}")
    results = report.get("Results")
    if results is None:
        results = []
    if not isinstance(results, list):
        raise ReportFormatError("trivy report 'Results' is not a list")

    out = NormalizedScan()
    counter = RedactionCounter()
    builder = FindingBuilder(ctx, out, counter)
    trivy_meta = report.get("Trivy") if isinstance(report.get("Trivy"), dict) else {}
    out.scanner_version = clean(trivy_meta.get("Version"), 64)

    successes = failures = exceptions = 0
    misconf_seen = False
    packages = 0
    ignored_secrets = 0
    classes: set[str] = set()
    for result in results:
        if not isinstance(result, dict):
            raise ReportFormatError("trivy result entry is not an object")
        klass = result.get("Class")
        if isinstance(klass, str):
            classes.add(klass)
        packages += len(result.get("Packages") or [])
        summary = result.get("MisconfSummary")
        if isinstance(summary, dict):
            misconf_seen = True
            successes += bounded_int(summary.get("Successes")) or 0
            failures += bounded_int(summary.get("Failures")) or 0
            exceptions += bounded_int(summary.get("Exceptions")) or 0
        for vuln in result.get("Vulnerabilities") or []:
            if isinstance(vuln, dict):
                _vulnerability(vuln, result, builder, counter)
            else:
                out.dropped += 1
        for mis in result.get("Misconfigurations") or []:
            if not isinstance(mis, dict):
                out.dropped += 1
            elif mis.get("Status", "FAIL") == "FAIL":
                _misconfiguration(mis, result, builder, counter)
        ignored_secrets += len(result.get("Secrets") or [])

    if misconf_seen:
        out.checks_total = successes + failures + exceptions
        out.checks_run = out.checks_total
        out.notes.append(
            f"misconfiguration checks evaluated: {successes} passed, {failures} failed, "
            f"{exceptions} exceptions"
        )
    out.notes.append(f"{len(results)} result targets, {packages} packages analysed")
    if ignored_secrets:
        out.notes.append(f"{ignored_secrets} trivy secret results ignored (Gitleaks owns secrets)")
    metadata = report.get("Metadata") if isinstance(report.get("Metadata"), dict) else {}
    os_info = metadata.get("OS") if isinstance(metadata.get("OS"), dict) else {}
    out.attributes = {
        k: v
        for k, v in {
            "artifact_type": clean(report.get("ArtifactType"), 64),
            "os_family": clean(os_info.get("Family"), 64),
            "os_name": clean(os_info.get("Name"), 64),
            "image_id": clean(metadata.get("ImageID"), 128),
            "packages_analysed": packages,
            "result_classes": sorted(classes),
        }.items()
        if v is not None
    }
    out.redactions = counter.count
    return out

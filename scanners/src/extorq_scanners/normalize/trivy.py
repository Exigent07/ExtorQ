"""Trivy JSON report (SchemaVersion 2) -> PostureFindings.

Handles ``fs``, ``config``, ``image`` and ``sbom`` reports: ``Vulnerabilities``
become ``vulnerability`` findings, failed ``Misconfigurations`` become
``misconfiguration`` findings. Secret results are ignored on purpose (secrets
are Gitleaks' job and Trivy is run without its secret scanner) and code
snippets (``CauseMetadata.Code``) are never stored.

Finding identity (``identity.finding_id``):

* vulnerability: (check=VulnerabilityID, resource=class|location|package|installed|pkg_path)
  where location is ``os`` for OS packages and the lock/manifest path otherwise. OS
  packages are grouped per source package (Debian/Ubuntu advisories are per source):
  package = ``src:<source>``, installed = full source version, and the affected binary
  packages are listed in ``attributes.binary_packages``. Image scans add the qualifier
  ``image:<repository>`` (NormalizeContext.identity_qualifier);
* misconfiguration: (check=ID, resource=target|object|sha256(message)[:16][#n]) where
  object is ``kind/namespace/name`` of the Kubernetes object containing the failure
  (from the manifest line index, empty otherwise) and ``#n`` (n >= 1) numbers repeated
  identical failures inside one object in line order. Stable across unrelated edits
  that only shift line numbers; distinct failures never share an id.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from extorq.contracts import FindingCategory, PackageRef, Resource
from extorq_scanners import severity as sev
from extorq_scanners.k8s_index import lookup, sole_workload
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
    obj,
    safe_identifier,
)
from extorq_scanners.services import ATTRIBUTION_BASIS

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


def _deb_version(epoch: object, version: object, release: object) -> str | None:
    """Full Debian version ``[epoch:]version[-release]`` from Trivy's package fields."""
    if not isinstance(version, str) or not version:
        return None
    text = version
    if isinstance(release, str) and release:
        text = f"{text}-{release}"
    if isinstance(epoch, int) and not isinstance(epoch, bool) and epoch > 0:
        text = f"{epoch}:{text}"
    return text


def _source_index(result: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """PkgID -> (source package, full source version) from the report's package list."""
    index: dict[str, tuple[str, str]] = {}
    for pkg in result.get("Packages") or []:
        if not isinstance(pkg, dict):
            continue
        pkg_id, src = pkg.get("ID"), pkg.get("SrcName")
        src_version = _deb_version(
            pkg.get("SrcEpoch"), pkg.get("SrcVersion"), pkg.get("SrcRelease")
        )
        if isinstance(pkg_id, str) and isinstance(src, str) and src and src_version:
            index[pkg_id] = (src, src_version)
    return index


def _group_vulnerabilities(
    result: dict[str, Any], vulns: list[dict[str, Any]]
) -> list[tuple[tuple[str, str] | None, list[dict[str, Any]]]]:
    """OS packages: one group per (vulnerability, source package, source version).

    Debian/Ubuntu advisories are per source package and Trivy repeats a source CVE
    for every binary package built from it (e.g. 7 kernel binary packages). Binary
    packages without source information form their own group. Language packages are
    never grouped. Group order is deterministic.
    """
    if result.get("Class") != "os-pkgs":
        return [(None, [v]) for v in vulns]
    sources = _source_index(result)
    groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = {}
    for vuln in vulns:
        vid = str(vuln.get("VulnerabilityID") or "")
        source = sources.get(str(vuln.get("PkgID") or ""))
        if source is not None:
            key = (vid, "src", *source)
        else:
            key = (
                vid,
                "bin",
                str(vuln.get("PkgName") or ""),
                str(vuln.get("InstalledVersion") or ""),
            )
        groups.setdefault(key, []).append(vuln)
    out: list[tuple[tuple[str, str] | None, list[dict[str, Any]]]] = []
    for key in sorted(groups):
        members = sorted(groups[key], key=lambda v: str(v.get("PkgName") or ""))
        out.append(((key[2], key[3]) if key[1] == "src" else None, members))
    return out


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _vulnerability(
    group: list[dict[str, Any]],
    source: tuple[str, str] | None,
    result: dict[str, Any],
    b: FindingBuilder,
    counter: RedactionCounter,
) -> None:
    # The most severe member represents the group (members share the vulnerability id).
    vuln = max(group, key=lambda v: _SEVERITY_RANK.get(str(v.get("Severity")).upper(), 0))
    vid = safe_identifier(vuln.get("VulnerabilityID"))
    binaries = sorted({n for n in (clean(v.get("PkgName"), SHORT, counter) for v in group) if n})
    if vid is None or not binaries:
        b.result.dropped += len(group)
        return
    klass = clean(result.get("Class"), 64) or "unknown"
    pkg_type = clean(result.get("Type"), 64)
    target = clean(result.get("Target"), MEDIUM, counter)
    is_os = klass == "os-pkgs"
    if source is not None:
        pkg_name = clean(source[0], SHORT, counter) or binaries[0]
        installed = clean(source[1], SHORT, counter)
    else:
        pkg_name = clean(vuln.get("PkgName"), SHORT, counter) or binaries[0]
        installed = clean(vuln.get("InstalledVersion"), SHORT, counter)
    fixed_versions = sorted(
        {f for f in (clean(v.get("FixedVersion"), SHORT, counter) for v in group) if f}
    )
    fixed = ", ".join(fixed_versions)[:256] or None
    pkg_path = clean(vuln.get("PkgPath"), MEDIUM, counter)
    location = "os" if is_os else (target or "")
    package_key = f"src:{pkg_name}" if source is not None else pkg_name
    resource_key = "|".join([klass, location, package_key, installed or "", pkg_path or ""])

    score, vector, cvss_source = _pick_cvss(vuln)
    severity, basis = sev.map_trivy(vuln.get("Severity"), score)
    trivy_title = clean(vuln.get("Title"), SHORT, counter)
    title = f"{vid} in {pkg_name} {installed or ''}".strip()
    if source is not None and binaries != [pkg_name]:
        shown = ", ".join(binaries[:3]) + (f" +{len(binaries) - 3}" if len(binaries) > 3 else "")
        title = f"{title} [{shown}]"
    artifact = b.ctx.artifact
    if artifact:
        title = f"{title} (image {artifact})"
    if trivy_title:
        title = f"{title}: {trivy_title}"
    hint = None
    if is_os:
        hint = next(
            (b.ctx.package_services[n] for n in binaries if n in b.ctx.package_services), None
        )
    status = clean(vuln.get("Status"), 64)
    if fixed:
        target_pkgs = (
            pkg_name if source is None else f"{', '.join(binaries[:8])} (source {pkg_name})"
        )
        remediation = f"Upgrade {target_pkgs} to {fixed} or later."
    elif status in {"affected", "fix_deferred", "will_not_fix", "end_of_life"}:
        remediation = f"No fixed version available (vendor status: {status})."
    else:
        remediation = None
    ident = obj(vuln, "PkgIdentifier")
    data_source = obj(vuln, "DataSource")
    b.add(
        check_id=vid,
        resource_key=resource_key,
        category=FindingCategory.VULNERABILITY,
        severity=severity,
        title=clean(title, SHORT, counter) or vid,
        description=clean(vuln.get("Description"), MEDIUM, counter),
        resource=Resource(
            type="package",
            name=pkg_name,
            path=(pkg_path or artifact) if is_os else (pkg_path or target),
        ),
        service_id=hint.service_id if hint else None,
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
            "package_basis": "source" if source is not None else "binary",
            "binary_packages": binaries,
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
            "image": artifact,
            "service_unit": hint.unit if hint else None,
            "service_attribution": ATTRIBUTION_BASIS if hint else None,
            "service_package": hint.package if hint else None,
        },
    )


def _lines(mis: dict[str, Any]) -> tuple[int, int]:
    cause = obj(mis, "CauseMetadata")
    return (bounded_int(cause.get("StartLine")) or 0, bounded_int(cause.get("EndLine")) or 0)


def _misconfiguration(
    mis: dict[str, Any],
    result: dict[str, Any],
    b: FindingBuilder,
    counter: RedactionCounter,
    occurrences: Counter[str],
) -> None:
    check = safe_identifier(mis.get("ID"))
    if check is None:
        b.result.dropped += 1
        return
    target = clean(result.get("Target"), MEDIUM, counter)
    config_type = clean(result.get("Type"), 64)
    message = clean(mis.get("Message"), MEDIUM, counter)
    cause = obj(mis, "CauseMetadata")
    start = bounded_int(cause.get("StartLine"))
    end = bounded_int(cause.get("EndLine"))
    k8s_obj = lookup(b.ctx.k8s_index, target, start)
    object_basis = "line_range" if k8s_obj is not None else None
    if k8s_obj is None and start is None and check.startswith("KSV"):
        # Pod-level checks report no lines; attribute only when the file has one workload.
        k8s_obj = sole_workload(b.ctx.k8s_index, target)
        object_basis = "sole_workload_in_file" if k8s_obj is not None else None
    if k8s_obj is not None:
        resource = Resource(
            type=k8s_obj.kind, name=k8s_obj.name, namespace=k8s_obj.namespace, path=target
        )
        obj_key = f"{k8s_obj.kind}/{k8s_obj.namespace or ''}/{k8s_obj.name or ''}"
    else:
        resource = Resource(type=config_type, path=target)
        obj_key = ""
    location = target or ""
    if start is not None:
        location += f":{start}" + (f"-{end}" if end is not None and end != start else "")
    digest = hashlib.sha256((message or "").encode("utf-8")).hexdigest()[:16]
    base_key = f"{target or ''}|{obj_key}|{digest}"
    ordinal = occurrences[f"{check}|{base_key}"]
    occurrences[f"{check}|{base_key}"] += 1
    severity, basis = sev.map_trivy(mis.get("Severity"))
    evidence = f"{message} ({location})" if message else location or None
    b.add(
        check_id=check,
        resource_key=base_key + (f"#{ordinal}" if ordinal else ""),
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
            "object_basis": object_basis,
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
    trivy_meta = obj(report, "Trivy")
    out.scanner_version = clean(trivy_meta.get("Version"), 64)

    successes = failures = exceptions = reported_vulns = 0
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
        vulns: list[dict[str, Any]] = []
        for vuln in result.get("Vulnerabilities") or []:
            if isinstance(vuln, dict):
                vulns.append(vuln)
            else:
                out.dropped += 1
        for source, group in _group_vulnerabilities(result, vulns):
            _vulnerability(group, source, result, builder, counter)
        reported_vulns += len(vulns)
        failed: list[dict[str, Any]] = []
        for mis in result.get("Misconfigurations") or []:
            if not isinstance(mis, dict):
                out.dropped += 1
            elif mis.get("Status", "FAIL") == "FAIL":
                failed.append(mis)
        occurrences: Counter[str] = Counter()
        for mis in sorted(failed, key=_lines):  # line order => stable occurrence numbers
            _misconfiguration(mis, result, builder, counter, occurrences)
        ignored_secrets += len(result.get("Secrets") or [])

    if misconf_seen:
        out.checks_total = successes + failures + exceptions
        out.checks_run = out.checks_total
        out.notes.append(
            f"misconfiguration checks evaluated: {successes} passed, {failures} failed, "
            f"{exceptions} exceptions"
        )
    out.notes.append(f"{len(results)} result targets, {packages} packages analysed")
    vuln_findings = sum(1 for f in out.findings if f.category == FindingCategory.VULNERABILITY)
    if reported_vulns:
        out.notes.append(
            f"{reported_vulns} package vulnerability entries reported; OS-package entries grouped "
            f"per (vulnerability, source package) into {vuln_findings} findings"
        )
    if ignored_secrets:
        out.notes.append(f"{ignored_secrets} trivy secret results ignored (Gitleaks owns secrets)")
    metadata = obj(report, "Metadata")
    os_info = obj(metadata, "OS")
    out.attributes = {
        k: v
        for k, v in {
            "artifact_type": clean(report.get("ArtifactType"), 64),
            "os_family": clean(os_info.get("Family"), 64),
            "os_name": clean(os_info.get("Name"), 64),
            "image_config_digest": clean(metadata.get("ImageID"), 128),
            "packages_analysed": packages,
            "result_classes": sorted(classes),
        }.items()
        if v is not None
    }
    out.redactions = counter.count
    return out

"""Trivy normaliser tests on REAL Trivy 0.76.2 output (tests/fixtures/scanners).

Inline inputs marked SYNTHETIC are constructed here for shapes no real run produced.
"""

from __future__ import annotations

import collections
import copy
from typing import Any

import pytest
from scanners_testlib import all_text, ctx, load_json, load_k8s_index

from extorq.contracts import FindingCategory, Severity
from extorq.contracts.identity import finding_id, service_id
from extorq_scanners.models import NormalizedScan, ReportFormatError
from extorq_scanners.normalize.trivy import normalize_trivy
from extorq_scanners.services import ATTRIBUTION_BASIS, ServiceHint

LAB_REPO = "github:exigent07/extorq-lab"
CLUSTER = "k8s:extorq-lab"
VM = "linux:lab-vm-01"


def _fs() -> NormalizedScan:
    return normalize_trivy(load_json("trivy-fs-lab-repo.json"), ctx(LAB_REPO, "trivy", "fs"))


def _config() -> NormalizedScan:
    return normalize_trivy(
        load_json("trivy-config-kind.json"),
        ctx(CLUSTER, "trivy", "config", k8s_index=load_k8s_index()),
    )


def _image(name: str, repo: str) -> NormalizedScan:
    return normalize_trivy(
        load_json(name),
        ctx(CLUSTER, "trivy", "image", identity_qualifier=f"image:{repo}", artifact=repo),
    )


def _sbom(hints: dict[str, ServiceHint] | None = None) -> NormalizedScan:
    return normalize_trivy(
        load_json("trivy-sbom-linux-vm.json"),
        ctx(VM, "trivy", "sbom", package_services=hints or {}),
    )


def _vulns(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [v for r in report["Results"] for v in r.get("Vulnerabilities") or []]


# ── fs: lab repository (pip lock + Dockerfile) ────────────────────────────────


def test_fs_report_yields_one_finding_per_reported_entry() -> None:
    report = load_json("trivy-fs-lab-repo.json")
    out = _fs()
    vulns = [f for f in out.findings if f.category is FindingCategory.VULNERABILITY]
    misconf = [f for f in out.findings if f.category is FindingCategory.MISCONFIGURATION]
    assert len(vulns) == len(_vulns(report)) == 37  # language packages are never grouped
    assert [f.check_id for f in misconf] == ["DS-0026"]
    assert out.dropped == 0 and out.duplicates == 0
    assert out.scanner_version == "0.76.2"
    # coverage from MisconfSummary: 26 passed + 1 failed
    assert (out.checks_total, out.checks_run) == (27, 27)
    assert len({f.finding_id for f in out.findings}) == len(out.findings)


def test_fs_flask_vulnerability_fields() -> None:
    out = _fs()
    flask = next(f for f in out.findings if f.check_id == "CVE-2023-30861")
    assert flask.severity is Severity.HIGH
    assert flask.package is not None
    assert flask.package.name == "Flask"
    assert flask.package.installed_version == "2.2.2"
    assert flask.package.fixed_version == "2.3.2, 2.2.5"
    assert flask.package.ecosystem == "pip"
    assert flask.cve_ids == ["CVE-2023-30861"]
    assert flask.cvss_score == 7.5
    assert flask.attributes["cvss_source"] == "ghsa"
    assert flask.resource is not None and flask.resource.path == "requirements.txt"
    assert 1 <= len(flask.references) <= 10
    assert flask.remediation == "Upgrade Flask to 2.3.2, 2.2.5 or later."
    assert flask.attributes["package_basis"] == "binary"
    assert flask.service_id is None
    assert flask.finding_id == finding_id(
        LAB_REPO, "trivy", "CVE-2023-30861", "lang-pkgs|requirements.txt|Flask|2.2.2|"
    )


def test_fs_severity_counts_match_scanner_and_are_mapped() -> None:
    report = load_json("trivy-fs-lab-repo.json")
    raw = collections.Counter(v["Severity"].lower() for v in _vulns(report))
    got = collections.Counter(
        f.severity.value for f in _fs().findings if f.category is FindingCategory.VULNERABILITY
    )
    assert got == raw


def test_ids_are_deterministic_across_runs() -> None:
    first = [f.finding_id for f in _fs().findings]
    second = [f.finding_id for f in _fs().findings]
    assert first == second


def test_references_are_bounded_to_ten() -> None:
    for scan in (_fs(), _image("trivy-image-lab-portal.json", "extorq/lab-portal")):
        assert all(len(f.references) <= 10 for f in scan.findings)


# ── config: applied kind manifests ─────────────────────────────────────────────


def test_config_keeps_every_failure_with_distinct_ids() -> None:
    report = load_json("trivy-config-kind.json")
    fails = [
        m
        for r in report["Results"]
        for m in r.get("Misconfigurations") or []
        if m["Status"] == "FAIL"
    ]
    out = _config()
    assert len(out.findings) == len(fails) == 27
    assert out.duplicates == 0 and out.dropped == 0
    assert len({f.finding_id for f in out.findings}) == 27


def test_config_repeated_identical_failure_in_one_object_gets_ordinal() -> None:
    out = _config()
    ksv105 = [
        f
        for f in out.findings
        if f.check_id == "KSV-0105" and f.resource is not None and f.resource.type == "DaemonSet"
    ]
    assert len(ksv105) == 2
    assert len({f.finding_id for f in ksv105}) == 2
    assert {f.attributes["start_line"] for f in ksv105} == {53, 97}


def test_config_findings_are_attributed_to_kubernetes_objects() -> None:
    out = _config()
    k8s = [f for f in out.findings if f.check_id.startswith("KSV")]
    assert k8s and all(f.resource is not None and f.resource.name for f in k8s)
    hostpath = next(
        f for f in k8s if f.check_id == "KSV-0023" and f.resource and f.resource.type == "DaemonSet"
    )
    assert hostpath.resource is not None
    assert (hostpath.resource.namespace, hostpath.resource.name) == (
        "extorq-system",
        "extorq-otel-collector",
    )
    assert hostpath.attributes["object_basis"] == "line_range"
    no_lines = next(f for f in k8s if f.check_id == "KSV-0116")
    assert no_lines.attributes["object_basis"] == "sole_workload_in_file"
    assert no_lines.resource is not None and no_lines.resource.name == "extorq-otel-collector"


def test_config_never_stores_code_snippets() -> None:
    report = load_json("trivy-config-kind.json")
    code_lines = {
        line["Content"].strip()
        for r in report["Results"]
        for m in r.get("Misconfigurations") or []
        for line in ((m.get("CauseMetadata") or {}).get("Code") or {}).get("Lines") or []
        if len((line.get("Content") or "").strip()) > 25
    }
    assert code_lines, "fixture should contain code snippets"
    text = "\n".join(all_text(f) for f in _config().findings)
    assert not [c for c in code_lines if c in text]


def test_config_without_index_still_identifies_findings() -> None:
    out = normalize_trivy(load_json("trivy-config-kind.json"), ctx(CLUSTER, "trivy", "config"))
    assert len(out.findings) == 27  # ordinals keep identical messages apart
    assert out.duplicates == 0


def test_line_shift_does_not_change_misconfiguration_ids() -> None:
    report = load_json("trivy-config-kind.json")
    shifted = copy.deepcopy(report)
    for result in shifted["Results"]:
        for mis in result.get("Misconfigurations") or []:
            cause = mis.get("CauseMetadata") or {}
            for key in ("StartLine", "EndLine"):
                if isinstance(cause.get(key), int):
                    cause[key] += 3
    index = {
        path: [type(r)(r.kind, r.name, r.namespace, r.start_line + 3, r.end_line + 3) for r in refs]
        for path, refs in load_k8s_index().items()
    }
    base = {f.finding_id for f in _config().findings}
    moved = normalize_trivy(shifted, ctx(CLUSTER, "trivy", "config", k8s_index=index))
    assert {f.finding_id for f in moved.findings} == base


# ── image: lab-portal (Debian) and OTel (Go) ───────────────────────────────────


def test_image_os_packages_grouped_by_source() -> None:
    report = load_json("trivy-image-lab-portal.json")
    os_result = next(r for r in report["Results"] if r["Class"] == "os-pkgs")
    sources = {p["ID"]: p["SrcName"] for p in os_result["Packages"]}
    groups = {(v["VulnerabilityID"], sources[v["PkgID"]]) for v in os_result["Vulnerabilities"]}
    out = _image("trivy-image-lab-portal.json", "extorq/lab-portal")
    os_findings = [f for f in out.findings if f.attributes.get("class") == "os-pkgs"]
    lang = [f for f in out.findings if f.attributes.get("class") == "lang-pkgs"]
    assert len(os_findings) == len(groups)
    assert len(lang) == 6
    for finding in os_findings:
        assert finding.attributes["package_basis"] == "source"
        assert finding.package is not None and finding.package.name in {
            "glibc",
            "openssl",
            "systemd",
        }
        assert "(image extorq/lab-portal)" in finding.title
    multi = [f for f in os_findings if len(f.attributes["binary_packages"]) > 1]
    assert multi, "glibc/openssl/systemd ship several binary packages"


def test_image_identity_qualifier_separates_images() -> None:
    a = _image("trivy-image-lab-portal.json", "extorq/lab-portal")
    b = _image("trivy-image-lab-portal.json", "other/image")
    assert {f.finding_id for f in a.findings}.isdisjoint({f.finding_id for f in b.findings})


def test_image_unknown_severity_is_info_not_promoted() -> None:
    out = _image("trivy-image-otel.json", "otel/opentelemetry-collector-contrib")
    by_id = {f.check_id: f for f in out.findings}
    assert set(by_id) == {"GO-2026-5932", "CVE-2026-97054"}
    unknown = by_id["GO-2026-5932"]
    assert unknown.attributes["source_severity"] == "UNKNOWN"
    if unknown.cvss_score is None:
        assert unknown.severity is Severity.INFO
        assert unknown.attributes["severity_basis"] == "unknown"
    assert by_id["CVE-2026-97054"].severity is Severity.MEDIUM
    assert by_id["GO-2026-5932"].cve_ids == []  # not a CVE id


# ── sbom: Ubuntu VM ─────────────────────────────────────────────────────────────


def test_sbom_kernel_cves_collapse_across_binary_packages() -> None:
    report = load_json("trivy-sbom-linux-vm.json")
    out = _sbom()
    assert len(_vulns(report)) == 67
    assert len(out.findings) == 11  # glibc 6, linux 4, openssh 1
    kernel = [f for f in out.findings if f.package and f.package.name == "linux"]
    assert len(kernel) == 4
    for finding in kernel:
        assert len(finding.attributes["binary_packages"]) == 7
        assert finding.package is not None
        assert finding.package.installed_version == "6.8.0-147.147"
        assert finding.finding_id == finding_id(
            VM, "trivy", finding.check_id, "os-pkgs|os|src:linux|6.8.0-147.147|"
        )
    assert any("source linux" in (f.remediation or "") for f in kernel if f.package.fixed_version)


def test_sbom_epoch_is_part_of_source_version() -> None:
    openssh = next(f for f in _sbom().findings if f.package and f.package.name == "openssh")
    assert openssh.package is not None
    assert openssh.package.installed_version is not None
    assert openssh.package.installed_version.startswith("1:9.6p1-")
    assert openssh.attributes["binary_packages"] == [
        "openssh-client",
        "openssh-server",
        "openssh-sftp-server",
    ]


def test_sbom_service_attribution_only_with_hint() -> None:
    assert all(f.service_id is None for f in _sbom().findings)
    sid = service_id(VM, "host_service", "ssh.service")
    out = _sbom({"openssh-server": ServiceHint(sid, "ssh.service", "openssh-server")})
    attributed = [f for f in out.findings if f.service_id]
    assert [f.package.name for f in attributed if f.package] == ["openssh"]
    finding = attributed[0]
    assert finding.service_id == sid
    assert finding.attributes["service_unit"] == "ssh.service"
    assert finding.attributes["service_attribution"] == ATTRIBUTION_BASIS
    # attribution never changes identity
    plain = {f.check_id: f.finding_id for f in _sbom().findings}
    assert plain[finding.check_id] == finding.finding_id


# ── malformed reports (SYNTHETIC) ───────────────────────────────────────────────


@pytest.mark.parametrize(
    "report",
    [
        [],  # SYNTHETIC: not an object
        {"SchemaVersion": 1, "Results": []},  # SYNTHETIC: unsupported schema
        {"SchemaVersion": 2, "Results": {}},  # SYNTHETIC: Results not a list
        {"SchemaVersion": 2, "Results": ["x"]},  # SYNTHETIC: entry not an object
    ],
)
def test_unusable_reports_raise(report: object) -> None:
    with pytest.raises(ReportFormatError):
        normalize_trivy(report, ctx(LAB_REPO, "trivy", "fs"))


def test_invalid_entries_are_counted_as_dropped() -> None:
    report = load_json("trivy-fs-lab-repo.json")
    lang = next(r for r in report["Results"] if r["Class"] == "lang-pkgs")
    lang["Vulnerabilities"][0]["VulnerabilityID"] = "bad id with spaces"  # SYNTHETIC corruption
    lang["Vulnerabilities"].append("not-an-object")  # SYNTHETIC
    out = normalize_trivy(report, ctx(LAB_REPO, "trivy", "fs"))
    assert out.dropped == 2
    assert len([f for f in out.findings if f.category is FindingCategory.VULNERABILITY]) == 36


def test_empty_results_is_a_valid_clean_report() -> None:
    out = normalize_trivy({"SchemaVersion": 2, "Results": None}, ctx(LAB_REPO, "trivy", "fs"))
    assert out.findings == [] and out.dropped == 0  # SYNTHETIC: nothing found

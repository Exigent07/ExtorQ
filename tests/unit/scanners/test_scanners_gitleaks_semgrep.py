"""Gitleaks and Semgrep normaliser tests on REAL output (tests/fixtures/scanners).

Inline inputs marked SYNTHETIC are built here for cases no real run produced.
Secret-shaped strings in synthetic inputs are generated at runtime so no
secret-like literal is committed.
"""

from __future__ import annotations

import copy
import secrets
import string

import pytest
from scanners_testlib import all_text, ctx, load_json, load_text

from extorq.contracts import FindingCategory, Severity
from extorq.contracts.identity import finding_id
from extorq_scanners.models import ReportFormatError
from extorq_scanners.normalize.gitleaks import normalize_gitleaks, parse_log
from extorq_scanners.normalize.semgrep import normalize_semgrep, parse_summary

LAB_REPO = "github:exigent07/extorq-lab"


def _fake_secret() -> str:
    """SYNTHETIC lab-format secret generated at runtime (never committed)."""
    alphabet = string.ascii_uppercase + string.digits
    return "EXTORQ_TEST_SECRET_" + "".join(secrets.choice(alphabet) for _ in range(24))


def _gitleaks_ctx(mode: str = "dir", **kwargs: object):  # type: ignore[no-untyped-def]
    return ctx(
        LAB_REPO,
        "gitleaks",
        mode,
        mount_point="/src",
        severity_overrides={"extorq-test-secret": Severity.MEDIUM},
        **kwargs,  # type: ignore[arg-type]
    )


# ── gitleaks ────────────────────────────────────────────────────────────────────


def test_gitleaks_real_report_stores_only_location_and_redacted_match() -> None:
    out = normalize_gitleaks(
        load_json("gitleaks-dir-lab-repo.json"),
        load_text("gitleaks-dir-lab-repo.stderr.txt"),
        _gitleaks_ctx(),
    )
    assert out.dropped == 0 and out.tool_errors == [] and not out.nothing_scanned
    [finding] = out.findings
    assert finding.check_id == "gitleaks:extorq-test-secret"
    assert finding.category is FindingCategory.SECRET
    assert finding.severity is Severity.MEDIUM  # configured override
    assert finding.resource is not None and finding.resource.path == "deploy/legacy-staging.conf"
    assert finding.evidence == "redacted match: REDACTED"
    assert finding.attributes["line"] == 9
    assert finding.attributes["rule_id"] == "extorq-test-secret"
    # native gitleaks fingerprint rebuilt from validated parts, not mangled by redaction
    assert finding.attributes["fingerprint"] == "deploy/legacy-staging.conf:extorq-test-secret:9"
    assert finding.finding_id == finding_id(
        LAB_REPO,
        "gitleaks",
        "gitleaks:extorq-test-secret",
        "deploy/legacy-staging.conf:extorq-test-secret:9",
    )
    text = all_text(finding)
    for dropped in ("Entropy", "Author", "Email", "StartColumn"):
        assert dropped not in text
    assert "EXTORQ_TEST_SECRET_" not in text.replace("EXTORQ_TEST_SECRET_ + 24", "")
    assert out.attributes["bytes_scanned"] == 13699


def test_gitleaks_unredacted_match_is_discarded() -> None:
    secret = _fake_secret()
    report = load_json("gitleaks-dir-lab-repo.json")
    leak = copy.deepcopy(report[0])
    leak["Match"] = f"api_token = {secret}"  # SYNTHETIC: tool failed to redact
    leak["Secret"] = secret
    out = normalize_gitleaks([leak], "", _gitleaks_ctx())
    [finding] = out.findings
    assert secret not in all_text(finding)
    assert finding.evidence == "redacted match: REDACTED"
    assert any("not redacted" in note for note in out.notes)


def test_gitleaks_redaction_applies_to_every_stored_string() -> None:
    secret = "ghp_" + "".join(secrets.choice(string.ascii_letters) for _ in range(36))
    report = load_json("gitleaks-dir-lab-repo.json")
    leak = copy.deepcopy(report[0])
    leak["File"] = f"/src/config/{secret}.env"  # SYNTHETIC: secret-shaped path
    leak["Description"] = f"rule text {secret}"  # SYNTHETIC
    out = normalize_gitleaks([leak], "", _gitleaks_ctx())
    [finding] = out.findings
    assert secret not in all_text(finding)
    assert out.redactions >= 2


def test_gitleaks_git_mode_keeps_commit_and_detects_silent_failure() -> None:
    report = load_json("gitleaks-dir-lab-repo.json")
    leak = copy.deepcopy(report[0])
    leak["Commit"] = "a" * 40  # SYNTHETIC commit id
    leak["File"] = "deploy/legacy-staging.conf"
    out = normalize_gitleaks([leak], "x INF 3 commits scanned.\n", _gitleaks_ctx("git"))
    [finding] = out.findings
    assert finding.attributes["commit"] == "a" * 40
    assert finding.attributes["fingerprint"].startswith("a" * 40 + ":deploy/legacy-staging.conf")
    # SYNTHETIC: git refused the repository (dubious ownership) yet exited 0 with "[]"
    stderr = (
        "1:00PM ERR fatal: detected dubious ownership in repository\n"
        "1:00PM INF 0 commits scanned.\n"
    )
    silent = normalize_gitleaks([], stderr, _gitleaks_ctx("git"))
    assert silent.nothing_scanned
    assert silent.tool_errors and "dubious ownership" in silent.tool_errors[0]


def test_gitleaks_log_leak_count_mismatch_is_a_tool_error() -> None:
    out = normalize_gitleaks([], "1:00PM WRN leaks found: 2\n", _gitleaks_ctx())  # SYNTHETIC
    assert out.tool_errors == ["gitleaks log reports 2 leaks but the report contains 0"]


def test_gitleaks_parse_log_real_stderr() -> None:
    parsed = parse_log(load_text("gitleaks-dir-lab-repo.stderr.txt"))
    assert parsed == {"errors": [], "commits": None, "bytes": 13699, "leaks": 1}


@pytest.mark.parametrize("report", [{}, "x", [1]])  # SYNTHETIC malformed shapes
def test_gitleaks_malformed_reports_raise(report: object) -> None:
    with pytest.raises(ReportFormatError):
        normalize_gitleaks(report, "", _gitleaks_ctx())


# ── semgrep ─────────────────────────────────────────────────────────────────────


def _semgrep_ctx():  # type: ignore[no-untyped-def]
    return ctx(
        LAB_REPO, "semgrep", "scan", mount_point="/src", rules_total=151, ruleset_label="python"
    )


def test_semgrep_real_report() -> None:
    out = normalize_semgrep(
        load_json("semgrep-lab-repo.json"), _semgrep_ctx(), load_text("semgrep-lab-repo.stderr.txt")
    )
    [finding] = out.findings
    rule = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
    assert finding.check_id == rule
    assert finding.category is FindingCategory.CODE
    assert finding.severity is Severity.HIGH  # semgrep ERROR
    assert finding.resource is not None and finding.resource.path == "app/diagnostics.py"
    assert finding.evidence == "match at app/diagnostics.py:18:15 (source excerpt not stored)"
    assert finding.attributes["cwe"] and finding.attributes["owasp"]
    assert finding.references[0].startswith("https://semgrep.dev/r/")
    assert finding.finding_id == finding_id(
        LAB_REPO, "semgrep", rule, "app/diagnostics.py:18:15:18:19"
    )
    assert (out.checks_total, out.checks_run) == (151, 151)
    assert "semgrep skipped: Files matching .semgrepignore patterns: 1" in out.notes
    assert out.attributes["files_scanned"] == 6
    assert out.attributes["parsed_lines_pct"] == 100.0
    assert out.scanner_version == "1.184.0"


def test_semgrep_errors_reduce_coverage() -> None:
    report = load_json("semgrep-lab-repo.json")
    report["errors"] = [  # SYNTHETIC tool errors
        {"type": "Syntax error", "level": "error", "path": "/src/app/x.py", "message": "bad"},
        {"type": "Timeout", "level": "warn", "path": "/src/app/y.py", "message": "slow"},
    ]
    report["skipped_rules"] = [{"rule_id": "some.rule", "details": "timeout"}]  # SYNTHETIC
    out = normalize_semgrep(report, _semgrep_ctx())
    assert len(out.tool_errors) == 1 and "Syntax error" in out.tool_errors[0]
    assert any("semgrep warning" in n for n in out.notes)
    assert [s.check for s in out.skipped] == ["some.rule"]
    assert out.checks_run == 150


def test_semgrep_nothing_scanned_with_errors() -> None:
    report = {  # SYNTHETIC
        "results": [],
        "errors": [{"type": "Fatal", "level": "error", "message": "no targets"}],
        "paths": {"scanned": []},
    }
    out = normalize_semgrep(report, _semgrep_ctx())
    assert out.nothing_scanned


def test_semgrep_summary_parser() -> None:
    notes, pct = parse_summary(load_text("semgrep-lab-repo.stderr.txt"))
    assert notes == ["semgrep skipped: Files matching .semgrepignore patterns: 1"]
    assert pct == 100.0


@pytest.mark.parametrize("report", [[], {"results": {}}, {"results": [1]}])  # SYNTHETIC
def test_semgrep_malformed_reports_raise(report: object) -> None:
    with pytest.raises(ReportFormatError):
        normalize_semgrep(report, _semgrep_ctx())

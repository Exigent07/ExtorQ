"""Posture checks, scan assembly (lifecycle rules) and alert builders (synthetic inputs)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from extorq.contracts import FindingCategory, ScanStatus, Severity
from extorq_collectors.github.alerts import (
    code_scanning_finding,
    dependabot_finding,
    secret_scanning_finding,
)
from extorq_collectors.github.findings import CheckOutcome, FindingDraft, build_scan_records
from extorq_collectors.github.posture import Gap, RepoSnapshot, evaluate_posture
from extorq_collectors.github.records import RepoRef, normalize_protection
from extorq_collectors.github.workflow import analyse_workflow

REPO = RepoRef.parse("Example-Org/extorq-lab")
T = datetime(2026, 11, 21, 10, 0, tzinfo=UTC)


def settings(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "private": True,
        "allow_forking": False,
        "secret_scanning": "enabled",
        "secret_scanning_push_protection": "enabled",
        "dependabot_security_updates": "enabled",
        "actions.default_workflow_permissions": "read",
        "actions.can_approve_pull_request_reviews": False,
        "actions.allowed_actions": "selected",
        "actions.sha_pinning_required": True,
    }
    base.update(overrides)
    return base


def protected_branch() -> dict[str, object]:
    return normalize_protection(
        protected=True,
        protection={
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "allow_force_pushes": {"enabled": False},
        },
        protection_status="present",
        protection_gap=None,
        rule_types=[],
        rulesets=[],
    )


def snapshot(**kwargs: object) -> RepoSnapshot:
    defaults: dict[str, object] = {
        "repo": REPO,
        "default_branch": "main",
        "head_sha": "a" * 40,
        "settings": settings(),
        "protection": protected_branch(),
        "vulnerability_alerts": True,
        "codeowners_path": ".github/CODEOWNERS",
        "codeowners_known": True,
        "workflows": [],
    }
    defaults.update(kwargs)
    return RepoSnapshot(**defaults)  # type: ignore[arg-type]


def findings(outcomes: list[CheckOutcome]) -> dict[str, list[FindingDraft]]:
    out: dict[str, list[FindingDraft]] = {}
    for outcome in outcomes:
        if outcome.evaluated and outcome.findings:
            out[outcome.check_id] = list(outcome.findings)
    return out


def test_hardened_repository_has_no_findings_and_every_check_evaluated() -> None:
    outcomes = evaluate_posture(snapshot())
    assert findings(outcomes) == {}
    assert all(o.evaluated for o in outcomes), [o.check_id for o in outcomes if not o.evaluated]
    assert len({o.check_id for o in outcomes}) == len(outcomes)


def test_weak_repository_settings_are_findings() -> None:
    weak = snapshot(
        settings=settings(
            **{
                "actions.default_workflow_permissions": "write",
                "actions.can_approve_pull_request_reviews": True,
                "actions.allowed_actions": "all",
                "actions.sha_pinning_required": False,
                "secret_scanning": "disabled",
                "secret_scanning_push_protection": "disabled",
                "dependabot_security_updates": "disabled",
                "allow_forking": True,
            }
        ),
        vulnerability_alerts=False,
        codeowners_path=None,
        protection=normalize_protection(
            protected=False,
            protection=None,
            protection_status="absent",
            protection_gap=None,
            rule_types=[],
            rulesets=[],
        ),
    )
    found = findings(evaluate_posture(weak))
    assert set(found) == {
        "github.actions.default_token_write",
        "github.actions.can_approve_pull_requests",
        "github.actions.allowed_actions_unrestricted",
        "github.actions.sha_pinning_not_required",
        "github.secret_scanning.disabled",
        "github.secret_scanning.push_protection_disabled",
        "github.dependabot.security_updates_disabled",
        "github.dependabot.alerts_disabled",
        "github.repo.private_fork_allowed",
        "github.repo.codeowners_missing",
        "github.branch.unprotected",
    }
    unprotected = found["github.branch.unprotected"][0]
    assert unprotected.resource_key == "example-org/extorq-lab:refs/heads/main"
    assert unprotected.severity == Severity.MEDIUM


def test_unknown_inputs_are_skipped_not_passed() -> None:
    hidden = snapshot(
        settings=settings(
            secret_scanning=None,
            secret_scanning_push_protection=None,
            dependabot_security_updates=None,
        ),
        vulnerability_alerts=None,
        protection=None,
        gaps={
            "vulnerability_alerts": Gap("feature unavailable or not authorised (HTTP 403)"),
            "protection": Gap("feature unavailable or not authorised (HTTP 403)"),
        },
    )
    outcomes = {o.check_id: o for o in evaluate_posture(hidden)}
    for check in (
        "github.secret_scanning.disabled",
        "github.dependabot.alerts_disabled",
        "github.branch.unprotected",
        "github.branch.force_push_allowed",
    ):
        assert not outcomes[check].evaluated, check
        assert outcomes[check].skip_reason
    assert "not authorised" in (outcomes["github.branch.unprotected"].skip_reason or "")


def test_workflow_checks_and_default_write_reliance() -> None:
    write_all = analyse_workflow(
        ".github/workflows/a.yml",
        "on: push\npermissions: write-all\n"
        "jobs:\n  x:\n    runs-on: u\n    steps:\n"
        "      - uses: someorg/act@v1\n",
    )
    no_perms = analyse_workflow(
        ".github/workflows/b.yml",
        "on: push\njobs:\n  x:\n    runs-on: u\n    steps: [{run: make}]\n",
    )
    broken = analyse_workflow(".github/workflows/c.yml", "on: [push\n")
    snap = snapshot(
        settings=settings(**{"actions.default_workflow_permissions": "write"}),
        workflows=[write_all, no_perms, broken],
    )
    found = findings(evaluate_posture(snap))
    assert [f.resource_key for f in found["github.workflow.write_all"]] == [
        "example-org/extorq-lab:.github/workflows/a.yml"
    ]
    assert found["github.workflow.write_all"][0].severity == Severity.HIGH
    assert found["github.workflow.unpinned_third_party_action"][0].attributes[
        "unpinned_actions"
    ] == ["someorg/act@v1"]
    assert [
        f.resource_key.rsplit(":", 1)[1] for f in found["github.workflow.relies_on_default_write"]
    ] == [".github/workflows/b.yml"]
    assert "github.workflow.unparseable" in found


def test_scan_scope_excludes_permanent_gaps_and_transients_make_it_partial() -> None:
    draft = FindingDraft(
        check_id="github.repo.codeowners_missing",
        severity=Severity.LOW,
        title="No CODEOWNERS file",
        resource_key="example-org/extorq-lab",
    )
    outcomes = [
        CheckOutcome.ok("github.repo.codeowners_missing", [draft]),
        CheckOutcome.skip("github.secret_scanning.disabled", "feature unavailable (HTTP 403)"),
    ]
    common = {
        "scanner": "extorq-posture-github",
        "scanner_version": "1.0.0",
        "asset_id": REPO.asset_id,
        "repo_target": "github:example-org/extorq-lab",
        "description": "test",
        "producer_id": "github-collector",
    }
    first = build_scan_records(
        started_at=T, finished_at=T + timedelta(seconds=2), outcomes=outcomes, **common
    )  # type: ignore[arg-type]
    scan = first.scan_run
    assert scan.status == ScanStatus.SUCCEEDED and scan.findings_count == 1
    assert "check:github.secret_scanning.disabled" not in scan.scope.targets
    assert [s.check for s in scan.coverage.skipped] == ["github.secret_scanning.disabled"]
    second = build_scan_records(
        started_at=T + timedelta(minutes=15),
        finished_at=T + timedelta(minutes=15, seconds=2),
        outcomes=outcomes,
        **common,
    )  # type: ignore[arg-type]
    # Same issue, same fingerprint across scans; new scan run identity.
    assert second.findings[0].finding_id == first.findings[0].finding_id
    assert second.scan_run.scan_run_id != scan.scan_run_id
    assert second.scan_run.scope.scope_hash == scan.scope.scope_hash

    transient = build_scan_records(
        started_at=T,
        finished_at=T,
        outcomes=[
            *outcomes,
            CheckOutcome.skip("github.branch.unprotected", "HTTP 502", transient=True),
        ],
        **common,  # type: ignore[arg-type]
    )
    assert transient.scan_run.status == ScanStatus.PARTIAL
    assert "check:github.branch.unprotected" in transient.scan_run.scope.targets
    nothing = build_scan_records(started_at=T, finished_at=T, outcomes=[outcomes[1]], **common)  # type: ignore[arg-type]
    assert nothing.scan_run.status == ScanStatus.PARTIAL
    assert nothing.scan_run.findings_count is None


def test_dependabot_alert_mapping_prefers_cvss_v4() -> None:
    draft = dependabot_finding(
        {
            "number": 3,
            "html_url": "https://github.com/Example-Org/extorq-lab/security/dependabot/3",
            "dependency": {
                "package": {"name": "requests", "ecosystem": "pip"},
                "manifest_path": "requirements.txt",
            },
            "security_advisory": {
                "ghsa_id": "GHSA-aaaa-bbbb-cccc",
                "cve_id": "CVE-2024-35195",
                "severity": "medium",
                "summary": "synthetic summary",
                "cvss_severities": {"cvss_v3": {"score": 5.6}, "cvss_v4": {"score": 5.1}},
            },
            "security_vulnerability": {
                "vulnerable_version_range": "< 2.32.0",
                "first_patched_version": {"identifier": "2.32.0"},
            },
        }
    )
    assert draft is not None
    assert draft.category == FindingCategory.VULNERABILITY
    assert draft.cvss_score == 5.1 and draft.severity == Severity.MEDIUM
    assert draft.resource_key == "dependabot-alert:3"
    assert draft.remediation == "Upgrade requests to 2.32.0 or later."
    assert dependabot_finding({"state": "open"}) is None  # no alert number


def test_code_scanning_alert_mapping() -> None:
    draft = code_scanning_finding(
        {
            "number": 7,
            "rule": {
                "id": "py/command-line-injection",
                "security_severity_level": "critical",
                "description": "Uncontrolled command line",
            },
            "tool": {"name": "CodeQL"},
            "most_recent_instance": {"location": {"path": "app/diagnostics.py", "start_line": 16}},
        }
    )
    assert draft is not None and draft.severity == Severity.CRITICAL
    assert draft.check_id == "code-scanning:CodeQL:py/command-line-injection"
    assert draft.evidence == "app/diagnostics.py:16"


def test_secret_scanning_alert_never_contains_the_secret() -> None:
    synthetic_secret = "ghp_" + "Q" * 36
    draft = secret_scanning_finding(
        {
            "number": 2,
            "secret_type": "github_personal_access_token",
            "secret_type_display_name": "GitHub Personal Access Token",
            "secret": synthetic_secret,  # the API omits it with hide_secret=true; defend anyway
            "validity": "active",
            "push_protection_bypassed": True,
        }
    )
    assert draft is not None and draft.severity == Severity.CRITICAL
    rendered = repr(draft)
    assert synthetic_secret not in rendered
    assert "secret value withheld" in (draft.evidence or "")


def test_out_of_range_cvss_is_ignored_not_fatal() -> None:
    draft = dependabot_finding(
        {
            "number": 9,
            "dependency": {"package": {"name": "x", "ecosystem": "pip"}},
            "security_advisory": {
                "severity": "high",
                "cvss_severities": {"cvss_v4": {"score": 11}},
                "cvss": {"score": float("nan")},
            },
            "security_vulnerability": {},
        }
    )
    assert draft is not None and draft.cvss_score is None


def test_invalid_finding_makes_the_check_partial_instead_of_dropping_it() -> None:
    good = FindingDraft(check_id="a", severity=Severity.LOW, title="ok", resource_key="r1")
    bad = FindingDraft(
        check_id="b", severity=Severity.LOW, title="bad", resource_key="r2", cvss_score=42.0
    )
    records = build_scan_records(
        scanner="github-security-alerts",
        scanner_version="1.0.0",
        asset_id=REPO.asset_id,
        repo_target="github:example-org/extorq-lab",
        description="test",
        producer_id="github-collector",
        started_at=T,
        finished_at=T,
        outcomes=[CheckOutcome.ok("a", [good]), CheckOutcome.ok("b", [bad])],
    )
    assert records.scan_run.status == ScanStatus.PARTIAL
    assert [f.check_id for f in records.findings] == ["a"]
    assert "check:b" in records.scan_run.scope.targets  # stays in scope: nothing resolved
    assert records.scan_run.error and "unconvertible" in records.scan_run.error

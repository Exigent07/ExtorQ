"""Repository posture checks (scanner ``extorq-posture-github``).

Pure evaluation over a :class:`RepoSnapshot` assembled by the collector. Each input
carries either a value or a gap (``Gap``): permanent gaps (feature unavailable or not
authorised for this token/plan) skip the dependent checks; transient gaps make the
scan PARTIAL (see findings.py for the lifecycle rules).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from extorq.contracts import Resource, Severity
from extorq_collectors.github.findings import CheckOutcome, FindingDraft
from extorq_collectors.github.records import RepoRef
from extorq_collectors.github.workflow import WorkflowAnalysis

SCANNER = "extorq-posture-github"
SCANNER_VERSION = "1.0.0"
SCOPE_DESCRIPTION = "extorq-posture-github v1: repository settings, default branch, workflows"

_DOCS = "https://docs.github.com/en"
REF_TOKEN = (
    f"{_DOCS}/actions/security-for-github-actions/security-guides/automatic-token-authentication"
)
REF_HARDENING = (
    f"{_DOCS}/actions/security-for-github-actions/security-guides/"
    "security-hardening-for-github-actions"
)
REF_PROTECTION = f"{_DOCS}/repositories/configuring-branches-and-merges-in-your-repository"
REF_SECRET_SCANNING = f"{_DOCS}/code-security/secret-scanning"
REF_DEPENDABOT = f"{_DOCS}/code-security/dependabot/dependabot-alerts"
REF_CODEOWNERS = (
    f"{_DOCS}/repositories/managing-your-repositorys-settings-and-features/"
    "customizing-your-repository/about-code-owners"
)
REF_PWN_REQUEST = "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"
REF_INJECTION = "https://securitylab.github.com/resources/github-actions-untrusted-input/"


@dataclass(frozen=True)
class Gap:
    reason: str
    transient: bool = False


@dataclass
class RepoSnapshot:
    repo: RepoRef
    default_branch: str
    head_sha: str | None = None
    #: normalize_repo_settings() + normalize_actions_settings() output.
    settings: dict[str, Any] = field(default_factory=dict)
    #: normalize_protection() output for the default branch, or None with a gap.
    protection: dict[str, Any] | None = None
    vulnerability_alerts: bool | None = None
    codeowners_path: str | None = None
    codeowners_known: bool = False
    workflows: list[WorkflowAnalysis] | None = None
    #: input name -> gap. Inputs: settings, security_and_analysis, actions_workflow,
    #: actions_permissions, protection, vulnerability_alerts, tree, workflows.
    gaps: dict[str, Gap] = field(default_factory=dict)


def _skip(check_id: str, snapshot: RepoSnapshot, *inputs: str) -> CheckOutcome | None:
    for name in inputs:
        gap = snapshot.gaps.get(name)
        if gap is not None:
            return CheckOutcome.skip(check_id, f"{name}: {gap.reason}", transient=gap.transient)
    return None


def _repo_resource(snapshot: RepoSnapshot) -> Resource:
    return Resource(
        type="github_repository", name=snapshot.repo.full_name, id=snapshot.repo.asset_id
    )


def _setting_check(
    check_id: str,
    snapshot: RepoSnapshot,
    *,
    inputs: tuple[str, ...],
    key: str,
    unavailable: str,
    predicate: Callable[[Any], bool],
    severity: Severity,
    title: str,
    remediation: str,
    reference: str,
) -> CheckOutcome:
    skipped = _skip(check_id, snapshot, *inputs)
    if skipped is not None:
        return skipped
    value = snapshot.settings.get(key)
    if value is None:
        return CheckOutcome.skip(check_id, unavailable)
    if not predicate(value):
        return CheckOutcome.ok(check_id)
    rendered = str(value).lower() if isinstance(value, bool) else str(value)
    return CheckOutcome.ok(
        check_id,
        [
            FindingDraft(
                check_id=check_id,
                severity=severity,
                title=title,
                resource_key=snapshot.repo.full_name.lower(),
                resource=_repo_resource(snapshot),
                evidence=f"{key}={rendered}",
                remediation=remediation,
                references=(reference,),
            )
        ],
    )


def _repo_checks(snapshot: RepoSnapshot) -> list[CheckOutcome]:
    s = snapshot
    sa_unavailable = (
        "security_and_analysis status not reported (requires admin visibility; secret scanning "
        "on private repositories requires GitHub Secret Protection)"
    )
    outcomes = [
        _setting_check(
            "github.actions.default_token_write",
            s,
            inputs=("actions_workflow",),
            key="actions.default_workflow_permissions",
            unavailable="default workflow permissions not reported",
            predicate=lambda v: v == "write",
            severity=Severity.MEDIUM,
            title="Default GITHUB_TOKEN permission is read-write",
            remediation="Set Settings > Actions > General > Workflow permissions to "
            "'Read repository "
            "contents and packages permissions' and grant write scopes per job.",
            reference=REF_TOKEN,
        ),
        _setting_check(
            "github.actions.can_approve_pull_requests",
            s,
            inputs=("actions_workflow",),
            key="actions.can_approve_pull_request_reviews",
            unavailable="can_approve_pull_request_reviews not reported",
            predicate=lambda v: v is True,
            severity=Severity.MEDIUM,
            title="GitHub Actions may create and approve pull requests",
            remediation="Disable 'Allow GitHub Actions to create and approve pull requests'.",
            reference=REF_TOKEN,
        ),
        _setting_check(
            "github.actions.allowed_actions_unrestricted",
            s,
            inputs=("actions_permissions",),
            key="actions.allowed_actions",
            unavailable="allowed_actions not reported",
            predicate=lambda v: v == "all",
            severity=Severity.LOW,
            title="Any action or reusable workflow may run",
            remediation="Restrict allowed actions to GitHub-owned, verified or selected actions.",
            reference=REF_HARDENING,
        ),
        _setting_check(
            "github.actions.sha_pinning_not_required",
            s,
            inputs=("actions_permissions",),
            key="actions.sha_pinning_required",
            unavailable="sha_pinning_required not reported by this GitHub API version",
            predicate=lambda v: v is False,
            severity=Severity.LOW,
            title="Actions are not required to be pinned to a full commit SHA",
            remediation="Enable 'Require actions to be pinned to a full-length commit SHA'.",
            reference=REF_HARDENING,
        ),
        _setting_check(
            "github.secret_scanning.disabled",
            s,
            inputs=("settings",),
            key="secret_scanning",
            unavailable=sa_unavailable,
            predicate=lambda v: v != "enabled",
            severity=Severity.MEDIUM,
            title="Secret scanning is disabled",
            remediation="Enable secret scanning (Settings > Code security).",
            reference=REF_SECRET_SCANNING,
        ),
        _setting_check(
            "github.secret_scanning.push_protection_disabled",
            s,
            inputs=("settings",),
            key="secret_scanning_push_protection",
            unavailable=sa_unavailable,
            predicate=lambda v: v != "enabled",
            severity=Severity.MEDIUM,
            title="Secret scanning push protection is disabled",
            remediation="Enable push protection so pushes containing supported secrets "
            "are blocked.",
            reference=REF_SECRET_SCANNING,
        ),
        _setting_check(
            "github.dependabot.security_updates_disabled",
            s,
            inputs=("settings",),
            key="dependabot_security_updates",
            unavailable="dependabot_security_updates status not reported "
            "(requires admin visibility)",
            predicate=lambda v: v != "enabled",
            severity=Severity.LOW,
            title="Dependabot security updates are disabled",
            remediation="Enable Dependabot security updates.",
            reference=REF_DEPENDABOT,
        ),
    ]

    check = "github.dependabot.alerts_disabled"
    skipped = _skip(check, s, "vulnerability_alerts")
    if skipped is not None:
        outcomes.append(skipped)
    elif s.vulnerability_alerts is None:
        outcomes.append(CheckOutcome.skip(check, "Dependabot alert status unknown"))
    elif s.vulnerability_alerts:
        outcomes.append(CheckOutcome.ok(check))
    else:
        outcomes.append(
            CheckOutcome.ok(
                check,
                [
                    FindingDraft(
                        check_id=check,
                        severity=Severity.MEDIUM,
                        title="Dependabot alerts are disabled",
                        resource_key=s.repo.full_name.lower(),
                        resource=_repo_resource(s),
                        evidence="GET /vulnerability-alerts returned 404 for an "
                        "admin-visible repository",
                        remediation="Enable Dependabot alerts (Settings > Code security).",
                        references=(REF_DEPENDABOT,),
                    )
                ],
            )
        )

    check = "github.repo.private_fork_allowed"
    skipped = _skip(check, s, "settings")
    private, forking = s.settings.get("private"), s.settings.get("allow_forking")
    if skipped is not None:
        outcomes.append(skipped)
    elif private is None or forking is None:
        outcomes.append(CheckOutcome.skip(check, "visibility or allow_forking not reported"))
    elif private and forking:
        outcomes.append(
            CheckOutcome.ok(
                check,
                [
                    FindingDraft(
                        check_id=check,
                        severity=Severity.LOW,
                        title="Forking is allowed on a private repository",
                        resource_key=s.repo.full_name.lower(),
                        resource=_repo_resource(s),
                        evidence="private=true allow_forking=true",
                        remediation="Disable 'Allow forking' unless private forks are required.",
                        references=(REF_HARDENING,),
                    )
                ],
            )
        )
    else:
        outcomes.append(CheckOutcome.ok(check))

    check = "github.repo.codeowners_missing"
    skipped = _skip(check, s, "tree")
    if skipped is not None:
        outcomes.append(skipped)
    elif not s.codeowners_known:
        outcomes.append(CheckOutcome.skip(check, "repository tree not inspected"))
    elif s.codeowners_path is None:
        outcomes.append(
            CheckOutcome.ok(
                check,
                [
                    FindingDraft(
                        check_id=check,
                        severity=Severity.LOW,
                        title="No CODEOWNERS file",
                        resource_key=s.repo.full_name.lower(),
                        resource=_repo_resource(s),
                        evidence="no CODEOWNERS in .github/, repository root or docs/",
                        remediation="Add a CODEOWNERS file covering .github/workflows/ "
                        "and require code "
                        "owner review.",
                        references=(REF_CODEOWNERS,),
                    )
                ],
            )
        )
    else:
        outcomes.append(CheckOutcome.ok(check))
    return outcomes


def _branch_checks(snapshot: RepoSnapshot) -> list[CheckOutcome]:
    s = snapshot
    branch = s.default_branch
    resource = Resource(type="github_branch", name=branch, path=f"refs/heads/{branch}")
    key = f"{s.repo.full_name.lower()}:refs/heads/{branch}"
    outcomes: list[CheckOutcome] = []
    p = s.protection

    check = "github.branch.unprotected"
    skipped = _skip(check, s, "protection")
    if skipped is not None:
        outcomes.append(skipped)
    elif p is None or p.get("protected") is None:
        outcomes.append(CheckOutcome.skip(check, "branch protection state unknown"))
    elif p["protected"] is False and not p.get("rule_types"):
        gap = p.get("protection_gap")
        evidence = "branches API reports protected=false; no ruleset rules apply"
        if gap:
            evidence += f"; protection endpoint: {gap}"
        outcomes.append(
            CheckOutcome.ok(
                check,
                [
                    FindingDraft(
                        check_id=check,
                        severity=Severity.MEDIUM,
                        title=f"Default branch '{branch}' has no protection or rulesets",
                        resource_key=key,
                        resource=resource,
                        evidence=evidence,
                        remediation="Protect the default branch (require pull requests and "
                        "reviews, block "
                        "force pushes and deletions) with branch protection or a ruleset.",
                        references=(REF_PROTECTION,),
                    )
                ],
            )
        )
    else:
        outcomes.append(CheckOutcome.ok(check))

    details_known = p is not None and p.get("protection_status") == "present"
    rule_types = set(p.get("rule_types") or []) if p is not None else set()

    check = "github.branch.force_push_allowed"
    skipped = _skip(check, s, "protection")
    if skipped is not None:
        outcomes.append(skipped)
    elif p is not None and p.get("protected") is False:
        outcomes.append(CheckOutcome.ok(check))  # covered by github.branch.unprotected
    elif not details_known:
        outcomes.append(CheckOutcome.skip(check, "protection details not visible to this token"))
    elif (
        p is not None
        and p.get("allow_force_pushes") is True
        and "non_fast_forward" not in rule_types
    ):
        outcomes.append(
            CheckOutcome.ok(
                check,
                [
                    FindingDraft(
                        check_id=check,
                        severity=Severity.MEDIUM,
                        title=f"Force pushes are allowed on default branch '{branch}'",
                        resource_key=key,
                        resource=resource,
                        evidence="allow_force_pushes=true",
                        remediation="Disable force pushes on the default branch.",
                        references=(REF_PROTECTION,),
                    )
                ],
            )
        )
    else:
        outcomes.append(CheckOutcome.ok(check))

    check = "github.branch.no_required_reviews"
    skipped = _skip(check, s, "protection")
    if skipped is not None:
        outcomes.append(skipped)
    elif p is not None and p.get("protected") is False:
        outcomes.append(CheckOutcome.ok(check))
    elif not details_known:
        outcomes.append(CheckOutcome.skip(check, "protection details not visible to this token"))
    elif p is not None and p.get("required_reviews") is False and "pull_request" not in rule_types:
        outcomes.append(
            CheckOutcome.ok(
                check,
                [
                    FindingDraft(
                        check_id=check,
                        severity=Severity.LOW,
                        title=f"Default branch '{branch}' does not require pull request reviews",
                        resource_key=key,
                        resource=resource,
                        evidence="required_pull_request_reviews not configured",
                        remediation="Require at least one approving review before merging.",
                        references=(REF_PROTECTION,),
                    )
                ],
            )
        )
    else:
        outcomes.append(CheckOutcome.ok(check))
    return outcomes


def _workflow_resource(analysis: WorkflowAnalysis) -> Resource:
    return Resource(
        type="github_workflow", name=analysis.path.rsplit("/", 1)[-1], path=analysis.path
    )


def _per_workflow(
    check_id: str,
    snapshot: RepoSnapshot,
    build: Callable[[WorkflowAnalysis], FindingDraft | None],
    *,
    extra_inputs: Sequence[str] = (),
) -> CheckOutcome:
    skipped = _skip(check_id, snapshot, "workflows", *extra_inputs)
    if skipped is not None:
        return skipped
    if snapshot.workflows is None:
        return CheckOutcome.skip(check_id, "workflow files not inspected")
    drafts = [d for d in (build(a) for a in snapshot.workflows) if d is not None]
    return CheckOutcome.ok(check_id, drafts)


def _workflow_checks(snapshot: RepoSnapshot) -> list[CheckOutcome]:
    s = snapshot
    repo_key = s.repo.full_name.lower()
    default = s.settings.get("actions.default_workflow_permissions")

    def write_all(a: WorkflowAnalysis) -> FindingDraft | None:
        if not a.ok or not a.has_write_all:
            return None
        return FindingDraft(
            check_id="github.workflow.write_all",
            severity=Severity.HIGH,
            title=f"Workflow {a.path} grants permissions: write-all",
            resource_key=f"{repo_key}:{a.path}",
            resource=_workflow_resource(a),
            evidence=f"permissions={a.permissions.render()}",
            remediation="Declare least-privilege permissions per job (e.g. 'contents: read').",
            references=(REF_TOKEN,),
        )

    def unpinned(a: WorkflowAnalysis) -> FindingDraft | None:
        refs = a.unpinned_third_party_actions if a.ok else ()
        if not refs:
            return None
        return FindingDraft(
            check_id="github.workflow.unpinned_third_party_action",
            severity=Severity.MEDIUM,
            title=f"Workflow {a.path} uses third-party actions not pinned to a commit SHA",
            resource_key=f"{repo_key}:{a.path}",
            resource=_workflow_resource(a),
            evidence="uses: " + ", ".join(refs[:10]),
            remediation="Pin third-party actions to a full-length commit SHA and track updates "
            "with Dependabot.",
            references=(REF_HARDENING,),
            attributes={"unpinned_actions": list(refs[:32])},
        )

    def untrusted(a: WorkflowAnalysis) -> FindingDraft | None:
        if not a.ok or not a.privileged_untrusted_checkout:
            return None
        return FindingDraft(
            check_id="github.workflow.privileged_untrusted_checkout",
            severity=Severity.HIGH,
            title=f"Workflow {a.path} checks out untrusted code in a privileged trigger",
            resource_key=f"{repo_key}:{a.path}",
            resource=_workflow_resource(a),
            evidence=f"triggers={','.join(a.privileged_triggers)}; "
            + "; ".join(a.untrusted_checkouts[:5]),
            remediation="Do not check out or execute pull request code in pull_request_target, "
            "workflow_run or issue_comment workflows; use pull_request with a read-only token.",
            references=(REF_PWN_REQUEST,),
        )

    def injection(a: WorkflowAnalysis) -> FindingDraft | None:
        if not a.ok or not a.script_injections:
            return None
        return FindingDraft(
            check_id="github.workflow.script_injection",
            severity=Severity.HIGH,
            title=f"Workflow {a.path} interpolates untrusted input into a script",
            resource_key=f"{repo_key}:{a.path}",
            resource=_workflow_resource(a),
            evidence="; ".join(a.script_injections[:5]),
            remediation="Pass untrusted values through environment variables instead of ${{ }} "
            "interpolation inside run/script.",
            references=(REF_INJECTION,),
        )

    def inherit(a: WorkflowAnalysis) -> FindingDraft | None:
        if not a.ok or not a.secrets_inherit_jobs:
            return None
        return FindingDraft(
            check_id="github.workflow.secrets_inherit",
            severity=Severity.LOW,
            title=f"Workflow {a.path} passes all secrets to a reusable workflow",
            resource_key=f"{repo_key}:{a.path}",
            resource=_workflow_resource(a),
            evidence="secrets: inherit in jobs " + ", ".join(a.secrets_inherit_jobs[:10]),
            remediation="Pass only the secrets the called workflow needs.",
            references=(REF_HARDENING,),
        )

    def unparseable(a: WorkflowAnalysis) -> FindingDraft | None:
        if a.ok:
            return None
        return FindingDraft(
            check_id="github.workflow.unparseable",
            severity=Severity.LOW,
            title=f"Workflow {a.path} could not be analysed",
            resource_key=f"{repo_key}:{a.path}",
            resource=_workflow_resource(a),
            evidence=a.error,
            remediation="Fix the workflow syntax; ExtorQ cannot assess an unparseable workflow.",
        )

    outcomes = [
        _per_workflow("github.workflow.write_all", s, write_all),
        _per_workflow("github.workflow.unpinned_third_party_action", s, unpinned),
        _per_workflow("github.workflow.privileged_untrusted_checkout", s, untrusted),
        _per_workflow("github.workflow.script_injection", s, injection),
        _per_workflow("github.workflow.secrets_inherit", s, inherit),
        _per_workflow("github.workflow.unparseable", s, unparseable),
    ]

    check = "github.workflow.relies_on_default_write"
    if default is None and "actions_workflow" not in s.gaps:
        outcomes.append(CheckOutcome.skip(check, "default workflow permissions not reported"))
    else:

        def relies(a: WorkflowAnalysis) -> FindingDraft | None:
            if not a.ok or default != "write" or not a.relies_on_default:
                return None
            return FindingDraft(
                check_id=check,
                severity=Severity.MEDIUM,
                title=f"Workflow {a.path} has no permissions block and the repository "
                "default is write",
                resource_key=f"{repo_key}:{a.path}",
                resource=_workflow_resource(a),
                evidence="permissions unset; actions.default_workflow_permissions=write",
                remediation="Add an explicit least-privilege permissions block.",
                references=(REF_TOKEN,),
            )

        outcomes.append(_per_workflow(check, s, relies, extra_inputs=("actions_workflow",)))
    return outcomes


def evaluate_posture(snapshot: RepoSnapshot) -> list[CheckOutcome]:
    """Run every posture check; the outcome list always has one entry per check."""
    return _repo_checks(snapshot) + _branch_checks(snapshot) + _workflow_checks(snapshot)


CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")

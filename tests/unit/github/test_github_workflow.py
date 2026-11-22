"""Workflow analyser: YAML safety, permissions, triggers, actions, injection (synthetic inputs).

The GH-001 tests at the end use the real lab baseline workflow
(lab/github-repo/.github/workflows/ci.yml) and the simulation template
(simulations/github/templates/ci-gh001.yml).
"""

from __future__ import annotations

import json
import textwrap
import time
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml

from extorq_collectors.github import analyze
from extorq_collectors.github.workflow import (
    MAX_LEXICAL_BYTES,
    MAX_WORKFLOW_BYTES,
    MAX_YAML_ALIASES,
    PERMISSIVE_DEFAULT,
    WRITE_CAPABLE_SCOPES,
    WorkflowAnalysis,
    analyse_workflow,
    analyse_workflow_document,
    compare_workflows,
    is_workflow_path,
    lexical_scan,
    load_workflow_yaml,
    parse_uses,
    render_permissions,
    workflow_inventory_attributes,
)

ROOT = Path(__file__).resolve().parents[3]
LAB_CI = ROOT / "lab/github-repo/.github/workflows/ci.yml"
GH001_TEMPLATE = ROOT / "simulations/github/templates/ci-gh001.yml"
PATH = ".github/workflows/ci.yml"
SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def wf(text: str) -> WorkflowAnalysis:
    analysis = analyse_workflow(PATH, textwrap.dedent(text))
    assert analysis.ok, analysis.error
    return analysis


def delta(before: str | None, after: str | None, repo_default: str | None = "read"):
    b = analyse_workflow(PATH, textwrap.dedent(before)) if before is not None else None
    a = analyse_workflow(PATH, textwrap.dedent(after)) if after is not None else None
    change = "added" if b is None else ("removed" if a is None else "modified")
    return compare_workflows(PATH, b, a, repo_default=repo_default, change_type=change)  # type: ignore[arg-type]


BASE = """
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      - run: make test
"""


# ── YAML loading ────────────────────────────────────────────────────────────


def test_on_key_stays_a_string_with_yaml_12_booleans() -> None:
    # PyYAML's default YAML 1.1 rules turn the key `on` into True.
    assert True in yaml.safe_load("on: push\n")
    document = load_workflow_yaml("on: push\njobs: {}\n")
    assert "on" in document and True not in document
    analysis = wf("on: [push, pull_request_target]\njobs: {}\n")
    assert analysis.triggers == ("pull_request_target", "push")


def test_yaml_11_style_document_with_true_key_is_still_understood() -> None:
    document = yaml.safe_load("on:\n  workflow_run:\n    workflows: [CI]\njobs: {}\n")
    analysis = analyse_workflow_document(PATH, document)
    assert analysis.triggers == ("workflow_run",)
    assert analysis.privileged_triggers == ("workflow_run",)


def test_yes_no_on_off_values_are_strings() -> None:
    document = load_workflow_yaml("on: push\nenv:\n  A: yes\n  B: off\n  C: true\n")
    assert document["env"] == {"A": "yes", "B": "off", "C": True}


@pytest.mark.parametrize(
    ("on_value", "expected"),
    [
        ("push", ("push",)),
        ("[push, pull_request]", ("pull_request", "push")),
        (
            "{issue_comment: {types: [created]}, schedule: [{cron: '0 0 * * *'}]}",
            ("issue_comment", "schedule"),
        ),
    ],
)
def test_trigger_forms(on_value: str, expected: tuple[str, ...]) -> None:
    assert wf(f"on: {on_value}\njobs: {{}}\n").triggers == expected


def test_malformed_yaml_is_reported_not_raised() -> None:
    analysis = analyse_workflow(PATH, "on: [push\njobs:\n  - :")
    assert not analysis.ok and analysis.error and "invalid YAML" in analysis.error


def test_duplicate_keys_are_rejected() -> None:
    text = "on: push\npermissions: read-all\npermissions: write-all\njobs: {}\n"
    analysis = analyse_workflow(PATH, text)
    assert not analysis.ok and "duplicate mapping key" in (analysis.error or "")


def test_alias_bomb_is_bounded() -> None:
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 30):
        refs = ", ".join([f"*a{i - 1}"] * 10)
        lines.append(f"a{i}: &a{i} [{refs}]")
    analysis = analyse_workflow(PATH, "\n".join(lines) + "\non: push\n")
    assert not analysis.ok and "aliases" in (analysis.error or "")


def test_oversized_and_non_mapping_documents() -> None:
    assert not analyse_workflow(PATH, "#" * (600 * 1024)).ok
    analysis = analyse_workflow(PATH, "- just\n- a list\n")
    assert not analysis.ok and "not a mapping" in (analysis.error or "")


def test_unsafe_yaml_tags_are_not_constructed() -> None:
    analysis = analyse_workflow(PATH, "on: !!python/object/apply:os.system ['id']\njobs: {}\n")
    assert not analysis.ok


def test_workflow_path_validation() -> None:
    assert is_workflow_path(".github/workflows/ci.yml")
    assert is_workflow_path(".github/workflows/release.yaml")
    assert not is_workflow_path(".github/workflows/sub/ci.yml")
    assert not is_workflow_path(".github/ci.yml")
    assert not is_workflow_path("docs/.github/workflows/ci.yml")
    assert not is_workflow_path(".github/workflows/ci.txt")


# ── Permissions ─────────────────────────────────────────────────────────────


def test_write_all_added_is_detected_with_every_write_scope() -> None:
    d = delta(BASE, BASE.replace("permissions:\n  contents: read", "permissions: write-all"))
    assert d.write_all_added
    assert set(d.added_write_scopes) == set(WRITE_CAPABLE_SCOPES)
    assert d.permissions_before == "workflow=contents:read"
    assert d.permissions_after == "workflow=write-all"
    assert "write_all_added" in d.risk_flags
    assert "scope_escalation:contents" in d.risk_flags
    assert d.escalation
    attributes = d.to_attributes()
    assert attributes["write_all_added"] is True
    assert attributes["permissions_after"] == "workflow=write-all"
    json.dumps(attributes)  # serialisable scalars / lists only


def test_scope_escalation_from_read_to_write() -> None:
    after = BASE.replace("contents: read", "contents: write\n  packages: write\n  issues: read")
    d = delta(BASE, after)
    assert not d.write_all_added
    assert d.added_write_scopes == ("contents", "packages")
    assert d.escalation


def test_write_all_already_present_is_not_reported_as_added() -> None:
    before = BASE.replace("permissions:\n  contents: read", "permissions: write-all")
    d = delta(before, before.replace("make test", "make lint"))
    assert not d.write_all_added and d.added_write_scopes == () and not d.escalation


def test_job_level_permissions_override_workflow_level() -> None:
    text = """
    on: push
    permissions: read-all
    jobs:
      build:
        runs-on: ubuntu-24.04
        steps: [{run: make}]
      release:
        permissions:
          contents: write
          id-token: write
        runs-on: ubuntu-24.04
        steps: [{run: make release}]
    """
    analysis = wf(text)
    effective = analysis.effective_permissions("read")
    assert effective.by_job["build"]["contents"] == "read"  # type: ignore[index]
    # The job-level block replaces the workflow block entirely (no inherited reads).
    assert effective.by_job["release"] == {"contents": "write", "id-token": "write"}
    assert effective.write_scopes == ("contents", "id-token")
    d = delta(text.replace("contents: write\n          id-token: write", "contents: read"), text)
    assert d.added_write_scopes == ("contents", "id-token")
    assert "job:release=contents:write,id-token:write" in d.permissions_after


def test_missing_permissions_block_uses_repository_default() -> None:
    text = "on: push\njobs:\n  a:\n    runs-on: x\n    steps: [{run: make}]\n"
    analysis = wf(text)
    assert analysis.relies_on_default
    assert analysis.effective_permissions("write").write_scopes == tuple(sorted(PERMISSIVE_DEFAULT))
    assert analysis.effective_permissions("read").write_scopes == ()
    unknown = analysis.effective_permissions(None)
    assert unknown.unknown and unknown.write_scopes == ()
    assert render_permissions(analysis, "write") == "workflow=unset;repo_default=write"


def test_removing_permissions_block_under_write_default_escalates() -> None:
    after = BASE.replace("permissions:\n  contents: read\n", "")
    d = delta(BASE, after, repo_default="write")
    assert "permissions_block_removed" in d.risk_flags
    assert "relies_on_repo_default_write" in d.risk_flags
    assert "contents" in d.added_write_scopes and d.escalation
    d_unknown = delta(BASE, after, repo_default=None)
    assert d_unknown.effective_permissions_unknown
    assert "effective_permissions_unknown" in d_unknown.risk_flags


def test_invalid_permission_values_are_flagged() -> None:
    d = delta(BASE, BASE.replace("contents: read", "contents: admin"))
    assert "invalid_permissions" in d.risk_flags
    assert wf("on: push\npermissions: write\njobs: {}\n").permissions.kind == "invalid"


def test_empty_permissions_mapping_means_none() -> None:
    analysis = wf("on: push\npermissions: {}\njobs: {}\n")
    assert analysis.permissions.kind == "none"
    assert analysis.effective_permissions("write").union == {}


# ── Triggers and untrusted checkout ─────────────────────────────────────────


PRT_CHECKOUT = """
on:
  pull_request_target:
    types: [opened]
permissions:
  contents: read
jobs:
  preview:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: make preview
"""


def test_pull_request_target_added_with_head_checkout() -> None:
    d = delta(BASE, PRT_CHECKOUT)
    assert d.triggers_added == ("pull_request_target",)
    assert d.dangerous_triggers_added == ("pull_request_target",)
    assert d.untrusted_checkout_added
    assert "dangerous_trigger_added:pull_request_target" in d.risk_flags
    assert "privileged_trigger_untrusted_checkout" in d.risk_flags
    assert d.escalation


def test_pull_request_target_without_checkout_is_dangerous_trigger_only() -> None:
    text = PRT_CHECKOUT.replace(
        "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n", ""
    )
    analysis = wf(text)
    assert analysis.privileged_triggers == ("pull_request_target",)
    assert analysis.untrusted_checkouts == ()
    assert not analysis.privileged_untrusted_checkout


def test_issue_comment_with_gh_pr_checkout_is_untrusted() -> None:
    text = """
    on: issue_comment
    jobs:
      bot:
        runs-on: ubuntu-24.04
        steps:
          - run: gh pr checkout ${{ github.event.issue.number }} && make
    """
    analysis = wf(text)
    assert analysis.privileged_untrusted_checkout
    assert any("run checks out pull request code" in u for u in analysis.untrusted_checkouts)


def test_workflow_run_checkout_of_head_sha_and_unsafe_opt_in() -> None:
    text = """
    on:
      workflow_run:
        workflows: [CI]
        types: [completed]
    jobs:
      report:
        runs-on: ubuntu-24.04
        steps:
          - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
            with:
              ref: ${{ github.event.workflow_run.head_sha }}
              allow-unsafe-pr-checkout: true
    """
    analysis = wf(text)
    assert analysis.privileged_untrusted_checkout
    assert len(analysis.untrusted_checkouts) == 2


def test_checkout_of_fork_repository_is_untrusted() -> None:
    text = PRT_CHECKOUT.replace(
        "ref: ${{ github.event.pull_request.head.sha }}",
        "repository: ${{ github.event.pull_request.head.repo.full_name }}",
    )
    assert wf(text).privileged_untrusted_checkout


# ── Actions pinning, secrets ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("uses", "kind", "pinned", "third_party"),
    [
        (f"actions/checkout@{SHA}", "remote", True, False),
        ("actions/checkout@v4", "remote", False, False),
        ("someorg/deploy-action@v1", "remote", False, True),
        (f"someorg/deploy-action@{SHA}", "remote", True, True),
        ("someorg/deploy-action@3d3c42e", "remote", False, True),
        ("someorg/monorepo/sub/dir@main", "remote", False, True),
        ("someorg/repo/.github/workflows/reuse.yml@main", "remote", False, True),
        ("./.github/actions/local", "local", True, False),
        ("docker://alpine:3.20", "docker", False, True),
        ("docker://alpine@sha256:" + "a" * 64, "docker", True, True),
        ("someorg/x@${{ inputs.ref }}", "invalid", False, False),
        ("not a reference", "invalid", False, False),
    ],
)
def test_uses_classification(uses: str, kind: str, pinned: bool, third_party: bool) -> None:
    ref = parse_uses(uses)
    assert ref.kind == kind
    assert ref.pinned is pinned
    assert ref.third_party is third_party


def test_unpinned_third_party_actions_added() -> None:
    after = BASE.replace(
        "      - run: make test", "      - uses: someorg/deploy@v2\n      - run: make test"
    )
    d = delta(BASE, after)
    assert d.unpinned_actions_added == ("someorg/deploy@v2",)
    assert "unpinned_third_party_action_added" in d.risk_flags
    # Unpinned third-party actions are posture risk, not privilege escalation.
    assert not d.escalation


def test_secrets_inherit_added() -> None:
    after = """
    on: push
    jobs:
      call:
        uses: someorg/shared/.github/workflows/deploy.yml@main
        secrets: inherit
    """
    analysis = wf(after)
    assert analysis.secrets_inherit_jobs == ("call",)
    d = delta(BASE, after)
    assert d.secrets_inherit_added and "secrets_inherit_added" in d.risk_flags


# ── Script injection ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "expression",
    [
        "github.event.issue.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.head_ref",
        "github.event.comment.body",
        "github.event.head_commit.message",
        "github.event.commits[0].author.email",
        "github.event.workflow_run.head_branch",
    ],
)
def test_untrusted_expressions_in_run_are_injection(expression: str) -> None:
    text = f"""
    on: pull_request_target
    jobs:
      x:
        runs-on: ubuntu-24.04
        steps:
          - run: echo "${{{{ {expression} }}}}"
    """
    analysis = wf(text)
    assert analysis.script_injections, expression


def test_safe_expressions_and_env_indirection_are_not_injection() -> None:
    text = """
    on: pull_request
    jobs:
      x:
        runs-on: ubuntu-24.04
        steps:
          - run: echo "PR ${{ github.event.pull_request.number }}"
          - env:
              TITLE: ${{ github.event.pull_request.title }}
            run: echo "$TITLE"
    """
    analysis = wf(text)
    assert analysis.script_injections == ()
    assert analysis.event_expressions_in_run  # number: recorded, not flagged as injection


def test_github_script_injection_and_delta_flag() -> None:
    after = """
    on: issues
    jobs:
      x:
        runs-on: ubuntu-24.04
        steps:
          - uses: actions/github-script@v7
            with:
              script: console.log("${{ github.event.issue.body }}")
    """
    d = delta(BASE, after)
    assert d.script_injection_added and "script_injection_added" in d.risk_flags


# ── Before/after edge cases ─────────────────────────────────────────────────


def test_added_and_removed_workflows() -> None:
    added = delta(None, BASE)
    assert added.change_type == "added" and "workflow_added" in added.risk_flags
    assert not added.escalation  # contents: read only
    removed = delta(BASE, None)
    assert removed.change_type == "removed" and "workflow_removed" in removed.risk_flags
    assert not removed.escalation
    assert removed.permissions_after == "absent"


def test_unparseable_after_version_is_flagged() -> None:
    before = analyse_workflow(PATH, textwrap.dedent(BASE))
    after = analyse_workflow(PATH, "on: [push\n")
    d = compare_workflows(PATH, before, after, repo_default="read", change_type="modified")
    assert "workflow_unparseable" in d.risk_flags
    assert d.analysis == "lexical_fallback"
    assert d.permissions_after == "unparseable;lexical=no permissions key"
    assert d.to_attributes()["parse_error_after"]
    assert not d.escalation  # nothing risky in the text: no privilege increase


def test_summary_and_inventory_attributes() -> None:
    d = delta(BASE, PRT_CHECKOUT.replace("contents: read", "contents: write"))
    assert "pull_request_target" in d.summary()
    analysis = wf(PRT_CHECKOUT)
    attrs = workflow_inventory_attributes(analysis, "read", blob_sha="b" * 40, head_sha="c" * 40)
    assert attrs["privileged_triggers"] == ["pull_request_target"]
    assert attrs["privileged_untrusted_checkout"] is True
    assert attrs["effective_write_scopes"] == []
    assert attrs["analysis"] == "structured"
    broken = workflow_inventory_attributes(analyse_workflow(PATH, "on: [x"), None)
    assert broken["parse_ok"] is False and "triggers" not in broken
    assert broken["analysis"] == "lexical_fallback" and broken["lexical_write_all"] is False
    risky = workflow_inventory_attributes(analyse_workflow(PATH, "permissions: write-all\n["), None)
    assert risky["lexical_write_all"] is True and risky["effective_permissions_unknown"] is True


# ── Lexical fallback: an unanalysable workflow is never treated as absent ──

#: The GH-001 escalation (write-all, pull_request_target, PR-head checkout) as plain YAML.
RISKY = textwrap.dedent(
    """
    name: CI
    on:
      push:
        branches: [main]
      pull_request_target:
        branches: [main]
    permissions: write-all
    jobs:
      preview:
        runs-on: ubuntu-24.04
        steps:
          - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
            with:
              ref: ${{ github.event.pull_request.head.sha }}
          - run: make preview
    """
)


def _oversized(text: str) -> str:
    """Valid YAML that exceeds the analyser's size budget (comment padding)."""
    return "# padding\n" * (MAX_WORKFLOW_BYTES // 10 + 16) + text


def _alias_bomb(text: str) -> str:
    """Valid YAML with more aliases than the analyser allows (GitHub supports anchors)."""
    reuse = "".join(f"  r{i}: *base\n" for i in range(MAX_YAML_ALIASES + 5))
    return text + "env:\n  BASE: &base synthetic\n" + reuse.replace("  r", "  R")


def _malformed(text: str) -> str:
    return text + "broken: [unclosed\n"


def _duplicate_key(text: str) -> str:
    return text + "name: second name\n"  # `name` is already defined


@pytest.mark.parametrize(
    "breaker",
    [_oversized, _alias_bomb, _malformed, _duplicate_key],
    ids=["oversized", "alias-bomb", "malformed", "duplicate-key"],
)
def test_unanalysable_escalation_is_detected_lexically(breaker: Callable[[str], str]) -> None:
    before = analyse_workflow(PATH, textwrap.dedent(BASE))
    after = analyse_workflow(PATH, breaker(RISKY))
    assert not after.ok and after.error and after.lexical is not None
    d = compare_workflows(PATH, before, after, repo_default="read", change_type="modified")
    assert d.analysis == "lexical_fallback"
    assert d.write_all_added and set(d.added_write_scopes) == set(WRITE_CAPABLE_SCOPES)
    assert d.dangerous_triggers_added == ("pull_request_target",)
    assert d.triggers_added == ("pull_request_target",)
    assert d.untrusted_checkout_added and d.escalation
    assert d.effective_permissions_unknown
    for flag in (
        "analysis_lexical_fallback",
        "write_all_added",
        "scope_escalation:contents",
        "dangerous_trigger_added:pull_request_target",
        "privileged_trigger_untrusted_checkout",
        "effective_permissions_unknown",
        "workflow_unparseable",
    ):
        assert flag in d.risk_flags, flag
    attributes = d.to_attributes()
    assert attributes["analysis"] == "lexical_fallback"
    assert attributes["effective_permissions_unknown"] is True
    assert attributes["write_all_added"] is True
    assert attributes["parse_error_after"] and attributes["parse_error_before"] is None
    assert attributes["permissions_before"] == "workflow=contents:read"
    assert attributes["permissions_after"] == "unparseable;lexical=write-all"
    assert attributes["lexical_truncated"] is False
    assert attributes["lexical_evidence"] == ["ref input uses github.event.pull_request.head.sha"]
    # Checks the lexical scan does not cover are unknown, never "none found".
    assert attributes["unpinned_actions_added"] is None
    assert attributes["script_injection_added"] is None
    assert attributes["secrets_inherit_added"] is None
    assert "compared lexically" in d.summary() and "write-all added" in d.summary()
    json.dumps(attributes)


@pytest.mark.parametrize(
    "permissions",
    [
        "permissions:\n  contents: write\n  id-token: write\n",
        "permissions: {contents: write, 'id-token': write}\n",
        '"permissions": {"contents": "write", "id-token": "write"}\n',
        "permissions:\n  contents: !!str write\n  ? id-token\n  : write\n",
        "jobs:\n  release:\n    permissions:\n      contents: WRITE\n      id-token: write\n",
    ],
    ids=["block", "flow", "json", "tag-and-explicit-key", "job-level"],
)
def test_lexical_write_scopes_in_permissions_blocks(permissions: str) -> None:
    after = analyse_workflow(PATH, "on: push\n" + permissions + "broken: [unclosed\n")
    assert not after.ok
    d = compare_workflows(PATH, wf(BASE), after, repo_default="read", change_type="modified")
    assert d.analysis == "lexical_fallback"
    assert d.added_write_scopes == ("contents", "id-token")
    assert not d.write_all_added and d.escalation
    assert d.permissions_after == "unparseable;lexical=write:contents,id-token"


def test_lexical_privileged_triggers_and_untrusted_checkout() -> None:
    text = textwrap.dedent(
        """
        on:
          workflow_run:
            workflows: [CI]
        jobs:
          report:
            steps:
              - uses: actions/checkout@v4
                with: {ref: "${{ github.event.workflow_run.head_sha }}"}
              - run: git fetch origin pull/${{ github.event.number }}/head
              - run: gh pr checkout 1
        broken: [unclosed
        """
    )
    scan = lexical_scan(text)
    assert scan.privileged_triggers == ("workflow_run",)
    assert scan.untrusted_checkout == (
        "ref input uses github.event.workflow_run.head_sha",
        "run: gh pr checkout",
        "run: git fetch of pull/${{",
    )
    assert scan.privileged_untrusted_checkout
    d = compare_workflows(
        PATH, wf(BASE), analyse_workflow(PATH, text), repo_default="read", change_type="modified"
    )
    assert d.dangerous_triggers_added == ("workflow_run",) and d.untrusted_checkout_added
    assert not d.write_all_added and d.added_write_scopes == ()


def test_lexical_scan_ignores_comments_expressions_and_lookalikes() -> None:
    text = textwrap.dedent(
        """
        # permissions: write-all
        #   contents: write
        # on: pull_request_target
        on: push
        permissions:
          contents: read
        jobs:
          x:
            if: ${{ github.event_name == 'pull_request_target' }}
            steps:
              - uses: actions/create-github-app-token@v1
                with:
                  permission-contents: write
              - run: echo "${{ github.event.workflow_run.conclusion }}"
        """
    )
    scan = lexical_scan(text)
    assert not scan.write_all and scan.write_scopes == ()
    assert scan.privileged_triggers == () and scan.untrusted_checkout == ()
    assert scan.has_permissions_key


def test_lexical_scan_sees_through_escapes_and_scalar_aliases() -> None:
    escaped = 'on: [push, "pull_request_t\\x61rget"]\npermissions: "write\\x2dall"\n'
    scan = lexical_scan(escaped)
    assert scan.write_all and scan.privileged_triggers == ("pull_request_target",)
    folded = 'permissions: "write-\\\n   all"\n'
    assert lexical_scan(folded).write_all
    aliased = "x: &w write\ny: &s contents\npermissions:\n  *s : *w\n  id-token: *w\n"
    assert lexical_scan(aliased).write_scopes == ("contents", "id-token")


def test_lexical_comparison_reports_only_added_risk() -> None:
    broken = _malformed(RISKY)
    same_risk = analyse_workflow(PATH, broken.replace("make preview", "make preview2"))
    unchanged = compare_workflows(
        PATH, analyse_workflow(PATH, broken), same_risk, repo_default="read", change_type="modified"
    )
    assert unchanged.analysis == "lexical_fallback" and not unchanged.escalation
    assert "baseline_unparseable" in unchanged.risk_flags
    # Like with like: a parsed baseline with the same risk does not count as added.
    parsed_before = compare_workflows(
        PATH, wf(RISKY), same_risk, repo_default="read", change_type="modified"
    )
    assert not parsed_before.escalation
    # Reverting to the least-privilege baseline removes the trigger and adds nothing.
    revert = compare_workflows(
        PATH, same_risk, wf(BASE), repo_default="read", change_type="modified"
    )
    assert revert.analysis == "lexical_fallback" and not revert.escalation
    assert revert.triggers_removed == ("pull_request_target",)
    # Added / removed unanalysable files: an absent version declares nothing.
    added = compare_workflows(PATH, None, same_risk, repo_default="read", change_type="added")
    assert added.write_all_added and "workflow_added" in added.risk_flags
    removed = compare_workflows(PATH, same_risk, None, repo_default="read", change_type="removed")
    assert not removed.escalation and removed.permissions_after == "absent"


def test_lexical_repo_default_write_without_permissions_key() -> None:
    after = analyse_workflow(PATH, "on: push\njobs: [unclosed\n")
    d = compare_workflows(PATH, wf(BASE), after, repo_default="write", change_type="modified")
    assert set(d.added_write_scopes) == set(PERMISSIVE_DEFAULT)
    assert "relies_on_repo_default_write" in d.risk_flags and d.escalation
    unknown = compare_workflows(PATH, wf(BASE), after, repo_default=None, change_type="modified")
    assert unknown.added_write_scopes == () and unknown.effective_permissions_unknown


def test_unavailable_text_is_not_treated_as_absent() -> None:
    # An analysis without text (e.g. built elsewhere) still fails closed.
    blind = WorkflowAnalysis(path=PATH, ok=False, error="workflow exceeds 524288 bytes")
    d = compare_workflows(PATH, wf(BASE), blind, repo_default="read", change_type="modified")
    assert d.analysis == "lexical_fallback" and d.effective_permissions_unknown
    assert "workflow_lexical_unavailable" in d.risk_flags
    assert d.permissions_after == "unparseable;lexical=unavailable"


def test_lexical_scan_is_bounded_and_reports_truncation() -> None:
    hidden = "#" * (MAX_LEXICAL_BYTES + 16) + "\npermissions: write-all\n"
    scan = lexical_scan(hidden)
    assert scan.truncated and not scan.write_all  # beyond the bound: not examined
    assert scan.chars_scanned == MAX_LEXICAL_BYTES
    d = compare_workflows(
        PATH, wf(BASE), analyse_workflow(PATH, hidden), repo_default="read", change_type="modified"
    )
    assert d.lexical_truncated and "lexical_scan_truncated" in d.risk_flags
    assert d.effective_permissions_unknown and not d.escalation
    # A prefix handed over by the fetcher is never parsed and is marked truncated.
    prefix = analyse_workflow(PATH, "on: push\npermissions: write-all\n", truncated=True)
    assert not prefix.ok and prefix.lexical is not None and prefix.lexical.truncated
    assert prefix.lexical.write_all


def test_lexical_scan_stays_fast_on_hostile_input() -> None:
    hostile = (
        "contents: write\n" * 20_000
        + "x: &a write\n"
        + "*a " * 300_000
        + "\nref: "
        + "github.event." * 40_000
        + "\n"
        + "git fetch " * 30_000
    )[:MAX_LEXICAL_BYTES]
    start = time.monotonic()
    scan = lexical_scan(hostile)
    elapsed = time.monotonic() - start
    assert scan.write_scopes == ("contents",)
    assert elapsed < 10, f"lexical scan took {elapsed:.1f}s"


# ── GH-001 lab files ────────────────────────────────────────────────────────


def test_lab_baseline_workflow_is_least_privilege() -> None:
    analysis = analyse_workflow(PATH, LAB_CI.read_text(encoding="utf-8"))
    assert analysis.ok
    assert analysis.permissions.render() == "contents:read"
    assert analysis.unpinned_third_party_actions == ()
    assert analysis.unpinned_github_owned_actions == ()  # pinned to full SHAs
    assert analysis.privileged_triggers == ()
    assert analysis.effective_permissions("write").write_scopes == ()


def test_gh001_template_escalates_against_baseline() -> None:
    before = analyse_workflow(PATH, LAB_CI.read_text(encoding="utf-8"))
    after = analyse_workflow(PATH, GH001_TEMPLATE.read_text(encoding="utf-8"))
    d = compare_workflows(PATH, before, after, repo_default="read", change_type="modified")
    assert d.write_all_added
    assert d.triggers_added == ("pull_request_target",)
    assert d.dangerous_triggers_added == ("pull_request_target",)
    assert d.untrusted_checkout_added
    assert {"contents", "actions", "packages", "id-token"} <= set(d.added_write_scopes)
    reverse = compare_workflows(PATH, after, before, repo_default="read", change_type="modified")
    assert not reverse.escalation and not reverse.write_all_added


def test_analyze_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before, after = str(LAB_CI), str(GH001_TEMPLATE)
    assert (
        analyze.main(
            [
                "--path",
                PATH,
                "--before",
                before,
                "--after",
                after,
                "--repo-default",
                "read",
                "--expect-escalation",
            ]
        )
        == 0
    )
    output = json.loads(capsys.readouterr().out)
    assert output["event_type"] == "github.workflow.modified"
    assert output["attributes"]["write_all_added"] is True
    assert (
        analyze.main(["--path", PATH, "--before", after, "--after", before, "--expect-escalation"])
        == 1
    )
    assert (
        analyze.main(
            ["--path", PATH, "--before", after, "--after", before, "--expect-no-escalation"]
        )
        == 0
    )
    assert analyze.main(["--path", "ci.yml", "--before", before, "--after", after]) == 2
    assert analyze.main(["--path", PATH, "--before", "none", "--after", "none"]) == 2
    missing = str(tmp_path / "missing.yml")
    assert analyze.main(["--path", PATH, "--before", missing, "--after", after]) == 2


def test_analyze_cli_scans_oversized_files_lexically(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    big = tmp_path / "big.yml"
    big.write_text(_oversized(GH001_TEMPLATE.read_text(encoding="utf-8")), encoding="utf-8")
    args = ["--path", PATH, "--before", str(LAB_CI), "--after", str(big), "--repo-default", "read"]
    assert analyze.main([*args, "--expect-escalation"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["attributes"]["analysis"] == "lexical_fallback"
    assert output["attributes"]["write_all_added"] is True
    assert output["attributes"]["effective_permissions_unknown"] is True

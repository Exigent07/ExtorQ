"""GitHub Actions workflow invariants for ExtorQ's own CI (``.github/workflows``).

* Every workflow declares top-level ``permissions`` that grant nothing beyond
  read access (``{}``, ``read-all`` or a map of ``read``/``none`` scopes).
* Job-level ``write`` grants are limited to a reviewed allow-list.
* No ``pull_request_target`` trigger (runs untrusted code with secrets).
* Every third-party action is pinned to a full 40-character commit SHA.
* ``run:`` scripts never interpolate attacker-controlled ``github.event.*`` /
  ``github.head_ref`` expressions directly (script injection).

Lab content under ``lab/`` (e.g. the GH-001 lab repository workflows, which are
deliberately risky) is out of scope: only the repository's own CI is checked.
Skipped until ``.github/workflows`` exists (owner: A).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from security_helpers import REPO_ROOT, format_findings, read_text, rel

WORKFLOW_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOWS = sorted(
    p
    for p in list(WORKFLOW_DIR.glob("*.yml")) + list(WORKFLOW_DIR.glob("*.yaml"))
    if not p.is_symlink()
)

#: Job-level write scopes that are acceptable after review (SARIF upload only).
ALLOWED_JOB_WRITE_SCOPES = frozenset({"security-events"})
SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|commits|head_commit|"
    r"pages|workflow_run|discussion)[^}]*|github\.head_ref)\s*\}\}"
)

requires_workflows = pytest.mark.skipif(
    not WORKFLOWS, reason=".github/workflows not present yet (owner: A)"
)


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(read_text(path)) or {}
    assert isinstance(data, dict), f"{rel(path)} is not a mapping"
    return data


def _triggers(workflow: dict[str, Any]) -> set[str]:
    # PyYAML (YAML 1.1) parses the bare key `on` as boolean True.
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on}
    return set()


def permission_problems(permissions: Any, where: str, *, job_level: bool) -> list[str]:
    if permissions is None:
        return (
            []
            if job_level
            else [f"{where}: missing top-level 'permissions' (defaults may grant write)"]
        )
    if permissions in ({}, "read-all"):
        return []
    if permissions == "write-all":
        return [f"{where}: permissions: write-all"]
    if not isinstance(permissions, dict):
        return [f"{where}: unrecognised permissions value {permissions!r}"]
    problems: list[str] = []
    for scope, level in permissions.items():
        if level in ("read", "none"):
            continue
        if level == "write" and job_level and scope in ALLOWED_JOB_WRITE_SCOPES:
            continue
        problems.append(f"{where}: grants {scope}: {level}")
    return problems


def workflow_problems(workflow: dict[str, Any], where: str) -> list[str]:
    problems = permission_problems(workflow.get("permissions"), where, job_level=False)
    if "pull_request_target" in _triggers(workflow):
        problems.append(f"{where}: uses the pull_request_target trigger")
    for job_name, job in (workflow.get("jobs") or {}).items():
        job = job or {}
        job_where = f"{where} job {job_name}"
        problems.extend(permission_problems(job.get("permissions"), job_where, job_level=True))
        uses_job = job.get("uses")
        if (
            isinstance(uses_job, str)
            and not uses_job.startswith("./")
            and not SHA_PIN.match(uses_job)
        ):
            problems.append(
                f"{job_where}: reusable workflow {uses_job!r} not pinned to a commit SHA"
            )
        for index, step in enumerate(job.get("steps") or []):
            step = step or {}
            uses = step.get("uses")
            if isinstance(uses, str):
                local = uses.startswith("./")
                docker_digest = uses.startswith("docker://") and "@sha256:" in uses
                if not (local or docker_digest or SHA_PIN.match(uses)):
                    problems.append(
                        f"{job_where} step {index}: action {uses!r} not pinned to a commit SHA"
                    )
            run = step.get("run")
            if isinstance(run, str) and UNTRUSTED_EXPR.search(run):
                problems.append(
                    f"{job_where} step {index}: run script interpolates untrusted github context; "
                    "pass it through env: instead"
                )
    return problems


@requires_workflows
def test_ci_workflows_follow_least_privilege_and_pinning() -> None:
    problems: list[str] = []
    for path in WORKFLOWS:
        problems.extend(workflow_problems(_load(path), rel(path)))
    assert not problems, format_findings(problems)


# ── self-tests ───────────────────────────────────────────────────────────────

GOOD = """
name: ci
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
        with: {persist-credentials: false}
      - run: uv run pytest -q
        env:
          TITLE: ${{ github.event.pull_request.title }}
"""

BAD = """
name: ci
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-24.04
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v5
      - run: echo "${{ github.event.pull_request.title }}"
"""


def test_checker_accepts_hardened_workflow() -> None:
    assert workflow_problems(yaml.safe_load(GOOD), "good.yml") == []


def test_checker_flags_risky_workflow() -> None:
    problems = workflow_problems(yaml.safe_load(BAD), "bad.yml")
    joined = "\n".join(problems)
    assert "missing top-level 'permissions'" in joined
    assert "pull_request_target" in joined
    assert "contents: write" in joined
    assert "not pinned" in joined
    assert "interpolates untrusted" in joined


def test_checker_flags_write_all() -> None:
    assert permission_problems("write-all", "w.yml", job_level=False)
    assert permission_problems({"security-events": "write"}, "w.yml", job_level=False)
    assert not permission_problems({"security-events": "write"}, "w.yml", job_level=True)

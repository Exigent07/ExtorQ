"""GitHub detection tests on the private repository ``Exigent07/extorq-lab``.

The repository is hard-coded: the suite refuses to push anywhere else, checks before every
run that the repository is private and that the clone's ``origin`` points at it, and works
in its own clone ``var/github/extorq-lab`` (reset to ``origin`` before every change).
Pushing to this disposable repository was approved by the user for detection testing
(``docs/team/PLAN.md`` section 12).

Each test pushes ONE commit to the default branch and undoes it with ``git revert`` (a new
commit; history is never rewritten), then verifies that the files at the branch head are
exactly as before. Git authenticates through the GitHub CLI for these commands only
(``credential.helper=!gh auth git-credential``): no credential is written to disk or printed.

Every test commit carries ``[skip ci]`` (a standard GitHub Actions directive), so no
workflow runs because of a test, and new workflows use triggers that do not fire on push
(pull requests, issues, manual dispatch). The fake credential of GH-005 is generated at
random in the shape of an AWS key pair; it is not a real key, and it stays in the history
of this private repository after the revert (as a real leaked key would).
"""

from __future__ import annotations

import functools
import json
import re
import secrets
import string
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from detection_tests.model import (
    ActionFailed,
    ActionRecord,
    AssetRef,
    CleanupStack,
    DetectionTest,
    LatencySource,
    PreconditionFailed,
    StepResult,
    TelemetryExpectation,
    TestSpec,
    validate_artefact_name,
)
from detection_tests.proc import ProcResult, run, which
from detection_tests.runner import AssetSuite, TestContext
from extorq.common.redaction import redact_text

ASSET = AssetRef("github", "github:exigent07/extorq-lab", "private repository Exigent07/extorq-lab")
#: The ONLY repository the suite writes to.
REPO = "Exigent07/extorq-lab"
REMOTE_URL = f"https://github.com/{REPO}.git"
CLONE_DIR = "var/github/extorq-lab"
CI_WORKFLOW = ".github/workflows/ci.yml"
WORKFLOW_DIR = ".github/workflows"
DEPLOY_DIR = "deploy"
COLLECTOR_ID = "github-repos"
#: Third-party action used by GH-003 (pinned by tag in the positive, by SHA in the negative).
BUILDX_ACTION = "docker/setup-buildx-action"
BUILDX_TAG = "v3"
#: First-party checkout pin used when ci.yml does not provide one.
DEFAULT_CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SKIP_CI = "[skip ci]"
#: Permissions block of the baseline CI workflow (lab/github-repo/.github/workflows/ci.yml).
BASELINE_COMMENT = "# Least privilege: the token can only read repository contents.\n"
BASELINE_PERMISSIONS = "permissions:\n  contents: read\n"
TEST_JOB_ANCHOR = "\n  test:\n    name: Unit tests\n"
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_CHECKOUT_RE = re.compile(r"uses:\s*(actions/checkout@[0-9a-f]{40})")
_GH_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]+$")

GITHUB_API = LatencySource(
    description="GitHub REST API poll (commits, workflow diffs, added lines)",
    config_file="config/collectors/github.yaml",
    collector_id=COLLECTOR_ID,
    interval_keys=(),
    default_seconds=120,
)


# ── workflow and file content (pure) ───────────────────────────────────────────────────


def _load(text: str) -> dict[Any, Any]:
    document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise ValueError("workflow is not a YAML mapping")
    return document


def ci_is_baseline(text: str) -> bool:
    """The live CI workflow still has the least-privilege permissions of the baseline."""
    try:
        document = _load(text)
    except (ValueError, yaml.YAMLError):
        return False
    return text.count(BASELINE_PERMISSIONS) == 1 and document.get("permissions") == {
        "contents": "read"
    }


def escalate_ci_permissions(text: str) -> str:
    """GH-001 positive: workflow-level ``permissions: write-all``."""
    if not ci_is_baseline(text):
        raise ValueError("ci.yml is not at the least-privilege baseline")
    changed = text.replace(
        BASELINE_COMMENT + BASELINE_PERMISSIONS,
        "# Release automation pushes tags with the workflow token.\npermissions: write-all\n",
    )
    if changed == text:
        changed = text.replace(BASELINE_PERMISSIONS, "permissions: write-all\n")
    if _load(changed).get("permissions") != "write-all":
        raise ValueError("escalation did not produce permissions: write-all")
    return changed


def reduce_ci_permissions(text: str) -> str:
    """GH-001 negative: no default token permissions, ``contents: read`` for the test job only."""
    if not ci_is_baseline(text) or text.count(TEST_JOB_ANCHOR) != 1:
        raise ValueError("ci.yml is not at the least-privilege baseline")
    changed = text.replace(
        BASELINE_COMMENT + BASELINE_PERMISSIONS,
        "# No default token permissions; each job declares what it needs.\npermissions: {}\n",
    )
    if changed == text:
        changed = text.replace(BASELINE_PERMISSIONS, "permissions: {}\n")
    changed = changed.replace(
        TEST_JOB_ANCHOR, TEST_JOB_ANCHOR + "    permissions:\n      contents: read\n"
    )
    document = _load(changed)
    job = (document.get("jobs") or {}).get("test") or {}
    if document.get("permissions") != {} or job.get("permissions") != {"contents": "read"}:
        raise ValueError("reduction did not produce the expected permissions")
    return changed


def checkout_pin(ci_text: str) -> str:
    """The pinned ``actions/checkout@<sha>`` the repository already uses (first-party)."""
    match = _CHECKOUT_RE.search(ci_text)
    return match.group(1) if match else DEFAULT_CHECKOUT


def pr_preview_workflow(checkout: str, *, privileged_trigger: bool) -> str:
    """GH-002: ``pull_request_target`` + checkout of the PR head, or plain ``pull_request``."""
    if privileged_trigger:
        trigger = "pull_request_target"
        checkout_with = (
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
            "          allow-unsafe-pr-checkout: true\n"
        )
    else:
        trigger = "pull_request"
        checkout_with = ""
    return (
        "name: PR preview\n\n"
        "on:\n"
        f"  {trigger}:\n"
        "    types: [opened, synchronize]\n\n"
        "permissions:\n"
        "  contents: read\n\n"
        "jobs:\n"
        "  preview:\n"
        "    name: Build preview\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 5\n"
        "    steps:\n"
        "      - name: Check out the pull request\n"
        f"        uses: {checkout}\n"
        "        with:\n"
        f"{checkout_with}"
        "          persist-credentials: false\n"
        "      - name: Show the revision\n"
        "        run: git log -1 --format='%H'\n"
    )


def image_build_workflow(checkout: str, buildx_ref: str) -> str:
    """GH-003: a third-party action referenced by ``buildx_ref`` (tag or 40-hex SHA)."""
    pinned = bool(_SHA40_RE.fullmatch(buildx_ref))
    comment = f" # {BUILDX_TAG}" if pinned else ""
    return (
        "name: Container image\n\n"
        "on:\n"
        "  workflow_dispatch:\n\n"
        "permissions:\n"
        "  contents: read\n\n"
        "jobs:\n"
        "  image:\n"
        "    name: Build image\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 15\n"
        "    steps:\n"
        "      - name: Check out repository\n"
        f"        uses: {checkout}\n"
        "        with:\n"
        "          persist-credentials: false\n"
        "      - name: Set up Docker Buildx\n"
        f"        uses: {BUILDX_ACTION}@{buildx_ref}{comment}\n"
        "      - name: Build image\n"
        "        run: docker buildx build --load -t extorq-lab:ci .\n"
    )


def issue_triage_workflow(*, injectable: bool) -> str:
    """GH-004: the issue title interpolated into ``run`` (injectable) or passed via ``env``."""
    if injectable:
        step = (
            "      - name: Print the issue title\n"
            "        run: |\n"
            '          echo "New issue: ${{ github.event.issue.title }}"\n'
        )
    else:
        step = (
            "      - name: Print the issue title\n"
            "        env:\n"
            "          ISSUE_TITLE: ${{ github.event.issue.title }}\n"
            "        run: |\n"
            '          echo "New issue: $ISSUE_TITLE"\n'
        )
    return (
        "name: Issue triage\n\n"
        "on:\n"
        "  issues:\n"
        "    types: [opened]\n\n"
        "permissions:\n"
        "  contents: read\n\n"
        "jobs:\n"
        "  triage:\n"
        "    name: Triage new issue\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 5\n"
        "    steps:\n"
        f"{step}"
    )


_AWS_KEY_ALPHABET = string.ascii_uppercase + "234567"
_AWS_SECRET_ALPHABET = string.ascii_letters + string.digits + "/+"


def fake_aws_credentials() -> str:
    """GH-005 positive: a random, credential-SHAPED AWS key pair (not a real key).

    The shape matches ExtorQ's own redaction patterns (``aws_access_key`` and
    ``aws_secret_key``), which is what the collector's secret detection uses.
    """
    key_id = "AKIA" + "".join(secrets.choice(_AWS_KEY_ALPHABET) for _ in range(16))
    secret = "".join(secrets.choice(_AWS_SECRET_ALPHABET) for _ in range(40))
    content = (
        "# Staging deployment settings\n"
        "AWS_REGION=eu-central-1\n"
        f"AWS_ACCESS_KEY_ID={key_id}\n"
        f"AWS_SECRET_ACCESS_KEY={secret}\n"
    )
    if redact_text(content)[1] < 2:
        raise ValueError("generated credential does not match the redaction patterns")
    return content


def release_checksum() -> str:
    """GH-005 negative: a high-entropy line that is NOT a credential (SHA-256 checksum)."""
    content = f"{secrets.token_hex(32)}  extorq-lab-1.4.2.tar.gz\n"
    if redact_text(content)[1] != 0:
        raise ValueError("checksum line unexpectedly matches a credential pattern")
    return content


def workflow_path(name: str, purpose: str) -> str:
    validate_artefact_name(name)
    if not re.fullmatch(r"[a-z][a-z-]{1,30}", purpose):
        raise ValueError(f"invalid purpose {purpose!r}")
    return f"{WORKFLOW_DIR}/{name}-{purpose}.yml"


def deploy_path(name: str, suffix: str) -> str:
    validate_artefact_name(name)
    if suffix not in ("env", "sha256"):
        raise ValueError(f"invalid suffix {suffix!r}")
    return f"{DEPLOY_DIR}/{name}.{suffix}"


def _check_repo_path(path: str) -> str:
    """Only plain relative paths inside the clone may be written (no .., no absolute)."""
    pure = PurePosixPath(path)
    if (
        not _SAFE_PATH_RE.fullmatch(path)
        or pure.is_absolute()
        or ".." in pure.parts
        or pure.parts[0] == ".git"
    ):
        raise ValueError(f"refusing repository path {path!r}")
    return path


# ── repository access ──────────────────────────────────────────────────────────────────


def _serialised(method):  # type: ignore[no-untyped-def]
    """Hold the repository lock for the whole method.

    Batch runs execute the GitHub tests concurrently (their *waits* overlap), but the shared
    clone must only be mutated by one test at a time: sync/commit/push/revert are short, so
    serialising them costs seconds, not minutes.
    """

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class LabRepository:
    """The clone of ``Exigent07/extorq-lab`` and the git/gh commands the tests need."""

    def __init__(self, root: Path) -> None:
        self._lock = threading.RLock()
        self.root = root
        self.clone_dir = root / CLONE_DIR
        self.branch: str | None = None
        self._identity: tuple[str, str] | None = None

    # commands

    def _gh_binary(self) -> str:
        path = which("gh")
        # The path is placed in git's credential.helper, which git runs through a shell:
        # only plain path characters are accepted.
        if path is None or not _SAFE_PATH_RE.fullmatch(path):
            raise PreconditionFailed("the GitHub CLI (gh) is not installed at a plain path")
        return path

    def gh(self, *args: str) -> ProcResult:
        return run(["gh", *args], timeout=60, what="gh")

    def git_argv(self, *args: str, network: bool = False) -> list[str]:
        argv = ["git", "-C", str(self.clone_dir)]
        if network:
            argv += [
                "-c",
                "credential.helper=",
                "-c",
                f"credential.helper=!{self._gh_binary()} auth git-credential",
            ]
        return [*argv, *args]

    def git(self, *args: str, network: bool = False, check: bool = True) -> ProcResult:
        return run(
            self.git_argv(*args, network=network),
            timeout=180 if network else 60,
            env={"GIT_TERMINAL_PROMPT": "0"},
            check=check,
            what="git",
        )

    # checks

    def check(self, _ctx: TestContext) -> list[StepResult]:
        checks = [
            StepResult("git on PATH", which("git") is not None, "git"),
            StepResult("gh on PATH", which("gh") is not None, "gh"),
        ]
        if not all(c.ok for c in checks):
            return checks
        auth = self.gh("auth", "status")
        checks.append(
            StepResult("gh authenticated", auth.ok, "yes" if auth.ok else "run `gh auth login`")
        )
        if not auth.ok:
            return checks
        view = self.gh("repo", "view", REPO, "--json", "nameWithOwner,isPrivate,defaultBranchRef")
        try:
            info = json.loads(view.stdout) if view.ok else {}
        except json.JSONDecodeError:
            info = {}
        name_ok = info.get("nameWithOwner") == REPO
        private = info.get("isPrivate") is True
        branch = (info.get("defaultBranchRef") or {}).get("name")
        checks.append(
            StepResult(
                f"repository {REPO}",
                name_ok and private,
                "private" if name_ok and private else "not found, not accessible or NOT private",
            )
        )
        branch_ok = isinstance(branch, str) and bool(
            re.fullmatch(r"[A-Za-z0-9._/-]{1,100}", branch)
        )
        checks.append(StepResult("default branch", branch_ok, str(branch)))
        if branch_ok:
            self.branch = str(branch)
        return checks

    def _identity_args(self) -> list[str]:
        """``-c user.name/user.email`` of the authenticated GitHub user (noreply address).

        Passed per command so the operator's global git configuration is never changed, and
        commits are attributed to the account that pushes them (no test identity).
        """
        if self._identity is None:
            result = self.gh("api", "user", "--jq", '.login + " " + (.id|tostring)')
            parts = result.stdout.split()
            if not result.ok or len(parts) != 2:
                raise ActionFailed("cannot read the GitHub user (gh api user)")
            login, user_id = parts
            if not _GH_LOGIN_RE.fullmatch(login) or not user_id.isdigit():
                raise ActionFailed("unexpected GitHub user identity")
            self._identity = (login, f"{user_id}+{login}@users.noreply.github.com")
        login, email = self._identity
        return [
            "-c",
            f"user.name={login}",
            "-c",
            f"user.email={email}",
            "-c",
            "commit.gpgsign=false",
        ]

    # working copy

    @_serialised
    def sync(self) -> str:
        """Clone or fetch, verify ``origin``, reset to the remote branch head; return its SHA."""
        branch = self.branch
        if branch is None:
            raise ActionFailed("default branch unknown (asset checks did not run)")
        if not (self.clone_dir / ".git").is_dir():
            self.clone_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            run(
                [
                    "git",
                    "-c",
                    "credential.helper=",
                    "-c",
                    f"credential.helper=!{self._gh_binary()} auth git-credential",
                    "clone",
                    "--quiet",
                    "--branch",
                    branch,
                    REMOTE_URL,
                    str(self.clone_dir),
                ],
                timeout=180,
                env={"GIT_TERMINAL_PROMPT": "0"},
                check=True,
                what="git clone",
            )
        origin = self.git("remote", "get-url", "origin").stdout.strip()
        if origin != REMOTE_URL:
            raise ActionFailed(f"{CLONE_DIR} points at another remote; refusing to push there")
        self.git("fetch", "--quiet", "origin", branch, network=True)
        self.git("checkout", "--quiet", "-B", branch, f"origin/{branch}")
        self.git("reset", "--quiet", "--hard", f"origin/{branch}")
        self.git("clean", "--quiet", "-fd")
        return self.git("rev-parse", "HEAD").stdout.strip()

    def read(self, path: str) -> str | None:
        """Content of ``path`` at the synced head (``None`` when absent)."""
        target = self.clone_dir / _check_repo_path(path)
        return target.read_text(encoding="utf-8") if target.is_file() else None

    def list_dir(self, path: str) -> list[str]:
        directory = self.clone_dir / _check_repo_path(path)
        if not directory.is_dir():
            return []
        return sorted(f"{path}/{p.name}" for p in directory.iterdir() if p.is_file())

    def _push(self) -> str:
        branch = self.branch
        if branch is None:
            raise ActionFailed("default branch unknown (asset checks did not run)")
        if not self.git(
            "push", "--quiet", "origin", f"HEAD:{branch}", network=True, check=False
        ).ok:
            # Someone else pushed meanwhile: replay on top once, then give up.
            self.git(
                *self._identity_args(),
                "pull",
                "--quiet",
                "--rebase",
                "origin",
                branch,
                network=True,
            )
            self.git("push", "--quiet", "origin", f"HEAD:{branch}", network=True)
        return self.git("rev-parse", "HEAD").stdout.strip()

    @_serialised
    def commit(self, changes: Mapping[str, str | None], message: str) -> str:
        """Write (or delete, value ``None``) files, commit with ``message`` and push."""
        if SKIP_CI not in message:
            raise ValueError("test commits must carry [skip ci]")
        self.sync()
        identity = self._identity_args()
        paths: list[str] = []
        for path, content in changes.items():
            target = self.clone_dir / _check_repo_path(path)
            if content is None:
                target.unlink(missing_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            paths.append(path)
        self.git("add", "-A", "--", *paths)
        self.git(*identity, "commit", "--quiet", "-m", message)
        return self._push()

    @_serialised
    def revert(self, sha: str) -> str:
        if not _SHA40_RE.fullmatch(sha):
            raise ValueError("invalid commit SHA")
        self.sync()
        self.git(*self._identity_args(), "revert", "--no-edit", sha)
        return self._push()

    @_serialised
    def restore(self, pushed: Sequence[str], expected: Mapping[str, str | None]) -> str:
        """Cleanup: revert pushed commits (newest first), then verify the files at the head."""
        reverts = [self.revert(sha) for sha in reversed(pushed)]
        self.sync()
        wrong = [path for path, content in expected.items() if self.read(path) != content]
        if wrong:
            raise ActionFailed(
                f"after the revert these files differ from before: {', '.join(wrong)}"
            )
        if not reverts:
            return "nothing was pushed; files verified unchanged"
        return f"reverted with {', '.join(r[:12] for r in reverts)}; files verified as before"

    def leftovers(self) -> list[str]:
        """Test files still present at the head (from an interrupted run)."""
        found = [
            path
            for path in self.list_dir(WORKFLOW_DIR) + self.list_dir(DEPLOY_DIR)
            if PurePosixPath(path).name.startswith("extorq-test-")
        ]
        return sorted(found)

    def sweep(self, _ctx: TestContext) -> list[StepResult]:
        """Remove leftover test files and undo a leftover GH-001 change of ci.yml."""
        self.sync()
        changes: dict[str, str | None] = {path: None for path in self.leftovers()}
        baseline_file = self.root / "lab/github-repo" / CI_WORKFLOW
        current = self.read(CI_WORKFLOW)
        if current is not None and baseline_file.is_file() and not ci_is_baseline(current):
            baseline = baseline_file.read_text(encoding="utf-8")
            # Only undo the suite's own edits; any other change of ci.yml is left alone.
            try:
                ours = {escalate_ci_permissions(baseline), reduce_ci_permissions(baseline)}
            except ValueError:
                ours = set()
            if current in ours:
                changes[CI_WORKFLOW] = baseline
        if not changes:
            return [StepResult(f"{REPO} leftovers", True, "none found")]
        sha = self.commit(changes, f"chore: remove leftover CI experiment files {SKIP_CI}")
        return [StepResult(f"{REPO} leftovers", True, f"removed {sorted(changes)} in {sha[:12]}")]


def workflow_modified(sha: str) -> TelemetryExpectation:
    return TelemetryExpectation(
        f"collector analysed the workflow change of commit {sha[:12]}",
        "github.workflow.modified",
        equals=(("gh_commit_sha", sha),),
        source_type="github.api",
    )


# ── tests ──────────────────────────────────────────────────────────────────────────────


class _RepoTest(DetectionTest):
    def __init__(self, repo: LabRepository) -> None:
        self.repo = repo

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        self.repo.sync()
        leftovers = self.repo.leftovers()
        if leftovers:
            raise PreconditionFailed(
                f"test files from an earlier run are still in {REPO}: {', '.join(leftovers)}; "
                "run `uv run python -m detection_tests cleanup --asset github`"
            )
        return [StepResult(f"{REPO} free of test files", True, "clean")]

    def _push_change(
        self, cleanup: CleanupStack, changes: Mapping[str, str | None], message: str
    ) -> str:
        """Commit + push ``changes``; the cleanup step reverts them and verifies the result."""
        expected = {path: self.repo.read(path) for path in changes}
        pushed: list[str] = []
        cleanup.push(
            f"revert {', '.join(changes)} in {REPO}",
            lambda: self.repo.restore(pushed, expected),
        )
        sha = self.repo.commit(changes, message)
        pushed.append(sha)
        return sha


class WorkflowPermissionsTest(_RepoTest):
    spec = TestSpec(
        test_id="github.gh-001",
        asset=ASSET,
        rule_id="GH-001",
        title="Workflow permission escalation (write-all)",
        positive="Change ci.yml from `permissions: contents: read` to `permissions: write-all`.",
        negative=(
            "Reduce ci.yml permissions: `permissions: {}` at workflow level, `contents: read` "
            "for the test job only."
        ),
        cleanup="git revert of each commit (new commit), then ci.yml verified identical to before.",
        expected_alert="GH-001 on github:exigent07/extorq-lab for the commit, confidence high.",
        safety="Commits carry [skip ci]: the escalated workflow never runs.",
        source=GITHUB_API,
    )

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        checks = super().preconditions(ctx)
        text = self.repo.read(CI_WORKFLOW)
        if text is None or not ci_is_baseline(text):
            raise PreconditionFailed(
                f"{CI_WORKFLOW} is not at the least-privilege baseline (contents: read); run "
                "`uv run python -m detection_tests cleanup --asset github`"
            )
        return [*checks, StepResult(f"{CI_WORKFLOW} at baseline", True, "contents: read")]

    def _change(self, cleanup: CleanupStack, *, escalate: bool) -> tuple[str, str]:
        self.repo.sync()
        text = self.repo.read(CI_WORKFLOW) or ""
        try:
            changed = escalate_ci_permissions(text) if escalate else reduce_ci_permissions(text)
        except ValueError as exc:
            raise ActionFailed(str(exc)) from None
        message = (
            "ci: let the workflow token push release tags"
            if escalate
            else "ci: drop default token permissions, grant per job"
        )
        sha = self._push_change(cleanup, {CI_WORKFLOW: changed}, f"{message} {SKIP_CI}")
        return sha, message

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        sha, message = self._change(cleanup, escalate=True)
        return ActionRecord(
            f"pushed {sha[:12]}: {CI_WORKFLOW} permissions -> write-all",
            details=[f"commit message: {message} {SKIP_CI}"],
            artefacts=[f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
            artefact_hint=sha[:7],
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        sha, message = self._change(cleanup, escalate=False)
        return ActionRecord(
            f"pushed {sha[:12]}: {CI_WORKFLOW} permissions reduced",
            details=[f"commit message: {message} {SKIP_CI}"],
            artefacts=[f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
        )


class PrivilegedTriggerTest(_RepoTest):
    spec = TestSpec(
        test_id="github.gh-002",
        asset=ASSET,
        rule_id="GH-002",
        title="pull_request_target workflow checking out untrusted code",
        positive=(
            "Add .github/workflows/extorq-test-<id>-pr-preview.yml: pull_request_target, "
            "actions/checkout of the pull request head (allow-unsafe-pr-checkout)."
        ),
        negative=(
            "The same preview workflow on the pull_request trigger, checking out the default ref."
        ),
        cleanup="git revert of each commit; the workflow files verified absent.",
        expected_alert=(
            "GH-002 on github:exigent07/extorq-lab; GH-001 also alerts (a privileged trigger "
            "was added), a documented overlap."
        ),
        safety="No pull request exists, so the workflow never runs; commits carry [skip ci].",
        source=GITHUB_API,
        positive_overlaps=frozenset({"GH-001"}),
    )

    def _add(self, ctx: TestContext, cleanup: CleanupStack, *, privileged: bool) -> tuple[str, str]:
        self.repo.sync()
        checkout = checkout_pin(self.repo.read(CI_WORKFLOW) or "")
        path = workflow_path(ctx.new_name(), "pr-preview")
        content = pr_preview_workflow(checkout, privileged_trigger=privileged)
        message = (
            "ci: add PR preview build for contributors"
            if privileged
            else "ci: add PR preview build"
        )
        sha = self._push_change(cleanup, {path: content}, f"{message} {SKIP_CI}")
        return sha, path

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        sha, path = self._add(ctx, cleanup, privileged=True)
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} (pull_request_target + PR head checkout)",
            artefacts=[path, f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
            artefact_hint=path,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        sha, path = self._add(ctx, cleanup, privileged=False)
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} (pull_request)",
            artefacts=[path, f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
        )


class UnpinnedActionTest(_RepoTest):
    spec = TestSpec(
        test_id="github.gh-003",
        asset=ASSET,
        rule_id="GH-003",
        title="Third-party action not pinned to a commit SHA",
        positive=(
            "Add .github/workflows/extorq-test-<id>-image-build.yml using "
            "docker/setup-buildx-action@v3 (tag)."
        ),
        negative="The same workflow with the action pinned to its full 40-hex commit SHA.",
        cleanup="git revert of each commit; the workflow files verified absent.",
        expected_alert="GH-003 on github:exigent07/extorq-lab naming the unpinned action.",
        safety="workflow_dispatch only (never triggered); commits carry [skip ci].",
        source=GITHUB_API,
    )

    def __init__(self, repo: LabRepository) -> None:
        super().__init__(repo)
        self.pinned_sha: str | None = None

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        checks = super().preconditions(ctx)
        # Read-only API call: resolve the tag to the commit it points at today.
        result = self.repo.gh("api", f"repos/{BUILDX_ACTION}/commits/{BUILDX_TAG}", "--jq", ".sha")
        sha = result.stdout.strip()
        if not result.ok or not _SHA40_RE.fullmatch(sha):
            raise PreconditionFailed(f"cannot resolve {BUILDX_ACTION}@{BUILDX_TAG} to a commit SHA")
        self.pinned_sha = sha
        return [*checks, StepResult(f"{BUILDX_ACTION}@{BUILDX_TAG}", True, f"resolves to {sha}")]

    def _add(
        self, ctx: TestContext, cleanup: CleanupStack, ref: str, message: str
    ) -> tuple[str, str]:
        self.repo.sync()
        checkout = checkout_pin(self.repo.read(CI_WORKFLOW) or "")
        path = workflow_path(ctx.new_name(), "image-build")
        sha = self._push_change(
            cleanup, {path: image_build_workflow(checkout, ref)}, f"{message} {SKIP_CI}"
        )
        return sha, path

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        sha, path = self._add(ctx, cleanup, BUILDX_TAG, "ci: add container image build")
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} ({BUILDX_ACTION}@{BUILDX_TAG})",
            artefacts=[path, f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
            artefact_hint=BUILDX_ACTION,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        if self.pinned_sha is None:
            raise ActionFailed("the pinned SHA was not resolved")
        sha, path = self._add(
            ctx, cleanup, self.pinned_sha, "ci: add container image build with pinned actions"
        )
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} ({BUILDX_ACTION}@{self.pinned_sha[:12]}...)",
            artefacts=[path, f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
        )


class ScriptInjectionTest(_RepoTest):
    spec = TestSpec(
        test_id="github.gh-004",
        asset=ASSET,
        rule_id="GH-004",
        title="Script injection through an untrusted context in run",
        positive=(
            "Add .github/workflows/extorq-test-<id>-issue-triage.yml whose run step "
            "interpolates ${{ github.event.issue.title }}."
        ),
        negative="The same workflow passing the title through env: and a quoted shell variable.",
        cleanup="git revert of each commit; the workflow files verified absent.",
        expected_alert="GH-004 on github:exigent07/extorq-lab naming the injectable expression.",
        safety=(
            "Runs only when an issue is opened in this private repository (nobody does during "
            "the test) and only echoes; the file exists for minutes."
        ),
        source=GITHUB_API,
    )

    def _add(self, ctx: TestContext, cleanup: CleanupStack, *, injectable: bool) -> tuple[str, str]:
        path = workflow_path(ctx.new_name(), "issue-triage")
        message = "ci: add issue triage workflow" + ("" if injectable else " (env-quoted title)")
        sha = self._push_change(
            cleanup, {path: issue_triage_workflow(injectable=injectable)}, f"{message} {SKIP_CI}"
        )
        return sha, path

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        sha, path = self._add(ctx, cleanup, injectable=True)
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} (issue title interpolated into run)",
            artefacts=[path, f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
            artefact_hint=path,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        sha, path = self._add(ctx, cleanup, injectable=False)
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} (title passed via env)",
            artefacts=[path, f"commit {sha}"],
            telemetry=[workflow_modified(sha)],
        )


class CommittedCredentialTest(_RepoTest):
    spec = TestSpec(
        test_id="github.gh-005",
        asset=ASSET,
        rule_id="GH-005",
        title="Credential committed to the repository",
        positive=(
            "Commit deploy/extorq-test-<id>.env with a randomly generated, AWS-key-SHAPED "
            "access key id and secret (not a real key)."
        ),
        negative=(
            "Commit deploy/extorq-test-<id>.sha256 with a SHA-256 checksum line (high entropy, "
            "not a credential)."
        ),
        cleanup="git revert of each commit; the files verified absent (they stay in history).",
        expected_alert=(
            "GH-005 on github:exigent07/extorq-lab: pattern aws_access_key/aws_secret_key, "
            "redacted match only."
        ),
        safety=(
            "The values are random and were never issued by AWS; the event stores only the "
            "pattern name and a redacted match; commits carry [skip ci]."
        ),
        source=GITHUB_API,
    )

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        path = deploy_path(ctx.new_name(), "env")
        sha = self._push_change(
            cleanup,
            {path: fake_aws_credentials()},
            f"deploy: add staging environment settings {SKIP_CI}",
        )
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} (fake AWS key pair)",
            artefacts=[path, f"commit {sha}"],
            telemetry=[
                TelemetryExpectation(
                    f"collector reported the added credential-shaped line in {sha[:12]}",
                    "github.secret.exposed",
                    equals=(("gh_commit_sha", sha),),
                    source_type="github.api",
                )
            ],
            artefact_hint=path,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        path = deploy_path(ctx.new_name(), "sha256")
        sha = self._push_change(
            cleanup,
            {path: release_checksum()},
            f"deploy: record release artifact checksum {SKIP_CI}",
        )
        return ActionRecord(
            f"pushed {sha[:12]}: added {path} (checksum line)",
            artefacts=[path, f"commit {sha}"],
            telemetry=[
                TelemetryExpectation(
                    f"collector observed commit {sha[:12]}",
                    "github.commit.observed",
                    equals=(("gh_commit_sha", sha),),
                    source_type="github.api",
                )
            ],
        )


def build_suite(root: Path) -> AssetSuite:
    repo = LabRepository(root)
    tests: list[DetectionTest] = [
        WorkflowPermissionsTest(repo),
        PrivilegedTriggerTest(repo),
        UnpinnedActionTest(repo),
        ScriptInjectionTest(repo),
        CommittedCredentialTest(repo),
    ]
    return AssetSuite(
        asset=ASSET,
        tests=tests,
        check=repo.check,
        sweep=repo.sweep,
        collector_ids=(COLLECTOR_ID,),
    )

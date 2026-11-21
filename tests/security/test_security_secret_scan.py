"""Secret scanning with a pinned gitleaks image (requires Docker; skipped otherwise).

Two scans:

1. **Committable working tree**: tracked files plus untracked files that
   ``git add -A`` would pick up are *copied* into a temporary staging
   directory, which is mounted read-only into the scanner. ``.env``, ``var/``,
   symlinks and ``node_modules`` are never copied, so the scanner container
   never sees local secrets.
2. **Git history**: the repository's ``.git`` directory is mounted read-only
   and every commit is scanned.

The container runs with no network, a read-only root filesystem, no
capabilities, ``no-new-privileges`` and an unprivileged uid. Gitleaks runs with
``--redact``, and failures report only ``file:line rule`` (never the match).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest
from security_helpers import (
    REPO_ROOT,
    SKIP_DIR_NAMES,
    committable_files,
    docker_available,
    format_findings,
    git_available,
    is_secret_name,
)

#: Pinned by tag *and* digest (linux/arm64 + amd64 manifest list).
GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.1"
    "@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)
CONFIG_DIR = Path(__file__).resolve().parent
MAX_STAGED_FILE_BYTES = 10 * 1024 * 1024

pytestmark = [
    pytest.mark.skipif(not git_available(), reason="git work tree not available"),
    pytest.mark.skipif(not docker_available(), reason="docker daemon not available"),
    pytest.mark.timeout(600),
]


def _hardened_docker_run(name_suffix: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        f"extorq-f-gitleaks-{name_suffix}-{uuid.uuid4().hex[:8]}",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--memory",
        "1g",
        "--pids-limit",
        "256",
        "-v",
        f"{CONFIG_DIR}:/cfg:ro",
    ]


_GITLEAKS_FLAGS = [
    "--config",
    "/cfg/gitleaks.toml",
    "--redact",
    "--no-banner",
    "--no-color",
    "--log-level",
    "warn",
    "--report-format",
    "json",
    "--report-path",
    "-",
    "--exit-code",
    "1",
]


def _invoke(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=540, check=False)
    except subprocess.TimeoutExpired:
        pytest.fail("gitleaks scan timed out")


def _run_gitleaks(args: list[str]) -> list[dict[str, Any]]:
    result = _invoke(args)
    if result.returncode not in (0, 1):
        # Exit codes other than 0 (clean) / 1 (leaks) are scanner errors. With
        # --redact the log never carries secret values; still show only a tail.
        pytest.fail(f"gitleaks failed (exit {result.returncode}): {result.stderr[-600:]}")
    try:
        report = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        pytest.fail("gitleaks did not produce a JSON report")
    if not isinstance(report, list):
        pytest.fail("unexpected gitleaks report shape")
    if result.returncode == 1 and not report:
        pytest.fail("gitleaks reported leaks but the report is empty")
    return report


def _describe(finding: dict[str, Any], prefix: str = "") -> str:
    file_name = str(finding.get("File", "?")).removeprefix(prefix)
    commit = str(finding.get("Commit", ""))[:10]
    where = f"{file_name}:{finding.get('StartLine', '?')}"
    return f"{where} rule={finding.get('RuleID', '?')}" + (f" commit={commit}" if commit else "")


def _stage(destination: Path) -> int:
    staged = 0
    for relative in committable_files():
        parts = Path(relative).parts
        if (
            relative.startswith("var/")
            or any(part in SKIP_DIR_NAMES for part in parts)
            or is_secret_name(Path(relative).name)
        ):
            continue
        source = REPO_ROOT / relative
        if source.is_symlink() or not source.is_file():
            continue
        if source.stat().st_size > MAX_STAGED_FILE_BYTES:
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        staged += 1
    return staged


def test_no_secrets_in_committable_working_tree(tmp_path: Path) -> None:
    staging = tmp_path / "stage"
    staging.mkdir()
    staged = _stage(staging)
    assert staged > 0, "nothing staged: git file listing is empty"
    assert not (staging / ".env").exists() and not (staging / "var").exists()
    args = [
        *_hardened_docker_run("tree"),
        "-v",
        f"{staging}:/scan:ro",
        GITLEAKS_IMAGE,
        "dir",
        "/scan",
        *_GITLEAKS_FLAGS,
    ]
    findings = _run_gitleaks(args)
    assert not findings, (
        "gitleaks found secret-shaped strings in committable files (values redacted):\n"
        + format_findings(_describe(f, "/scan/") for f in findings)
    )


def test_no_secrets_in_git_history() -> None:
    git_dir = REPO_ROOT / ".git"
    if not git_dir.is_dir():
        pytest.skip(".git is not a directory (worktree or submodule)")
    args = [
        *_hardened_docker_run("history"),
        "-e",
        "GIT_CONFIG_COUNT=1",
        "-e",
        "GIT_CONFIG_KEY_0=safe.directory",
        "-e",
        "GIT_CONFIG_VALUE_0=*",
        "-v",
        f"{git_dir}:/src/.git:ro",
        GITLEAKS_IMAGE,
        "git",
        "/src",
        *_GITLEAKS_FLAGS,
    ]
    findings = _run_gitleaks(args)
    assert not findings, (
        "gitleaks found secret-shaped strings in git history (values redacted):\n"
        + format_findings(_describe(f) for f in findings)
    )


def test_scanner_self_check_detects_and_redacts_synthetic_token(tmp_path: Path) -> None:
    """Positive control: the pinned image + config + flags really detect secrets.

    The token is SYNTHETIC: generated at runtime from random hex so no
    credential-shaped literal ever exists in the repository, and it is written
    only to a temporary directory outside the work tree.
    """
    synthetic = "ghp_" + (uuid.uuid4().hex + uuid.uuid4().hex)[:36]
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    (probe_dir / "settings.py").write_text(f'GITHUB_TOKEN = "{synthetic}"\n', encoding="utf-8")
    args = [
        *_hardened_docker_run("selfcheck"),
        "-v",
        f"{probe_dir}:/scan:ro",
        GITLEAKS_IMAGE,
        "dir",
        "/scan",
        *_GITLEAKS_FLAGS,
    ]
    result = _invoke(args)
    assert result.returncode == 1, "the synthetic token was not detected (scanner misconfigured)"
    report = json.loads(result.stdout)
    assert any(f.get("RuleID") == "github-pat" for f in report), [f.get("RuleID") for f in report]
    assert synthetic not in result.stdout and synthetic not in result.stderr, (
        "gitleaks output contained the unredacted value"
    )

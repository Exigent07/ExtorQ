"""Repository hygiene: secrets and runtime state can never be committed.

Checks (no running stack required; needs ``git``):

* ``.env`` (and variants) and ``var/`` are ignored by git; ``.env.example`` is not.
* No secret-named file (keys, tokens, kubeconfigs, ``.env``) and nothing under
  ``var/`` is tracked or would be picked up by ``git add -A``.
* ``.env.example`` holds placeholders only (it is a committed template).
* Every Docker build context that exists has a ``.dockerignore`` that keeps
  ``.env`` and ``var/`` out of images.

These tests never open ``.env`` or anything under ``var/``; they only ask git
about path names.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import pytest
from security_helpers import (
    REPO_ROOT,
    SECRET_FILE_GLOBS,
    committable_files,
    format_findings,
    git_available,
    read_text,
    run,
)

pytestmark = pytest.mark.skipif(not git_available(), reason="git work tree not available")

#: Synthetic paths (they need not exist): git must report each as ignored.
MUST_BE_IGNORED = (
    ".env",
    ".env.local",
    ".env.production",
    "var/",
    "var/secrets/producers.json",
    "var/secrets/tokens/example.token",
    "var/secrets/clickhouse/extorq_admin_password",
    "var/tls/ca.key",
    "var/tls/gateway.pem",
    "var/spool/spool.db",
)

MUST_NOT_BE_IGNORED = (".env.example",)


def _is_ignored(path: str) -> bool:
    # --no-index: answer from ignore rules even if the path were tracked.
    result = run(["git", "check-ignore", "-q", "--no-index", path], check=False)
    return result.returncode == 0


@pytest.mark.parametrize("path", MUST_BE_IGNORED)
def test_secret_and_runtime_paths_are_gitignored(path: str) -> None:
    assert _is_ignored(path), f"{path} must be ignored by .gitignore"


@pytest.mark.parametrize("path", MUST_NOT_BE_IGNORED)
def test_env_template_is_committable(path: str) -> None:
    assert not _is_ignored(path), f"{path} is the committed template and must not be ignored"


def _secret_named(path: str) -> bool:
    name = Path(path).name
    if name == ".env.example":
        return False
    return any(fnmatch.fnmatch(name, pattern) for pattern in SECRET_FILE_GLOBS)


def test_no_secret_named_or_runtime_files_are_committable() -> None:
    """Covers tracked files *and* untracked files not covered by .gitignore."""
    offenders = [
        p
        for p in committable_files()
        if p.startswith("var/") or _secret_named(p) or p.endswith((".qcow2", ".sqlite", ".db"))
    ]
    assert not offenders, (
        "secret-named or runtime files are tracked or committable "
        "(move them under var/ or extend .gitignore):\n" + format_findings(offenders)
    )


_PLACEHOLDER = re.compile(r"^(|replace-with-[a-z0-9-]+|changeme-placeholder|<[^>]+>)$")
_ASSIGNMENT = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_SENSITIVE_NAME = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)


def test_env_example_contains_placeholders_only() -> None:
    template = REPO_ROOT / ".env.example"
    if not template.exists():
        pytest.skip(".env.example not present")
    problems: list[str] = []
    for number, line in enumerate(read_text(template).splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        match = _ASSIGNMENT.match(line)
        if not match:
            problems.append(f".env.example:{number}: not a NAME=value line")
            continue
        name, value = match.group(1), match.group(2).strip("'\"")
        if _SENSITIVE_NAME.search(name) and not _PLACEHOLDER.match(value):
            # Never echo the value itself.
            problems.append(f".env.example:{number}: {name} is not an obvious placeholder")
    assert not problems, format_findings(problems)


def _compose_build_contexts() -> list[Path]:
    compose = REPO_ROOT / "compose.yaml"
    if not compose.exists():
        return []
    import yaml

    data = yaml.safe_load(read_text(compose)) or {}
    contexts: set[Path] = set()
    for service in (data.get("services") or {}).values():
        build = (service or {}).get("build")
        if isinstance(build, str):
            contexts.add((REPO_ROOT / build).resolve())
        elif isinstance(build, dict):
            contexts.add((REPO_ROOT / str(build.get("context", "."))).resolve())
    return sorted(contexts)


def _dockerignore_patterns(context: Path) -> list[str]:
    ignore_file = context / ".dockerignore"
    if not ignore_file.exists():
        return []
    return [
        line.strip()
        for line in read_text(ignore_file).splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _excludes(patterns: list[str], candidate: str) -> bool:
    """Approximate .dockerignore semantics (last matching rule wins, ``!`` re-includes)."""
    excluded = False
    for raw in patterns:
        negate = raw.startswith("!")
        pattern = raw[1:] if negate else raw
        pattern = pattern.lstrip("/").rstrip("/")
        pattern = pattern.removeprefix("**/")
        if fnmatch.fnmatch(candidate, pattern) or fnmatch.fnmatch(candidate.split("/")[0], pattern):
            excluded = not negate
    return excluded


def _secret_like_paths(context: Path) -> list[str]:
    """Secret-like files that actually exist in a build context (names only, never read)."""
    found: list[str] = []
    for path in context.rglob("*"):
        relative = path.relative_to(context).as_posix()
        if any(part in {"node_modules", ".next", ".git", ".venv"} for part in path.parts):
            continue
        if relative == "var" or (path.is_file() and _secret_named(relative)):
            found.append(relative)
    return sorted(found)


def test_docker_build_contexts_exclude_secrets() -> None:
    """The repo-root context must always exclude .env and var/; other contexts must
    exclude any secret-like file that is actually present in them."""
    contexts = _compose_build_contexts()
    if not contexts:
        pytest.skip("compose.yaml with build contexts not present yet")
    problems: list[str] = []
    for context in contexts:
        patterns = _dockerignore_patterns(context)
        where = context.relative_to(REPO_ROOT).as_posix() or "."
        if context == REPO_ROOT:
            candidates = [".env", ".env.local", "var", "var/secrets/x"]
            if not patterns:
                problems.append(f"{where}: repo-root build context has no .dockerignore")
                continue
        else:
            candidates = _secret_like_paths(context)
        for candidate in candidates:
            if not _excludes(patterns, candidate):
                problems.append(
                    f"{where}: build context would include {candidate} (extend .dockerignore)"
                )
    assert not problems, format_findings(problems)

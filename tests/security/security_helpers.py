"""Shared helpers for the ExtorQ security test suite (owner: agent F).

Design rules for every scanner in this package:

* Read-only. Nothing here writes into the repository.
* Never open secret material. File discovery prunes runtime/secret locations
  (``var/``, ``.env*``, keys, tokens, kubeconfigs) *by name* before any file is
  read, and never follows symlinks (a symlink could point at ``.env``).
* Findings are reported as ``path:line: message`` and never include matched
  secret values.
"""

from __future__ import annotations

import fnmatch
import os
import shutil
import subprocess
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

#: Directory names that are never walked (vendored code, caches, build output, VCS).
SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        ".next",
        "out",
        "dist",
        "build",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".pnpm-store",
        ".turbo",
        "coverage",
        "htmlcov",
    }
)

#: Top-level directories holding runtime state or secrets: never walked.
SKIP_TOP_LEVEL = frozenset({"var"})

#: File names that may hold secret material: never opened by any scanner.
SECRET_FILE_GLOBS = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.token",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "id_dsa*",
    "*kubeconfig*",
    "*.kubeconfig",
)

#: Paths that are lab content (the monitored targets), not ExtorQ itself.
#: Deliberately weak lab material (e.g. a workflow that GH-001 must flag) lives here.
LAB_CONTENT_PREFIXES = ("lab/", "simulations/")


def rel(path: Path) -> str:
    """Repository-relative POSIX path used in findings."""
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


#: Committed templates that match a secret glob by name but hold placeholders only.
NON_SECRET_TEMPLATES = frozenset({".env.example"})


def is_secret_name(name: str) -> bool:
    if name in NON_SECRET_TEMPLATES:
        return False
    return any(fnmatch.fnmatch(name, pattern) for pattern in SECRET_FILE_GLOBS)


def iter_files(
    *,
    suffixes: Iterable[str] | None = None,
    names: Iterable[str] | None = None,
    roots: Iterable[str] | None = None,
    exclude_prefixes: Iterable[str] = (),
) -> Iterator[Path]:
    """Yield regular files below the repository (or the given relative roots).

    ``suffixes`` matches file suffixes (e.g. ``.py``); ``names`` matches exact
    file names or globs (e.g. ``Dockerfile*``). Symlinks are never followed or
    yielded, and secret-named files are never yielded.
    """
    wanted_suffixes = tuple(suffixes or ())
    wanted_names = tuple(names or ())
    excluded = tuple(exclude_prefixes)
    start_dirs = [REPO_ROOT / r for r in roots] if roots else [REPO_ROOT]
    for start in start_dirs:
        if not start.is_dir() or start.is_symlink():
            continue
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            current = Path(dirpath)
            relative_dir = current.relative_to(REPO_ROOT).as_posix()
            dirnames[:] = [
                d
                for d in dirnames
                if d not in SKIP_DIR_NAMES
                and not (current == REPO_ROOT and d in SKIP_TOP_LEVEL)
                and not (current / d).is_symlink()
            ]
            for filename in filenames:
                path = current / filename
                if path.is_symlink() or is_secret_name(filename):
                    continue
                relative = filename if relative_dir == "." else f"{relative_dir}/{filename}"
                if excluded and relative.startswith(excluded):
                    continue
                matches_suffix = bool(wanted_suffixes) and filename.endswith(wanted_suffixes)
                matches_name = bool(wanted_names) and any(
                    fnmatch.fnmatch(filename, n) for n in wanted_names
                )
                if (not wanted_suffixes and not wanted_names) or matches_suffix or matches_name:
                    yield path


def read_text(path: Path) -> str:
    """Read a text file that discovery already vetted (never a secret-named file)."""
    if is_secret_name(path.name) or path.is_symlink():
        raise PermissionError(f"refusing to read secret-named or symlinked file {rel(path)}")
    return path.read_text(encoding="utf-8", errors="replace")


def load_yaml_documents(path: Path) -> list[Any]:
    """All YAML documents of a file (safe loader), skipping empty documents."""
    docs = [doc for doc in yaml.safe_load_all(read_text(path)) if doc is not None]
    expanded: list[Any] = []
    for doc in docs:
        if (
            isinstance(doc, dict)
            and doc.get("kind") == "List"
            and isinstance(doc.get("items"), list)
        ):
            expanded.extend(item for item in doc["items"] if item is not None)
        else:
            expanded.append(doc)
    return expanded


# ── git helpers ──────────────────────────────────────────────────────────────


def git_available() -> bool:
    if shutil.which("git") is None:
        return False
    result = run(["git", "rev-parse", "--is-inside-work-tree"], check=False)
    return result.returncode == 0 and result.stdout.strip() == "true"


def run(
    args: list[str], *, check: bool = True, timeout: float = 60.0
) -> subprocess.CompletedProcess[str]:
    """Run a fixed argument list (never a shell) from the repository root."""
    return subprocess.run(
        args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def committable_files() -> list[str]:
    """Tracked files plus untracked files that ``git add -A`` would pick up.

    These are exactly the files that can reach the remote repository, which is
    the set the secret scan must cover.
    """
    result = run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
    return sorted({p for p in result.stdout.split("\0") if p})


# ── docker helpers ───────────────────────────────────────────────────────────


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and bool(result.stdout.strip())


def format_findings(findings: Iterable[str]) -> str:
    items = sorted(set(findings))
    return "\n".join(f"  - {item}" for item in items)

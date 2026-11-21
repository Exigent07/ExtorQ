"""GitHub token resolution for the collector.

Precedence (first match wins):

1. ``EXTORQ_GITHUB_TOKEN_FILE`` (or the config ``token_file`` path): a file holding a
   fine-grained, read-only personal access token. This is the recommended setup.
2. ``EXTORQ_GITHUB_TOKEN`` environment variable.
3. ``gh auth token`` (GitHub CLI), only when the collector config sets
   ``allow_gh_cli_token: true``. The CLI token is an OAuth token whose scopes
   (typically ``repo``, ``workflow``, ``read:org``, ``gist``) are far broader than
   the read-only access the collector needs, so its use is reported as a health warning.

The token value is never logged, printed, returned in errors or shown by ``repr()``.
Only non-secret metadata (source, token kind derived from the documented prefix) is
exposed.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

TOKEN_FILE_ENV = "EXTORQ_GITHUB_TOKEN_FILE"  # noqa: S105 - variable name, not a secret
TOKEN_ENV = "EXTORQ_GITHUB_TOKEN"  # noqa: S105 - variable name, not a secret
MAX_TOKEN_FILE_BYTES = 4096
GH_CLI_TIMEOUT_SECONDS = 10.0

TokenSource = Literal["file", "env", "gh_cli"]

# Phrased without "<word>_token=<value>" so secret redaction never mangles it in health.
GH_CLI_WARNING = (
    "using the GitHub CLI token (gh CLI fallback enabled in the collector settings): it "
    "carries broad OAuth scopes (typically repo, workflow) far beyond the read-only access "
    "needed; configure a fine-grained read-only token via EXTORQ_GITHUB_TOKEN_FILE"
)

_PREFIX_KINDS = (
    ("github_pat_", "fine_grained_pat"),
    ("ghp_", "classic_pat"),
    ("gho_", "oauth"),
    ("ghu_", "user_to_server"),
    ("ghs_", "app_installation"),
)


class TokenUnavailable(RuntimeError):
    """No usable token. The message names settings, never values."""


@dataclass(frozen=True)
class GitHubToken:
    value: str = field(repr=False)
    source: TokenSource
    kind: str
    warnings: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return f"GitHubToken(source={self.source!r}, kind={self.kind!r})"

    __str__ = __repr__


def token_kind(value: str) -> str:
    for prefix, kind in _PREFIX_KINDS:
        if value.startswith(prefix):
            return kind
    return "unknown"


def _validate(value: str, origin: str) -> str:
    value = value.strip()
    if not value:
        raise TokenUnavailable(f"{origin} is empty")
    if len(value) < 20 or len(value) > 512:
        raise TokenUnavailable(f"{origin} does not look like a GitHub token (unexpected length)")
    if not all("\x21" <= ch <= "\x7e" for ch in value):
        raise TokenUnavailable(f"{origin} contains whitespace or non-printable characters")
    return value


def read_token_file(path: Path) -> tuple[str, tuple[str, ...]]:
    """Read a token file; returns (token, warnings). Errors never include content."""
    warnings: list[str] = []
    try:
        info = path.stat()
    except FileNotFoundError:
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} points to a missing file") from None
    except OSError as exc:
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} is not readable ({type(exc).__name__})") from None
    if not stat.S_ISREG(info.st_mode):
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} is not a regular file")
    if info.st_size > MAX_TOKEN_FILE_BYTES:
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} is larger than {MAX_TOKEN_FILE_BYTES} bytes")
    if info.st_mode & 0o077:
        warnings.append(
            f"token file is accessible by group/other (mode {oct(info.st_mode & 0o777)}); use 0600"
        )
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise TokenUnavailable(
            f"{TOKEN_FILE_ENV} could not be read ({type(exc).__name__})"
        ) from None
    return _validate(content, TOKEN_FILE_ENV), tuple(warnings)


def gh_cli_token(hostname: str = "github.com", *, timeout: float = GH_CLI_TIMEOUT_SECONDS) -> str:
    """Return ``gh auth token`` output for ``hostname`` (argument list, no shell)."""
    if not hostname or any(
        ch not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for ch in hostname.lower()
    ):
        raise TokenUnavailable("invalid GitHub hostname for gh CLI fallback")
    gh = shutil.which("gh")
    if gh is None:
        raise TokenUnavailable("allow_gh_cli_token is true but the gh CLI is not installed")
    env = {
        k: v
        for k, v in os.environ.items()
        if k in ("HOME", "PATH", "USER", "LANG", "XDG_CONFIG_HOME", "GH_CONFIG_DIR")
    }
    try:
        completed = subprocess.run(
            [gh, "auth", "token", "--hostname", hostname],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise TokenUnavailable(f"gh auth token failed ({type(exc).__name__})") from None
    if completed.returncode != 0:
        # stderr may mention the account; it never contains the token. Keep it out anyway.
        raise TokenUnavailable(
            f"gh auth token exited with status {completed.returncode} (not logged in?)"
        )
    return _validate(completed.stdout, "gh auth token output")


def resolve_token(
    *,
    config_token_file: str | None = None,
    allow_gh_cli: bool = False,
    environ: Mapping[str, str] | None = None,
    gh_hostname: str = "github.com",
    gh_runner: Callable[[str], str] | None = None,
) -> GitHubToken:
    """Resolve the collector token following the documented precedence."""
    env = os.environ if environ is None else environ
    file_path = env.get(TOKEN_FILE_ENV) or config_token_file
    if file_path:
        value, warnings = read_token_file(Path(file_path).expanduser())
        return GitHubToken(value, "file", token_kind(value), warnings + _kind_warnings(value))
    env_value = env.get(TOKEN_ENV)
    if env_value:
        value = _validate(env_value, TOKEN_ENV)
        return GitHubToken(value, "env", token_kind(value), _kind_warnings(value))
    if allow_gh_cli:
        runner = gh_runner or gh_cli_token
        value = runner(gh_hostname)
        return GitHubToken(value, "gh_cli", token_kind(value), (GH_CLI_WARNING,))
    raise TokenUnavailable(
        f"no GitHub token configured: set {TOKEN_FILE_ENV} (recommended, fine-grained read-only "
        f"token) or {TOKEN_ENV}, or enable allow_gh_cli_token in config/collectors/github.yaml"
    )


def _kind_warnings(value: str) -> tuple[str, ...]:
    kind = token_kind(value)
    if kind in ("classic_pat", "oauth"):
        return (f"{kind} tokens carry coarse OAuth scopes; prefer a fine-grained read-only token",)
    return ()


def scope_warnings(scopes: tuple[str, ...] | None) -> tuple[str, ...]:
    """Warn about write-capable OAuth scopes reported by ``X-OAuth-Scopes`` (names only)."""
    if not scopes:
        return ()
    risky = sorted(
        s
        for s in scopes
        if s
        in (
            "repo",
            "workflow",
            "delete_repo",
            "write:packages",
            "write:org",
            "admin:org",
            "admin:repo_hook",
        )
        or s.startswith("admin:")
    )
    if not risky:
        return ()
    return (
        f"token has write-capable OAuth scopes: {', '.join(risky)} "
        "(collector needs read-only access)",
    )

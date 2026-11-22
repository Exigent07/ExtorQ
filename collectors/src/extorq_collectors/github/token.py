"""Load a dedicated GitHub fine-grained personal access token from a private file."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

TOKEN_FILE_ENV = "EXTORQ_GITHUB_TOKEN_FILE"  # noqa: S105 - setting name, not a secret
MAX_TOKEN_FILE_BYTES = 4096


class TokenUnavailable(RuntimeError):
    """No usable token. The message names settings, never values."""


@dataclass(frozen=True)
class GitHubToken:
    value: str = field(repr=False)
    source: str = field(default="file", init=False)
    #: ``fine_grained_pat`` (the supported credential) or ``broad_token`` (operator opt-in).
    kind: str = field(default="fine_grained_pat")


#: Prefixes of GitHub's broad (OAuth app / classic) tokens, e.g. what ``gh auth token`` returns.
_BROAD_PREFIXES = ("gho_", "ghp_")


def _validate(content: str, *, allow_broad: bool = False) -> str:
    value = content.strip()
    if not value:
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} is empty")
    if len(value) < 20 or len(value) > 512:
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} has an unexpected token length")
    if not all("\x21" <= ch <= "\x7e" for ch in value):
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} contains whitespace or non-printable characters")
    if value.startswith("github_pat_"):
        return value
    if allow_broad and value.startswith(_BROAD_PREFIXES):
        return value
    raise TokenUnavailable(f"{TOKEN_FILE_ENV} requires a dedicated fine-grained GitHub PAT")


def read_token_file(path: Path, *, allow_broad: bool = False) -> str:
    """Open without following symlinks and validate the same descriptor before reading it."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise TokenUnavailable(f"{TOKEN_FILE_ENV} points to a missing file") from None
    except OSError as exc:
        raise TokenUnavailable(
            f"{TOKEN_FILE_ENV} cannot be opened ({type(exc).__name__})"
        ) from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise TokenUnavailable(f"{TOKEN_FILE_ENV} is not a regular file")
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}:
            raise TokenUnavailable(
                f"{TOKEN_FILE_ENV} must be owned by the collector with mode 0600 or 0400"
            )
        if info.st_size > MAX_TOKEN_FILE_BYTES:
            raise TokenUnavailable(f"{TOKEN_FILE_ENV} is larger than {MAX_TOKEN_FILE_BYTES} bytes")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            content = handle.read(MAX_TOKEN_FILE_BYTES + 1)
        if len(content) > MAX_TOKEN_FILE_BYTES:
            raise TokenUnavailable(f"{TOKEN_FILE_ENV} is larger than {MAX_TOKEN_FILE_BYTES} bytes")
        return _validate(content.decode("utf-8"), allow_broad=allow_broad)
    except (OSError, UnicodeDecodeError) as exc:
        raise TokenUnavailable(
            f"{TOKEN_FILE_ENV} could not be read ({type(exc).__name__})"
        ) from None
    finally:
        os.close(fd)


def resolve_token(
    *,
    config_token_file: str | None = None,
    environ: Mapping[str, str] | None = None,
    allow_broad_token: bool = False,
) -> GitHubToken:
    env = os.environ if environ is None else environ
    file_path = env.get(TOKEN_FILE_ENV) or config_token_file
    if not file_path:
        raise TokenUnavailable(
            f"no dedicated GitHub token file configured: set {TOKEN_FILE_ENV} "
            "or settings.token_file"
        )
    value = read_token_file(Path(file_path).expanduser(), allow_broad=allow_broad_token)
    kind = "fine_grained_pat" if value.startswith("github_pat_") else "broad_token"
    return GitHubToken(value, kind=kind)

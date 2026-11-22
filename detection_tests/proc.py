"""Subprocess helper: argument lists only, timeouts always, output sanitised for reports.

Every external command of the suite (ssh, kubectl, git, gh, sudo, codesign, ...) goes
through :func:`run`. The rules it enforces:

* ``argv`` is a list of strings without NUL characters and is never passed to a shell;
  values that reach a remote shell are validated by the caller first (artefact names).
* Every call has a timeout; a timeout raises :class:`CommandError` instead of hanging.
* Output that is shown in the console or stored in a report goes through
  :func:`display`, which redacts credentials (``extorq.common.redaction``) and strips
  control characters, so a hostile string from a remote system cannot inject terminal
  escapes or leak a token into the report.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from extorq.common.redaction import redact_text, sanitize_untrusted

#: Output kept per stream (the suite never needs more; bounded memory on noisy commands).
MAX_OUTPUT_CHARS = 256 * 1024


class CommandError(RuntimeError):
    """A command failed to start, timed out or returned an unexpected status."""


@dataclass(frozen=True)
class ProcResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def display(text: str, limit: int = 300) -> str:
    """Redacted, single-line, bounded rendering of command output or untrusted text."""
    redacted, _count = redact_text(text or "")
    return sanitize_untrusted(redacted, limit)


def which(name: str) -> str | None:
    """Absolute path of an executable on PATH (``None`` when missing)."""
    return shutil.which(name)


def run(
    argv: Sequence[str],
    *,
    timeout: float,
    input_text: str | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    capture_stdout: bool = True,
    check: bool = False,
    what: str | None = None,
) -> ProcResult:
    """Run ``argv`` (no shell) and return its exit status and decoded output.

    ``capture_stdout=False`` discards stdout at the OS level (used when the output could
    contain data the suite has no reason to hold, e.g. a list of Kubernetes secrets).
    ``what`` names the command in errors; by default the program name is used, never the
    full argument list (arguments may carry paths or identities not meant for reports).
    """
    args = list(argv)
    if not args or not all(isinstance(a, str) and "\x00" not in a for a in args):
        raise CommandError("invalid argument list")
    label = what or Path(args[0]).name
    merged_env = None
    if env is not None:
        merged_env = {**os.environ, **env}
    try:
        completed = subprocess.run(
            args,
            input=input_text,
            stdout=subprocess.PIPE if capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=cwd,
            env=merged_env,
            check=False,
        )
    except FileNotFoundError:
        raise CommandError(f"{label}: command not found") from None
    except subprocess.TimeoutExpired:
        raise CommandError(f"{label}: timed out after {timeout:.0f}s") from None
    result = ProcResult(
        completed.returncode,
        (completed.stdout or "")[:MAX_OUTPUT_CHARS],
        (completed.stderr or "")[:MAX_OUTPUT_CHARS],
    )
    if check and not result.ok:
        raise CommandError(
            f"{label}: exit {result.returncode}: {display(result.stderr or result.stdout)}"
        )
    return result

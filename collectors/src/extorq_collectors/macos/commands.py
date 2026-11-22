"""Safe execution of fixed, read-only macOS system commands.

Every command the macOS collector runs goes through :func:`run_command`:

* the executable is an absolute path from :data:`ALLOWED_EXECUTABLES` (no PATH
  lookup, so a planted binary earlier in ``PATH`` is never executed; note that
  ``log`` is also a zsh builtin, which is irrelevant here because no shell runs);
* arguments are an explicit list (never ``shell=True``) and are validated
  (strings, no NUL bytes, bounded length and count);
* executables that *can* change system state are restricted to their read-only
  sub-commands by :func:`check_read_only_policy` (for example ``launchctl`` may
  only ``print``/``print-disabled``: never ``load``, ``bootstrap``, ``enable``,
  ``kickstart`` ...; ``defaults`` may only ``read``/``export``; ``sysctl`` may
  only read named keys; ``codesign`` may only ``--verify``/``-dv`` one application
  bundle in an application folder, never sign or strip anything);
* the child gets a minimal fixed environment, ``stdin`` is ``/dev/null``, the
  working directory is ``/`` and it runs in its own session so the whole process
  group can be killed;
* a hard wall-clock timeout and byte limits on stdout/stderr bound memory use.
  Exceeding the stdout limit stops the command and marks the result truncated.

Nothing here needs or requests elevated privileges.
"""

from __future__ import annotations

import contextlib
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from extorq.common.redaction import redact_text, sanitize_untrusted

#: The only executables the collector may run (all ship with macOS, all read-only use).
ALLOWED_EXECUTABLES: frozenset[str] = frozenset(
    {
        "/usr/bin/log",
        "/usr/bin/fdesetup",
        "/usr/bin/csrutil",
        "/usr/libexec/ApplicationFirewall/socketfilterfw",
        "/usr/sbin/spctl",
        "/usr/bin/defaults",
        "/usr/bin/dscl",
        "/usr/bin/sw_vers",
        "/usr/sbin/sysctl",
        "/usr/sbin/netstat",
        "/usr/sbin/lsof",
        "/bin/ps",
        "/usr/sbin/system_profiler",
        "/bin/launchctl",
        "/usr/bin/codesign",
    }
)

_SOCKETFILTERFW_READS = frozenset(
    {"--getglobalstate", "--getstealthmode", "--getallowsigned", "--getblockall"}
)
_SYSCTL_READABLE = frozenset({"hw.model", "hw.machine", "kern.osversion", "kern.boottime"})
#: launchctl targets: a domain (system, gui/<uid>, user/<uid>) optionally followed by a label.
_LAUNCHCTL_TARGET = re.compile(
    r"^(?:system|gui/\d{1,10}|user/\d{1,10})(?:/[A-Za-z0-9._-]{1,255})?$"
)
#: codesign targets: an application bundle at the top of, or one folder below, /Applications
#: or a user's ~/Applications (the only places the software source scans).
_APP_BUNDLE = re.compile(
    r"^/(?:Applications|Users/[^/]{1,255}/Applications)/(?:[^/]{1,255}/)?[^/]{1,255}\.app$"
)
_CODESIGN_MODES = (["--verify", "--strict"], ["-dv", "--verbose=2"])


def _is_app_bundle_path(path: str) -> bool:
    return bool(_APP_BUNDLE.match(path)) and not any(
        part in (".", "..") for part in path.split("/")
    )


def check_read_only_policy(argv: Sequence[str]) -> None:
    """Refuse every sub-command that could change state (defence in depth).

    The collector only ever builds the argument lists below; this check makes a
    programming error (or a future change) fail closed instead of running, for
    example, ``launchctl load`` or ``defaults write``.
    """
    exe, args = argv[0], list(argv[1:])
    ok = True
    if exe == "/bin/launchctl":
        ok = (
            len(args) == 2
            and args[0] in ("print", "print-disabled")
            and bool(_LAUNCHCTL_TARGET.match(args[1]))
        )
    elif exe == "/usr/bin/log":
        ok = bool(args) and args[0] == "show"
    elif exe == "/usr/bin/defaults":
        ok = len(args) >= 2 and args[0] in ("read", "export")
    elif exe == "/usr/bin/dscl":
        ok = len(args) >= 3 and args[0] == "." and args[1] in ("-read", "-search", "-list")
    elif exe == "/usr/sbin/sysctl":
        ok = len(args) >= 2 and args[0] == "-n" and all(a in _SYSCTL_READABLE for a in args[1:])
    elif exe == "/usr/bin/fdesetup":
        ok = args == ["status"]
    elif exe == "/usr/bin/csrutil":
        ok = args in (["status"], ["authenticated-root", "status"])
    elif exe == "/usr/libexec/ApplicationFirewall/socketfilterfw":
        ok = len(args) == 1 and args[0] in _SOCKETFILTERFW_READS
    elif exe == "/usr/sbin/spctl":
        ok = args == ["--status"]
    elif exe == "/usr/bin/codesign":
        ok = len(args) == 3 and args[:2] in _CODESIGN_MODES and _is_app_bundle_path(args[2])
    if not ok:
        raise CommandValidationError(
            f"arguments refused by the read-only policy for {os.path.basename(exe)}"
        )


#: Fixed child environment: no inherited secrets, deterministic (non-localised) output.
SAFE_ENV: dict[str, str] = {
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LC_ALL": "C",
    "LANG": "C",
}

MAX_ARGS = 64
MAX_ARG_CHARS = 8192
DEFAULT_MAX_STDOUT = 4 * 1024 * 1024
DEFAULT_MAX_STDERR = 64 * 1024
_READ_CHUNK = 65536
_KILL_WAIT_SECONDS = 5.0


class CommandValidationError(ValueError):
    """Raised for a command line that violates the execution policy."""


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: bytes
    stderr: bytes
    duration_seconds: float
    timed_out: bool = False
    stdout_truncated: bool = False
    #: Spawn failure summary (executable missing, permission denied, ...).
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when the command ran to completion with exit status 0."""
        return (
            self.error is None
            and not self.timed_out
            and not self.stdout_truncated
            and self.returncode == 0
        )

    def text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")

    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")

    def summary(self, limit: int = 300) -> str:
        """Secret-free, bounded one-line description for health/errors."""
        name = os.path.basename(self.argv[0]) if self.argv else "?"
        if self.error:
            state = self.error
        elif self.timed_out:
            state = "timed out"
        elif self.stdout_truncated:
            state = "output limit exceeded"
        else:
            state = f"exit {self.returncode}"
        detail = self.stderr_text().strip() or ("" if self.ok else self.text().strip())
        text = f"{name}: {state}" + (f": {detail}" if detail else "")
        redacted, _ = redact_text(text)
        return sanitize_untrusted(redacted, limit)


class CommandRunner(Protocol):
    """Boundary used by every collector source; unit tests substitute a fake."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_stdout: int = DEFAULT_MAX_STDOUT,
    ) -> CommandResult: ...


def validate_argv(argv: Sequence[str]) -> tuple[str, ...]:
    """Return ``argv`` as a tuple after enforcing the execution policy."""
    if isinstance(argv, str | bytes) or not argv:
        raise CommandValidationError("argv must be a non-empty sequence of strings")
    if len(argv) > MAX_ARGS:
        raise CommandValidationError(f"too many arguments ({len(argv)} > {MAX_ARGS})")
    for arg in argv:
        if not isinstance(arg, str):
            raise CommandValidationError("every argument must be a str")
        if "\x00" in arg:
            raise CommandValidationError("argument contains a NUL byte")
        if len(arg) > MAX_ARG_CHARS:
            raise CommandValidationError("argument too long")
    if argv[0] not in ALLOWED_EXECUTABLES:
        raise CommandValidationError(f"executable not allow-listed: {argv[0]!r}")
    check_read_only_policy(argv)
    return tuple(argv)


def _kill_group(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        with contextlib.suppress(ProcessLookupError):
            proc.kill()


def run_command(
    argv: Sequence[str],
    *,
    timeout: float,
    max_stdout: int = DEFAULT_MAX_STDOUT,
    max_stderr: int = DEFAULT_MAX_STDERR,
) -> CommandResult:
    """Run an allow-listed command with a timeout and bounded output capture."""
    args = validate_argv(argv)
    if timeout <= 0:
        raise CommandValidationError("timeout must be positive")
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(SAFE_ENV),
            cwd="/",
            close_fds=True,
            start_new_session=True,
        )
    except FileNotFoundError:
        return CommandResult(args, None, b"", b"", 0.0, error="executable not found")
    except PermissionError:
        return CommandResult(args, None, b"", b"", 0.0, error="permission denied")
    except OSError as exc:
        return CommandResult(args, None, b"", b"", 0.0, error=f"spawn failed: {exc.strerror}")

    if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE always sets them
        _kill_group(proc)
        return CommandResult(args, None, b"", b"", 0.0, error="pipes unavailable")
    out = bytearray()
    err = bytearray()
    limits = {proc.stdout.fileno(): (out, max_stdout), proc.stderr.fileno(): (err, max_stderr)}
    timed_out = False
    truncated = False
    selector = selectors.DefaultSelector()
    try:
        for stream in (proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        deadline = started + timeout
        while selector.get_map() and not truncated:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _events in selector.select(timeout=min(remaining, 1.0)):
                try:
                    chunk = os.read(key.fd, _READ_CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer, limit = limits[key.fd]
                room = limit - len(buffer)
                if room > 0:
                    buffer += chunk[:room]
                if len(chunk) > room and key.fd == proc.stdout.fileno():
                    truncated = True
                    break
                # stderr beyond its limit is drained and discarded so the child never blocks.
    finally:
        selector.close()
        if timed_out or truncated:
            _kill_group(proc)
        try:
            returncode: int | None = proc.wait(timeout=_KILL_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            try:
                returncode = proc.wait(timeout=_KILL_WAIT_SECONDS)
            except subprocess.TimeoutExpired:
                returncode = None
        proc.stdout.close()
        proc.stderr.close()
    return CommandResult(
        argv=args,
        returncode=returncode,
        stdout=bytes(out),
        stderr=bytes(err),
        duration_seconds=round(time.monotonic() - started, 3),
        timed_out=timed_out,
        stdout_truncated=truncated,
    )


class SubprocessRunner:
    """Production :class:`CommandRunner` backed by :func:`run_command`."""

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout: float,
        max_stdout: int = DEFAULT_MAX_STDOUT,
    ) -> CommandResult:
        return run_command(argv, timeout=timeout, max_stdout=max_stdout)

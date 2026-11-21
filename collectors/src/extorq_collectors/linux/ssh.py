"""Agentless SSH transport to the lab VM's read-only dispatch boundary.

``SSHDispatchClient(target).run(command)`` executes one allow-listed dispatch
command (``version``, ``journal``, ``audit``, ``inventory``, ``packages``,
``posture``) through the system ``ssh`` binary as the restricted
``extorq-collector`` account. The VM enforces the allow-list
(``/usr/local/sbin/extorq-collect-dispatch`` via sshd ``ForceCommand``); this
client validates the same grammar first so a bug here can never send anything
else.

Security properties:

* ``ssh`` runs with an argument list (never a shell) and ``-F /dev/null`` so the
  operator's ``~/.ssh/config`` cannot change behaviour (no ProxyCommand, agent,
  forwarding);
* host keys are pinned: ``StrictHostKeyChecking=yes`` with a dedicated
  ``UserKnownHostsFile``; a mismatch raises :class:`HostKeyVerificationError`
  and is never retried;
* only the configured identity is offered (``IdentitiesOnly``,
  ``IdentityAgent=none``), no password/keyboard-interactive fallback;
* every call has a hard timeout and bounded stdout/stderr (the VM is treated as
  untrusted: a compromised guest cannot exhaust collector memory);
* ``ControlMaster``/``ControlPersist`` reuse one authenticated connection to
  limit reconnect noise on the VM;
* transient failures are retried a bounded number of times with jittered
  exponential backoff.
"""

from __future__ import annotations

import contextlib
import os
import random
import re
import selectors
import stat
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DISPATCH_COMMANDS = ("version", "journal", "audit", "inventory", "packages", "posture")
EXIT_DENIED = 77
EXIT_TEMPFAIL = 75
EXIT_SSH = 255
DEFAULT_MAX_OUTPUT = 32 * 1024 * 1024
MAX_STDERR = 64 * 1024

_HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,63})*"
                      r"|\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9A-Fa-f:]{2,39}\]?)$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_CURSOR_RE = re.compile(
    r"^s=[0-9a-f]{32};i=[0-9a-f]{1,16};b=[0-9a-f]{32};m=[0-9a-f]{1,16};"
    r"t=[0-9a-f]{1,16};x=[0-9a-f]{1,16}$"
)
_UINT_RE = re.compile(r"^(0|[1-9][0-9]{0,18})$")


class SSHDispatchError(Exception):
    """Base class; ``retryable`` tells callers whether a retry can help."""

    retryable = False


class HostKeyVerificationError(SSHDispatchError):
    """The VM presented an unexpected host key (possible MITM). Never retried."""


class SSHAuthenticationError(SSHDispatchError):
    """The collector key was rejected. Never retried."""


class SSHConnectionError(SSHDispatchError):
    """Connection refused/reset/timed out (VM down or booting)."""

    retryable = True


class SSHTimeoutError(SSHDispatchError):
    """The command exceeded its deadline and was killed."""

    retryable = True


class DispatchDenied(SSHDispatchError):
    """The VM-side dispatcher refused the command (exit 77)."""


class DispatchError(SSHDispatchError):
    """The dispatcher accepted the command but failed (exit 70/75)."""

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class OutputTooLargeError(SSHDispatchError):
    """The remote side produced more output than allowed."""


def validate_command(command: str) -> str:
    """Client-side mirror of the dispatcher grammar. Raises ValueError."""
    if not isinstance(command, str) or not command or len(command) > 512:
        raise ValueError("invalid dispatch command")
    tokens = command.split(" ")
    if any(not t or not t.isascii() or not t.isprintable() for t in tokens):
        raise ValueError("invalid dispatch command spacing/characters")
    name, args = tokens[0], tokens[1:]
    if name in ("version", "inventory", "packages", "posture") and not args:
        return command
    if name == "journal" and len(args) == 2:
        if (args[0] == "-" or _CURSOR_RE.match(args[0])) and _UINT_RE.match(args[1]) \
                and 1 <= int(args[1]) <= 5000:
            return command
    if name == "audit" and len(args) == 3:
        inode_ok = args[0] == "-" or (_UINT_RE.match(args[0]) and int(args[0]) >= 1)
        if inode_ok and _UINT_RE.match(args[1]) and _UINT_RE.match(args[2]) \
                and 4096 <= int(args[2]) <= 1048576:
            return command
    raise ValueError(f"dispatch command not allowed: {name!r}")


def _check_private_file(path: Path, what: str) -> None:
    try:
        st = path.stat()
    except FileNotFoundError:
        raise SSHDispatchError(f"{what} not found: {path}") from None
    if not stat.S_ISREG(st.st_mode):
        raise SSHDispatchError(f"{what} is not a regular file: {path}")
    if st.st_mode & 0o077:
        raise SSHDispatchError(f"{what} must not be accessible by group/others (chmod 600): {path}")


@dataclass(frozen=True)
class SSHTarget:
    """Where and how to reach the VM. Paths may be relative to ``base_dir``."""

    host: str = "127.0.0.1"
    port: int = 2222
    user: str = "extorq-collector"
    identity_file: Path = Path("var/vm/keys/extorq-collector")
    known_hosts_file: Path = Path("var/vm/known_hosts")
    connect_timeout_seconds: int = 10
    command_timeout_seconds: float = 120.0
    control_dir: Path | None = Path("var/run/ssh")
    control_persist_seconds: int = 300
    ssh_binary: str = "/usr/bin/ssh"
    max_attempts: int = 3
    backoff_base_seconds: float = 1.0
    backoff_cap_seconds: float = 10.0
    host_key_algorithms: str = "ssh-ed25519"
    extra_env: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _HOST_RE.match(self.host):
            raise ValueError(f"invalid ssh host {self.host!r}")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("invalid ssh port")
        if not _USER_RE.match(self.user):
            raise ValueError(f"invalid ssh user {self.user!r}")
        if not 1 <= self.connect_timeout_seconds <= 120:
            raise ValueError("connect_timeout_seconds must be 1..120")
        if not 1 <= self.command_timeout_seconds <= 900:
            raise ValueError("command_timeout_seconds must be 1..900")
        if not 1 <= self.max_attempts <= 10:
            raise ValueError("max_attempts must be 1..10")
        if not re.fullmatch(r"[a-z0-9@.,-]{3,200}", self.host_key_algorithms):
            raise ValueError("invalid host_key_algorithms")

    @classmethod
    def from_mapping(cls, cfg: Mapping[str, Any], base_dir: Path | None = None) -> SSHTarget:
        """Build from the ``ssh:`` block of config/collectors/linux.yaml."""
        base = base_dir or Path.cwd()

        def resolve(value: Any, default: Path | None) -> Path | None:
            if value is None:
                return None if default is None else (base / default)
            path = Path(str(value)).expanduser()
            return path if path.is_absolute() else base / path

        control = cfg.get("control_dir", "var/run/ssh")
        return cls(
            host=str(cfg.get("host", "127.0.0.1")),
            port=int(cfg.get("port", 2222)),
            user=str(cfg.get("user", "extorq-collector")),
            identity_file=resolve(cfg.get("identity_file"), Path("var/vm/keys/extorq-collector"))
            or Path(),
            known_hosts_file=resolve(cfg.get("known_hosts_file"), Path("var/vm/known_hosts"))
            or Path(),
            connect_timeout_seconds=int(cfg.get("connect_timeout_seconds", 10)),
            command_timeout_seconds=float(cfg.get("command_timeout_seconds", 120)),
            control_dir=None if control in (None, "", False) else resolve(control, None),
            control_persist_seconds=int(cfg.get("control_persist_seconds", 300)),
            ssh_binary=str(cfg.get("ssh_binary", "/usr/bin/ssh")),
            max_attempts=int(cfg.get("max_attempts", 3)),
            backoff_base_seconds=float(cfg.get("backoff_base_seconds", 1.0)),
            backoff_cap_seconds=float(cfg.get("backoff_cap_seconds", 10.0)),
            host_key_algorithms=str(cfg.get("host_key_algorithms", "ssh-ed25519")),
        )


@dataclass
class RunResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_seconds: float


Runner = Callable[[list[str], float, int], RunResult]


def _default_runner(argv: list[str], timeout: float, max_output: int) -> RunResult:
    """Run argv with a deadline and bounded output (no shell, stdin closed)."""
    start = time.monotonic()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, close_fds=True, shell=False,
                            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})
    assert proc.stdout is not None and proc.stderr is not None
    out = bytearray()
    err = bytearray()
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ, out)
    sel.register(proc.stderr, selectors.EVENT_READ, err)
    deadline = start + timeout
    try:
        while sel.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SSHTimeoutError(f"ssh command exceeded {timeout:.0f}s")
            for key, _ in sel.select(timeout=min(remaining, 1.0)):
                chunk = os.read(key.fd, 262144)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                if len(out) > max_output:
                    raise OutputTooLargeError(f"remote output exceeded {max_output} bytes")
                if len(err) > MAX_STDERR:
                    del err[MAX_STDERR:]
        try:
            rc = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise SSHTimeoutError(f"ssh command exceeded {timeout:.0f}s") from None
    finally:
        sel.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    return RunResult(rc, bytes(out), bytes(err), time.monotonic() - start)


def _stderr_summary(stderr: bytes) -> str:
    """First meaningful stderr line, bounded (ssh errors never contain key material)."""
    for line in stderr.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith("Warning: Permanently added"):
            return line[:300]
    return ""


class SSHDispatchClient:
    """Run allow-listed dispatch commands on the VM over SSH."""

    def __init__(self, target: SSHTarget, *, runner: Runner | None = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.target = target
        self._runner = runner or _default_runner
        self._sleep = sleep
        self._checked_files = False

    # ── argv construction ──
    def _control_path(self) -> str | None:
        if self.target.control_dir is None:
            return None
        return str(self.target.control_dir / "%C")

    def base_argv(self) -> list[str]:
        t = self.target
        argv = [
            # No -q: it would hide "Host key verification failed" (LogLevel=ERROR below).
            t.ssh_binary, "-F", "/dev/null", "-T",
            "-i", str(t.identity_file),
            "-p", str(t.port),
            "-l", t.user,
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none",
            "-o", "BatchMode=yes",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "PreferredAuthentications=publickey",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={t.known_hosts_file}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "UpdateHostKeys=no",
            "-o", f"HostKeyAlgorithms={t.host_key_algorithms}",
            "-o", f"ConnectTimeout={t.connect_timeout_seconds}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no",
            "-o", "ClearAllForwardings=yes",
            "-o", "PermitLocalCommand=no",
            "-o", "LogLevel=ERROR",
        ]
        control = self._control_path()
        if control is not None:
            argv += ["-o", "ControlMaster=auto", "-o", f"ControlPath={control}",
                     "-o", f"ControlPersist={t.control_persist_seconds}"]
        else:
            argv += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
        return argv

    def build_argv(self, command: str) -> list[str]:
        return [*self.base_argv(), "--", self.target.host, validate_command(command)]

    # ── execution ──
    def _prepare(self) -> None:
        if self._checked_files:
            return
        _check_private_file(self.target.identity_file, "SSH identity file")
        if not self.target.known_hosts_file.is_file():
            raise SSHDispatchError(f"known_hosts file not found: {self.target.known_hosts_file}")
        if self.target.control_dir is not None:
            self.target.control_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(self.target.control_dir, 0o700)
        self._checked_files = True

    @staticmethod
    def _classify(result: RunResult) -> SSHDispatchError | None:
        if result.returncode == 0:
            return None
        summary = _stderr_summary(result.stderr)
        lowered = summary.lower()
        if result.returncode == EXIT_DENIED:
            return DispatchDenied(f"dispatcher denied the command ({summary or 'denied'})")
        if result.returncode == EXIT_SSH:
            if "host key verification failed" in lowered or "remote host identification" in lowered:
                return HostKeyVerificationError("VM host key does not match known_hosts")
            if "permission denied" in lowered or "too many authentication failures" in lowered:
                return SSHAuthenticationError("collector key rejected by the VM")
            return SSHConnectionError(f"ssh connection failed: {summary or 'exit 255'}")
        return DispatchError(f"dispatcher failed (exit {result.returncode}): {summary}",
                             retryable=result.returncode == EXIT_TEMPFAIL)

    def run_bytes(self, command: str, *, timeout: float | None = None,
                  max_output: int = DEFAULT_MAX_OUTPUT) -> bytes:
        argv = self.build_argv(command)
        self._prepare()
        deadline = timeout or self.target.command_timeout_seconds
        last: SSHDispatchError | None = None
        for attempt in range(1, self.target.max_attempts + 1):
            try:
                result = self._runner(argv, deadline, max_output)
                error = self._classify(result)
            except SSHDispatchError as exc:
                error = exc
            except OSError as exc:
                raise SSHDispatchError(f"cannot execute ssh: {exc.strerror}") from None
            if error is None:
                return result.stdout
            last = error
            if not error.retryable or attempt == self.target.max_attempts:
                break
            delay = min(self.target.backoff_cap_seconds,
                        self.target.backoff_base_seconds * (2 ** (attempt - 1)))
            self._sleep(delay * (0.5 + random.random() / 2))  # noqa: S311 - jitter only
        assert last is not None
        raise last

    def run(self, command: str, *, timeout: float | None = None,
            max_output: int = DEFAULT_MAX_OUTPUT) -> str:
        return self.run_bytes(command, timeout=timeout, max_output=max_output).decode(
            "utf-8", "replace")

    def close(self) -> None:
        """Stop the ControlMaster connection (best effort)."""
        if self._control_path() is None:
            return
        argv = [*self.base_argv(), "-O", "exit", "--", self.target.host]
        with contextlib.suppress(SSHDispatchError, OSError):
            self._runner(argv, 10.0, 65536)

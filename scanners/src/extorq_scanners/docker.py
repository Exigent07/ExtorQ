"""Hardened, bounded execution of pinned scanner images.

Every container runs with: ``--rm``, ``--pull never`` (scans never touch a
registry), ``--network none`` unless explicitly requested (only for database
updates that mount no scan target), ``--read-only`` root filesystem with a small
``noexec`` tmpfs, ``--cap-drop ALL``, ``no-new-privileges``, pids/memory/CPU
limits, the invoking non-root uid:gid and read-only bind mounts created with
``--mount`` (which, unlike ``-v``, never creates missing host paths).

Output is read concurrently with hard byte caps; exceeding a cap or the timeout
kills the container *by name* (killing the ``docker run`` client alone does not
stop the container) and is reported so the scan can never be ``succeeded``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from extorq.common.redaction import sanitize_untrusted

from extorq_scanners.status import ProcessOutcome

_CONTAINER_PATH = re.compile(r"^/[A-Za-z0-9_./-]{1,255}$")
_ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
#: docker run's own failure codes (daemon error / cannot invoke / not found).
_DOCKER_START_CODES = {125, 126, 127}


class DockerError(RuntimeError):
    """The container could not be prepared or started."""


@dataclass(frozen=True)
class Mount:
    source: Path
    target: str
    read_only: bool = True


@dataclass(frozen=True)
class ContainerSpec:
    image: str
    args: list[str]
    mounts: list[Mount] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    network: str = "none"
    workdir: str = "/tmp"
    platform: str | None = None
    purpose: str = "scan"


@dataclass
class ContainerResult:
    outcome: ProcessOutcome
    stdout: bytes
    stderr: str


class _CappedReader(threading.Thread):
    def __init__(self, stream: IO[bytes], cap: int, on_overflow: threading.Event) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.cap = cap
        self.on_overflow = on_overflow
        self.chunks: list[bytes] = []
        self.size = 0

    def run(self) -> None:
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    break
                if self.size + len(chunk) > self.cap:
                    keep = max(0, self.cap - self.size)
                    self.chunks.append(chunk[:keep])
                    self.size += keep
                    self.on_overflow.set()
                    # Keep draining (and discarding) so the process cannot block on a full pipe.
                    continue
                self.chunks.append(chunk)
                self.size += len(chunk)
        except (OSError, ValueError):
            return

    def data(self) -> bytes:
        return b"".join(self.chunks)


class DockerRunner:
    def __init__(
        self,
        *,
        docker_bin: str = "docker",
        name_prefix: str = "extorq-c3-scan",
        memory: str = "2g",
        cpus: str = "4",
        pids_limit: int = 512,
        tmpfs_mb: int = 512,
        allowed_images: Iterable[str] = (),
        allowed_roots: Iterable[Path] = (),
    ) -> None:
        resolved = shutil.which(docker_bin)
        self.docker = resolved or docker_bin
        self.available = resolved is not None
        self.name_prefix = name_prefix
        self.memory = memory
        self.cpus = cpus
        self.pids_limit = pids_limit
        self.tmpfs_mb = tmpfs_mb
        self.allowed_images = frozenset(allowed_images)
        self.allowed_roots = tuple(p.resolve() for p in allowed_roots)

    # ── validation ────────────────────────────────────────────────────
    def _check_spec(self, spec: ContainerSpec) -> None:
        if spec.image not in self.allowed_images:
            raise DockerError(f"image {spec.image!r} is not one of the configured pinned images")
        if spec.network not in {"none", "bridge"}:
            raise DockerError(f"network {spec.network!r} not allowed")
        if not _CONTAINER_PATH.match(spec.workdir):
            raise DockerError("invalid container workdir")
        for mount in spec.mounts:
            src = mount.source
            if not src.is_absolute() or "," in str(src) or "\n" in str(src):
                raise DockerError(f"invalid mount source {src}")
            if src.is_symlink() or not src.exists():
                raise DockerError(f"mount source missing or a symlink: {src.name}")
            real = src.resolve()
            if self.allowed_roots and not any(
                real == root or root in real.parents for root in self.allowed_roots
            ):
                raise DockerError(f"mount source {src.name} is outside the allowed roots")
            if not _CONTAINER_PATH.match(mount.target) or "," in mount.target:
                raise DockerError(f"invalid mount target {mount.target}")
        for key, value in spec.env.items():
            if not _ENV_KEY.match(key) or "\n" in value or "\x00" in value:
                raise DockerError(f"invalid environment variable {key!r}")
        for arg in spec.args:
            if "\x00" in arg:
                raise DockerError("NUL byte in container argument")

    def command(self, spec: ContainerSpec, name: str) -> list[str]:
        self._check_spec(spec)
        cmd = [
            self.docker, "run", "--rm", "--name", name, "--pull", "never",
            "--network", spec.network,
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={self.tmpfs_mb}m",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", str(self.pids_limit),
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--workdir", spec.workdir,
            "--label", "org.extorq.component=scanner-runner",
        ]  # fmt: skip
        if spec.platform:
            cmd += ["--platform", spec.platform]
        for mount in spec.mounts:
            opt = f"type=bind,source={mount.source},target={mount.target}"
            cmd += ["--mount", opt + (",readonly" if mount.read_only else "")]
        for key, value in sorted(spec.env.items()):
            cmd += ["--env", f"{key}={value}"]
        return [*cmd, spec.image, *spec.args]

    # ── execution ─────────────────────────────────────────────────────
    def image_present(self, image: str) -> bool:
        if not self.available:
            return False
        try:
            proc = subprocess.run(
                [self.docker, "image", "inspect", "--format", "{{.Id}}", image],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0

    def _remove(self, name: str) -> None:
        try:
            subprocess.run(
                [self.docker, "rm", "--force", name], capture_output=True, timeout=60, check=False
            )
        except (OSError, subprocess.SubprocessError):
            pass

    def run(
        self,
        spec: ContainerSpec,
        *,
        timeout: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int = 1_000_000,
    ) -> ContainerResult:
        if not self.available:
            return ContainerResult(ProcessOutcome(None, start_error="docker CLI not found"), b"", "")
        name = f"{self.name_prefix}-{spec.purpose}-{uuid.uuid4().hex[:10]}"
        try:
            cmd = self.command(spec, name)
        except DockerError as exc:
            return ContainerResult(ProcessOutcome(None, start_error=str(exc)), b"", "")
        overflow = threading.Event()
        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except OSError as exc:
            return ContainerResult(
                ProcessOutcome(None, start_error=f"cannot execute docker: {type(exc).__name__}"),
                b"",
                "",
            )
        assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - Popen contract
        out_reader = _CappedReader(proc.stdout, max_stdout_bytes, overflow)
        err_reader = _CappedReader(proc.stderr, max_stderr_bytes, threading.Event())
        out_reader.start()
        err_reader.start()
        timed_out = False
        deadline = started + timeout
        try:
            while proc.poll() is None:
                if overflow.is_set():
                    self._remove(name)
                    break
                if time.monotonic() > deadline:
                    timed_out = True
                    self._remove(name)
                    break
                time.sleep(0.1)
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        finally:
            out_reader.join(timeout=10)
            err_reader.join(timeout=10)
            if timed_out or overflow.is_set():
                self._remove(name)
        duration = time.monotonic() - started
        stderr = err_reader.data().decode("utf-8", errors="replace")
        code = proc.returncode
        start_error = None
        if code in _DOCKER_START_CODES and not timed_out and not overflow.is_set():
            first = next((ln for ln in stderr.splitlines() if ln.strip()), f"docker exit {code}")
            start_error = sanitize_untrusted(first, 300)
        outcome = ProcessOutcome(
            exit_code=None if (timed_out or start_error) else code,
            timed_out=timed_out,
            output_truncated=overflow.is_set(),
            start_error=start_error,
            duration_seconds=round(duration, 3),
        )
        return ContainerResult(outcome, out_reader.data(), stderr)

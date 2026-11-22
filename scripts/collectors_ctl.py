#!/usr/bin/env python3
"""Background host collectors (``make collectors-start | collectors-stop | collectors-status``).

Runs ``extorq-collect run`` (every enabled collector in ``config/collectors/``, each in
its own thread) as ONE detached background process:

* ``start``  ``nohup uv run --frozen extorq-collect run [--only ids]`` in a new session
  (no controlling terminal, survives the shell), stdin ``/dev/null``, stdout+stderr
  appended to ``var/log/collectors.log`` (0600), pid in ``var/run/collectors.pid``.
  Refuses to start a second runner, and refuses while another ``extorq-collect run`` is
  active (duplicate collection) unless ``--force``.
* ``stop``   SIGTERM to the runner's process group (the runner finishes the current
  cycle, commits, and exits), SIGKILL after ``--timeout`` seconds. Outboxes and
  checkpoints are SQLite transactions, so even a kill loses nothing already committed.
* ``status`` runner state (pid, uptime) plus ``extorq-collect status`` (outbox depth,
  dead letters, last health per collector). Exit 0 running, 3 not running (LSB).

This is an operator convenience, not a service manager: it never installs launchd jobs or any
other persistence and restarts nothing on its own. Standard library only; prints pids,
paths and states, never tokens or telemetry.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PIDFILE = REPO / "var" / "run" / "collectors.pid"
LOGFILE = REPO / "var" / "log" / "collectors.log"
#: The log is rotated once (to ``collectors.log.1``) at start when larger than this.
LOG_ROTATE_BYTES = 50 * 1024 * 1024
START_GRACE_SECONDS = 5.0
EXIT_NOT_RUNNING = 3


def _command_of(pid: int) -> str | None:
    """Command line of ``pid`` (``None`` when there is no such LIVE process; zombies are dead)."""
    try:
        proc = subprocess.run(
            ["ps", "-o", "stat=", "-o", "command=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    state, _, command = proc.stdout.strip().partition(" ")
    if not state or state.startswith("Z"):
        return None
    return command.strip() or None


def _elapsed_of(pid: int) -> str | None:
    try:
        proc = subprocess.run(
            ["ps", "-o", "etime=", "-p", str(pid)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() or None


def _is_runner(command: str | None) -> bool:
    """True for ``... extorq-collect run ...`` (not ``status`` or ``flush``)."""
    tokens = (command or "").split()
    return any(
        token.endswith("extorq-collect") and tokens[index + 1] == "run"
        for index, token in enumerate(tokens[:-1])
    )


def read_pid() -> int | None:
    try:
        text = PIDFILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return None
    return int(text) if text.isdigit() else None


def running_pid() -> int | None:
    """Pid of OUR runner when it is alive (a recycled pid is never mistaken for it)."""
    pid = read_pid()
    if pid is None:
        return None
    return pid if _is_runner(_command_of(pid)) else None


def other_runners(exclude: int | None) -> list[int]:
    """Other ``extorq-collect run`` processes (foreground runs, other shells)."""
    try:
        proc = subprocess.run(
            ["ps", "-axo", "pid=,pgid=,command="],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    found = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        pid, pgid, command = int(parts[0]), int(parts[1]), parts[2]
        if pid == os.getpid() or (exclude is not None and pgid == exclude):
            continue
        if _is_runner(command) and "collectors_ctl" not in command:
            found.append(pid)
    return found


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        path.chmod(0o700)


def _rotate_log() -> None:
    with contextlib.suppress(FileNotFoundError):
        if LOGFILE.stat().st_size > LOG_ROTATE_BYTES:
            LOGFILE.replace(LOGFILE.with_name(LOGFILE.name + ".1"))


def _tail(path: Path, lines: int = 5) -> list[str]:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            handle.seek(max(0, handle.tell() - 8192))
            return handle.read().decode("utf-8", "replace").splitlines()[-lines:]
    except OSError:
        return []


def start(only: str | None, force: bool) -> int:
    pid = running_pid()
    if pid is not None:
        print(f"collectors already running (pid {pid}); log {LOGFILE.relative_to(REPO)}")
        return 0
    others = other_runners(exclude=None)
    if others and not force:
        print(
            "refusing to start: other `extorq-collect run` process(es) active "
            f"(pid {', '.join(map(str, others))}); stop them or use --force",
            file=sys.stderr,
        )
        return 1
    uv = shutil.which("uv")
    nohup = shutil.which("nohup")
    if uv is None or nohup is None:
        print("error: `uv` and `nohup` must be on PATH", file=sys.stderr)
        return 2
    _private_dir(PIDFILE.parent)
    _private_dir(LOGFILE.parent)
    _rotate_log()
    argv = [nohup, uv, "run", "--frozen", "extorq-collect", "run"]
    if only:
        argv += ["--only", only]
    env = dict(os.environ, EXTORQ_HOME=str(REPO), PYTHONUNBUFFERED="1")
    fd = os.open(LOGFILE, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with contextlib.suppress(OSError):
        os.fchmod(fd, 0o600)
    try:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        os.write(fd, f"--- collectors-start {stamp} only={only or 'all'} ---\n".encode())
        proc = subprocess.Popen(  # argument list, no shell
            argv,
            cwd=REPO,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=fd,
            stderr=subprocess.STDOUT,
            start_new_session=True,  # own process group, no controlling terminal
            close_fds=True,
        )
    finally:
        os.close(fd)
    tmp = PIDFILE.with_name(PIDFILE.name + ".tmp")
    tmp.write_text(f"{proc.pid}\n", encoding="utf-8")
    tmp.replace(PIDFILE)
    deadline = time.monotonic() + START_GRACE_SECONDS
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            PIDFILE.unlink(missing_ok=True)
            print(
                f"collectors exited during start-up (code {proc.returncode}); last log lines:",
                file=sys.stderr,
            )
            for line in _tail(LOGFILE):
                print(f"  {line[:300]}", file=sys.stderr)
            return 1
        time.sleep(0.25)
    print(
        f"collectors started (pid {proc.pid}, only={only or 'all enabled'}); "
        f"log {LOGFILE.relative_to(REPO)}; stop with `make collectors-stop`"
    )
    return 0


def stop(timeout: float) -> int:
    pid = read_pid()
    if pid is None or not _is_runner(_command_of(pid)):
        PIDFILE.unlink(missing_ok=True)
        print("collectors not running (no live runner for the pidfile)")
        return 0
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        PIDFILE.unlink(missing_ok=True)
        print("collectors already stopped")
        return 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _command_of(pid) is None:
            PIDFILE.unlink(missing_ok=True)
            print(f"collectors stopped (pid {pid})")
            return 0
        time.sleep(0.5)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pid, signal.SIGKILL)
    PIDFILE.unlink(missing_ok=True)
    print(f"collectors did not stop within {timeout:.0f} s: killed (pid {pid})")
    return 0


def status() -> int:
    pid = running_pid()
    if pid is None:
        stale = read_pid()
        print(
            "collectors runner: NOT RUNNING"
            + (f" (stale pidfile for pid {stale})" if stale is not None else "")
        )
    else:
        print(f"collectors runner: running (pid {pid}, up {_elapsed_of(pid) or '?'})")
    others = other_runners(exclude=pid)
    if others:
        print(f"other extorq-collect run processes: {', '.join(map(str, others))}")
    print(f"log: {LOGFILE.relative_to(REPO)}", flush=True)
    uv = shutil.which("uv")
    if uv is not None:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                [uv, "run", "--frozen", "extorq-collect", "status"],
                cwd=REPO,
                env=dict(os.environ, EXTORQ_HOME=str(REPO)),
                timeout=120,
                check=False,
            )
    return 0 if pid is not None else EXIT_NOT_RUNNING


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    start_p = sub.add_parser("start", help="start the background runner")
    start_p.add_argument("--only", help="comma-separated collector ids (default: all enabled)")
    start_p.add_argument(
        "--force", action="store_true", help="start even if another runner is active"
    )
    stop_p = sub.add_parser("stop", help="stop the background runner")
    stop_p.add_argument("--timeout", type=float, default=90.0)
    sub.add_parser("status", help="runner state and per-collector local status")
    args = parser.parse_args(argv)
    if args.command == "start":
        return start(args.only, args.force)
    if args.command == "stop":
        return stop(args.timeout)
    return status()


if __name__ == "__main__":
    sys.exit(main())

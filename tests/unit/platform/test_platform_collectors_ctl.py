"""scripts/collectors_ctl.py: background runner start/stop/status with a FAKE ``uv``.

The fake ``uv`` is a tiny Python script that sleeps (its command line still reads
``... uv run --frozen extorq-collect run``), so these tests start and stop real
processes without running any collector.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[3]


def _load() -> Any:
    spec = importlib.util.spec_from_file_location(
        "extorq_collectors_ctl", REPO / "scripts" / "collectors_ctl.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ctl = _load()


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/opt/homebrew/bin/uv run --frozen extorq-collect run", True),
        ("/repo/.venv/bin/python /repo/.venv/bin/extorq-collect run --only a,b", True),
        ("uv run --frozen extorq-collect status", False),
        ("uv run extorq-collect sim-record --scenario VM-001", False),
        ("uv run extorq-collect flush", False),
        ("vim extorq-collect", False),
        ("", False),
        (None, False),
    ],
)
def test_is_runner_matches_only_the_run_command(command: str | None, expected: bool) -> None:
    assert ctl._is_runner(command) is expected


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    fake_uv = tmp_path / "bin" / "uv"
    fake_uv.parent.mkdir()
    fake_uv.write_text(
        f"#!{sys.executable}\nimport signal, sys, time\n"
        "if 'status' in sys.argv: sys.exit(0)\n"  # `extorq-collect status` returns at once
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))\n"
        "time.sleep(60)\n"
    )
    fake_uv.chmod(fake_uv.stat().st_mode | stat.S_IXUSR)
    real_which = shutil.which

    def which(name: str) -> str | None:
        return str(fake_uv) if name == "uv" else real_which(name)

    monkeypatch.setattr(ctl.shutil, "which", which)
    monkeypatch.setattr(ctl, "PIDFILE", tmp_path / "run" / "collectors.pid")
    monkeypatch.setattr(ctl, "LOGFILE", tmp_path / "log" / "collectors.log")
    monkeypatch.setattr(ctl, "REPO", tmp_path)
    monkeypatch.setattr(ctl, "START_GRACE_SECONDS", 0.5)
    monkeypatch.setattr(ctl, "other_runners", lambda exclude: [])
    return tmp_path


def test_start_is_idempotent_and_stop_terminates_the_group(
    sandbox: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert ctl.start(None, force=False) == 0
    pid = ctl.read_pid()
    assert pid is not None and ctl.running_pid() == pid
    assert stat.S_IMODE((sandbox / "log" / "collectors.log").stat().st_mode) == 0o600
    assert stat.S_IMODE((sandbox / "run").stat().st_mode) == 0o700
    assert os.getpgid(pid) == pid  # own session / process group
    assert ctl.start(None, force=False) == 0
    assert "already running" in capsys.readouterr().out
    try:
        assert ctl.stop(timeout=10) == 0
    finally:
        if ctl._command_of(pid) is not None:
            os.killpg(pid, 9)
    deadline = time.monotonic() + 5
    while ctl._command_of(pid) is not None and time.monotonic() < deadline:
        time.sleep(0.1)
    assert ctl._command_of(pid) is None
    assert ctl.read_pid() is None
    assert ctl.stop(timeout=1) == 0  # stopping again is harmless
    assert "not running" in capsys.readouterr().out


def test_stale_pidfile_is_not_mistaken_for_a_runner(sandbox: Path) -> None:
    ctl.PIDFILE.parent.mkdir(parents=True)
    ctl.PIDFILE.write_text(f"{os.getpid()}\n")  # alive, but not a collector runner
    assert ctl.running_pid() is None
    assert ctl.status() == ctl.EXIT_NOT_RUNNING
    assert ctl.stop(timeout=1) == 0  # never signals the unrelated process
    assert not ctl.PIDFILE.exists()


def test_start_refuses_while_another_runner_is_active(
    sandbox: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ctl, "other_runners", lambda exclude: [424242])
    assert ctl.start(None, force=False) == 1
    assert ctl.read_pid() is None

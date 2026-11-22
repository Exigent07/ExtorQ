"""scripts/reset_data.py orchestration with a FAKE ``docker compose`` and collector control.

No docker, no ClickHouse, no real collectors: ``_compose`` and the collectors controller
are replaced by recorders. The repository root is a temporary directory with synthetic
collector and spool state. Exercise backup ordering, partial failure and restoration.
"""

from __future__ import annotations

import importlib.util
import json
import sqlite3
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from extorq.storage.reset import DATA_TABLES
from extorq_collectors.sdk.state import StagedSnapshot, StateStore

REPO = Path(__file__).resolve().parents[3]
LINUX_ID = "linux-ssh-lab-vm-01"


def _load() -> Any:
    spec = importlib.util.spec_from_file_location(
        "extorq_reset_data_orchestration", REPO / "scripts" / "reset_data.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeCtl:
    """Stands in for scripts/collectors_ctl.py (a background runner with --only)."""

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls
        self.pid: int | None = 4242

    def running_pid(self) -> int | None:
        return self.pid

    def other_runners(self, exclude: int | None) -> list[int]:
        return []

    def _command_of(self, pid: int) -> str:
        return f"uv run --frozen extorq-collect run --only {LINUX_ID}"

    def stop(self, timeout: float) -> int:
        self.calls.append("collectors stop")
        self.pid = None
        return 0

    def start(self, only: str | None, force: bool) -> int:
        self.calls.append(f"collectors start only={only}")
        return 0


class FakeCompose:
    """Answers the docker compose invocations reset_data.py makes."""

    def __init__(self, calls: list[str], *, fail_truncate: bool = False) -> None:
        self.calls = calls
        self.fail_truncate = fail_truncate
        self.stopped = False

    def __call__(self, args: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        self.calls.append(" ".join(args))
        out, code = "", 0
        if args[:1] == ["stop"]:
            self.stopped = True
        elif args[:1] == ["start"]:
            self.stopped = False
        elif args[:1] == ["ps"]:
            rows = [
                ("clickhouse", "running", "healthy"),
                ("ingest", "running", "healthy"),
                ("writer", "running", "healthy"),
                ("detector", "running", ""),
                ("api", "running", "healthy"),
                ("ai-worker", "exited", ""),
                ("migrate", "exited", ""),
            ]
            out = "\n".join(
                json.dumps(
                    {
                        "Service": s,
                        "State": "exited" if self.stopped and s != "clickhouse" else st,
                        "Health": h,
                    }
                )
                for s, st, h in rows
            )
        elif args[-2:] == ["data", "counts"]:
            out = json.dumps({"database": "extorq", "tables": dict.fromkeys(DATA_TABLES, 7)})
        elif args[-3:-1] == ["data", "backup"]:
            assert self.stopped
            out = json.dumps(
                {
                    "archive": args[-1],
                    "status": "BACKUP_CREATED",
                    "tables": dict.fromkeys(DATA_TABLES, 7),
                    "migrations": {"0009": "0" * 64},
                    "schema_sha256": "4" * 64,
                }
            )
        elif args[:1] == ["cp"]:
            if args[1].startswith("clickhouse:"):
                with zipfile.ZipFile(args[-1], "w") as archive:
                    archive.writestr("metadata/extorq.sql", "synthetic archive")
            else:
                source = sqlite3.connect(Path(args[-1]) / "spool.db")
                try:
                    source.execute("CREATE TABLE records (payload TEXT)")
                    source.execute("INSERT INTO records VALUES ('synthetic pending event')")
                    source.commit()
                finally:
                    source.close()
        elif args[-3:] == ["data", "reset", "--yes"]:
            if self.fail_truncate:
                return subprocess.CompletedProcess(args, 1, "", "Code: 241. MEMORY_LIMIT")
            out = json.dumps(
                {
                    "before": dict.fromkeys(DATA_TABLES, 7),
                    "after": dict.fromkeys(DATA_TABLES, 0),
                    "truncated": list(DATA_TABLES),
                    "unknown": [],
                    "rows_remaining": {},
                }
            )
        elif args[-3:] == ["spool", "clear", "--yes"]:
            out = json.dumps({"spool": "spool.db", "exists": True, "cleared": {"records": 3}})
        return subprocess.CompletedProcess(args, code, out, "")


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    rd = _load()
    root = tmp_path / "repo"
    (root / "config" / "collectors").mkdir(parents=True)
    (root / "config" / "collectors" / "linux.yaml").write_text(
        f"collector_id: {LINUX_ID}\nproducer_id: {LINUX_ID}\nasset_id: linux:lab-vm-01\n"
        "module: extorq_collectors.linux.collector:LinuxSSHCollector\ninterval_seconds: 30\n",
        encoding="utf-8",
    )
    state = root / "var" / "collectors" / LINUX_ID / "state.db"
    store = StateStore(state)
    store.commit(
        [("event", '{"kind":"event"}')],
        {"journal.cursor": "s=synthetic;i=7"},
        [StagedSnapshot("inventory.units", {"ssh.service": ("{}", "0" * 64)})],
    )
    store.close()
    retired = root / "var" / "collectors" / "simulation-runner"
    retired.mkdir(parents=True)
    (retired / "state.db").write_bytes(b"")
    calls: list[str] = []
    monkeypatch.setattr(rd, "REPO", root)
    monkeypatch.setattr(rd, "_load_ctl", lambda: FakeCtl(calls))
    monkeypatch.setattr(rd.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(rd, "HEALTH_WAIT_SECONDS", 0)
    monkeypatch.setattr(rd.time, "sleep", lambda _s: None)
    backup = tmp_path / "recovery"
    args = ["--sources-paused", "--backup-dir", str(backup)]
    return {
        "rd": rd,
        "calls": calls,
        "state": state,
        "retired": retired,
        "backup": backup,
        "args": args,
    }


def _store_view(path: Path) -> tuple[int, str | None, bool]:
    store = StateStore(path)
    try:
        return (
            store.outbox_depth(),
            store.checkpoint("journal.cursor"),
            store.has_snapshot("inventory.units"),
        )
    finally:
        store.close()


def test_full_reset_runs_every_step_in_order(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    rd, calls = env["rd"], env["calls"]
    rd._compose = FakeCompose(calls)
    assert rd.main(["--yes", *env["args"]]) == 0
    assert calls[:5] == [
        "ps --all --format json",
        "run --rm --no-deps -T migrate data counts",
        "collectors stop",
        "stop ingest writer detector api",
        "ps --all --format json",
    ]
    assert calls[5].startswith("run --rm --no-deps -T migrate data backup extorq-")
    assert calls[6].startswith("cp clickhouse:")
    assert calls[7].startswith("cp writer:")
    assert calls[8].startswith("exec -T clickhouse rm --")
    assert calls[9:] == [
        "run --rm --no-deps -T migrate data reset --yes",
        "run --rm --no-deps -T writer spool clear --yes",
        "start ingest writer detector api",
        "ps --all --format json",  # health wait
        f"collectors start only={LINUX_ID}",
    ]
    assert _store_view(env["state"]) == (0, "s=synthetic;i=7", False)  # cursor kept
    assert not env["retired"].exists()
    assert _store_view(env["backup"] / f"collector-{LINUX_ID}.sqlite3") == (
        1,
        "s=synthetic;i=7",
        True,
    )
    out = capsys.readouterr().out
    assert "RESET DONE" in out and "events" in out


def test_failed_truncation_keeps_writers_stopped(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    rd, calls = env["rd"], env["calls"]
    rd._compose = FakeCompose(calls, fail_truncate=True)
    assert rd.main(["--yes", *env["args"]]) == rd.EXIT_FAILED
    assert not any("spool clear" in c for c in calls)  # nothing else is cleared
    assert not any(call.startswith(("start ", "collectors start")) for call in calls)
    assert (env["backup"] / "manifest.json").is_file()
    assert _store_view(env["state"]) == (1, "s=synthetic;i=7", True)  # state untouched
    assert env["retired"].exists()
    out = capsys.readouterr().out
    assert "RESET INCOMPLETE" in out and "truncate" in out and "Writers remain stopped" in out


def test_backup_only_and_restore_rehearsal(env: dict[str, Any]) -> None:
    rd, calls, backup = env["rd"], env["calls"], env["backup"]
    rd._compose = FakeCompose(calls)
    assert rd.main(["--backup-only", *env["args"]]) == 0
    assert not any("data reset" in call or "spool clear" in call for call in calls)
    assert calls[-1] == f"collectors start only={LINUX_ID}"
    restored = backup.parent / "sqlite-restore"
    assert rd.main(["--verify-backup", str(backup), "--restore-sqlite", str(restored)]) == 0
    assert _store_view(restored / f"collector-{LINUX_ID}.sqlite3") == (
        1,
        "s=synthetic;i=7",
        True,
    )
    with sqlite3.connect(restored / "spool.sqlite3") as spool:
        assert spool.execute("SELECT payload FROM records").fetchall() == [
            ("synthetic pending event",)
        ]
    (backup / "spool.sqlite3").write_bytes(b"corrupted")
    assert rd.main(["--verify-backup", str(backup)]) == rd.EXIT_FAILED


def test_backup_failure_restarts_without_mutation(env: dict[str, Any]) -> None:
    rd, calls = env["rd"], env["calls"]
    fake = FakeCompose(calls)

    def compose(args: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        if args[-3:-1] == ["data", "backup"]:
            return subprocess.CompletedProcess(args, 1, "", "backup unavailable")
        return fake(args, timeout=timeout)

    rd._compose = compose
    assert rd.main(["--yes", *env["args"]]) == rd.EXIT_FAILED
    assert not any("data reset" in call or "spool clear" in call for call in calls)
    assert calls[-1] == f"collectors start only={LINUX_ID}"
    assert _store_view(env["state"]) == (1, "s=synthetic;i=7", True)


def test_reset_requires_backup_destination_and_quiescence(env: dict[str, Any]) -> None:
    rd = env["rd"]
    with pytest.raises(SystemExit, match="2"):
        rd.main(["--yes"])
    assert not env["calls"]


def test_plan_only_changes_nothing(env: dict[str, Any], capsys: pytest.CaptureFixture[str]) -> None:
    rd, calls = env["rd"], env["calls"]
    rd._compose = FakeCompose(calls)
    assert rd.main([]) == rd.EXIT_PLAN_ONLY
    assert calls == ["ps --all --format json", "run --rm --no-deps -T migrate data counts"]
    assert _store_view(env["state"]) == (1, "s=synthetic;i=7", True)
    out = capsys.readouterr().out
    assert "nothing changed" in out and f"collector {LINUX_ID}" in out
    assert "remove retired state: var/collectors/simulation-runner" in out


def test_preflight_refuses_when_clickhouse_is_down(
    env: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    rd, calls = env["rd"], env["calls"]

    def compose(args: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        calls.append(" ".join(args))
        row = json.dumps({"Service": "clickhouse", "State": "exited", "Health": ""})
        return subprocess.CompletedProcess(args, 0, row, "")

    rd._compose = compose
    assert rd.main(["--yes", *env["args"]]) == rd.EXIT_FAILED
    assert calls == ["ps --all --format json"]
    assert "nothing was changed" in capsys.readouterr().out


def test_old_backend_image_is_reported_clearly(env: dict[str, Any]) -> None:
    rd = env["rd"]

    def compose(args: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args, 2, "", "Error: No such command 'data'.")

    rd._compose = compose
    with pytest.raises(rd.StepError, match="rebuild it first"):
        rd.run_admin_command("migrate", ["data", "counts"])

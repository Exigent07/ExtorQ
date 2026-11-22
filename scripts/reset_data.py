#!/usr/bin/env python3
"""Plan or run an authorized clean-slate reset with a local recovery bundle.

Quiesce external producers before running a reset. The script stops managed writers,
exports native ClickHouse and consistent SQLite backups, then resets the stores and
re-baselines collectors. A failure after the first mutation leaves writers stopped.
See docs/recovery.md for isolated acceptance and restoration.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from extorq.storage.recovery import snapshot_sqlite
from extorq.storage.reset import ResetError

REPO = Path(__file__).resolve().parents[1]
COMPOSE = ("docker", "compose", "--profile", "full")
#: Services that write into the spool or ClickHouse; stopped during the reset.
PIPELINE_SERVICES = ("ingest", "writer", "detector", "ai-worker", "api")
#: State directories of retired producers, removed by the reset (schema 2.0 removed the
#: simulation category and its recorder ``extorq-collect sim-record``).
RETIRED_STATE_DIRS = ("simulation-runner",)
#: Files a collector state directory may contain (anything else stops a removal).
STATE_FILES = ("state.db", "state.db-wal", "state.db-shm")
BACKUP_DISK_PATH = "/var/lib/clickhouse/extorq-backups"
SPOOL_PATH = "/var/lib/extorq/spool"
CONTAINER_TIMEOUT_SECONDS = 300
BACKUP_TIMEOUT_SECONDS = 600
STOP_TIMEOUT_SECONDS = 120
HEALTH_WAIT_SECONDS = 180
EXIT_FAILED = 1
EXIT_PLAN_ONLY = 2


class StepError(RuntimeError):
    """A reset step failed; the message is safe to print (no secrets, no row data)."""


# ── pure planning (unit tested) ───────────────────────────────────────


@dataclass(frozen=True)
class CollectorTarget:
    """One collector state database to re-baseline."""

    collector_id: str
    state_path: Path
    policy_name: str
    policy_description: str


@dataclass(frozen=True)
class StatePlan:
    targets: tuple[CollectorTarget, ...]
    #: Retired state directories that exist and will be removed.
    retired: tuple[Path, ...]
    #: State directories without a collector configuration: left unchanged.
    unconfigured: tuple[str, ...]
    #: Configured collectors that have no state yet: nothing to reset.
    without_state: tuple[str, ...]


def plan_collector_state(state_root: Path, configs: Sequence[Any]) -> StatePlan:
    """Map ``var/collectors/<collector_id>/`` to configured collectors and their policies.

    ``configs`` are ``CollectorConfig`` objects (enabled and disabled). Only reads the
    directory listing.
    """
    from extorq_collectors.sdk.baseline import policy_for

    by_id = {c.collector_id: c for c in configs}
    targets: list[CollectorTarget] = []
    without_state: list[str] = []
    for collector_id, config in sorted(by_id.items()):
        path = state_root / collector_id / "state.db"
        if not path.is_file():
            without_state.append(collector_id)
            continue
        policy = policy_for(config.module)
        targets.append(CollectorTarget(collector_id, path, policy.name, policy.description))
    retired: list[Path] = []
    unconfigured: list[str] = []
    if state_root.is_dir():
        for child in sorted(p for p in state_root.iterdir() if p.is_dir()):
            if child.name in by_id:
                continue
            if child.name in RETIRED_STATE_DIRS:
                retired.append(child)
            else:
                unconfigured.append(child.name)
    return StatePlan(tuple(targets), tuple(retired), tuple(unconfigured), tuple(without_state))


def last_json_line(stdout: str) -> dict[str, Any]:
    """The last stdout line that is a JSON object (the reset commands print exactly one)."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
    raise StepError("no JSON result in the command output")


def count_table(before: dict[str, int], after: dict[str, int] | None) -> list[str]:
    """Aligned ``table  before  after`` lines (``-`` where a count is unknown)."""
    names = sorted(set(before) | set(after or {}))
    width = max([len(n) for n in names] + [5])
    lines = [f"  {'table':<{width}}  {'before':>12}  {'after':>12}"]
    for name in names:
        b = before.get(name)
        a = (after or {}).get(name)
        lines.append(
            f"  {name:<{width}}  {'-' if b is None else b:>12}  {'-' if a is None else a:>12}"
        )
    return lines


def only_selection(command: str | None) -> str | None:
    """The ``--only`` value of a running ``extorq-collect run`` command line, if any."""
    words = (command or "").split()
    for index, word in enumerate(words):
        if word == "--only" and index + 1 < len(words):
            return words[index + 1]
        if word.startswith("--only="):
            return word.partition("=")[2] or None
    return None


def removable_state_dir(path: Path, state_root: Path) -> bool:
    """True when ``path`` is a direct child of ``state_root`` holding only state files."""
    try:
        if path.parent.resolve() != state_root.resolve() or path.is_symlink():
            return False
        return all(
            not child.is_symlink() and child.is_file() and child.name in STATE_FILES
            for child in path.iterdir()
        )
    except OSError:
        return False


# ── docker compose ─────────────────────────────────────────────────────


def _compose(args: Sequence[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [*COMPOSE, *args],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StepError(f"docker compose {args[0]} failed: {type(exc).__name__}") from None


def _tail(text: str, lines: int = 3) -> str:
    kept = [line.strip()[:200] for line in text.strip().splitlines() if line.strip()]
    return " | ".join(kept[-lines:]) or "(no output)"


def service_states() -> dict[str, tuple[str, str]]:
    """``{service: (state, health)}`` of the project's containers."""
    proc = _compose(["ps", "--all", "--format", "json"], timeout=60)
    if proc.returncode != 0:
        raise StepError(f"docker compose ps failed (exit {proc.returncode}): {_tail(proc.stderr)}")
    states: dict[str, tuple[str, str]] = {}
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        for entry in data if isinstance(data, list) else [data]:
            if isinstance(entry, dict):
                name = str(entry.get("Service"))
                state = str(entry.get("State"))
                if name not in states or state in ("running", "restarting", "paused"):
                    states[name] = (state, str(entry.get("Health") or ""))
    return states


def run_admin_command(
    service: str, args: Sequence[str], *, timeout: float = CONTAINER_TIMEOUT_SECONDS
) -> dict[str, Any]:
    """``extorq <args>`` in a one-off container of ``service``; returns its JSON line.

    ``migrate`` holds the ClickHouse admin password, ``writer`` mounts the spool volume.
    ``--no-deps`` never starts other services; ``--rm`` removes the container.
    """
    proc = _compose(["run", "--rm", "--no-deps", "-T", service, *args], timeout=timeout)
    combined = f"{proc.stdout}\n{proc.stderr}"
    if "No such command" in combined:
        raise StepError(
            f"the backend image does not know 'extorq {' '.join(args[:2])}': rebuild it first "
            "(make up-full, or make build)"
        )
    try:
        result = last_json_line(proc.stdout)
    except StepError:
        raise StepError(
            f"extorq {' '.join(args[:2])} in a one-off {service} container failed "
            f"(exit {proc.returncode}): {_tail(proc.stderr or proc.stdout)}"
        ) from None
    if "error" in result:
        raise StepError(f"extorq {' '.join(args[:2])}: {str(result['error'])[:200]}")
    if proc.returncode != 0:
        raise StepError(f"extorq {' '.join(args[:2])} failed (exit {proc.returncode})")
    return result


def wait_healthy(services: Sequence[str], timeout: float) -> dict[str, str]:
    """Poll until each service is running and healthy (or has no healthcheck)."""
    deadline = time.monotonic() + timeout
    status: dict[str, str] = {}
    while True:
        try:
            states = service_states()
        except StepError:
            states = {}  # docker compose ps itself failed: report "missing", keep polling
        status = {}
        for name in services:
            state, health = states.get(name, ("missing", ""))
            status[name] = f"{state}{'/' + health if health else ''}"
        if all(s in ("running", "running/healthy") for s in status.values()):
            return status
        if time.monotonic() >= deadline:
            return status
        time.sleep(3)


# ── collectors ─────────────────────────────────────────────────────────


def _load_ctl() -> Any:
    """``scripts/collectors_ctl.py`` as a module (works with or without scripts/ on sys.path)."""
    spec = importlib.util.spec_from_file_location(
        "extorq_collectors_ctl", Path(__file__).with_name("collectors_ctl.py")
    )
    if spec is None or spec.loader is None:
        raise StepError("scripts/collectors_ctl.py not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_configs() -> list[Any]:
    from extorq_collectors.sdk.config import ConfigLoadError, load_collector_configs

    try:
        return load_collector_configs(REPO / "config" / "collectors", include_disabled=True)
    except ConfigLoadError as exc:
        raise StepError(f"collector configuration: {exc}") from None


def scanner_outbox() -> Path | None:
    """The scanner runner's outbox (``config/scanners.yaml`` ``state_dir``), if it exists."""
    state_dir = Path("var/state/scanners")
    with contextlib.suppress(Exception):  # optional package/config: fall back to the default
        from extorq_scanners.config import load_config

        state_dir = Path(load_config(REPO / "config" / "scanners.yaml").state_dir)
    path = (state_dir if state_dir.is_absolute() else REPO / state_dir) / "outbox.db"
    return path if path.is_file() else None


@dataclass
class Outcome:
    failures: list[str] = field(default_factory=list)
    table_report: dict[str, Any] | None = None
    spool: dict[str, Any] | None = None
    collectors: list[str] = field(default_factory=list)
    mutation_started: bool = False
    reset_complete: bool = False

    def fail(self, step: str, error: object) -> None:
        message = f"{step}: {error}"
        self.failures.append(message)
        print(f"  [FAIL] {message}")


def _checked_compose(args: Sequence[str]) -> None:
    proc = _compose(args, timeout=BACKUP_TIMEOUT_SECONDS)
    if proc.returncode != 0:
        raise StepError(f"docker compose {args[0]} failed (exit {proc.returncode})")


def _file_digest(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise StepError("recovery bundle is missing a regular file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_bundle(directory: Path, restore_sqlite: Path | None = None) -> dict[str, Any]:
    """Validate bundle checksums and optionally rehearse SQLite restoration to a new directory."""
    manifest = directory / "manifest.json"
    if manifest.is_symlink():
        raise StepError("recovery manifest must be a regular file")
    report = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("version") != 1:
        raise StepError("unsupported recovery manifest")
    files = report.get("files")
    clickhouse = report.get("clickhouse")
    if not isinstance(clickhouse, dict) or not isinstance(files, dict):
        raise StepError("recovery manifest is incomplete")
    archive = clickhouse.get("archive")
    if not isinstance(archive, str) or archive not in files or "spool.sqlite3" not in files:
        raise StepError("recovery manifest is missing ClickHouse or spool state")
    for name, expected in files.items():
        if not isinstance(name, str) or Path(name).name != name or name in (".", ".."):
            raise StepError("recovery manifest contains an invalid file name")
        if name != archive and not name.endswith(".sqlite3"):
            raise StepError("recovery manifest contains an unexpected file")
        if _file_digest(directory / name) != expected:
            raise StepError(f"recovery checksum mismatch for {name}")
    with zipfile.ZipFile(directory / archive) as compressed:
        if not compressed.namelist() or compressed.testzip() is not None:
            raise StepError("ClickHouse recovery archive is corrupt")
    if restore_sqlite is not None:
        restore_sqlite.mkdir(mode=0o700)
        for name in files:
            if name.endswith(".sqlite3"):
                snapshot_sqlite(directory / name, restore_sqlite / name)
    return report


def backup_stores(
    directory: Path,
    plan: StatePlan,
    running: list[str],
    collectors_only: str | None,
    collectors_running: bool,
) -> None:
    """Back up quiesced ClickHouse, spool, collector cursors/outboxes and scanner outbox."""
    from extorq_collectors.sdk.baseline import instance_locks

    directory.mkdir(mode=0o700)
    archive = f"extorq-{uuid.uuid4().hex}.zip"
    database = run_admin_command(
        "migrate", ["data", "backup", archive], timeout=BACKUP_TIMEOUT_SECONDS
    )
    if database.get("archive") != archive or database.get("status") != "BACKUP_CREATED":
        raise StepError("ClickHouse did not confirm the requested backup")
    if (
        not database.get("migrations")
        or not database.get("tables")
        or not database.get("schema_sha256")
    ):
        raise StepError("ClickHouse backup report is missing migration checksums or table counts")
    archive_path = f"{BACKUP_DISK_PATH}/{archive}"
    _checked_compose(["cp", f"clickhouse:{archive_path}", str(directory / archive)])
    with tempfile.TemporaryDirectory(dir=directory) as staging:
        _checked_compose(["cp", f"writer:{SPOOL_PATH}/.", staging])
        snapshot_sqlite(Path(staging) / "spool.db", directory / "spool.sqlite3")
    for target in plan.targets:
        with instance_locks(target.state_path.parent):
            snapshot_sqlite(
                target.state_path, directory / f"collector-{target.collector_id}.sqlite3"
            )
    for path in plan.retired:
        if not removable_state_dir(path, REPO / "var" / "collectors"):
            raise StepError(f"unexpected content in retired collector state {path.name}")
        if (path / "state.db").is_file():
            snapshot_sqlite(path / "state.db", directory / f"retired-{path.name}.sqlite3")
    outbox = scanner_outbox()
    if outbox is not None:
        with instance_locks(outbox.parent):
            snapshot_sqlite(outbox, directory / "scanner.sqlite3")

    files: dict[str, str] = {}
    for path in sorted(directory.iterdir()):
        files[path.name] = _file_digest(path)
        path.chmod(0o600)
        with path.open("rb") as stream:
            os.fsync(stream.fileno())
    report = {
        "version": 1,
        "captured_at": datetime.now(UTC).isoformat(),
        "clickhouse": database,
        "files": files,
        "previously_running": running,
        "collectors_running": collectors_running,
        "collectors_only": collectors_only,
    }
    manifest = directory / "manifest.json"
    with manifest.open("x", encoding="utf-8") as stream:
        manifest.chmod(0o600)
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    for path in (directory, directory.parent):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    verify_bundle(directory)
    _checked_compose(["exec", "-T", "clickhouse", "rm", "--", archive_path])


def reset_collector_state(plan: StatePlan, outcome: Outcome) -> None:
    from extorq_collectors.sdk.baseline import (
        CollectorBusyError,
        clear_outbox,
        policy_for,
        rebaseline,
    )

    configs = {c.collector_id: c for c in load_configs()}
    for target in plan.targets:
        policy = policy_for(configs[target.collector_id].module)
        try:
            result = rebaseline(target.state_path, collector_id=target.collector_id, policy=policy)
        except (CollectorBusyError, sqlite3.Error, OSError) as exc:
            outcome.fail(f"collector {target.collector_id}", f"{type(exc).__name__}: {exc}")
            continue
        kept = f" (kept: {', '.join(result.snapshots_kept)})" if result.snapshots_kept else ""
        rewritten = (
            f", rewritten {len(result.checkpoints_rewritten)}"
            if result.checkpoints_rewritten
            else ""
        )
        line = (
            f"{target.collector_id} ({result.policy}): outbox {result.outbox_cleared} + dead "
            f"{result.dead_cleared} cleared, {len(result.snapshots_dropped)} snapshots reset"
            f"{kept}, kv reset {len(result.kv_dropped)}, checkpoints kept "
            f"{len(result.checkpoints_kept)}{rewritten}"
        )
        outcome.collectors.append(line)
        print(f"  [ok  ] {line}")
    outbox = scanner_outbox()
    if outbox is not None:
        try:
            cleared, dead = clear_outbox(outbox)
            print(f"  [ok  ] scanner outbox: {cleared} pending + {dead} dead cleared")
        except (CollectorBusyError, sqlite3.Error, OSError) as exc:
            outcome.fail("scanner outbox", f"{type(exc).__name__}: {exc}")
    state_root = REPO / "var" / "collectors"
    for path in plan.retired:
        if not removable_state_dir(path, state_root):
            outcome.fail(f"retired state {path.name}", "unexpected content: left in place")
            continue
        try:
            shutil.rmtree(path)
            print(f"  [ok  ] removed retired state var/collectors/{path.name}")
        except OSError as exc:
            outcome.fail(f"retired state {path.name}", type(exc).__name__)


def destructive_steps(
    ctl: Any,
    plan: StatePlan,
    running: list[str],
    collectors_running: bool,
    only: str | None,
    backup: Path,
    outcome: Outcome,
    *,
    backup_only: bool,
) -> None:
    """Quiesce writers, verify a recovery bundle, then change stores in order."""
    if collectors_running and ctl.stop(timeout=90.0) != 0:
        outcome.fail("stop", "background collectors did not stop")
        return
    if running:
        try:
            proc = _compose(["stop", *running], timeout=STOP_TIMEOUT_SECONDS)
        except StepError as exc:
            outcome.fail("stop", exc)
            return
        if proc.returncode != 0:
            outcome.fail("stop", f"docker compose stop failed: {_tail(proc.stderr)}")
            return
        print(f"  [ok  ] stopped {', '.join(running)}")
    from extorq_collectors.sdk.baseline import CollectorBusyError

    try:
        states = service_states()
        if any(
            states.get(name, ("", ""))[0] in ("running", "restarting", "paused")
            for name in (*PIPELINE_SERVICES, "migrate")
        ):
            raise StepError("a pipeline writer is still active")
        if ctl.running_pid() is not None or ctl.other_runners(exclude=None):
            raise StepError("a collector runner is still active")
        backup_stores(backup, plan, running, only, collectors_running)
    except StepError as exc:
        outcome.fail("backup", exc)
        return
    except (
        CollectorBusyError,
        OSError,
        ResetError,
        ValueError,
        sqlite3.Error,
        zipfile.BadZipFile,
    ) as exc:
        outcome.fail("backup", type(exc).__name__)
        return
    print(f"  [ok  ] verified recovery bundle {backup}")
    if backup_only:
        return
    outcome.mutation_started = True
    try:
        outcome.table_report = run_admin_command("migrate", ["data", "reset", "--yes"])
    except StepError as exc:
        # Without the truncation the remaining steps would only make the data inconsistent.
        outcome.fail("truncate", exc)
        return
    print(f"  [ok  ] truncated {len(outcome.table_report.get('truncated') or [])} tables")
    remaining = outcome.table_report.get("rows_remaining") or {}
    if remaining:
        outcome.fail("truncate", f"rows arrived after the truncation: {remaining}")
        return
    try:
        outcome.spool = run_admin_command("writer", ["spool", "clear", "--yes"])
        print(f"  [ok  ] spool cleared {outcome.spool.get('cleared') or {}}")
    except StepError as exc:
        outcome.fail("spool", exc)
        return
    try:
        reset_collector_state(plan, outcome)
    except StepError as exc:
        outcome.fail("collector state", exc)
    outcome.reset_complete = not outcome.failures


def restart(
    ctl: Any, running: list[str], collectors_running: bool, only: str | None, outcome: Outcome
) -> None:
    """Start what was running before, after a complete reset or a pre-mutation failure."""
    _section("restart")
    if outcome.reset_complete and "ai-worker" in running:
        # Truncating assessments also removes this day's persisted provider usage.
        running = [name for name in running if name != "ai-worker"]
        print("  [info] Jev worker left stopped; reconcile the UTC daily budget before enabling")
    if running:
        try:
            proc = _compose(["start", *running], timeout=STOP_TIMEOUT_SECONDS)
            if proc.returncode != 0:
                outcome.fail("restart", _tail(proc.stderr))
                return
        except StepError as exc:
            outcome.fail("restart", exc)
            return
        healthy = True
        for name, status in wait_healthy(running, HEALTH_WAIT_SECONDS).items():
            ok = status in ("running", "running/healthy")
            print(f"  [{'ok  ' if ok else 'FAIL'}] {name} {status}")
            if not ok:
                healthy = False
                outcome.failures.append(f"restart: {name} {status}")
        if not healthy:
            return
    if collectors_running:
        if ctl.start(only, False) != 0:
            outcome.fail("restart", "background collectors did not start")
    else:
        print("  [info] background collectors were not running: make collectors-start")


# ── main ───────────────────────────────────────────────────────────────


def _section(title: str) -> None:
    print(f"\n{title}")


def _print_plan(plan: StatePlan, running: list[str], collectors_running: bool) -> None:
    _section("plan")
    print(
        "  stop: background collectors"
        + (" (running)" if collectors_running else " (not running)")
        + f"; services {', '.join(running) or '(none running)'}"
    )
    print("  backup: native ClickHouse archive plus spool, collector and scanner SQLite files")
    print("  truncate: every data table (extorq.storage.reset.DATA_TABLES; never")
    print("            schema_migrations, users, roles or grants)")
    print("  spool: queued records, replay results, dedup keys, dead letters, counters")
    for target in plan.targets:
        print(f"  collector {target.collector_id}: {target.policy_description}")
    for collector_id in plan.without_state:
        print(f"  collector {collector_id}: no state yet (nothing to reset)")
    for path in plan.retired:
        print(f"  remove retired state: var/collectors/{path.name}")
    for name in plan.unconfigured:
        print(f"  leave unchanged (no collector configuration): var/collectors/{name}")
    print(
        "  restart: previously running services after success. "
        "Writers stay stopped after a partial reset"
    )


def preflight(ctl: Any) -> tuple[dict[str, tuple[str, str]], dict[str, int]]:
    """Checks that change nothing; returns the service states and the BEFORE row counts."""
    if shutil.which("docker") is None:
        raise StepError("docker is not on PATH")
    states = service_states()
    state, health = states.get("clickhouse", ("missing", ""))
    if state != "running" or health not in ("", "healthy"):
        raise StepError(f"ClickHouse is {state}{'/' + health if health else ''}: run make up")
    if states.get("writer", ("missing", ""))[0] == "missing":
        raise StepError("the Compose writer container is missing; cannot identify the spool volume")
    others = ctl.other_runners(exclude=ctl.running_pid())
    if others:
        raise StepError(
            "foreground `extorq-collect run` process(es) active (pid "
            f"{', '.join(map(str, others))}): stop them first"
        )
    outbox = scanner_outbox()
    if outbox is not None:
        from extorq_collectors.sdk.baseline import CollectorBusyError, instance_locks

        try:
            with instance_locks(outbox.parent):
                pass
        except CollectorBusyError:
            raise StepError("a scan is running (scanner run.lock is held): wait for it") from None
    counts = run_admin_command("migrate", ["data", "counts"])
    tables = counts.get("tables")
    if not isinstance(tables, dict):
        raise StepError("extorq data counts returned no table counts")
    return states, {str(k): int(v) for k, v in tables.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--yes", action="store_true", help="confirm an explicitly authorized destructive reset"
    )
    parser.add_argument(
        "--backup-dir", type=Path, help="new private directory for a recovery bundle"
    )
    parser.add_argument(
        "--backup-only", action="store_true", help="back up without changing persisted data"
    )
    parser.add_argument(
        "--sources-paused",
        action="store_true",
        help="confirm external senders are paused and their offsets/queues are backed up",
    )
    parser.add_argument("--verify-backup", type=Path, help="verify an existing recovery bundle")
    parser.add_argument(
        "--restore-sqlite", type=Path, help="rehearse restoring SQLite into a new directory"
    )
    args = parser.parse_args(argv)
    if args.verify_backup is not None:
        if args.yes or args.backup_only or args.backup_dir:
            parser.error("--verify-backup is a separate operation")
        try:
            report = verify_bundle(args.verify_backup, args.restore_sqlite)
        except (
            OSError,
            ResetError,
            StepError,
            ValueError,
            sqlite3.Error,
            zipfile.BadZipFile,
        ) as exc:
            print(f"  [FAIL] recovery bundle verification: {type(exc).__name__}")
            return EXIT_FAILED
        print(json.dumps(report, sort_keys=True))
        return 0
    if args.restore_sqlite:
        parser.error("--restore-sqlite requires --verify-backup")
    if args.yes and args.backup_only:
        parser.error("--yes and --backup-only are separate operations")
    execute = args.yes or args.backup_only
    if execute and (args.backup_dir is None or not args.sources_paused):
        parser.error("--backup-dir and --sources-paused are required to quiesce the pipeline")
    backup = args.backup_dir.absolute() if args.backup_dir else None
    if (
        execute
        and backup
        and (backup.exists() or backup.is_symlink() or not backup.parent.is_dir())
    ):
        parser.error("--backup-dir must be a new directory under an existing parent")

    ctl = _load_ctl()
    print("ExtorQ clean-slate reset" + ("" if execute else " (plan only)"))
    try:
        states, before = preflight(ctl)
        plan = plan_collector_state(REPO / "var" / "collectors", load_configs())
    except StepError as exc:
        print(f"  [FAIL] preflight: {exc} (nothing was changed)")
        return EXIT_FAILED
    running = [s for s in PIPELINE_SERVICES if states.get(s, ("", ""))[0] == "running"]
    collectors_pid = ctl.running_pid()
    _print_plan(plan, running, collectors_pid is not None)
    if not execute:
        _section("ClickHouse row counts now (counts only)")
        print("\n".join(count_table(before, None)))
        print("\nnothing changed; see docs/recovery.md for backup and reset commands")
        return EXIT_PLAN_ONLY

    if backup is None:
        parser.error("--backup-dir is required")
    outcome = Outcome()
    only = only_selection(ctl._command_of(collectors_pid)) if collectors_pid else None
    try:
        with (REPO / "var" / "reset.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _section("backup" if args.backup_only else "reset")
            try:
                destructive_steps(
                    ctl,
                    plan,
                    running,
                    collectors_pid is not None,
                    only,
                    backup,
                    outcome,
                    backup_only=args.backup_only,
                )
            finally:
                if not outcome.mutation_started or outcome.reset_complete:
                    restart(ctl, running, collectors_pid is not None, only, outcome)
                else:
                    print(
                        "Writers remain stopped. Follow docs/recovery.md with the recovery bundle."
                    )
    except BlockingIOError:
        print("  [FAIL] another backup or reset holds the maintenance lock")
        return EXIT_FAILED
    if args.backup_only:
        if outcome.failures:
            return EXIT_FAILED
        print("\nBACKUP DONE")
        return 0

    report = outcome.table_report or {}
    _section("ClickHouse row counts (counts only; before = after the services stopped)")
    print("\n".join(count_table(report.get("before") or before, report.get("after"))))
    if report.get("unknown"):
        print(f"  unknown tables left unchanged: {', '.join(report['unknown'])}")
    if outcome.failures:
        print(
            f"\nRESET INCOMPLETE ({len(outcome.failures)} failed): " + "; ".join(outcome.failures)
        )
        return EXIT_FAILED
    _section("next")
    print(
        "  wait for inventory and source freshness. "
        "See docs/recovery.md before resuming external senders"
    )
    print("\nRESET DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())

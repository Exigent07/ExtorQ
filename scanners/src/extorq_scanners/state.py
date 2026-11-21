"""Local runner state under ``var/state/scanners`` (0700 dir, 0600 files).

* ``run.lock``: an exclusive ``flock`` so two runs never scan concurrently
  (concurrent scans of one scope would make lifecycle ordering ambiguous).
* ``inflight/<scan_run_id>.json``: the ``running`` ScanRun of a scan that has not
  reported a terminal status yet. If the runner dies, the next run reports
  these scans as ``failed`` ("runner interrupted") so they can never linger as
  ``running`` (the lifecycle view additionally treats >6 h running as failed).
* ``last_results.json``: last status / last success per target (health records).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from extorq.contracts import ScanRun, ScanStatus
from extorq.contracts.identity import iso_utc


class LockedError(RuntimeError):
    """Another extorq-scan run holds the lock."""


def _write_atomic(path: Path, data: str) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class StateStore:
    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.inflight_dir = directory / "inflight"
        for d in (self.dir, self.inflight_dir):
            d.mkdir(parents=True, exist_ok=True)
            os.chmod(d, 0o700)
        self.results_file = directory / "last_results.json"

    @contextlib.contextmanager
    def lock(self) -> Iterator[None]:
        path = self.dir / "run.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise LockedError("another extorq-scan run is in progress") from None
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    # ── in-flight scans ───────────────────────────────────────────────
    def mark_inflight(self, run: ScanRun) -> None:
        _write_atomic(self.inflight_dir / f"{run.scan_run_id}.json", run.model_dump_json())

    def clear_inflight(self, scan_run_id: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            (self.inflight_dir / f"{scan_run_id}.json").unlink()

    def interrupted(self) -> list[ScanRun]:
        runs: list[ScanRun] = []
        for path in sorted(self.inflight_dir.glob("*.json")):
            try:
                run = ScanRun.model_validate_json(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                path.unlink(missing_ok=True)
                continue
            if run.status is ScanStatus.RUNNING:
                runs.append(run)
            else:
                path.unlink(missing_ok=True)
        return runs

    # ── last results ──────────────────────────────────────────────────
    def results(self) -> dict[str, Any]:
        try:
            data = json.loads(self.results_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def last_success(self, target: str) -> datetime | None:
        value = self.results().get(target, {}).get("last_success_at")
        if not isinstance(value, str):
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    def record(self, target: str, run: ScanRun) -> None:
        data = self.results()
        previous = data.get(target)
        entry: dict[str, Any] = dict(previous) if isinstance(previous, dict) else {}
        finished = iso_utc(run.finished_at) if run.finished_at else None
        entry.update(
            {"scan_run_id": run.scan_run_id, "status": run.status.value, "finished_at": finished}
        )
        if run.status is ScanStatus.SUCCEEDED and finished:
            entry["last_success_at"] = finished
        data[target] = entry
        _write_atomic(self.results_file, json.dumps(data, indent=2, sort_keys=True))

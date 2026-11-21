"""Shared helpers for the Linux collector tests (owner B1); imported as ``linux_testlib``.

Fixtures under tests/fixtures/linux/ are REAL responses captured from lab-vm-01 through
the dispatch boundary on 2026-11-21 (see tests/fixtures/linux/README.md). The fake VM
below serves them with the dispatcher's semantics (journal cursors, audit offsets) so
the real SSHDispatchClient, parsers, adapters and collector run unchanged; only the
``ssh`` subprocess is replaced (``SSHDispatchClient(runner=...)``).
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from extorq_collectors.linux import adapters as _adapters  # noqa: F401  (registers adapters)
from extorq_collectors.linux.common import ParseContext
from extorq_collectors.linux.journal import JournalEntry, entry_from_json
from extorq_collectors.linux.ssh import RunResult, SSHDispatchClient, SSHTarget
from extorq_collectors.sdk import CollectorConfig, CollectorContext, StateStore

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "linux"
ASSET = "linux:lab-vm-01"
COLLECTOR_ID = "linux-ssh-lab-vm-01"
SELF_UID = 1001  # uid of extorq-collector on lab-vm-01 (fixture inventory)


def load_ndjson(relative: str) -> list[dict[str, Any]]:
    path = FIXTURES / relative
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def load_json(relative: str) -> dict[str, Any]:
    return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))


def entries(relative: str) -> list[JournalEntry]:
    parsed = [entry_from_json(obj) for obj in load_ndjson(relative)]
    assert all(e is not None for e in parsed), f"invalid fixture entry in {relative}"
    return [e for e in parsed if e is not None]


def find(relative: str, needle: str) -> JournalEntry:
    for entry in entries(relative):
        if needle in entry.message:
            return entry
    raise AssertionError(f"no entry containing {needle!r} in {relative}")


def pctx(**overrides: Any) -> ParseContext:
    base: dict[str, Any] = {
        "asset_id": ASSET,
        "collector_id": COLLECTOR_ID,
        "self_uid": SELF_UID,
        "observed_time": datetime(2026, 11, 21, 15, 0, tzinfo=UTC),
    }
    base.update(overrides)
    return ParseContext(**base)


# ── fake dispatch boundary ───────────────────────────────────────────────────────


def _journal_trailer(**fields: Any) -> bytes:
    meta = {
        "type": "journal_end",
        "protocol": 1,
        "truncated": False,
        "timed_out": False,
        "skipped_malformed": 0,
        "skipped_oversized": 0,
        "journalctl_exit": 0,
        "error": None,
    }
    meta.update(fields)
    return json.dumps({"_extorq": meta}).encode() + b"\n"


@dataclass
class FakeVM:
    """Serves captured dispatcher responses with the dispatcher's cursor/offset semantics."""

    journal: list[dict[str, Any]] = field(default_factory=list)
    audit_log: bytes = b""
    audit_inode: int = 262353
    inventory: dict[str, Any] | None = None
    packages: dict[str, Any] | None = None
    posture: dict[str, Any] | None = None
    commands: list[str] = field(default_factory=list)
    fail: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    vacuumed: set[str] = field(default_factory=set)

    def respond(self, command: str) -> bytes:
        name, *args = command.split(" ")
        if name == "version":
            return (FIXTURES / "dispatch" / "version.json").read_bytes()
        if name == "journal":
            return self._journal(args[0], int(args[1]))
        if name == "audit":
            return self._audit(args[0], int(args[1]), int(args[2]))
        doc = {"inventory": self.inventory, "packages": self.packages, "posture": self.posture}.get(
            name
        )
        if doc is None:
            raise AssertionError(f"unexpected command {command!r}")
        return json.dumps(doc).encode() + b"\n"

    def _journal(self, cursor: str, limit: int) -> bytes:
        available = [e for e in self.journal if e["__CURSOR"] not in self.vacuumed]
        exact: bool | None = None
        start = 0
        if cursor != "-":
            index = next((i for i, e in enumerate(available) if e["__CURSOR"] == cursor), None)
            if index is None:
                exact = False  # checkpoint entry no longer in the journal
            else:
                exact, start = True, index + 1
        chunk = available[start : start + limit]
        body = b"".join(json.dumps(e).encode() + b"\n" for e in chunk)
        return body + _journal_trailer(
            entries=len(chunk),
            truncated=start + limit < len(available),
            cursor_requested=cursor != "-",
            cursor_exact=exact,
            last_cursor=chunk[-1]["__CURSOR"] if chunk else None,
            since=None if cursor != "-" else "-2h",
        )

    def _audit(self, inode: str, offset: int, max_bytes: int) -> bytes:
        gap, reason = False, None
        if inode != "-" and int(inode) != self.audit_inode:
            gap, reason, offset = True, "rotated_past_offset", 0
        elif offset > len(self.audit_log):
            gap, reason, offset = True, "file_truncated", 0
        data = self.audit_log[offset : offset + max_bytes]
        cut = data.rfind(b"\n")
        payload = data[: cut + 1] if cut >= 0 else b""
        header = {
            "_extorq": {
                "type": "audit",
                "protocol": 1,
                "file": "audit.log",
                "inode": self.audit_inode,
                "size": len(self.audit_log),
                "start_offset": offset,
                "next_offset": offset + len(payload),
                "bytes": len(payload),
                "gap": gap,
                "gap_reason": reason,
                "oversized_line_skipped": False,
                "more": offset + len(payload) < len(self.audit_log),
                "current_inode": self.audit_inode,
                "current_size": len(self.audit_log),
                "rotated_files": 0,
            }
        }
        return json.dumps(header).encode() + b"\n" + payload

    def runner(self) -> Callable[[list[str], float, int], RunResult]:
        def run(argv: list[str], timeout: float, max_output: int) -> RunResult:
            command = argv[-1]
            self.commands.append(command)
            if command in self.fail:
                code, err = self.fail[command]
                return RunResult(code, b"", err, 0.01)
            return RunResult(0, self.respond(command), b"", 0.01)

        return run


def write_ssh_files(tmp_path: Path) -> tuple[Path, Path]:
    key = tmp_path / "collector-key"
    key.write_text("placeholder identity: never used, ssh is faked in unit tests\n")
    os.chmod(key, 0o600)
    known = tmp_path / "known_hosts"
    known.write_text("[127.0.0.1]:2222 ssh-ed25519 AAAA-test-only\n")
    return key, known


def make_client(fake: FakeVM, ssh_files: tuple[Path, Path]) -> SSHDispatchClient:
    key, known = ssh_files
    target = SSHTarget(identity_file=key, known_hosts_file=known, control_dir=None)
    return SSHDispatchClient(target, runner=fake.runner(), sleep=lambda _s: None)


def make_context(
    tmp_path: Path, settings: dict[str, Any] | None = None, store: StateStore | None = None
) -> CollectorContext:
    config = CollectorConfig(
        collector_id=COLLECTOR_ID,
        producer_id="linux-ssh-lab-vm-01",
        asset_id=ASSET,
        module="extorq_collectors.linux.collector:LinuxSSHCollector",
        interval_seconds=30,
        settings=settings or {},
    )
    return CollectorContext(config, store or StateStore(tmp_path / "state.db"))


def outbox(ctx: CollectorContext) -> list[dict[str, Any]]:
    """Every record committed to the outbox so far ({kind, data} dicts)."""
    with ctx.store.transaction() as conn:
        rows = conn.execute("SELECT record FROM outbox ORDER BY seq").fetchall()
    return [json.loads(row[0]) for row in rows]


def events_of(records: list[dict[str, Any]], event_type: str | None = None) -> list[dict[str, Any]]:
    return [
        r["data"]
        for r in records
        if r["kind"] == "event" and (event_type is None or r["data"]["event_type"] == event_type)
    ]

"""Restart-safe per-repository checkpoint state.

One JSON document per monitored repository is stored as a collector checkpoint
(``ctx.emit(records, checkpoints={key: state.to_json()})``), so records and the
cursor that produced them are committed atomically by the SDK outbox. After a crash
the collector resumes from the last committed state and re-derives identical event
identities for anything it re-processes (duplicates collapse downstream).

All collections are bounded so the checkpoint cannot grow without limit.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from extorq.contracts.identity import canonical_json

STATE_VERSION = 1
MAX_ETAGS = 64
MAX_RUNS_TRACKED = 1000
MAX_SNAPSHOT_CHARS = 32 * 1024
MAX_INVENTORY_KEYS = 256
#: Commits awaiting a retry after a transient detail failure (beyond: gap at once).
MAX_COMMIT_RETRIES = 32

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RETRY_KEYS = frozenset(
    {"branch", "attempts", "initial_backfill", "last_failed_at", "last_error", "push"}
)


def checkpoint_key(full_name: str) -> str:
    return f"github:repo:{full_name.lower()}"


@dataclass
class RepoState:
    version: int = STATE_VERSION
    repo_id: int | None = None
    #: First time ExtorQ observed the repository (ISO-8601 UTC).
    first_seen: str | None = None
    last_poll_at: str | None = None
    #: branch name -> last fully processed commit SHA.
    branch_heads: dict[str, str] = field(default_factory=dict)
    #: request key -> ETag of the last 200 response.
    etags: dict[str, str] = field(default_factory=dict)
    #: Compact repository metadata (id, display name, owner type, token admin flag).
    repo_meta: dict[str, Any] | None = None
    #: Normalised repository settings snapshot (for diffing and 304 reuse).
    settings: dict[str, Any] | None = None
    #: branch name -> {"sha": head sha, "protected": bool|None} from the branches API.
    branch_info: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: branch name -> normalised protection/ruleset snapshot.
    protection: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: Workflow run id -> "<attempt>:<status>:<conclusion>|<updated_at>|<created_at>".
    runs_seen: dict[str, str] = field(default_factory=dict)
    #: Last emitted run signatures for open runs, including runs older than the list window.
    runs_open: dict[str, str] = field(default_factory=dict)
    #: Last run ID inspected via the bounded late-transition queue.
    runs_open_after: int = 0
    #: ``created_at`` of the oldest run still open at the last listing (None: none open).
    runs_cursor: str | None = None
    #: When workflow runs were last listed successfully (gap detection).
    runs_listed_at: str | None = None
    #: Monotonic counter making diff-event identities unique per observed change.
    change_seq: int = 0
    last_posture_at: str | None = None
    last_alerts_at: str | None = None
    last_asset_at: str | None = None
    #: Latest repository activity id processed (push timestamps / pusher enrichment).
    last_activity_id: int | None = None
    #: Item keys of the last inventory snapshot (to emit tombstones for removed items).
    inventory_workflows: list[str] = field(default_factory=list)
    inventory_branches: list[str] = field(default_factory=list)
    #: commit sha -> retry entry for a commit whose detail failed transiently. The branch
    #: checkpoint has already moved past it (one commit never blinds the repository);
    #: entry keys: branch, attempts, initial_backfill, last_failed_at, last_error, push.
    commit_retries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def remember_etag(self, key: str, etag: str | None) -> None:
        self.etags.pop(key, None)
        if not etag:
            return
        self.etags[key] = etag[:256]
        while len(self.etags) > MAX_ETAGS:
            self.etags.pop(next(iter(self.etags)))

    def forget_etag(self, key: str) -> None:
        self.etags.pop(key, None)

    def prune_runs(self, keep_since_iso: str | None) -> None:
        """Drop tracked runs created before ``keep_since_iso`` and bound the map size."""
        if keep_since_iso:
            for run_id in [
                k for k, v in self.runs_seen.items() if v.rpartition("|")[2] < keep_since_iso
            ]:
                del self.runs_seen[run_id]
        if len(self.runs_seen) > MAX_RUNS_TRACKED:
            ordered = sorted(self.runs_seen.items(), key=lambda kv: kv[1].rpartition("|")[2])
            self.runs_seen = dict(ordered[-MAX_RUNS_TRACKED:])

    def to_json(self) -> str:
        data = asdict(self)
        for name in ("settings", "repo_meta", "protection", "branch_info"):
            if data[name] and len(canonical_json(data[name])) > MAX_SNAPSHOT_CHARS:
                # Never persist an unbounded snapshot. Dropping it also drops the ETags,
                # so a later 304 can never be paired with a missing snapshot.
                data[name] = None if name in ("settings", "repo_meta") else {}
                data["etags"] = {}
        return canonical_json(data)

    @classmethod
    def from_json(cls, text: str | None) -> RepoState:
        """Load state; unknown versions or corrupt documents start a fresh baseline."""
        if not text:
            return cls()
        try:
            data = json.loads(text)
        except ValueError:
            return cls()
        if not isinstance(data, dict) or data.get("version") != STATE_VERSION:
            return cls()
        state = cls()
        for name, default in asdict(cls()).items():
            value = data.get(name, default)
            if (isinstance(default, dict) and not isinstance(value, dict)) or (
                isinstance(default, list) and not isinstance(value, list)
            ):
                value = default
            setattr(state, name, value)
        state.branch_heads = {str(k): str(v) for k, v in state.branch_heads.items()}
        state.etags = {str(k): str(v) for k, v in state.etags.items()}
        state.runs_seen = {str(k): str(v) for k, v in state.runs_seen.items()}
        # Version 1 checkpoints written before the open-run map already carry run state.
        open_runs = state.runs_open if "runs_open" in data else state.runs_seen
        state.runs_open = {
            key: value
            for key, value in open_runs.items()
            if re.fullmatch(r"[1-9][0-9]{0,18}", key)
            and isinstance(value, str)
            and len(value) <= 128
            and value.partition(":")[2].partition(":")[0] != "completed"
        }
        if not isinstance(state.runs_open_after, int):
            state.runs_open_after = 0
        state.inventory_workflows = [str(v) for v in state.inventory_workflows][:MAX_INVENTORY_KEYS]
        state.inventory_branches = [str(v) for v in state.inventory_branches][:MAX_INVENTORY_KEYS]
        retries: dict[str, dict[str, Any]] = {}
        for sha, entry in state.commit_retries.items():
            if (
                isinstance(sha, str)
                and _SHA_RE.match(sha)
                and isinstance(entry, dict)
                and isinstance(entry.get("branch"), str)
                and isinstance(entry.get("attempts"), int)
                and len(retries) < MAX_COMMIT_RETRIES
            ):
                retries[sha] = {k: v for k, v in entry.items() if k in _RETRY_KEYS}
        state.commit_retries = retries
        return state

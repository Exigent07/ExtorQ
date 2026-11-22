"""Clean-slate re-baseline of collector state (used by ``make reset-data``).

After the ClickHouse data tables are truncated, every collector must send its current
inventory, services, posture and assets again, while log-like sources must NOT re-read
activity that happened before the reset. A collector's state database
(``var/collectors/<collector_id>/state.db``, see :mod:`extorq_collectors.sdk.state`) is
therefore reset *selectively*, in one SQLite transaction:

* ``outbox`` / ``outbox_dead``: cleared. Those records were collected before the reset;
  delivering them afterwards would put pre-reset activity into the clean database.
* ``snapshots``: cleared, except the snapshots a policy keeps because they act as a
  source cursor (Kubernetes ``k8s-events``: the Events already emitted). With no stored
  snapshot the next cycle is a *baseline*: full records, no change events
  (``collectors/AGENTS.md`` rule 4), so the reset never produces false detections.
* ``checkpoints``: kept (journald cursor, audit inode/offset, unified-log window,
  Kubernetes cycle mark). A policy may rewrite a checkpoint value: GitHub keeps one JSON
  document per repository that holds both the commit/run cursors (kept) and the
  repository settings, protection and inventory snapshots (reset).
* ``kv``: keys matching the policy's prefixes are dropped (collection schedules such as
  "posture last ran at" and "last event per service", which refer to data that no longer
  exists). First-seen history and the last health summary are kept.

Policies are selected by the collector's ``module`` (its package) from
``config/collectors/*.yaml``; unknown collectors get :data:`DEFAULT_POLICY` (clear the
outbox and the snapshots, keep everything else). Owners of a collector that adds new
state keep :data:`POLICIES` in sync (``tests/unit/platform/test_platform_reset.py``).
The selection is pure (:func:`plan_state_reset`) and unit tested; :func:`rebaseline`
applies it.
"""

from __future__ import annotations

import contextlib
import copy
import fcntl
import json
import os
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from extorq.contracts.identity import canonical_json
from extorq_collectors.sdk.state import StateStore

#: GitHub repository state (``extorq_collectors.github.state.RepoState``) version handled.
GITHUB_STATE_VERSION = 1
#: Checkpoint keys of the GitHub collector (``github.state.checkpoint_key``).
GITHUB_CHECKPOINT_PREFIX = "github:repo:"
#: RepoState fields reset to their defaults: the repository settings, branch protection,
#: branch info and inventory snapshots, the ETags that validate them (an ETag must never
#: outlive its snapshot, or a 304 would leave the collector without data) and the
#: posture/alerts/asset schedules. A missing "before" snapshot is never reported as a
#: change by the GitHub collector, so the next poll is a baseline. Everything else is a
#: cursor and stays: branch heads (commits), run tracking, activity id, change sequence,
#: commit retries, first-seen and repository id.
GITHUB_BASELINE_FIELDS: Mapping[str, Any] = {
    "settings": None,
    "repo_meta": None,
    "protection": {},
    "branch_info": {},
    "etags": {},
    "last_posture_at": None,
    "last_alerts_at": None,
    "last_asset_at": None,
    "inventory_workflows": [],
    "inventory_branches": [],
}

CheckpointRewrite = Callable[[str, str], str | None]


def reset_github_repo_checkpoint(key: str, value: str) -> str | None:
    """New value for one GitHub repository checkpoint, or ``None`` to leave it unchanged.

    Unparseable documents and unknown state versions are left alone (the collector itself
    starts a fresh baseline for those), so this never invents state.
    """
    if not key.startswith(GITHUB_CHECKPOINT_PREFIX):
        return None
    try:
        data = json.loads(value)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("version") != GITHUB_STATE_VERSION:
        return None
    for name, default in GITHUB_BASELINE_FIELDS.items():
        data[name] = copy.deepcopy(default)
    return canonical_json(data)


@dataclass(frozen=True)
class BaselinePolicy:
    """What a clean-slate reset keeps and clears in one collector's state database."""

    name: str
    #: Snapshot names that act as source cursors and survive the reset.
    keep_snapshots: frozenset[str] = frozenset()
    #: KV keys starting with any of these prefixes are dropped.
    drop_kv_prefixes: tuple[str, ...] = ()
    #: Rewrites a checkpoint value (``None``: keep it as is).
    rewrite_checkpoint: CheckpointRewrite | None = None
    #: One line for the operator: what the policy does and why.
    description: str = ""


DEFAULT_POLICY = BaselinePolicy(
    name="default",
    description="outbox and snapshots cleared; checkpoints and kv kept",
)

#: Policies by collector package (prefix of ``module`` in ``config/collectors``).
POLICIES: Mapping[str, BaselinePolicy] = {
    "extorq_collectors.linux": BaselinePolicy(
        name="linux",
        drop_kv_prefixes=(
            "linux.last_run.",  # inventory / packages / posture schedules
            "linux.inventory.last_full",  # full inventory re-send schedule
            "linux.services.last_event",  # last attributed event per service
        ),
        description=(
            "snapshots and schedules reset (inventory, packages, posture, services re-sent); "
            "journald cursor and audit inode/offset kept"
        ),
    ),
    "extorq_collectors.macos": BaselinePolicy(
        name="macos",
        drop_kv_prefixes=(
            "macos.sources",  # per-source schedule (last attempt / success)
            "macos.full_inventory",  # full inventory re-send schedule
            "macos.adapter_last_event",  # last attributed event per adapter
        ),
        description=(
            "snapshots and source schedules reset (launchd, listeners, processes, "
            "applications, accounts, posture, services re-sent); unified-log window kept"
        ),
    ),
    "extorq_collectors.kubernetes": BaselinePolicy(
        name="kubernetes",
        keep_snapshots=frozenset({"k8s-events"}),
        drop_kv_prefixes=("k8s.last_full_refresh",),
        description=(
            "object, service, instance and asset snapshots reset (baseline records are "
            "marked baseline=true); emitted Event versions (k8s-events) kept"
        ),
    ),
    "extorq_collectors.github": BaselinePolicy(
        name="github",
        rewrite_checkpoint=reset_github_repo_checkpoint,
        description=(
            "repository settings, protection, inventory, ETags and posture schedules reset; "
            "commit heads, workflow-run tracking and activity cursor kept"
        ),
    ),
}


def policy_for(module: str) -> BaselinePolicy:
    """Policy for a collector ``module`` spec (``package.module:ClassName``)."""
    package = module.partition(":")[0]
    for prefix, policy in POLICIES.items():
        if package == prefix or package.startswith(prefix + "."):
            return policy
    return DEFAULT_POLICY


@dataclass(frozen=True)
class StateResetPlan:
    """Pure selection: which rows of one state database a reset removes or rewrites."""

    drop_snapshots: tuple[str, ...]
    keep_snapshots: tuple[str, ...]
    drop_kv: tuple[str, ...]
    keep_kv: tuple[str, ...]
    rewrite_checkpoints: dict[str, str]
    keep_checkpoints: tuple[str, ...]


def plan_state_reset(
    policy: BaselinePolicy,
    *,
    checkpoints: Mapping[str, str],
    kv_keys: Iterable[str],
    snapshot_names: Iterable[str],
) -> StateResetPlan:
    """Decide what to clear for one collector (no I/O; the outbox is always cleared)."""
    snapshots = sorted(set(snapshot_names))
    keys = sorted(set(kv_keys))
    rewrites: dict[str, str] = {}
    if policy.rewrite_checkpoint is not None:
        for key, value in sorted(checkpoints.items()):
            new = policy.rewrite_checkpoint(key, value)
            if new is not None and new != value:
                rewrites[key] = new
    return StateResetPlan(
        drop_snapshots=tuple(n for n in snapshots if n not in policy.keep_snapshots),
        keep_snapshots=tuple(n for n in snapshots if n in policy.keep_snapshots),
        drop_kv=tuple(k for k in keys if k.startswith(policy.drop_kv_prefixes)),
        keep_kv=tuple(k for k in keys if not k.startswith(policy.drop_kv_prefixes)),
        rewrite_checkpoints=rewrites,
        keep_checkpoints=tuple(k for k in sorted(checkpoints) if k not in rewrites),
    )


@dataclass
class StateResetResult:
    """Counts of what :func:`rebaseline` changed (never values: cursors stay private)."""

    collector_id: str
    policy: str
    outbox_cleared: int = 0
    dead_cleared: int = 0
    snapshots_dropped: list[str] = field(default_factory=list)
    snapshots_kept: list[str] = field(default_factory=list)
    kv_dropped: list[str] = field(default_factory=list)
    checkpoints_rewritten: list[str] = field(default_factory=list)
    checkpoints_kept: list[str] = field(default_factory=list)


class CollectorBusyError(RuntimeError):
    """Another process holds the collector's instance lock (it is still running)."""


@contextlib.contextmanager
def instance_locks(directory: Path) -> Iterator[None]:
    """Hold every ``*.lock`` file of a state directory exclusively (non-blocking).

    Collectors that guard their state with an instance lock (the macOS collector's
    ``flock`` on ``macos-collector.lock``, the scanner runner's ``run.lock``) are
    detected as running: the reset refuses instead of racing them.
    """
    held: list[int] = []
    try:
        for path in sorted(directory.glob("*.lock")):
            fd = os.open(path, os.O_RDWR)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                raise CollectorBusyError(f"{path.name} is held by a running process") from None
            held.append(fd)
        yield
    finally:
        for fd in held:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def rebaseline(path: Path, *, collector_id: str, policy: BaselinePolicy) -> StateResetResult:
    """Apply the clean-slate reset to one EXISTING state database in ONE transaction.

    The caller makes sure the collector is stopped; the instance locks of the state
    directory are taken here as a second line of defence.
    """
    if not path.is_file():
        raise FileNotFoundError(f"no collector state at {path}")
    result = StateResetResult(collector_id=collector_id, policy=policy.name)
    with instance_locks(path.parent):
        store = StateStore(path)
        try:
            with store.transaction() as conn:
                checkpoints = {
                    str(k): str(v) for k, v in conn.execute("SELECT key, value FROM checkpoints")
                }
                kv_keys = [str(r[0]) for r in conn.execute("SELECT key FROM kv")]
                names = {str(r[0]) for r in conn.execute("SELECT DISTINCT name FROM snapshots")}
                names |= {str(r[0]) for r in conn.execute("SELECT name FROM snapshot_names")}
                plan = plan_state_reset(
                    policy, checkpoints=checkpoints, kv_keys=kv_keys, snapshot_names=names
                )
                result.outbox_cleared = conn.execute("DELETE FROM outbox").rowcount
                result.dead_cleared = conn.execute("DELETE FROM outbox_dead").rowcount
                for name in plan.drop_snapshots:
                    conn.execute("DELETE FROM snapshots WHERE name = ?", (name,))
                    conn.execute("DELETE FROM snapshot_names WHERE name = ?", (name,))
                for key in plan.drop_kv:
                    conn.execute("DELETE FROM kv WHERE key = ?", (key,))
                now = time.time()
                for key, value in plan.rewrite_checkpoints.items():
                    conn.execute(
                        "UPDATE checkpoints SET value = ?, updated_at = ? WHERE key = ?",
                        (value, now, key),
                    )
        finally:
            store.close()
    result.snapshots_dropped = list(plan.drop_snapshots)
    result.snapshots_kept = list(plan.keep_snapshots)
    result.kv_dropped = list(plan.drop_kv)
    result.checkpoints_rewritten = sorted(plan.rewrite_checkpoints)
    result.checkpoints_kept = list(plan.keep_checkpoints)
    return result


def clear_outbox(path: Path) -> tuple[int, int]:
    """Clear only the outbox and dead letters of an EXISTING state database.

    Used for producers whose other state must stay (the scanner runner). Returns
    ``(outbox rows, dead letters)`` removed; instance locks are honoured.
    """
    if not path.is_file():
        raise FileNotFoundError(f"no outbox at {path}")
    with instance_locks(path.parent):
        store = StateStore(path)
        try:
            with store.transaction() as conn:
                outbox = conn.execute("DELETE FROM outbox").rowcount
                dead = conn.execute("DELETE FROM outbox_dead").rowcount
        finally:
            store.close()
    return outbox, dead

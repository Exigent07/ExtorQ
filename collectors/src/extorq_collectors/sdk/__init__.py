"""ExtorQ collector SDK (owner: platform; PLAN §5, docs/collectors.md).

Public API::

    from extorq_collectors.sdk import Collector, CollectorContext

    class MyCollector(Collector):
        collector_type = "linux_ssh"
        source_types = ("linux.journald",)

        def collect(self, ctx: CollectorContext) -> None:
            cursor = ctx.checkpoints.get("journal.cursor")
            events, new_cursor = read_somehow(cursor)
            ctx.emit(events, {"journal.cursor": new_cursor})   # atomic outbox + checkpoint

* ``ctx.emit(records, checkpoints)`` validates every record against the contracts
  (schema 2.0, including ``Service`` / ``ServiceInstance``) and commits outbox rows,
  checkpoints and staged snapshots in ONE SQLite transaction.
* ``ctx.diff_snapshot(name, items)`` -> ``(added, changed, removed)``; the new
  snapshot is persisted by the next ``emit`` together with the diff records.
* ``ctx.committed_snapshot(name)`` returns the last committed snapshot (a read-only
  copy), e.g. to carry over items of a source that could not be read this cycle.
* ``ctx.mark_degraded(reason)`` reports a cycle that completed only partly: health
  ``status=degraded`` with the reason, while ``last_success_at`` still advances.
* :func:`asset_upsert` builds Asset records only when content changed (or a
  refresh is due), persisted atomically with the emit.
* The runner (``extorq-collect run``) isolates collectors in threads, emits
  CollectorHealth every cycle and delivers the outbox at least once.
"""

from extorq_collectors.sdk.assets import asset_upsert
from extorq_collectors.sdk.base import (
    Checkpoints,
    Collector,
    CollectorContext,
    KVState,
    SnapshotDiff,
    to_record_json,
)
from extorq_collectors.sdk.client import (
    AuthError,
    GatewayClient,
    GatewayError,
    RejectedError,
    RetryableError,
)
from extorq_collectors.sdk.config import CollectorConfig, ConfigLoadError, load_collector_configs
from extorq_collectors.sdk.sender import Sender, SendReport
from extorq_collectors.sdk.state import StateStore

__all__ = [
    "AuthError",
    "Checkpoints",
    "Collector",
    "CollectorConfig",
    "CollectorContext",
    "ConfigLoadError",
    "GatewayClient",
    "GatewayError",
    "KVState",
    "RejectedError",
    "RetryableError",
    "SendReport",
    "Sender",
    "SnapshotDiff",
    "StateStore",
    "asset_upsert",
    "load_collector_configs",
    "to_record_json",
]

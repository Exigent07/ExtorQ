"""Collector SDK core: the :class:`Collector` interface and :class:`CollectorContext`.

A collector is a class with ``collector_type``, ``source_types`` and
``collect(ctx)``. It is instantiated with no arguments and reads its settings
from ``ctx.config``. Inside ``collect`` it reads its checkpoints, gathers
telemetry and calls ``ctx.emit(records, checkpoints)``:

* ``emit`` validates every record against the contracts, then commits the
  outbox rows, the checkpoint updates and any staged snapshot in ONE SQLite
  transaction. A crash before the commit loses nothing (the source is re-read
  from the old checkpoint); a crash after it loses nothing (the outbox is
  durable). Re-reads produce the same deterministic ids, so the gateway's dedup
  and ClickHouse's ReplacingMergeTree absorb repeats.
* ``diff_snapshot(name, items)`` compares the current item set with the stored
  one and returns ``(added, changed, removed)``; the new snapshot is persisted
  by the next ``emit`` in the same transaction as the records describing it.

Exceptions raised by ``collect`` are caught by the runner, reported in
CollectorHealth (sanitised) and never affect other collectors. A cycle that
succeeded only partly (one source of several failed, rate limited, a broader
token than needed) calls ``ctx.mark_degraded(reason)``: the runner then reports
``status=degraded`` with the reasons in ``last_error`` and ``details``, while
``last_success_at`` still advances (the cycle did complete).

``ctx.committed_snapshot(name)`` returns the last COMMITTED snapshot (read-only
copy), e.g. to carry over items of a source that could not be read this cycle.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel

from extorq.common.logging import get_logger
from extorq.contracts.asset import Asset, InventoryItem
from extorq.contracts.common import utc_now
from extorq.contracts.event import SecurityEvent
from extorq.contracts.finding import PostureFinding
from extorq.contracts.health import CollectorHealth
from extorq.contracts.identity import canonical_json, sha256_hex
from extorq.contracts.ingest import INGEST_RECORD_ADAPTER, MAX_RECORD_BYTES, IngestRecord
from extorq.contracts.scan import ScanRun
from extorq.contracts.service import Service, ServiceInstance
from extorq_collectors.sdk.config import CollectorConfig
from extorq_collectors.sdk.state import StagedSnapshot, StateStore

#: Upper bound of distinct ``mark_degraded`` reasons kept per cycle.
MAX_DEGRADED_REASONS = 8

_KIND_BY_MODEL: dict[type[BaseModel], str] = {
    SecurityEvent: "event",
    Asset: "asset",
    InventoryItem: "inventory_item",
    PostureFinding: "finding",
    ScanRun: "scan_run",
    CollectorHealth: "collector_health",
    Service: "service",
    ServiceInstance: "service_instance",
}


class Collector(ABC):
    """Base class for every ExtorQ collector."""

    #: e.g. "macos", "linux_ssh", "k8s_inventory", "github", "scanner".
    collector_type: ClassVar[str]
    #: Source types this collector emits (must be allowed for its producer).
    source_types: ClassVar[tuple[str, ...]]
    collector_version: ClassVar[str] = "0.1.0"

    def setup(self, ctx: CollectorContext) -> None:  # noqa: B027 - optional hook
        """Called once before the first ``collect`` (open clients, verify access)."""

    @abstractmethod
    def collect(self, ctx: CollectorContext) -> None:
        """Gather telemetry and call ``ctx.emit``. Raise on failure (the runner reports it)."""

    def close(self) -> None:  # noqa: B027 - optional hook
        """Release resources at shutdown."""


@dataclass
class SnapshotDiff:
    """Result of :meth:`CollectorContext.diff_snapshot` (unpacks as a 3-tuple).

    ``previous`` holds the stored item for every changed or removed key.
    """

    added: dict[str, dict[str, Any]]
    changed: dict[str, dict[str, Any]]
    removed: dict[str, dict[str, Any]]
    previous: dict[str, dict[str, Any]] = field(default_factory=dict)
    baseline: bool = False

    def __iter__(self) -> Iterator[dict[str, dict[str, Any]]]:
        yield self.added
        yield self.changed
        yield self.removed

    def __bool__(self) -> bool:
        return bool(self.added or self.changed or self.removed)


class Checkpoints:
    """Read-only view; checkpoints are written only through ``ctx.emit``."""

    def __init__(self, store: StateStore) -> None:
        self._store = store

    def get(self, key: str, default: str | None = None) -> str | None:
        value = self._store.checkpoint(key)
        return default if value is None else value

    def all(self) -> dict[str, str]:
        return self._store.checkpoints()


class KVState:
    """Small JSON-serialisable state that does not need to be atomic with records."""

    def __init__(self, store: StateStore) -> None:
        self._store = store

    def get(self, key: str, default: Any = None) -> Any:
        value = self._store.kv_get(key)
        return default if value is None else value

    def set(self, key: str, value: Any) -> None:
        self._store.kv_set(key, value)

    def delete(self, key: str) -> None:
        self._store.kv_delete(key)


def to_record_json(record: IngestRecord | BaseModel | Mapping[str, Any]) -> tuple[str, str]:
    """Validate one record and return ``(kind, canonical JSON)`` for the outbox."""
    if isinstance(record, BaseModel) and type(record) in _KIND_BY_MODEL:
        raw: Any = {"kind": _KIND_BY_MODEL[type(record)], "data": record.model_dump(mode="json")}
    elif isinstance(record, BaseModel):
        raw = record.model_dump(mode="json")
    else:
        raw = dict(record)
    validated = INGEST_RECORD_ADAPTER.validate_python(raw)
    text = canonical_json({"kind": validated.kind, "data": validated.data.model_dump(mode="json")})
    size = len(text.encode("utf-8"))
    if size > MAX_RECORD_BYTES:
        raise ValueError(
            f"record of kind {validated.kind} is {size} bytes (limit {MAX_RECORD_BYTES})"
        )
    return validated.kind, text


class CollectorContext:
    """Everything a collector needs during ``collect``."""

    def __init__(
        self, config: CollectorConfig, store: StateStore, collector_version: str = "0.1.0"
    ) -> None:
        self.collector_id = config.collector_id
        self.asset_id = config.asset_id
        self.producer_id = config.producer_id
        self.collector_config = config
        self.config: dict[str, Any] = dict(config.settings)
        self.collector_version = collector_version
        self.store = store
        self.state = KVState(store)
        self.checkpoints = Checkpoints(store)
        self.log = get_logger(f"extorq.collector.{config.collector_id}")
        self._staged: dict[str, StagedSnapshot] = {}
        # Per-cycle observations used for CollectorHealth.
        self.events_emitted = 0
        self.records_emitted = 0
        self.lag_seconds: float | None = None
        self.checkpoint_summary: str | None = None
        self.health_details: dict[str, Any] = {}
        self._degraded: list[str] = []

    def begin_cycle(self) -> None:
        self.events_emitted = 0
        self.records_emitted = 0
        self.lag_seconds = None
        self.health_details = {}
        self._degraded = []
        self._staged.clear()

    # ── health hints ──────────────────────────────────────────────────

    def mark_degraded(self, reason: str) -> None:
        """Report the CURRENT cycle as degraded (partial success) with a short reason.

        Use it when ``collect`` completes but some of its work did not (one source or
        repository failed, rate limited, a broader credential than required in use). The
        runner reports ``HealthStatus.DEGRADED``, puts the reasons in ``last_error`` and
        ``details.degraded_reasons``, and still advances ``last_success_at``. Reasons are
        redacted and sanitised by the runner; never put secrets or raw telemetry in them.
        Applies to this cycle only: call it again every cycle while the condition lasts.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("mark_degraded needs a non-empty reason")
        text = reason.strip()
        if text not in self._degraded and len(self._degraded) < MAX_DEGRADED_REASONS:
            self._degraded.append(text)

    @property
    def degraded_reasons(self) -> tuple[str, ...]:
        """Reasons passed to :meth:`mark_degraded` during the current cycle (raw)."""
        return tuple(self._degraded)

    # ── snapshots (read side) ─────────────────────────────────────────

    def committed_snapshot(self, name: str) -> dict[str, dict[str, Any]]:
        """The last COMMITTED snapshot ``name`` as ``{item_key: item}`` (a fresh copy).

        Read-only: changing the result changes nothing. Items staged by
        :meth:`diff_snapshot` in this cycle are not included until ``emit`` commits them.
        ``{}`` when the snapshot was never committed (see :meth:`has_snapshot`).
        """
        return {key: json.loads(text) for key, (text, _digest) in self.store.snapshot(name).items()}

    def discard_staged(self) -> list[str]:
        """Drop snapshots staged by ``diff_snapshot`` but never emitted; return their names.

        The runner calls this after every cycle: a snapshot only advances together with
        the records describing it, never on its own (e.g. after a failed cycle).
        """
        names = sorted(self._staged)
        self._staged.clear()
        return names

    @staticmethod
    def now() -> datetime:
        return utc_now()

    def emit(
        self,
        records: Sequence[IngestRecord | BaseModel | Mapping[str, Any]],
        checkpoints: Mapping[str, str] | None = None,
    ) -> int:
        """Atomically append ``records`` to the outbox with checkpoints and staged snapshots."""
        prepared = [to_record_json(record) for record in records]  # validate ALL first
        for key, value in (checkpoints or {}).items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise TypeError("checkpoint keys and values must be strings")
        staged = list(self._staged.values())
        count = self.store.commit(prepared, checkpoints, staged)
        self._staged.clear()
        self.records_emitted += count
        self.events_emitted += sum(1 for kind, _ in prepared if kind == "event")
        return count

    def has_snapshot(self, name: str) -> bool:
        """False before the first committed snapshot (a baseline diff reports everything added)."""
        return self.store.has_snapshot(name)

    def diff_snapshot(self, name: str, items: Mapping[str, Mapping[str, Any]]) -> SnapshotDiff:
        """Diff ``items`` against the stored snapshot; stage the new one for the next emit."""
        stored = self.store.snapshot(name)
        current: dict[str, tuple[str, str]] = {}
        for key, item in items.items():
            text = canonical_json(item)
            current[str(key)] = (text, sha256_hex(text))
        added: dict[str, dict[str, Any]] = {}
        changed: dict[str, dict[str, Any]] = {}
        removed: dict[str, dict[str, Any]] = {}
        previous: dict[str, dict[str, Any]] = {}
        for key, (_text, digest) in current.items():
            if key not in stored:
                added[key] = dict(items[key])
            elif stored[key][1] != digest:
                changed[key] = dict(items[key])
                previous[key] = json.loads(stored[key][0])
        for key, (text, _digest) in stored.items():
            if key not in current:
                removed[key] = json.loads(text)
                previous[key] = removed[key]
        self._staged[name] = StagedSnapshot(name=name, items=current)
        return SnapshotDiff(
            added, changed, removed, previous, baseline=not self.store.has_snapshot(name)
        )

    def report_lag(self, newest_source_time: datetime | None) -> None:
        """Record how far behind the newest collected source timestamp is."""
        if newest_source_time is None:
            return
        lag = (utc_now() - newest_source_time).total_seconds()
        self.lag_seconds = max(0.0, lag)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

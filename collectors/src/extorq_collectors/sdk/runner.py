"""Collector runner: ``extorq-collect run [--only a,b] [--once]``.

* Loads ``config/collectors/*.yaml``; each enabled collector runs in its own
  thread with its own state DB, gateway client and sender. An exception (or a
  hang inside one collector) never stops the others.
* Every cycle: ``collect(ctx)`` -> CollectorHealth record (status, last attempt,
  last success, lag, outbox depth, sanitised last error) -> drain the outbox.
  Status: ``failed`` when ``collect`` raised; ``degraded`` when it completed but called
  ``ctx.mark_degraded(reason)``, or delivery is failing / records were dead-lettered;
  otherwise ``ok``.
* Snapshots staged with ``diff_snapshot`` advance ONLY with an explicit
  ``ctx.emit``: after a failed cycle (or a diff that was never emitted) they are
  discarded, so the next cycle diffs against the last committed state again.
* Between cycles the thread keeps retrying delivery of buffered records (with
  the sender's backoff), so a gateway outage only delays delivery.
* ``--once`` runs one cycle per collector, then drains outboxes up to a
  deadline; exit code 0 only if every collector succeeded and its outbox drained.
"""

from __future__ import annotations

import importlib
import re
import signal
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import FrameType
from typing import Any

from pydantic import ValidationError

from extorq.common.config import Settings, get_settings, read_secret_file
from extorq.common.logging import get_logger
from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts.common import HealthStatus, utc_now
from extorq.contracts.health import CollectorHealth
from extorq.contracts.identity import canonical_json
from extorq_collectors.sdk.base import Collector, CollectorContext, to_record_json
from extorq_collectors.sdk.client import GatewayClient
from extorq_collectors.sdk.config import CollectorConfig
from extorq_collectors.sdk.sender import Sender
from extorq_collectors.sdk.state import StateStore, read_status

log = get_logger("extorq.collect.runner")

ONCE_DRAIN_SECONDS = 60.0
RETRY_POLL_SECONDS = 5.0
HEALTH_KV_KEY = "health.last"
MAX_DETAIL_KEYS = 48
_DETAIL_KEY_RE = re.compile(r"[^a-z0-9_.-]+")


class RunnerError(RuntimeError):
    """Programming/lifecycle error inside the runner (never caused by telemetry)."""


def sanitize_error(exc: BaseException, limit: int = 1024) -> str:
    return sanitize_untrusted(redact_text(f"{type(exc).__name__}: {exc}")[0], limit)


def _clean_str(value: str, limit: int) -> str:
    return sanitize_untrusted(redact_text(value)[0], limit)


def sanitize_details(details: Mapping[str, Any]) -> dict[str, Any]:
    """Coerce collector-provided health details into the contract's Attributes shape.

    Keys are normalised to ``^[a-z0-9][a-z0-9_.-]{0,63}$``; nested mappings become
    canonical JSON strings; strings/lists are redacted, sanitised and bounded. A bad
    detail therefore never prevents the health record itself from being emitted.
    """
    clean: dict[str, Any] = {}
    for raw_key, value in details.items():
        if len(clean) >= MAX_DETAIL_KEYS:
            clean["details_truncated"] = True
            break
        key = _DETAIL_KEY_RE.sub("_", str(raw_key).lower()).strip("_.-")[:64] or "detail"
        if not key[0].isalnum():
            key = f"k{key}"[:64]
        if value is None or isinstance(value, bool | int):
            clean[key] = value
        elif isinstance(value, float):
            clean[key] = value if value == value and abs(value) != float("inf") else None
        elif isinstance(value, str):
            clean[key] = _clean_str(value, 2048)
        elif isinstance(value, list | tuple | set | frozenset):
            items: list[str | int | float | bool] = []
            for item in list(value)[:64]:
                finite = isinstance(item, float) and item == item and abs(item) != float("inf")
                if isinstance(item, bool | int) or finite:
                    items.append(item)
                else:
                    items.append(_clean_str(item if isinstance(item, str) else str(item), 512))
            clean[key] = items
        else:
            try:
                text = canonical_json(value)
            except (TypeError, ValueError):
                text = str(value)
            clean[key] = _clean_str(text, 2048)
    return clean


def load_collector_class(spec: str) -> type[Collector]:
    module_name, _, class_name = spec.partition(":")
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    if not (isinstance(cls, type) and issubclass(cls, Collector)):
        raise TypeError(f"{spec} is not a Collector subclass")
    return cls


def state_path(settings: Settings, collector_id: str) -> Path:
    return settings.resolve(settings.collectors_state_dir) / collector_id / "state.db"


def token_for(settings: Settings, producer_id: str) -> str:
    return read_secret_file(settings.resolve(settings.tokens_dir) / f"{producer_id}.token")


def default_client(settings: Settings, producer_id: str) -> GatewayClient:
    return GatewayClient(
        settings.gateway_url,
        token_for(settings, producer_id),
        settings.resolve(settings.tls_ca_file),
    )


@dataclass
class CycleOutcome:
    ok: bool
    error: str | None = None


@dataclass
class WorkerStatus:
    collector_id: str
    last_attempt_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    cycles: int = 0
    failures: int = 0
    finished: bool = False
    results: list[CycleOutcome] = field(default_factory=list)


class CollectorWorker:
    """Runs one collector: collect -> health -> send, on its interval."""

    def __init__(
        self,
        config: CollectorConfig,
        settings: Settings,
        *,
        collector: Collector | None = None,
        client_factory: Callable[[CollectorConfig], GatewayClient] | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self.config = config
        self.settings = settings
        self.stop_event = stop_event or threading.Event()
        self.status = WorkerStatus(config.collector_id)
        self._collector = collector
        self._client_factory = client_factory or (
            lambda cfg: default_client(self.settings, cfg.producer_id)
        )
        self._store: StateStore | None = None
        self._ctx: CollectorContext | None = None
        self._sender: Sender | None = None
        self._setup_done = False

    # ── lifecycle ─────────────────────────────────────────────────────

    def open(self) -> None:
        if self._collector is None:
            self._collector = load_collector_class(self.config.module)()
        self._store = StateStore(state_path(self.settings, self.config.collector_id))
        self._ctx = CollectorContext(
            self.config, self._store, collector_version=self._collector.collector_version
        )
        self._sender = Sender(
            self._store, self._client_factory(self.config), self.config.producer_id
        )
        restored = self._store.kv_get(HEALTH_KV_KEY) or {}
        if restored.get("last_success_at"):
            self.status.last_success_at = datetime.fromisoformat(restored["last_success_at"])

    @property
    def collector(self) -> Collector:
        if self._collector is None:
            raise RunnerError("worker not opened")
        return self._collector

    @property
    def store(self) -> StateStore:
        if self._store is None:
            raise RunnerError("worker not opened")
        return self._store

    @property
    def ctx(self) -> CollectorContext:
        if self._ctx is None:
            raise RunnerError("worker not opened")
        return self._ctx

    @property
    def sender(self) -> Sender:
        if self._sender is None:
            raise RunnerError("worker not opened")
        return self._sender

    @property
    def opened(self) -> bool:
        return self._store is not None

    # ── one cycle ─────────────────────────────────────────────────────

    def run_cycle(self) -> CycleOutcome:
        ctx = self.ctx
        ctx.begin_cycle()
        self.status.last_attempt_at = utc_now()
        self.status.cycles += 1
        outcome = CycleOutcome(ok=True)
        try:
            if not self._setup_done:
                self.collector.setup(ctx)
                self._setup_done = True
            self.collector.collect(ctx)
            self.status.last_success_at = utc_now()
            self.status.last_error = None
            if ctx.degraded_reasons:
                log.warning(
                    "collector_cycle_degraded",
                    collector_id=self.config.collector_id,
                    reasons=[_clean_str(r, 256) for r in ctx.degraded_reasons],
                )
        except Exception as exc:  # noqa: BLE001 - isolation: report, never propagate
            self.status.failures += 1
            self.status.last_error = sanitize_error(exc)
            outcome = CycleOutcome(ok=False, error=self.status.last_error)
            log.error(
                "collector_cycle_failed",
                collector_id=self.config.collector_id,
                error=self.status.last_error,
            )
        leftover = ctx.discard_staged()
        if leftover and outcome.ok:
            log.warning(
                "collector_snapshot_not_emitted",
                collector_id=self.config.collector_id,
                snapshots=leftover[:10],
            )
        try:
            self.emit_health(outcome)
        except Exception as exc:  # noqa: BLE001 - health must not kill the worker
            log.error(
                "collector_health_failed",
                collector_id=self.config.collector_id,
                error=sanitize_error(exc),
            )
        self.status.results.append(outcome)
        self.send(deadline=time.monotonic() + min(30.0, self.config.interval_seconds))
        return outcome

    def health_status(self, outcome: CycleOutcome) -> HealthStatus:
        if not outcome.ok:
            return HealthStatus.FAILED
        if self.ctx.degraded_reasons or self.sender.state.last_error or self.store.dead_count():
            return HealthStatus.DEGRADED
        return HealthStatus.OK

    def build_health(self, outcome: CycleOutcome) -> CollectorHealth:
        ctx, store, sender = self.ctx, self.store, self.sender
        source_types = [str(s) for s in (getattr(self.collector, "source_types", ()) or ())]
        degraded = [_clean_str(reason, 256) for reason in ctx.degraded_reasons]
        parts = [self.status.last_error, sender.state.last_error]
        if degraded and outcome.ok:
            parts.append("degraded: " + "; ".join(degraded))
        last_error = "; ".join(part for part in parts if part)
        details: dict[str, Any] = {
            "outbox_dead": store.dead_count(),
            "sender_consecutive_failures": sender.state.consecutive_failures,
            "quarantined_total": sender.state.totals["quarantined"],
        }
        oldest = store.oldest_outbox_age()
        if oldest is not None:
            details["outbox_oldest_age_seconds"] = round(oldest, 1)
        details.update(sanitize_details(ctx.health_details))
        if degraded:
            details["degraded_reasons"] = degraded
        summary = ctx.checkpoint_summary
        fields: dict[str, Any] = {
            "collector_id": self.config.collector_id,
            "collector_type": self.collector.collector_type,
            "asset_id": self.config.asset_id,
            "source_types": source_types,
            "status": self.health_status(outcome),
            "reported_at": utc_now(),
            "last_attempt_at": self.status.last_attempt_at,
            "last_success_at": self.status.last_success_at,
            "last_error": _clean_str(last_error, 2048) if last_error else None,
            "events_collected": ctx.events_emitted,
            "records_buffered": store.outbox_depth(),
            "lag_seconds": ctx.lag_seconds,
            "checkpoint_summary": _clean_str(summary, 256) if summary else None,
            "collector_version": self.collector.collector_version,
            "interval_seconds": self.config.interval_seconds,
            "details": details,
        }
        try:
            return CollectorHealth(**fields)
        except ValidationError:
            # Never lose the health signal because of collector-provided extras.
            fields["details"] = {"details_invalid": True}
            fields["checkpoint_summary"] = None
            return CollectorHealth(**fields)

    def emit_health(self, outcome: CycleOutcome) -> None:
        health = self.build_health(outcome)
        # Committed directly (not via ctx.emit): health never carries staged snapshots.
        self.store.commit([to_record_json(health)])
        self.store.kv_set(
            HEALTH_KV_KEY,
            {
                "status": health.status.value,
                "reported_at": health.reported_at.isoformat(),
                "last_success_at": health.last_success_at.isoformat()
                if health.last_success_at
                else None,
                "last_error": health.last_error,
            },
        )

    def send(self, *, deadline: float) -> bool:
        report = self.sender.send_pending(deadline=deadline)
        if report.error:
            log.warning(
                "collector_send_deferred", collector_id=self.config.collector_id, error=report.error
            )
        return report.drained

    def drain(self, deadline: float) -> None:
        """Deliver buffered records until empty, deadline, or stop requested."""
        while self.store.outbox_depth() and time.monotonic() < deadline:
            if self.stop_event.is_set():
                return
            if self.sender.ready():
                self.send(deadline=deadline)
            else:
                self.stop_event.wait(min(0.5, max(0.0, deadline - time.monotonic())))

    def run_forever(self) -> None:
        next_cycle = time.monotonic()
        while not self.stop_event.is_set():
            now = time.monotonic()
            if now >= next_cycle:
                self.run_cycle()
                next_cycle = time.monotonic() + self.config.interval_seconds
                continue
            wait = min(RETRY_POLL_SECONDS, next_cycle - now)
            if self.stop_event.wait(wait):
                break
            if self.store.outbox_depth() and self.sender.ready():
                self.send(deadline=time.monotonic() + RETRY_POLL_SECONDS)

    def close(self) -> None:
        try:
            if self._collector is not None:
                self._collector.close()
        finally:
            if self._sender is not None:
                self._sender.client.close()
            if self._store is not None:
                self._store.close()
            self.status.finished = True


class Runner:
    def __init__(
        self,
        configs: list[CollectorConfig],
        settings: Settings | None = None,
        *,
        client_factory: Callable[[CollectorConfig], GatewayClient] | None = None,
        drain_seconds: float = ONCE_DRAIN_SECONDS,
    ) -> None:
        self.configs = configs
        self.settings = settings or get_settings()
        self.stop_event = threading.Event()
        self.workers: list[CollectorWorker] = []
        self.client_factory = client_factory
        self.drain_seconds = drain_seconds

    def _start(self, target: Callable[[CollectorWorker], None]) -> list[threading.Thread]:
        threads = []
        for config in self.configs:
            worker = CollectorWorker(
                config,
                self.settings,
                stop_event=self.stop_event,
                client_factory=self.client_factory,
            )
            self.workers.append(worker)
            thread = threading.Thread(
                target=self._guard,
                args=(worker, target),
                name=f"collector-{config.collector_id}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)
        return threads

    def _guard(self, worker: CollectorWorker, target: Callable[[CollectorWorker], None]) -> None:
        try:
            worker.open()
            target(worker)
        except Exception as exc:  # noqa: BLE001 - one collector must never stop the others
            worker.status.last_error = sanitize_error(exc)
            worker.status.results.append(CycleOutcome(ok=False, error=worker.status.last_error))
            log.error(
                "collector_worker_crashed",
                collector_id=worker.config.collector_id,
                error=worker.status.last_error,
            )
        finally:
            try:
                worker.close()
            except Exception as exc:  # noqa: BLE001
                log.error(
                    "collector_close_failed",
                    collector_id=worker.config.collector_id,
                    error=sanitize_error(exc),
                )

    def _once(self, worker: CollectorWorker) -> None:
        worker.run_cycle()
        worker.drain(time.monotonic() + self.drain_seconds)

    def run(self, *, once: bool = False) -> int:
        if not self.configs:
            log.warning("no_collectors_configured")
            return 1
        if threading.current_thread() is threading.main_thread():

            def _stop(signum: int, _frame: FrameType | None) -> None:
                log.info("collectors_stop_requested", signal=signum)
                self.stop_event.set()

            signal.signal(signal.SIGTERM, _stop)
            signal.signal(signal.SIGINT, _stop)
        log.info(
            "collectors_starting", collectors=[c.collector_id for c in self.configs], once=once
        )
        threads = self._start(self._once if once else (lambda w: w.run_forever()))
        for thread in threads:
            while thread.is_alive():
                thread.join(timeout=1.0)
        failed = [
            w.config.collector_id
            for w in self.workers
            if not w.status.results or not all(r.ok for r in w.status.results)
        ]
        if once:
            undelivered = [
                w.config.collector_id for w in self.workers if self._outbox_depth(w) != 0
            ]
            log.info("collectors_once_complete", failed=failed, undelivered=undelivered)
            return 1 if failed or undelivered else 0
        return 0

    def _outbox_depth(self, worker: CollectorWorker) -> int:
        status = read_status(state_path(self.settings, worker.config.collector_id))
        depth = status.get("outbox_depth") if status else None
        return depth if isinstance(depth, int) else -1

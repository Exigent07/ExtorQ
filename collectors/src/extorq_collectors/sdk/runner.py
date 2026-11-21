"""Collector runner: ``extorq-collect run [--only a,b] [--once]``.

* Loads ``config/collectors/*.yaml``; each enabled collector runs in its own
  thread with its own state DB, gateway client and sender. An exception (or a
  hang inside one collector) never stops the others.
* Every cycle: ``collect(ctx)`` -> CollectorHealth record (status, last attempt,
  last success, lag, outbox depth, sanitised last error) -> drain the outbox.
* Between cycles the thread keeps retrying delivery of buffered records (with
  the sender's backoff), so a gateway outage only delays delivery.
* ``--once`` runs one cycle per collector, then drains outboxes up to a
  deadline; exit code 0 only if every collector succeeded and its outbox drained.
"""

from __future__ import annotations

import importlib
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from types import FrameType
from typing import Any

from extorq.common.config import Settings, get_settings, read_secret_file
from extorq.common.logging import get_logger
from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts.common import HealthStatus, utc_now
from extorq.contracts.health import CollectorHealth
from extorq_collectors.sdk.base import Collector, CollectorContext
from extorq_collectors.sdk.client import GatewayClient
from extorq_collectors.sdk.config import CollectorConfig
from extorq_collectors.sdk.sender import Sender
from extorq_collectors.sdk.state import StateStore

log = get_logger("extorq.collect.runner")

ONCE_DRAIN_SECONDS = 60.0
RETRY_POLL_SECONDS = 5.0
HEALTH_KV_KEY = "health.last"


def sanitize_error(exc: BaseException, limit: int = 1024) -> str:
    return sanitize_untrusted(redact_text(f"{type(exc).__name__}: {exc}")[0], limit)


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
        self._client_factory = client_factory or self._default_client
        self.store: StateStore | None = None
        self.ctx: CollectorContext | None = None
        self.sender: Sender | None = None
        self._setup_done = False

    def _default_client(self, config: CollectorConfig) -> GatewayClient:
        return GatewayClient(self.settings.gateway_url, token_for(self.settings, config.producer_id),
                             self.settings.resolve(self.settings.tls_ca_file))

    def open(self) -> None:
        if self._collector is None:
            self._collector = load_collector_class(self.config.module)()
        self.store = StateStore(state_path(self.settings, self.config.collector_id))
        self.ctx = CollectorContext(self.config, self.store,
                                    collector_version=self._collector.collector_version)
        self.sender = Sender(self.store, self._client_factory(self.config), self.config.producer_id)
        restored = self.store.kv_get(HEALTH_KV_KEY) or {}
        if restored.get("last_success_at"):
            self.status.last_success_at = datetime.fromisoformat(restored["last_success_at"])

    @property
    def collector(self) -> Collector:
        if self._collector is None:
            raise RuntimeError("worker not opened")
        return self._collector

    def run_cycle(self) -> CycleOutcome:
        assert self.ctx is not None and self.store is not None and self.sender is not None
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
        except Exception as exc:  # noqa: BLE001 - isolation: report, never propagate
            self.status.failures += 1
            self.status.last_error = sanitize_error(exc)
            outcome = CycleOutcome(ok=False, error=self.status.last_error)
            log.error("collector_cycle_failed", collector_id=self.config.collector_id,
                      error=self.status.last_error)
        try:
            self.emit_health(outcome)
        except Exception as exc:  # noqa: BLE001 - health must not kill the worker
            log.error("collector_health_failed", collector_id=self.config.collector_id,
                      error=sanitize_error(exc))
        self.status.results.append(outcome)
        self.send(deadline=time.monotonic() + min(30.0, self.config.interval_seconds))
        return outcome

    def health_status(self, outcome: CycleOutcome) -> HealthStatus:
        if not outcome.ok:
            return HealthStatus.FAILED
        assert self.store is not None and self.sender is not None
        if self.sender.state.last_error or self.store.dead_count():
            return HealthStatus.DEGRADED
        return HealthStatus.OK

    def emit_health(self, outcome: CycleOutcome) -> None:
        assert self.ctx is not None and self.store is not None and self.sender is not None
        ctx, store, sender = self.ctx, self.store, self.sender
        source_types = list(getattr(self.collector, "source_types", ()) or ())
        last_error = self.status.last_error or sender.state.last_error
        details: dict[str, Any] = {
            "outbox_dead": store.dead_count(),
            "sender_consecutive_failures": sender.state.consecutive_failures,
            "quarantined_total": sender.state.totals["quarantined"],
        }
        oldest = store.oldest_outbox_age()
        if oldest is not None:
            details["outbox_oldest_age_seconds"] = round(oldest, 1)
        for key, value in list(ctx.health_details.items())[:32]:
            details[str(key)[:64].lower()] = value
        health = CollectorHealth(
            collector_id=self.config.collector_id,
            collector_type=self.collector.collector_type,
            asset_id=self.config.asset_id,
            source_types=source_types,
            status=self.health_status(outcome),
            reported_at=utc_now(),
            last_attempt_at=self.status.last_attempt_at,
            last_success_at=self.status.last_success_at,
            last_error=last_error[:2048] if last_error else None,
            events_collected=ctx.events_emitted,
            records_buffered=store.outbox_depth(),
            lag_seconds=ctx.lag_seconds,
            checkpoint_summary=(ctx.checkpoint_summary or None) and ctx.checkpoint_summary[:256],
            collector_version=self.collector.collector_version,
            interval_seconds=self.config.interval_seconds,
            details=details,
        )
        ctx_events = ctx.events_emitted
        ctx.emit([health])
        ctx.events_emitted = ctx_events
        store.kv_set(HEALTH_KV_KEY, {
            "status": health.status.value,
            "reported_at": health.reported_at.isoformat(),
            "last_success_at": health.last_success_at.isoformat()
            if health.last_success_at else None,
            "last_error": health.last_error,
        })

    def send(self, *, deadline: float) -> bool:
        assert self.sender is not None
        report = self.sender.send_pending(deadline=deadline)
        if report.error:
            log.warning("collector_send_deferred", collector_id=self.config.collector_id,
                        error=report.error)
        return report.drained

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
            assert self.store is not None and self.sender is not None
            if self.store.outbox_depth() and self.sender.ready():
                self.send(deadline=time.monotonic() + RETRY_POLL_SECONDS)

    def close(self) -> None:
        try:
            if self._collector is not None:
                self._collector.close()
        finally:
            if self.sender is not None:
                self.sender.client.close()
            if self.store is not None:
                self.store.close()
            self.status.finished = True


class Runner:
    def __init__(self, configs: list[CollectorConfig], settings: Settings | None = None) -> None:
        self.configs = configs
        self.settings = settings or get_settings()
        self.stop_event = threading.Event()
        self.workers: list[CollectorWorker] = []

    def _start(self, target: Callable[[CollectorWorker], None]) -> list[threading.Thread]:
        threads = []
        for config in self.configs:
            worker = CollectorWorker(config, self.settings, stop_event=self.stop_event)
            self.workers.append(worker)
            thread = threading.Thread(target=self._guard, args=(worker, target),
                                      name=f"collector-{config.collector_id}", daemon=True)
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
            log.error("collector_worker_crashed", collector_id=worker.config.collector_id,
                      error=worker.status.last_error)
        finally:
            try:
                worker.close()
            except Exception as exc:  # noqa: BLE001
                log.error("collector_close_failed", collector_id=worker.config.collector_id,
                          error=sanitize_error(exc))

    @staticmethod
    def _once(worker: CollectorWorker) -> None:
        worker.run_cycle()
        deadline = time.monotonic() + ONCE_DRAIN_SECONDS
        assert worker.store is not None and worker.sender is not None
        while worker.store.outbox_depth() and time.monotonic() < deadline:
            if worker.sender.ready():
                worker.send(deadline=deadline)
            else:
                time.sleep(0.5)

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
        log.info("collectors_starting", collectors=[c.collector_id for c in self.configs],
                 once=once)
        threads = self._start(self._once if once else (lambda w: w.run_forever()))
        for thread in threads:
            while thread.is_alive():
                thread.join(timeout=1.0)
        failed = [w.config.collector_id for w in self.workers
                  if not w.status.results or not all(r.ok for r in w.status.results)]
        if once:
            undelivered = [w.config.collector_id for w in self.workers
                           if w.store is not None and _safe_depth(w) > 0]
            log.info("collectors_once_complete", failed=failed, undelivered=undelivered)
            return 1 if failed or undelivered else 0
        return 0


def _safe_depth(worker: CollectorWorker) -> int:
    try:
        return StateStore(state_path(worker.settings, worker.config.collector_id)).outbox_depth()
    except Exception:  # noqa: BLE001
        return -1

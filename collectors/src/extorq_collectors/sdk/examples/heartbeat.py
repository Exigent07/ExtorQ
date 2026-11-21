"""Heartbeat example collector: the smallest real collector (SDK self-test).

It gathers no source telemetry. Each cycle it advances a checkpoint (cycle
counter) through ``ctx.emit`` and lets the runner report CollectorHealth, which
exercises the whole path: outbox -> sender -> HTTPS gateway -> spool -> writer ->
``extorq.collector_health``. Its health record says so explicitly
(``collector_type = heartbeat``, ``details.selftest = true``, source
``extorq.pipeline``) and it runs under the least-privilege ``extorq-selftest``
producer, which may only send collector_health for ``extorq.pipeline``.

Config: ``collectors/src/extorq_collectors/sdk/examples/heartbeat.yaml``.
"""

from __future__ import annotations

from typing import ClassVar

from extorq.contracts.identity import iso_utc
from extorq_collectors import __version__
from extorq_collectors.sdk.base import Collector, CollectorContext

CYCLES_KEY = "heartbeat.cycles"
LAST_CYCLE_KEY = "heartbeat.last_cycle_at"


class HeartbeatCollector(Collector):
    collector_type: ClassVar[str] = "heartbeat"
    source_types: ClassVar[tuple[str, ...]] = ("extorq.pipeline",)
    collector_version: ClassVar[str] = __version__

    def collect(self, ctx: CollectorContext) -> None:
        if ctx.config.get("fail"):
            # Used by tests to prove failure isolation; never set in shipped configs.
            raise RuntimeError("heartbeat configured to fail (test setting)")
        cycles = int(ctx.checkpoints.get(CYCLES_KEY) or "0") + 1
        now = ctx.now()
        ctx.emit([], {CYCLES_KEY: str(cycles), LAST_CYCLE_KEY: iso_utc(now)})
        ctx.checkpoint_summary = f"cycles={cycles}"
        ctx.health_details = {"selftest": True, "cycles": cycles}

"""``extorq detector``: the long-running detection service (compose service ``detector``).

Loop: load + validate rules (invalid rules are reported and skipped), register
them in ``detection_rules``, then evaluate due rules on their own interval,
build investigation contexts for created/updated alerts, and report
``pipeline_health`` for component ``detector``. ClickHouse outages degrade the
service (failed rule runs, backlog, health) but never crash the loop.
"""

from __future__ import annotations

import random
import signal
import threading
from datetime import UTC, datetime
from typing import Any

from extorq.contracts.common import utc_now
from extorq.detection._compat import configure_logging, get_logger, sanitize_error
from extorq.detection.clients import DbClient, connect
from extorq.detection.engine import ContextHook, DetectionEngine, EngineConfig
from extorq.detection.registry import LoadedRule, load_rules_report
from extorq.detection.settings import DetectorSettings

log = get_logger(__name__)


def make_context_hook(
    read_client: DbClient,
    write_client: DbClient,
    rules: list[LoadedRule],
    *,
    max_per_run: int = 50,
) -> ContextHook:
    """Correlation hook: build + persist an InvestigationContext per touched alert."""
    from extorq.correlation.builder import ContextBuilder
    from extorq.correlation.store import save_context

    builder = ContextBuilder(read_client, rules={r.rule_id: r.metadata for r in rules})

    def hook(rule: LoadedRule, alert_ids: list[str]) -> tuple[int, int]:
        built = failed = 0
        for alert_id in alert_ids[:max_per_run]:
            try:
                save_context(write_client, builder.build(alert_id))
                built += 1
            except Exception as exc:  # noqa: BLE001 - one context failure must not stop others
                failed += 1
                log.warning(
                    "context_build_failed",
                    rule_id=rule.rule_id,
                    alert_id=alert_id,
                    error=sanitize_error(exc),
                )
        if len(alert_ids) > max_per_run:
            log.warning(
                "context_build_capped", rule_id=rule.rule_id, skipped=len(alert_ids) - max_per_run
            )
        return built, failed

    return hook


class _Stopper:
    def __init__(self) -> None:
        self.event = threading.Event()

    def install(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, self._handle)

    def _handle(self, signum: int, _frame: Any) -> None:
        log.info("detector_stopping", signal=signum)
        self.event.set()


def build_engine(settings: DetectorSettings) -> tuple[DetectionEngine, list[LoadedRule]]:
    rules, problems = load_rules_report(settings.rules_dir)
    for problem in problems:
        log.error("rule_invalid", problem=str(problem))
    if not rules:
        raise SystemExit("no valid detection rules; refusing to start")
    rules_client = connect("rules_ro")
    detect_client = connect("detect")
    config = EngineConfig(
        ingest_delay_seconds=settings.ingest_delay_seconds,
        max_rows_per_rule=settings.max_rows_per_rule,
        max_episode_seconds=settings.max_episode_seconds,
        catchup_max_seconds=settings.catchup_max_seconds,
        catchup_margin_seconds=settings.catchup_margin_seconds,
    )
    if settings.instance:
        config.instance = settings.instance
    hook = None
    if settings.correlation_enabled:
        hook = make_context_hook(
            detect_client, detect_client, rules, max_per_run=settings.max_contexts_per_run
        )
    engine = DetectionEngine(
        rules,
        rules_client=rules_client,
        read_client=detect_client,
        write_client=detect_client,
        config=config,
        context_hook=hook,
        invalid_rules=len(problems),
    )
    return engine, rules


def _register_with_retry(
    engine: DetectionEngine, rules: list[LoadedRule], attempts: int, stop: threading.Event
) -> bool:
    for attempt in range(1, attempts + 1):
        try:
            engine.register_rules(rules)
            log.info("rules_registered", count=len(rules))
            return True
        except Exception as exc:  # noqa: BLE001 - ClickHouse may still be starting
            delay = min(30.0, 1.0 * 2 ** min(attempt, 5)) * random.uniform(0.5, 1.0)  # noqa: S311
            log.warning(
                "rules_register_failed",
                attempt=attempt,
                retry_in_s=round(delay, 1),
                error=sanitize_error(exc),
            )
            if stop.wait(delay):
                return False
    return False


def _write_health(engine: DetectionEngine) -> None:
    try:
        engine.store.write_health(engine.health())
    except Exception as exc:  # noqa: BLE001 - health is best effort
        log.warning("health_write_failed", error=sanitize_error(exc))


def main(once: bool = False) -> None:
    """Run the detector. ``once`` evaluates every rule a single time and exits."""
    configure_logging("detector")
    settings = DetectorSettings()
    engine, rules = build_engine(settings)
    stopper = _Stopper()
    stopper.install()
    registered = _register_with_retry(
        engine, rules, 1 if once else settings.startup_attempts, stopper.event
    )
    if once:
        runs = engine.run_once(force=True)
        _write_health(engine)
        failed = [r.rule_id for r in runs if r.status.value == "failed"]
        log.info("detector_once_complete", runs=len(runs), failed=failed, registered=registered)
        if failed:
            raise SystemExit(1)
        return
    last_health = datetime.min.replace(tzinfo=UTC)
    while not stopper.event.is_set():
        if not registered:
            registered = _register_with_retry(engine, rules, 1, stopper.event)
        engine.run_once()
        now = utc_now()
        if (now - last_health).total_seconds() >= settings.health_interval_seconds:
            _write_health(engine)
            last_health = now
        next_due = engine.next_due_at()
        wait = settings.poll_seconds
        if next_due is not None:
            wait = max(0.2, min(settings.poll_seconds, (next_due - utc_now()).total_seconds()))
        stopper.event.wait(wait)
    _write_health(engine)
    log.info("detector_stopped")


if __name__ == "__main__":  # pragma: no cover
    import sys

    main(once="--once" in sys.argv)

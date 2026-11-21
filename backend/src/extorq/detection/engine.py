"""Detection engine: schedule rules, evaluate windows, write alerts deterministically.

Evaluation of one rule at time ``now``::

    window = [now - lookback - late_tolerance, now - ingest_delay)

Consecutive windows overlap heavily (lookback >> interval), so events that
arrive late are evaluated again by later runs. Rule SQL runs under the readonly
``extorq_rules_ro`` identity; everything else (missing-source probe, existing
alerts, writes) uses ``extorq_detect``.

For each validated row the engine derives the alert identity
``alert_id(rule_id, group_key, bucket_start | signature)``, loads the newest stored
version (duplicate-safe), and either creates the alert, writes a new version
with merged evidence (created_at preserved), or does nothing. For window_bucket
rules a row whose activity is continuous with an existing alert of the same group
(gap <= bucket_seconds, span <= max_episode_seconds) extends that alert instead
of opening a second one. ``alert_evidence`` rows are written before the alert
version so an interrupted write is repaired by the next run.

Every evaluation produces a ``rule_runs`` row (status, rows, alerts created /
updated, duration, sanitised error, missing sources). A failing rule never stops
the others. If ClickHouse is unavailable, runs fail with a sanitised error, the
rule-run records are kept in a bounded backlog and flushed later, and health is
reported as degraded.
"""

from __future__ import annotations

import socket
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from extorq.contracts.alert import (
    AlertEvidence,
    DedupStrategy,
    DetectionAlert,
    RuleRun,
    RuleRunStatus,
)
from extorq.contracts.common import HealthStatus, utc_now
from extorq.contracts.health import PipelineHealth
from extorq.detection._compat import get_logger, sanitize_error
from extorq.detection.alerts import (
    DETECTOR_VERSION,
    RowError,
    RuleRow,
    alert_identity,
    decide,
    find_continuation,
    parse_rows,
    with_service_ids,
)
from extorq.detection.clients import DbClient
from extorq.detection.registry import LoadedRule
from extorq.detection.store import DetectionStore, rule_to_row

log = get_logger(__name__)

#: Called with (rule, alert_ids) after alerts were created/updated; returns
#: (contexts_built, contexts_failed). Exceptions are contained by the engine.
ContextHook = Callable[[LoadedRule, list[str]], tuple[int, int]]


@dataclass
class EngineConfig:
    ingest_delay_seconds: int = 10
    max_rows_per_rule: int = 1000
    max_episode_seconds: int = 3600
    rule_run_backlog: int = 1000
    #: Late-data catch-up: evaluate events ingested since the rule's last successful run
    #: even if their event_time is older than the normal window (bounded; 0 disables).
    catchup_max_seconds: int = 6 * 3600
    #: Overlap with the previous run's start (covers writer batching and clock skew).
    catchup_margin_seconds: int = 300
    instance: str = field(default_factory=lambda: socket.gethostname()[:128] or "detector")
    detector_version: str = DETECTOR_VERSION


@dataclass
class EngineStats:
    cycles_total: int = 0
    rule_runs_total: int = 0
    rule_failures_total: int = 0
    alerts_created_total: int = 0
    alerts_updated_total: int = 0
    write_errors_total: int = 0
    contexts_built_total: int = 0
    context_failures_total: int = 0
    rule_runs_dropped_total: int = 0
    last_cycle_at: datetime | None = None
    last_cycle_duration_ms: int = 0
    last_cycle_failed_rules: list[str] = field(default_factory=list)
    last_cycle_rules: int = 0
    last_write_at: datetime | None = None
    last_error: str | None = None


class DetectionEngine:
    def __init__(
        self,
        rules: Sequence[LoadedRule],
        *,
        rules_client: DbClient,
        read_client: DbClient,
        write_client: DbClient,
        config: EngineConfig | None = None,
        context_hook: ContextHook | None = None,
        invalid_rules: int = 0,
    ) -> None:
        self.config = config or EngineConfig()
        self.rules = sorted((r for r in rules if r.enabled), key=lambda r: r.rule_id)
        self.disabled_rules = sorted(r.rule_id for r in rules if not r.enabled)
        self.rules_client = rules_client
        self.store = DetectionStore(read_client, write_client, instance=self.config.instance)
        self.context_hook = context_hook
        self.invalid_rules = invalid_rules
        self.stats = EngineStats()
        self._next_due: dict[str, datetime] = {}
        self._last_success: dict[str, datetime] = {}
        self._backlog: deque[RuleRun] = deque()

    # ── registration ─────────────────────────────────────────────────
    def register_rules(self, all_rules: Sequence[LoadedRule], now: datetime | None = None) -> None:
        """Populate ``detection_rules`` (enabled flag per rule; vanished rules are disabled)."""
        loaded_at = now or utc_now()
        rows = [rule_to_row(r, loaded_at, enabled=r.enabled) for r in all_rules]
        try:
            known = self.store.registered_rule_ids()
        except Exception as exc:  # noqa: BLE001 - registration must not prevent detection
            log.warning("rule_registry_read_failed", error=sanitize_error(exc))
            known = set()
        current = {r.rule_id for r in all_rules}
        for vanished in sorted(known - current):
            log.info("rule_no_longer_present", rule_id=vanished)
        self.store.write_rules(rows)
        if known - current:
            self.store.write.insert_rows(
                "detection_rules",
                self._disable_rows(sorted(known - current), loaded_at),
            )

    def _disable_rows(self, rule_ids: list[str], loaded_at: datetime) -> list[dict[str, object]]:
        """Copy the latest registered definition of vanished rules with enabled = 0."""
        result = self.store.read.select(
            "SELECT * FROM detection_rules WHERE rule_id IN {ids:Array(String)} "
            "ORDER BY loaded_at DESC LIMIT 1 BY rule_id",
            {"ids": rule_ids},
        )
        rows = []
        for record in result.dicts():
            record["enabled"] = 0
            record["loaded_at"] = loaded_at
            rows.append(record)
        return rows

    # ── scheduling ───────────────────────────────────────────────────
    def due_rules(self, now: datetime) -> list[LoadedRule]:
        return [r for r in self.rules if self._next_due.get(r.rule_id, now) <= now]

    def next_due_at(self) -> datetime | None:
        if not self.rules:
            return None
        if any(r.rule_id not in self._next_due for r in self.rules):
            return utc_now()
        return min(self._next_due.values())

    def run_once(self, now: datetime | None = None, *, force: bool = False) -> list[RuleRun]:
        """Evaluate every due rule (all rules when ``force``) and record the runs."""
        now = now or utc_now()
        cycle_start = time.monotonic()
        due = list(self.rules) if force else self.due_rules(now)
        runs: list[RuleRun] = []
        for rule in due:
            run = self.evaluate(rule, now)
            runs.append(run)
            self._next_due[rule.rule_id] = now + timedelta(
                seconds=rule.metadata.schedule.interval_seconds
            )
        self._record_runs(runs)
        self.stats.cycles_total += 1
        if due:
            self.stats.last_cycle_at = now
            self.stats.last_cycle_rules = len(due)
            self.stats.last_cycle_duration_ms = int((time.monotonic() - cycle_start) * 1000)
            self.stats.last_cycle_failed_rules = [
                r.rule_id for r in runs if r.status is RuleRunStatus.FAILED
            ]
        return runs

    def _record_runs(self, runs: list[RuleRun]) -> None:
        for run in runs:
            if len(self._backlog) >= self.config.rule_run_backlog:
                self._backlog.popleft()
                self.stats.rule_runs_dropped_total += 1
            self._backlog.append(run)
        if not self._backlog:
            return
        pending = list(self._backlog)
        try:
            self.store.write_rule_runs(pending)
        except Exception as exc:  # noqa: BLE001 - keep detecting; flush later
            self.stats.write_errors_total += 1
            self.stats.last_error = sanitize_error(exc)
            log.warning("rule_runs_write_failed", pending=len(pending), error=self.stats.last_error)
            return
        self._backlog.clear()

    @property
    def backlog_size(self) -> int:
        return len(self._backlog)

    # ── evaluation ───────────────────────────────────────────────────
    def window_for(self, rule: LoadedRule, now: datetime) -> tuple[datetime, datetime]:
        schedule = rule.metadata.schedule
        start = now - timedelta(seconds=schedule.lookback_seconds + schedule.late_tolerance_seconds)
        end = now - timedelta(seconds=self.config.ingest_delay_seconds)
        return start, end

    def evaluate(self, rule: LoadedRule, now: datetime) -> RuleRun:
        started_at = utc_now()
        t0 = time.monotonic()
        window_start, window_end = self.window_for(rule, now)
        status = RuleRunStatus.SUCCEEDED
        error: str | None = None
        rows_matched = created = updated = 0
        missing: list[str] = []
        try:
            required = rule.required_source_types
            caught_up = self._catchup_start(rule, required, window_start, now)
            if caught_up is not None:
                log.info(
                    "late_data_catchup",
                    rule_id=rule.rule_id,
                    window_start=caught_up.isoformat(),
                    normal_window_start=window_start.isoformat(),
                )
                window_start = caught_up
            present = self.store.present_source_types(required, window_start, window_end)
            missing = [s for s in required if s not in present]
            result = self.rules_client.select(
                rule.query_text, rule.query_parameters(window_start, window_end)
            )
            rows_matched = len(result.rows)
            rows, problems = parse_rows(rule, result)
            notes: list[str] = []
            if problems:
                notes.append(f"rejected {len(problems)} malformed rows ({problems[0]})")
                log.warning(
                    "rule_rows_rejected",
                    rule_id=rule.rule_id,
                    count=len(problems),
                    first=problems[0],
                )
            if len(rows) > self.config.max_rows_per_rule:
                limit = self.config.max_rows_per_rule
                notes.append(f"row limit {limit} exceeded ({len(rows)} rows); rest skipped")
                rows = rows[: self.config.max_rows_per_rule]
            created, updated, touched = self._apply(rule, rows, window_start, window_end, now)
            if notes:
                error = "; ".join(notes)[:2000]
            if touched:
                self._run_context_hook(rule, touched)
        except RowError as exc:
            status, error = RuleRunStatus.FAILED, sanitize_error(exc)
        except Exception as exc:  # noqa: BLE001 - one failing rule must never stop the others
            status, error = RuleRunStatus.FAILED, sanitize_error(exc)
        duration_ms = int((time.monotonic() - t0) * 1000)
        if status is RuleRunStatus.SUCCEEDED:
            self._last_success[rule.rule_id] = now
        self.stats.rule_runs_total += 1
        if status is RuleRunStatus.FAILED:
            self.stats.rule_failures_total += 1
            self.stats.last_error = error
            log.warning(
                "rule_run_failed", rule_id=rule.rule_id, error=error, duration_ms=duration_ms
            )
        else:
            log.info(
                "rule_run",
                rule_id=rule.rule_id,
                rows=rows_matched,
                created=created,
                updated=updated,
                missing_sources=missing,
                duration_ms=duration_ms,
            )
        return RuleRun(
            run_id=uuid.uuid4().hex,
            rule_id=rule.rule_id,
            rule_version=rule.version,
            started_at=started_at,
            finished_at=max(utc_now(), started_at),
            window_start=window_start,
            window_end=window_end,
            status=status,
            rows_matched=rows_matched,
            alerts_created=created,
            alerts_updated=updated,
            duration_ms=duration_ms,
            error=error,
            missing_sources=missing[:16],
        )

    def _catchup_start(
        self, rule: LoadedRule, sources: list[str], window_start: datetime, now: datetime
    ) -> datetime | None:
        """Earlier window start when late telemetry arrived since the last successful run.

        Telemetry can arrive long after it happened (a collector backfilling after an
        outage or its first start). Events of the rule's source types ingested since the
        previous successful run (minus a margin; on the first run: the catch-up horizon)
        whose event_time precedes the normal window pull the window start back to
        ``earliest - lookback`` (bounded by ``catchup_max_seconds``). Alert identities do
        not depend on the window, so a longer window never duplicates alerts.
        """
        horizon = self.config.catchup_max_seconds
        if horizon <= 0 or not sources:
            return None
        floor = window_start - timedelta(seconds=horizon)
        last = self._last_success.get(rule.rule_id)
        since = (
            last - timedelta(seconds=self.config.catchup_margin_seconds)
            if last is not None
            else now - timedelta(seconds=horizon)
        )
        earliest = self.store.earliest_late_event(
            sources, ingested_since=since, floor=floor, before=window_start
        )
        if earliest is None:
            return None
        lookback = timedelta(seconds=rule.metadata.schedule.lookback_seconds)
        return max(floor, earliest - lookback)

    def _apply(
        self,
        rule: LoadedRule,
        rows: list[RuleRow],
        window_start: datetime,
        window_end: datetime,
        now: datetime,
    ) -> tuple[int, int, list[str]]:
        if not rows:
            return 0, 0, []
        bucketed = rule.metadata.dedup.strategy is DedupStrategy.WINDOW_BUCKET
        identities = {id(row): alert_identity(rule, row) for row in rows}
        since = window_start - timedelta(seconds=self.config.max_episode_seconds)
        existing = self.store.load_alerts(
            rule.rule_id,
            alert_ids=identities.values(),
            group_keys=[row.group_key for row in rows] if bucketed else (),
            since=since if bucketed else None,
        )
        evidence = self.store.load_evidence(existing.keys() | set(identities.values()))
        states: dict[str, DetectionAlert] = dict(existing)
        stored: dict[str, dict[str, str]] = defaultdict(
            dict, {k: dict(v) for k, v in evidence.items()}
        )
        by_group: dict[str, list[DetectionAlert]] = defaultdict(list)
        for alert in existing.values():
            by_group[alert.group_key].append(alert)

        pending_alerts: dict[str, DetectionAlert] = {}
        pending_evidence: list[AlertEvidence] = []
        created_ids: set[str] = set()
        updated_ids: set[str] = set()
        ordered = sorted(rows, key=lambda r: (r.group_key, r.first_seen, str(r.bucket)))
        for row in ordered:
            aid = identities[id(row)]
            if bucketed and aid not in states:
                bucket_seconds = rule.metadata.dedup.bucket_seconds or 0
                match = find_continuation(
                    by_group[row.group_key],
                    row,
                    gap_seconds=bucket_seconds,
                    max_span_seconds=self.config.max_episode_seconds,
                )
                if match is not None:
                    aid = match.alert_id
            current = states.get(aid)
            decision = decide(
                rule,
                row,
                aid,
                existing=current,
                stored_evidence=stored.get(aid, {}),
                window_start=window_start,
                window_end=window_end,
                now=now,
                detector_version=self.config.detector_version,
            )
            if decision is None:
                continue
            states[aid] = decision.alert
            group_alerts = [a for a in by_group[row.group_key] if a.alert_id != aid]
            group_alerts.append(decision.alert)
            by_group[row.group_key] = group_alerts
            for ev in decision.new_evidence:
                stored[aid][ev.event_id] = ev.role.value
            pending_alerts[aid] = decision.alert
            pending_evidence.extend(decision.new_evidence)
            if decision.created or aid in created_ids:
                created_ids.add(aid)
            else:
                updated_ids.add(aid)

        if pending_alerts:
            pending_alerts = self._attach_services(rule, pending_alerts)
            try:
                self.store.write_evidence(pending_evidence)
                self.store.write_alerts(list(pending_alerts.values()))
            except Exception:
                self.stats.write_errors_total += 1
                raise
            self.stats.last_write_at = utc_now()
            self.stats.alerts_created_total += len(created_ids)
            self.stats.alerts_updated_total += len(updated_ids - created_ids)
        return len(created_ids), len(updated_ids - created_ids), sorted(pending_alerts)

    def _attach_services(
        self, rule: LoadedRule, alerts: dict[str, DetectionAlert]
    ) -> dict[str, DetectionAlert]:
        """Set ``service_ids`` from the evidence events' service attribution (contract 1.1).

        Enrichment only: if the lookup fails the alerts are written with the service ids
        they already had, and the failure is logged (detection is never blocked by it).
        """
        wanted = {eid for alert in alerts.values() for eid in alert.evidence_event_ids}
        try:
            by_event = self.store.evidence_service_ids(wanted)
        except Exception as exc:  # noqa: BLE001 - enrichment must not block alert writes
            log.warning(
                "alert_service_lookup_failed", rule_id=rule.rule_id, error=sanitize_error(exc)
            )
            return alerts
        return {
            aid: with_service_ids(
                alert,
                (sid for e in alert.evidence_event_ids for sid in by_event.get(e, ())),
            )
            for aid, alert in alerts.items()
        }

    def _run_context_hook(self, rule: LoadedRule, alert_ids: list[str]) -> None:
        if self.context_hook is None:
            return
        try:
            built, failed = self.context_hook(rule, alert_ids)
            self.stats.contexts_built_total += built
            self.stats.context_failures_total += failed
        except Exception as exc:  # noqa: BLE001 - correlation must never fail detection
            self.stats.context_failures_total += 1
            log.warning("context_hook_failed", rule_id=rule.rule_id, error=sanitize_error(exc))

    # ── health ───────────────────────────────────────────────────────
    def health(self, now: datetime | None = None) -> PipelineHealth:
        now = now or utc_now()
        failed = len(self.stats.last_cycle_failed_rules)
        ran = self.stats.last_cycle_rules
        if not self.rules or (ran and failed >= ran):
            status = HealthStatus.FAILED
        elif failed or self._backlog or self.invalid_rules:
            status = HealthStatus.DEGRADED
        elif self.stats.last_cycle_at is None:
            status = HealthStatus.UNKNOWN
        else:
            status = HealthStatus.OK
        oldest = None
        if self._backlog:
            oldest = max(0.0, (now - self._backlog[0].finished_at).total_seconds())
        details: dict[str, object] = {
            "rules_loaded": len(self.rules),
            "rules_disabled": len(self.disabled_rules),
            "rules_invalid": self.invalid_rules,
            "cycles_total": self.stats.cycles_total,
            "rule_runs_total": self.stats.rule_runs_total,
            "rule_failures_total": self.stats.rule_failures_total,
            "last_cycle_failed_rules": self.stats.last_cycle_failed_rules[:16],
            "last_cycle_duration_ms": self.stats.last_cycle_duration_ms,
            "alerts_created_total": self.stats.alerts_created_total,
            "alerts_updated_total": self.stats.alerts_updated_total,
            "contexts_built_total": self.stats.contexts_built_total,
            "context_failures_total": self.stats.context_failures_total,
            "rule_runs_dropped_total": self.stats.rule_runs_dropped_total,
            "detector_version": self.config.detector_version,
        }
        if self.stats.last_error:
            details["last_error"] = self.stats.last_error
        return PipelineHealth(
            component="detector",
            instance=self.config.instance,
            reported_at=now,
            status=status,
            queue_depth=len(self._backlog),
            oldest_queued_age_seconds=oldest,
            accepted_total=self.stats.rule_runs_total,
            written_total=self.stats.alerts_created_total + self.stats.alerts_updated_total,
            write_errors_total=self.stats.write_errors_total,
            dead_letter_total=self.stats.rule_runs_dropped_total,
            last_write_at=self.stats.last_write_at,
            details=details,
        )

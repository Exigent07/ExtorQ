"""Pure derivation and mapping logic of the analyst API.

Nothing here talks to ClickHouse: functions take repository rows (dicts keyed by SQL
alias) and the current time, and return API schema objects. This keeps staleness,
coverage and "never fabricate" rules unit-testable with a fake repository.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict, deque
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import ValidationError

from extorq.api import schemas as s
from extorq.api.errors import BadRequest, Conflict, TooManyRequests
from extorq.api.logs import get_logger
from extorq.api.repository import CLOSED_STATUSES, Row
from extorq.api.settings import EXPECTED_ASSET_TYPES
from extorq.contracts import ServiceEndpoint, ServiceKind

log = get_logger("extorq.api.service")

STALE_FACTOR = 3
#: Allowed explicit time-series bucket sizes (seconds).
BUCKET_CHOICES: tuple[int, ...] = (60, 300, 900, 3600, 21600, 86400)
MAX_BUCKETS = 1000
AUTO_TARGET_BUCKETS = 300
SEVERITY_KEYS: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def utc_now() -> datetime:
    return datetime.now(UTC)


# ── Generic helpers ───────────────────────────────────────────────────────────────


def parse_json(text: Any) -> Any:
    """Parse a stored canonical-JSON column; ``None`` when absent or unparsable."""
    if text is None or text == "":
        return None
    if not isinstance(text, str):
        return None
    try:
        return json.loads(text)
    except ValueError:
        log.warning("stored_json_unparsable", length=len(text))
        return None


def parse_json_object(text: Any) -> dict[str, Any] | None:
    value = parse_json(text)
    return value if isinstance(value, dict) else None


def as_bool(value: Any) -> bool:
    return bool(int(value)) if isinstance(value, int | bool) else bool(value)


def opt_int(value: Any) -> int | None:
    return None if value is None else int(value)


def opt_float(value: Any) -> float | None:
    return None if value is None else float(value)


def resolve_range(
    since: datetime | None,
    until: datetime | None,
    *,
    now: datetime,
    default: timedelta,
    maximum: timedelta,
    future_tolerance: timedelta = timedelta(0),
) -> s.TimeRange:
    """Validate an optional [since, until) window (aware UTC, bounded length).

    Defaults: ``since = now - default``; ``until = now + future_tolerance``. List endpoints
    use a tolerance of one day so records stamped slightly ahead by a skewed source clock
    (the gateway accepts up to now + 1 day) are not hidden.
    """
    for name, value in (("since", since), ("until", until)):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise BadRequest(f"'{name}' must include a timezone (e.g. 2026-11-21T10:00:00Z)")
    end = until.astimezone(UTC) if until is not None else now + future_tolerance
    start = since.astimezone(UTC) if since is not None else now - default
    if start >= end:
        raise BadRequest("'since' must be earlier than 'until'")
    if end - start > maximum:
        raise BadRequest(f"time range exceeds the maximum of {int(maximum.total_seconds())}s")
    return s.TimeRange(since=start, until=end)


def page_info(
    *, limit: int, offset: int, returned: int, total: int | None, has_more: bool | None = None
) -> s.PageInfo:
    more = has_more if has_more is not None else (total is not None and offset + returned < total)
    return s.PageInfo(
        limit=limit,
        offset=offset,
        returned=returned,
        has_more=more,
        next_offset=offset + returned if more else None,
        total=total,
    )


def severity_counts(rows: Iterable[Row], key: str, count_key: str) -> s.SeverityCounts:
    counts = dict.fromkeys(SEVERITY_KEYS, 0)
    for row in rows:
        severity = str(row.get(key) or "")
        if severity in counts:
            counts[severity] += int(row.get(count_key) or 0)
    return s.SeverityCounts(**counts, total=sum(counts.values()))


def choose_bucket(time_range: s.TimeRange, requested: int | None) -> int:
    span = (time_range.until - time_range.since).total_seconds()
    if requested is not None:
        if requested not in BUCKET_CHOICES:
            raise BadRequest(f"bucket_seconds must be one of {list(BUCKET_CHOICES)}")
        if span / requested > MAX_BUCKETS:
            raise BadRequest(f"range/bucket would produce more than {MAX_BUCKETS} buckets")
        return requested
    for choice in BUCKET_CHOICES:
        if span / choice <= AUTO_TARGET_BUCKETS:
            return choice
    return BUCKET_CHOICES[-1]


# ── Collectors / coverage ─────────────────────────────────────────────────────────


def collector_status(row: Row, now: datetime) -> s.CollectorStatus:
    interval = int(row.get("interval_seconds") or 0)
    last_success: datetime | None = row.get("last_success_at")
    since_success = (now - last_success).total_seconds() if last_success else None
    threshold = STALE_FACTOR * interval
    if last_success is None:
        stale, reason = True, "no successful collection has been reported"
    elif interval <= 0:
        stale, reason = True, "collector reported no valid interval"
    elif since_success is not None and since_success > threshold:
        stale = True
        reason = (
            f"last success {int(since_success)}s ago exceeds {STALE_FACTOR} x interval "
            f"({threshold}s)"
        )
    else:
        stale, reason = False, None
    return s.CollectorStatus(
        collector_id=str(row["collector_id"]),
        collector_type=str(row.get("collector_type") or ""),
        asset_id=str(row.get("asset_id") or ""),
        source_types=[str(x) for x in row.get("source_types") or []],
        status=row["status"],
        last_reported_at=row["last_reported_at"],
        last_attempt_at=row.get("last_attempt_at"),
        last_success_at=last_success,
        last_error=row.get("last_error"),
        events_collected=int(row.get("events_collected") or 0),
        records_buffered=int(row.get("records_buffered") or 0),
        lag_seconds=opt_float(row.get("lag_seconds")),
        checkpoint_summary=row.get("checkpoint_summary"),
        collector_version=str(row.get("collector_version") or ""),
        interval_seconds=interval,
        stale=stale,
        stale_reason=reason,
        seconds_since_success=since_success,
        details=parse_json_object(row.get("details")) or {},
    )


def coverage_status(collectors: Sequence[s.CollectorStatus]) -> s.CoverageStatus:
    if not collectors:
        return "missing"
    if all(c.stale for c in collectors):
        return "stale"
    if any(c.stale or c.status.value != "ok" for c in collectors):
        return "degraded"
    return "ok"


def asset_class_coverage(
    assets: Sequence[Row],
    collectors: Sequence[s.CollectorStatus],
    last_event_by_type: dict[str, datetime | None],
) -> list[s.AssetClassCoverage]:
    by_asset: dict[str, list[s.CollectorStatus]] = defaultdict(list)
    for collector in collectors:
        by_asset[collector.asset_id].append(collector)
    by_type: dict[str, list[Row]] = defaultdict(list)
    for asset in assets:
        by_type[str(asset["asset_type"])].append(asset)
    ordered = list(EXPECTED_ASSET_TYPES) + sorted(
        t for t in by_type if t not in EXPECTED_ASSET_TYPES
    )
    result: list[s.AssetClassCoverage] = []
    for asset_type in ordered:
        members = by_type.get(asset_type, [])
        statuses = [coverage_status(by_asset.get(str(a["asset_id"]), [])) for a in members]
        total = len(members)
        ok = statuses.count("ok")
        degraded = statuses.count("degraded")
        stale = statuses.count("stale")
        missing = statuses.count("missing")
        if total == 0 or missing == total:
            status: s.CoverageStatus = "missing"
        elif ok == total:
            status = "ok"
        elif ok == 0 and degraded == 0:
            status = "stale"
        else:
            status = "degraded"
        result.append(
            s.AssetClassCoverage(
                asset_type=asset_type,
                expected=asset_type in EXPECTED_ASSET_TYPES,
                assets_total=total,
                assets_ok=ok,
                assets_degraded=degraded,
                assets_stale=stale,
                assets_without_collector=missing,
                status=status,
                last_event_at=last_event_by_type.get(asset_type),
            )
        )
    return result


# ── Alerts / events ───────────────────────────────────────────────────────────────


def alert_item(row: Row) -> s.AlertListItem:
    return s.AlertListItem(
        alert_id=str(row["alert_id"]),
        rule_id=str(row["rule_id"]),
        rule_version=str(row["rule_version"]),
        rule_title=str(row["rule_title"]),
        severity=row["severity"],
        confidence=str(row["confidence"]),
        asset_id=str(row["asset_id"]),
        asset_type=str(row["asset_type"]),
        summary=str(row["summary"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        event_count=int(row["event_count"]),
        entities={str(k): str(v) for k, v in (row.get("entities") or {}).items()},
        mitre_techniques=[str(x) for x in row.get("mitre_techniques") or []],
        simulation_run_ids=[str(x) for x in row.get("simulation_run_ids") or []],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        analyst_status=row.get("analyst_status") or "new",
        analyst_state_recorded=as_bool(row.get("analyst_state_recorded")),
        assignee=row.get("assignee"),
        service_ids=[str(x) for x in row.get("service_ids") or []],
    )


def alert_record(row: Row) -> s.AlertRecord:
    return s.AlertRecord(
        alert_id=str(row["alert_id"]),
        schema_version=str(row["schema_version"]),
        rule_id=str(row["rule_id"]),
        rule_version=str(row["rule_version"]),
        rule_title=str(row["rule_title"]),
        severity=row["severity"],
        confidence=str(row["confidence"]),
        asset_id=str(row["asset_id"]),
        asset_type=str(row["asset_type"]),
        group_key=str(row["group_key"]),
        entities={str(k): str(v) for k, v in (row.get("entities") or {}).items()},
        summary=str(row["summary"]),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        window_start=row["window_start"],
        window_end=row["window_end"],
        event_count=int(row["event_count"]),
        evidence_event_ids=[str(x) for x in row.get("evidence_event_ids") or []],
        evidence_truncated=as_bool(row.get("evidence_truncated")),
        features=parse_json_object(row.get("features")),
        mitre_techniques=[str(x) for x in row.get("mitre_techniques") or []],
        simulation_run_ids=[str(x) for x in row.get("simulation_run_ids") or []],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        detector_version=str(row["detector_version"]),
        service_ids=[str(x) for x in row.get("service_ids") or []],
    )


def analyst_state_view(row: Row | None) -> s.AnalystStateView:
    if row is None:
        return s.AnalystStateView(status="new", recorded=False)
    return s.AnalystStateView(
        status=row["status"],
        assignee=row.get("assignee"),
        note=row.get("note"),
        updated_by=row.get("updated_by"),
        updated_at=row.get("updated_at"),
        recorded=True,
    )


_EVENT_FIELDS = tuple(s.EventListItem.model_fields)


def event_item(row: Row) -> s.EventListItem:
    return s.EventListItem(**{name: row.get(name) for name in _EVENT_FIELDS})


def evidence_event(row: Row, ref: Row | None) -> s.EvidenceEvent:
    return s.EvidenceEvent(
        **{name: row.get(name) for name in _EVENT_FIELDS},
        role=(str(ref["role"]) if ref and ref.get("role") else None),
        added_at=(ref.get("added_at") if ref else None),
        attributes=parse_json_object(row.get("attributes")),
    )


def ordered_evidence_ids(
    refs: Sequence[Row], array_ids: Sequence[str], cap: int
) -> tuple[list[str], dict[str, Row]]:
    """Evidence ids in display order: alert_evidence rows (trigger first) then array-only ids."""
    ref_by_id: dict[str, Row] = {}
    ordered: list[str] = []
    for ref in refs:
        event_id = str(ref["event_id"])
        if event_id not in ref_by_id:
            ref_by_id[event_id] = ref
            ordered.append(event_id)
    for event_id in array_ids:
        if event_id not in ref_by_id and event_id not in ordered:
            ordered.append(event_id)
    return ordered[:cap], ref_by_id


def action_item(row: Row) -> s.AnalystActionItem:
    return s.AnalystActionItem(
        action_id=str(row["action_id"]),
        occurred_at=row["occurred_at"],
        actor=str(row["actor"]),
        role=str(row["role"]),
        action=str(row["action"]),
        alert_id=row.get("alert_id"),
        details=parse_json_object(row.get("details")),
    )


# ── Assets ────────────────────────────────────────────────────────────────────────


def asset_item(
    row: Row,
    collectors: Sequence[s.CollectorStatus],
    last_event_at: datetime | None,
    open_alerts: int,
) -> s.AssetListItem:
    return s.AssetListItem(
        asset_id=str(row["asset_id"]),
        asset_type=row["asset_type"],
        name=str(row["name"]),
        display_name=row.get("display_name"),
        parent_asset_id=row.get("parent_asset_id"),
        environment=str(row["environment"]),
        criticality=str(row["criticality"]),
        owner=row.get("owner"),
        labels={str(k): str(v) for k, v in (row.get("labels") or {}).items()},
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        observed_by=str(row["observed_by"]),
        collectors_total=len(collectors),
        collectors_stale=sum(1 for c in collectors if c.stale),
        coverage_status=coverage_status(collectors),
        last_event_at=last_event_at,
        open_alerts=open_alerts,
    )


def asset_brief(row: Row) -> s.AssetBrief:
    return s.AssetBrief(
        asset_id=str(row["asset_id"]),
        asset_type=row["asset_type"],
        name=str(row["name"]),
        display_name=row.get("display_name"),
        environment=str(row["environment"]),
        criticality=str(row["criticality"]),
    )


# ── Findings ──────────────────────────────────────────────────────────────────────

LIFECYCLE_UNAVAILABLE_NOTE = (
    "Finding lifecycle (open/resolved/unverified) is unavailable: counts are distinct finding "
    "fingerprints observed within retention, using each finding's latest observation."
)


def finding_item(
    row: Row, lifecycle: bool, attribution: dict[str, str] | None = None
) -> s.FindingItem:
    """Map a findings row; ``attribution`` maps finding_id -> attributed service_id."""
    state = row.get("state") if lifecycle else None
    return s.FindingItem(
        finding_id=str(row["finding_id"]),
        asset_id=str(row["asset_id"]),
        scanner=str(row["scanner"]),
        check_id=str(row["check_id"]),
        category=str(row.get("category") or ""),
        severity=row["severity"],
        title=str(row["title"]),
        state=state if state in ("open", "unverified", "resolved") else None,
        first_observed_at=row.get("first_observed_at"),
        last_observed_at=row["last_observed_at"],
        last_scan_run_id=row.get("last_scan_run_id"),
        resource_type=row.get("resource_type"),
        resource_name=row.get("resource_name"),
        resource_namespace=row.get("resource_namespace"),
        resource_path=row.get("resource_path"),
        package_name=row.get("package_name"),
        installed_version=row.get("installed_version"),
        fixed_version=row.get("fixed_version"),
        cve_ids=[str(x) for x in row.get("cve_ids") or []],
        cvss_score=opt_float(row.get("cvss_score")),
        remediation=row.get("remediation"),
        accepted_risk_reason=row.get("accepted_risk_reason"),
        service_id=(attribution or {}).get(str(row["finding_id"])),
        scope_hash=(row.get("scope_hash") or None) if lifecycle else None,
        last_success_at=row.get("last_success_at") if lifecycle else None,
        latest_scan_status=row.get("latest_scan_status") if lifecycle else None,
    )


def findings_summary(rows: Sequence[Row], lifecycle: bool) -> s.FindingsSummary:
    if lifecycle:
        return s.FindingsSummary(
            lifecycle_available=True,
            source="v_findings_current",
            counts=severity_counts(
                (r for r in rows if r.get("state") == "open"), "severity", "findings"
            ),
            unverified=severity_counts(
                (r for r in rows if r.get("state") == "unverified"), "severity", "findings"
            ),
        )
    return s.FindingsSummary(
        lifecycle_available=False,
        source="finding_observations",
        counts=severity_counts(rows, "severity", "findings"),
        note=LIFECYCLE_UNAVAILABLE_NOTE,
    )


# ── Rules ─────────────────────────────────────────────────────────────────────────


def interval_from_schedule(schedule: Any) -> int | None:
    data = schedule if isinstance(schedule, dict) else parse_json_object(schedule)
    if not data:
        return None
    value = data.get("interval_seconds")
    return int(value) if isinstance(value, int) and value > 0 else None


def run_summary(row: Row | None) -> s.RuleRunSummary | None:
    if row is None:
        return None
    return s.RuleRunSummary(
        rule_version=str(row["rule_version"]),
        last_run_at=row["last_run_at"],
        last_status=str(row["last_status"]),
        last_error=row.get("last_error"),
        last_duration_ms=int(row.get("last_duration_ms") or 0),
        missing_sources=[str(x) for x in row.get("missing_sources") or []],
        runs_24h=int(row.get("runs_24h") or 0),
        failures_24h=int(row.get("failures_24h") or 0),
    )


def run_stale(
    summary: s.RuleRunSummary | None, interval: int | None, enabled: bool | None, now: datetime
) -> bool | None:
    if enabled is False or interval is None:
        return None
    if summary is None:
        return True
    return (now - summary.last_run_at).total_seconds() > STALE_FACTOR * interval


def rule_item(
    row: Row, latest_run: Row | None, alert_counts: Row | None, now: datetime
) -> s.RuleListItem:
    enabled = as_bool(row.get("enabled"))
    interval = interval_from_schedule(row.get("schedule"))
    summary = run_summary(latest_run)
    return s.RuleListItem(
        rule_id=str(row["rule_id"]),
        version=str(row["version"]),
        title=str(row["title"]),
        severity=row["severity"],
        status=str(row["status"]),
        enabled=enabled,
        mitre_techniques=[str(x) for x in row.get("mitre_techniques") or []],
        asset_types=[str(x) for x in row.get("asset_types") or []],
        loaded_at=row["loaded_at"],
        interval_seconds=interval,
        last_run=summary,
        run_stale=run_stale(summary, interval, enabled, now),
        alerts_total=int((alert_counts or {}).get("alerts_total") or 0),
        alerts_open=int((alert_counts or {}).get("alerts_open") or 0),
    )


def rule_record(row: Row) -> s.RuleRecord:
    return s.RuleRecord(
        rule_id=str(row["rule_id"]),
        version=str(row["version"]),
        title=str(row["title"]),
        description=str(row["description"]),
        severity=row["severity"],
        status=str(row["status"]),
        enabled=as_bool(row.get("enabled")),
        mitre_techniques=[str(x) for x in row.get("mitre_techniques") or []],
        asset_types=[str(x) for x in row.get("asset_types") or []],
        requires=parse_json(row.get("requires")),
        schedule=parse_json_object(row.get("schedule")),
        dedup=parse_json_object(row.get("dedup")),
        group_by=[str(x) for x in row.get("group_by") or []],
        params=parse_json_object(row.get("params")),
        false_positives=[str(x) for x in row.get("false_positives") or []],
        blind_spots=[str(x) for x in row.get("blind_spots") or []],
        references=[str(x) for x in row.get("reference_urls") or []],
        query_sha256=str(row["query_sha256"]),
        query_text=str(row["query_text"]),
        loaded_at=row["loaded_at"],
    )


def rule_brief(row: Row) -> s.RuleBrief:
    return s.RuleBrief(
        rule_id=str(row["rule_id"]),
        version=str(row["version"]),
        title=str(row["title"]),
        description=str(row["description"]),
        false_positives=[str(x) for x in row.get("false_positives") or []],
        blind_spots=[str(x) for x in row.get("blind_spots") or []],
        mitre_techniques=[str(x) for x in row.get("mitre_techniques") or []],
    )


def rule_run_item(row: Row) -> s.RuleRunItem:
    return s.RuleRunItem(
        run_id=str(row["run_id"]),
        rule_version=str(row["rule_version"]),
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        window_start=row["window_start"],
        window_end=row["window_end"],
        status=str(row["status"]),
        rows_matched=int(row.get("rows_matched") or 0),
        alerts_created=int(row.get("alerts_created") or 0),
        alerts_updated=int(row.get("alerts_updated") or 0),
        duration_ms=int(row.get("duration_ms") or 0),
        error=row.get("error"),
        missing_sources=[str(x) for x in row.get("missing_sources") or []],
        detector_instance=str(row.get("detector_instance") or ""),
    )


def rule_health(
    rules: Sequence[Row], latest_runs: Sequence[Row], now: datetime
) -> list[s.RuleHealthItem]:
    runs = {str(r["rule_id"]): r for r in latest_runs}
    items: list[s.RuleHealthItem] = []
    seen: set[str] = set()
    for row in rules:
        rule_id = str(row["rule_id"])
        seen.add(rule_id)
        enabled = as_bool(row.get("enabled"))
        interval = interval_from_schedule(row.get("schedule"))
        summary = run_summary(runs.get(rule_id))
        items.append(
            s.RuleHealthItem(
                rule_id=rule_id,
                title=str(row.get("title") or "") or None,
                enabled=enabled,
                interval_seconds=interval,
                last_run=summary,
                run_stale=run_stale(summary, interval, enabled, now),
            )
        )
    # Runs for rules missing from the registry table are still reported (unknown metadata).
    for rule_id, run in sorted(runs.items()):
        if rule_id not in seen:
            items.append(s.RuleHealthItem(rule_id=rule_id, last_run=run_summary(run)))
    return items


# ── Pipeline / AI health ──────────────────────────────────────────────────────────


def pipeline_health(
    rows: Sequence[Row], now: datetime, stale_seconds: int
) -> list[s.PipelineComponentHealth]:
    newest_fresh: dict[str, datetime] = {}
    for row in rows:
        reported: datetime = row["last_reported_at"]
        if (now - reported).total_seconds() <= stale_seconds:
            component = str(row["component"])
            if component not in newest_fresh or reported > newest_fresh[component]:
                newest_fresh[component] = reported
    items: list[s.PipelineComponentHealth] = []
    for row in rows:
        reported = row["last_reported_at"]
        age = (now - reported).total_seconds()
        stale = age > stale_seconds
        component = str(row["component"])
        items.append(
            s.PipelineComponentHealth(
                component=component,
                instance=str(row["instance"]),
                status=row["status"],
                last_reported_at=reported,
                report_age_seconds=age,
                stale=stale,
                superseded=stale and component in newest_fresh,
                queue_depth=int(row.get("queue_depth") or 0),
                oldest_queued_age_seconds=opt_float(row.get("oldest_queued_age_seconds")),
                accepted_total=int(row.get("accepted_total") or 0),
                duplicate_total=int(row.get("duplicate_total") or 0),
                rejected_total=int(row.get("rejected_total") or 0),
                quarantined_total=int(row.get("quarantined_total") or 0),
                written_total=int(row.get("written_total") or 0),
                write_errors_total=int(row.get("write_errors_total") or 0),
                dead_letter_total=int(row.get("dead_letter_total") or 0),
                last_write_at=row.get("last_write_at"),
                details=parse_json_object(row.get("details")) or {},
            )
        )
    return items


#: Provider/task pairs ExtorQ uses (PLAN: Jev triage, Gemini summary).
AI_PROVIDER_TASKS: tuple[tuple[str, str], ...] = (
    ("typesafe-jev", "triage"),
    ("google-gemini", "summary"),
)


def ai_health(
    counts: Sequence[Row],
    latest: Sequence[Row],
    configuration: dict[tuple[str, str], dict[str, bool | None]],
    window_hours: int,
) -> list[s.AIProviderHealth]:
    pairs = list(AI_PROVIDER_TASKS)
    for row in [*counts, *latest]:
        pair = (str(row["provider"]), str(row["task"]))
        if pair not in pairs:
            pairs.append(pair)
    latest_by_pair = {(str(r["provider"]), str(r["task"])): r for r in latest}
    items: list[s.AIProviderHealth] = []
    for provider, task in pairs:
        status_counts: dict[str, int] = {}
        for row in counts:
            if (str(row["provider"]), str(row["task"])) == (provider, task):
                status_counts[str(row["status"])] = int(row["assessments"])
        last = latest_by_pair.get((provider, task))
        config = configuration.get((provider, task), {})
        items.append(
            s.AIProviderHealth(
                provider=provider,
                task=task,
                configured=config.get("configured"),
                enabled=config.get("enabled"),
                window_hours=window_hours,
                status_counts=status_counts,
                last_assessment_at=last.get("last_assessment_at") if last else None,
                last_ok_at=last.get("last_ok_at") if last else None,
                last_status=str(last["last_status"]) if last else None,
                last_error=last.get("last_error") if last else None,
            )
        )
    return items


def collection_summary(
    collectors: Sequence[s.CollectorStatus],
    pipeline: Sequence[s.PipelineComponentHealth],
    rules: Sequence[s.RuleHealthItem],
    registry_size: int,
) -> s.CollectionHealthSummary:
    active_pipeline = [p for p in pipeline if not p.superseded]
    return s.CollectionHealthSummary(
        collectors_total=len(collectors),
        collectors_ok=sum(1 for c in collectors if c.status.value == "ok" and not c.stale),
        collectors_stale=sum(1 for c in collectors if c.stale),
        collectors_failing=sum(1 for c in collectors if c.status.value in ("failed", "degraded")),
        pipeline_components=len(active_pipeline),
        pipeline_unhealthy=sum(1 for p in active_pipeline if p.stale or p.status.value != "ok"),
        rules_total=registry_size,
        rules_failing=sum(
            1 for r in rules if r.last_run is not None and r.last_run.last_status == "failed"
        ),
        rule_failures_24h=sum(r.last_run.failures_24h for r in rules if r.last_run is not None),
        no_collector_reports=not collectors,
        no_pipeline_reports=not pipeline,
        no_rule_runs=all(r.last_run is None for r in rules),
    )


def series_points(rows: Sequence[Row], grouped: bool) -> list[s.SeriesPoint]:
    return [
        s.SeriesPoint(
            bucket_start=row["bucket_start"],
            group=(str(row["grp"]) if grouped else None),
            count=int(row["n"]),
        )
        for row in rows
    ]


def is_open(status: str) -> bool:
    return status not in CLOSED_STATUSES


# ── Services (schema 1.1) ─────────────────────────────────────────────────────────

SourceCollection = Literal["fresh", "stale", "no_collector_health"]
COVERAGE_STATES: tuple[str, ...] = (
    "monitored",
    "degraded",
    "unmonitored",
    "planned",
    "unsupported",
)
#: Widest first. ``unknown`` ranks above ``private`` because it also covers public binds.
EXPOSURE_ORDER: tuple[str, ...] = ("any", "unknown", "private", "loopback")
NO_SERVICES_NOTE = (
    "no service discovery records exist for this scope yet; services are reported by the "
    "host and Kubernetes collectors (absence is not proof that nothing runs)"
)


def collectors_for_asset(
    asset_id: str, collectors: Sequence[s.CollectorStatus]
) -> list[s.CollectorStatus]:
    """Collectors of the asset itself or of an ancestor in the asset-id namespace.

    Kubernetes node assets are ``k8s:<cluster>/node/<name>``: the cluster collector
    (asset ``k8s:<cluster>``) covers them.
    """
    return [
        c for c in collectors if c.asset_id == asset_id or asset_id.startswith(c.asset_id + "/")
    ]


def parse_endpoints(text: Any) -> tuple[list[s.ServiceEndpointView], int]:
    """Stored endpoints JSON -> validated views, plus the number of invalid entries."""
    if text is None or text == "":
        return [], 0
    value = parse_json(text)
    if not isinstance(value, list):
        return [], 1
    views: list[s.ServiceEndpointView] = []
    invalid = 0
    for item in value[:64]:
        try:
            endpoint = ServiceEndpoint.model_validate(item)
        except ValidationError:
            invalid += 1
            continue
        views.append(
            s.ServiceEndpointView(
                protocol=endpoint.protocol,
                address=endpoint.address,
                port=endpoint.port,
                exposure=endpoint.exposure,
                attribution=endpoint.attribution,
                attribution_basis=endpoint.attribution_basis,
            )
        )
    return views, invalid + max(0, len(value) - 64)


def effective_coverage(
    adapter_support: str,
    monitoring_status: str,
    *,
    report_stale: bool,
    report_age: float,
    stale_seconds: int,
    stale_sources: dict[str, list[str]],
) -> tuple[s.CoverageState, list[str]]:
    """Effective coverage state at request time plus API-derived reasons.

    Only an implemented adapter reported ``monitored`` can be downgraded (to
    ``degraded``): when its discovery record is no longer refreshed, or when every
    collector reporting one of its declared sources is stale. Nothing is upgraded.
    """
    reasons: list[str] = []
    if report_stale:
        reasons.append(
            f"discovery has not refreshed this service for {int(report_age)}s "
            f"(threshold {stale_seconds}s): current coverage cannot be confirmed"
        )
    for source, collector_ids in sorted(stale_sources.items()):
        reasons.append(f"telemetry source {source}: collector {', '.join(collector_ids)} stale")
    if adapter_support == "none":
        return "unsupported", reasons
    if adapter_support == "planned":
        return "planned", reasons
    if monitoring_status == "unmonitored":
        return "unmonitored", reasons
    if monitoring_status == "degraded":
        return "degraded", reasons
    return ("degraded" if reasons else "monitored"), reasons


class ServiceEvaluator:
    """Maps stored service rows to API items with effective coverage at ``now``."""

    def __init__(
        self, collectors: Sequence[s.CollectorStatus], now: datetime, stale_seconds: int
    ) -> None:
        self._collectors = list(collectors)
        self._now = now
        self._stale_seconds = stale_seconds

    def source_collectors(self, asset_id: str, source_type: str) -> list[s.CollectorStatus]:
        return [
            c
            for c in collectors_for_asset(asset_id, self._collectors)
            if source_type in c.source_types
        ]

    def stale_sources(self, asset_id: str, sources: Sequence[str]) -> dict[str, list[str]]:
        """Declared sources whose every reporting collector is stale (no collector: skipped)."""
        result: dict[str, list[str]] = {}
        for source in sources:
            reporting = self.source_collectors(asset_id, source)
            if reporting and all(c.stale for c in reporting):
                result[source] = sorted(c.collector_id for c in reporting)
        return result

    def is_stale(self, observed: datetime) -> bool:
        return (self._now - observed).total_seconds() > self._stale_seconds

    def _fields(self, row: Row) -> dict[str, Any]:
        last_seen: datetime = row["last_seen"]
        report_age = (self._now - last_seen).total_seconds()
        report_stale = report_age > self._stale_seconds
        sources = [str(x) for x in row.get("telemetry_sources") or []]
        asset_id = str(row["asset_id"])
        state, reasons = effective_coverage(
            str(row["adapter_support"]),
            str(row["monitoring_status"]),
            report_stale=report_stale,
            report_age=report_age,
            stale_seconds=self._stale_seconds,
            stale_sources=self.stale_sources(asset_id, sources),
        )
        endpoints, invalid = parse_endpoints(row.get("endpoints"))
        present_exposures = {e.exposure for e in endpoints}
        return {
            "service_id": str(row["service_id"]),
            "asset_id": asset_id,
            "service_kind": row["service_kind"],
            "service_key": str(row["service_key"]),
            "name": str(row["name"]),
            "category": row["category"],
            "product": row.get("product"),
            "version": row.get("version"),
            "discovered_via": [str(x) for x in row.get("discovered_via") or []],
            "adapter_id": row.get("adapter_id"),
            "adapter_support": row["adapter_support"],
            "monitoring_status": row["monitoring_status"],
            "coverage_state": state,
            "coverage_note": row.get("coverage_note"),
            "coverage_reasons": reasons,
            "telemetry_sources": sources,
            "endpoints": endpoints,
            "exposures": [e for e in EXPOSURE_ORDER if e in present_exposures],
            "config_refs": [str(x) for x in row.get("config_refs") or []],
            "instance_count": opt_int(row.get("instance_count")),
            "last_telemetry_at": row.get("last_telemetry_at"),
            "first_seen": row["first_seen"],
            "last_seen": last_seen,
            "report_age_seconds": report_age,
            "report_stale": report_stale,
            "present": as_bool(row.get("present", 1)),
            "observed_by": str(row.get("observed_by") or ""),
            "_invalid_endpoints": invalid,
        }

    def item(self, row: Row) -> s.ServiceListItem:
        fields = self._fields(row)
        invalid = fields.pop("_invalid_endpoints")
        if invalid:
            log.warning("service_endpoints_invalid", service_id=fields["service_id"], count=invalid)
        return s.ServiceListItem(**fields)

    def record(self, row: Row) -> s.ServiceRecord:
        fields = self._fields(row)
        invalid = fields.pop("_invalid_endpoints")
        return s.ServiceRecord(
            **fields,
            attributes=parse_json_object(row.get("attributes")),
            invalid_endpoints=invalid,
        )

    def items(self, rows: Iterable[Row]) -> tuple[list[s.ServiceListItem], int]:
        """Valid items plus the count of rows that failed validation (logged, not shown)."""
        items: list[s.ServiceListItem] = []
        invalid = 0
        for row in rows:
            try:
                items.append(self.item(row))
            except (ValidationError, KeyError, TypeError, ValueError):
                invalid += 1
        if invalid:
            log.warning("stored_services_invalid", count=invalid)
        return items, invalid

    def instance(self, row: Row) -> s.ServiceInstanceItem:
        observed: datetime = row["observed_at"]
        return s.ServiceInstanceItem(
            instance_id=str(row["instance_id"]),
            service_id=str(row["service_id"]),
            asset_id=row.get("asset_id"),
            instance_kind=row["instance_kind"],
            instance_key=str(row["instance_key"]),
            parent_instance_id=row.get("parent_instance_id"),
            state=row.get("state") or "unknown",
            pid=opt_int(row.get("pid")),
            process_name=row.get("process_name"),
            user=row.get("process_user"),
            namespace=row.get("namespace"),
            pod_name=row.get("pod_name"),
            pod_uid=row.get("pod_uid"),
            container_name=row.get("container_name"),
            container_id=row.get("container_id"),
            image=row.get("image"),
            node_name=row.get("node_name"),
            workload_kind=row.get("workload_kind"),
            workload_name=row.get("workload_name"),
            started_at=row.get("started_at"),
            observed_at=observed,
            observed_by=str(row.get("observed_by") or ""),
            stale=self.is_stale(observed),
            attributes=parse_json_object(row.get("attributes")),
        )

    def telemetry(
        self, service: s.ServiceListItem, event_rows: Sequence[Row]
    ) -> list[s.ServiceTelemetrySource]:
        """Declared sources (adapter order) then sources seen only in attributed events."""
        by_source = {str(r["source_type"]): r for r in event_rows}
        ordered = list(dict.fromkeys(service.telemetry_sources))
        ordered += sorted(src for src in by_source if src not in ordered)
        result: list[s.ServiceTelemetrySource] = []
        for source in ordered:
            reporting = self.source_collectors(service.asset_id, source)
            collection: SourceCollection
            if not reporting:
                collection = "no_collector_health"
            elif all(c.stale for c in reporting):
                collection = "stale"
            else:
                collection = "fresh"
            counts = by_source.get(source, {})
            result.append(
                s.ServiceTelemetrySource(
                    source_type=source,
                    declared=source in service.telemetry_sources,
                    collectors=[
                        s.ServiceSourceCollector(
                            collector_id=c.collector_id,
                            asset_id=c.asset_id,
                            status=c.status,
                            last_success_at=c.last_success_at,
                            interval_seconds=c.interval_seconds,
                            stale=c.stale,
                            stale_reason=c.stale_reason,
                        )
                        for c in reporting
                    ],
                    collection=collection,
                    events=int(counts.get("events") or 0),
                    last_event_at=counts.get("last_event_at"),
                    last_ingested_at=counts.get("last_ingested_at"),
                )
            )
        return result


def coverage_counts(items: Iterable[s.ServiceListItem]) -> s.ServiceCoverageCounts:
    counts = dict.fromkeys(COVERAGE_STATES, 0)
    for item in items:
        counts[item.coverage_state] += 1
    return s.ServiceCoverageCounts(**counts, total=sum(counts.values()))


def services_summary(
    items: Sequence[s.ServiceListItem], *, truncated: bool, note: str | None = None
) -> s.ServicesSummary:
    """Coverage over present services; tombstones are counted in ``removed`` only."""
    present = [i for i in items if i.present]
    by_kind = [
        s.ServiceKindSummary(
            service_kind=kind,
            coverage=coverage_counts(i for i in present if i.service_kind == kind),
        )
        for kind in ServiceKind
        if any(i.service_kind == kind for i in present)
    ]
    reported = bool(items)
    return s.ServicesSummary(
        reported=reported,
        coverage=coverage_counts(present),
        by_kind=by_kind,
        removed=len(items) - len(present),
        truncated=truncated,
        note=note if note is not None else (None if reported else NO_SERVICES_NOTE),
    )


def auth_activity(
    time_range: s.TimeRange, summary: Row, sources: Sequence[Row]
) -> s.ServiceAuthActivity:
    outcomes = ("success", "failure", "denied", "unknown")
    by_outcome = {o: int(summary.get(o) or 0) for o in outcomes if int(summary.get(o) or 0)}
    return s.ServiceAuthActivity(
        range=time_range,
        total=int(summary.get("total") or 0),
        by_outcome=by_outcome,
        distinct_actors=int(summary.get("distinct_actors") or 0),
        distinct_sources=int(summary.get("distinct_sources") or 0),
        top_sources=[
            s.AuthSourceActivity(
                src_ip=str(r["source_ip"]),
                events=int(r["events"]),
                failures=int(r["failures"]),
                last_seen=r["last_seen"],
            )
            for r in sources
        ],
    )


# ── Summary request gate (protects the AI budget from UI loops) ─────────────────────


class SummaryGate:
    """Per-user sliding-window limit plus one in-flight summary per alert."""

    def __init__(self, per_minute: int) -> None:
        self._per_minute = per_minute
        self._lock = threading.Lock()
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._in_flight: set[str] = set()

    def acquire(self, user: str, alert_id: str) -> None:
        now = time.monotonic()
        with self._lock:
            window = self._requests[user]
            while window and now - window[0] > 60.0:
                window.popleft()
            if len(window) >= self._per_minute:
                raise TooManyRequests(
                    "summary request limit reached; retry later", headers={"Retry-After": "60"}
                )
            if alert_id in self._in_flight:
                raise Conflict("a summary for this alert is already being generated")
            window.append(now)
            self._in_flight.add(alert_id)

    def release(self, alert_id: str) -> None:
        with self._lock:
            self._in_flight.discard(alert_id)

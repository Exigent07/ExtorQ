"""Read-only evaluation of the current rule definitions over a historical window.

``uv run python -m extorq.detection.dryrun --rule CORR-002 --start 2026-11-21T14:00:00Z
--end 2026-11-21T16:00:00Z``

Runs a rule exactly as the engine does (the rule SQL under the readonly identity
``extorq_rules_ro``, row validation, alert identity and window-bucket continuation), then
compares each row with the stored alert it would create or extend (read-only, by default
``extorq_api_ro``):

* ``NEW``     no stored alert has this identity (the engine would create one)
* ``STORED``  the identity (or a continuous episode of the same group) already exists;
  the report shows the stored rule version and confidence, the evidence this version
  produces, and stored evidence this version no longer produces (for example evidence an
  older rule version attached: alert evidence is append-only, see
  docs/detection-engine.md)

Nothing is written: no alerts, evidence, rule runs or health rows. Use it to check a rule
change against genuine telemetry before (and after) deploying it, and to explain what a
historical alert would look like under the current version. Output is plain text and every
telemetry-derived value is sanitised and truncated.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from extorq.contracts.alert import DedupStrategy, DetectionAlert
from extorq.detection._compat import sanitize
from extorq.detection.alerts import RuleRow, alert_identity, find_continuation, parse_rows
from extorq.detection.clients import DbClient, QueryRows, chunked, connect
from extorq.detection.registry import LoadedRule, load_rules_report
from extorq.detection.store import DetectionStore

MAX_WINDOW = timedelta(days=7)
#: Same default as EngineConfig.max_episode_seconds (window-bucket continuation span).
MAX_EPISODE_SECONDS = 3600
EVENTS_SQL = (
    "SELECT event_id, any(event_type) AS event_type, any(source_type) AS source_type, "
    "any(JSONExtractString(attributes, 'syscall')) AS syscall, "
    "any(ifNull(process_executable, '')) AS executable "
    "FROM events WHERE event_id IN {ids:Array(String)} GROUP BY event_id"
)


class ReadOnlyClient:
    """Wraps a client so any write attempt fails loudly (defence in depth)."""

    def __init__(self, inner: DbClient) -> None:
        self._inner = inner

    def select(self, sql: str, parameters: dict[str, Any] | None = None) -> QueryRows:
        return self._inner.select(sql, parameters)

    def insert_rows(self, table: str, rows: Sequence[dict[str, Any]]) -> None:
        raise RuntimeError("dry run: writes are not allowed")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError("timestamps must carry a time zone (e.g. ...Z)")
    return parsed.astimezone(UTC)


def _describe(client: DbClient, event_ids: Sequence[str]) -> Counter[str]:
    """``event_type source_type [syscall] [executable]`` -> count, for a set of events."""
    labels: Counter[str] = Counter()
    for batch in chunked(sorted(set(event_ids)), 500):
        for record in client.select(EVENTS_SQL, {"ids": batch}).dicts():
            parts = [str(record["event_type"]), str(record["source_type"])]
            if record.get("syscall"):
                parts.append(f"syscall={record['syscall']}")
            if record.get("executable"):
                parts.append(f"exe={record['executable']}")
            labels[sanitize(" ".join(parts), 160)] += 1
    return labels


def _match_stored(
    rule: LoadedRule,
    rows: list[RuleRow],
    store: DetectionStore,
    window_start: datetime,
) -> tuple[dict[int, DetectionAlert | None], dict[str, dict[str, str]]]:
    bucketed = rule.metadata.dedup.strategy is DedupStrategy.WINDOW_BUCKET
    identities = {id(r): alert_identity(rule, r) for r in rows}
    existing = store.load_alerts(
        rule.rule_id,
        alert_ids=identities.values(),
        group_keys=[r.group_key for r in rows] if bucketed else (),
        since=window_start - timedelta(seconds=MAX_EPISODE_SECONDS) if bucketed else None,
    )
    matches: dict[int, DetectionAlert | None] = {}
    for r in rows:
        alert = existing.get(identities[id(r)])
        if alert is None and bucketed:
            alert = find_continuation(
                [a for a in existing.values() if a.group_key == r.group_key],
                r,
                gap_seconds=rule.metadata.dedup.bucket_seconds or 0,
                max_span_seconds=MAX_EPISODE_SECONDS,
            )
        matches[id(r)] = alert
    evidence = store.load_evidence({a.alert_id for a in matches.values() if a is not None})
    return matches, evidence


def _features(row: RuleRow, limit: int = 12) -> list[str]:
    out = []
    for key in sorted(row.features)[:limit]:
        value = row.features[key]
        shown = ", ".join(str(v) for v in value[:6]) if isinstance(value, list) else str(value)
        out.append(f"{key}={sanitize(shown, 160)}")
    return out


def run(
    rule: LoadedRule,
    start: datetime,
    end: datetime,
    *,
    rules_client: DbClient,
    read_client: DbClient,
) -> list[str]:
    """Evaluate ``rule`` over ``[start, end)``; return report lines (nothing is written)."""
    result = rules_client.select(rule.query_text, rule.query_parameters(start, end))
    rows, problems = parse_rows(rule, result)
    lines = [
        f"{rule.rule_id} v{rule.version} over [{start.isoformat()}, {end.isoformat()}): "
        f"{len(rows)} row(s), {len(problems)} rejected"
    ]
    lines.extend(f"  rejected row: {sanitize(p, 200)}" for p in problems[:5])
    if not rows:
        return lines
    store = DetectionStore(read_client, ReadOnlyClient(read_client), instance="dry-run")
    matches, stored_evidence = _match_stored(rule, rows, store, start)
    for n, r in enumerate(sorted(rows, key=lambda x: (x.first_seen, x.group_key)), start=1):
        alert = matches[id(r)]
        identity = alert.alert_id if alert is not None else alert_identity(rule, r)
        state = (
            f"STORED (v{alert.rule_version}, {alert.confidence.value}, "
            f"updated {alert.updated_at.isoformat()})"
            if alert is not None
            else "NEW"
        )
        lines.append(f"row {n}: alert {identity} {state}")
        lines.append(
            f"  group {sanitize(r.group_key, 160)}; {r.first_seen.isoformat()} .. "
            f"{r.last_seen.isoformat()}; confidence {r.confidence.value}; "
            f"simulation runs {', '.join(r.simulation_run_ids) or 'none'}"
        )
        produced = _describe(read_client, r.evidence_event_ids)
        lines.append(
            f"  evidence produced by v{rule.version}: {len(r.evidence_event_ids)} event(s)"
        )
        lines.extend(f"    {count:4d} x {label}" for label, count in produced.most_common(12))
        if alert is not None:
            stored = set(stored_evidence.get(alert.alert_id, {})) | set(alert.evidence_event_ids)
            stale = sorted(stored - set(r.evidence_event_ids))
            lines.append(
                f"  stored evidence not produced by v{rule.version} in this window: "
                f"{len(stale)} event(s) (older rule versions or other windows)"
            )
            for label, count in _describe(read_client, stale).most_common(12):
                lines.append(f"    {count:4d} x {label}")
        lines.extend(f"  feature {item}" for item in _features(r))
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m extorq.detection.dryrun", description=__doc__)
    parser.add_argument("--rule", action="append", required=True, help="rule id (repeatable)")
    parser.add_argument("--start", type=parse_time, required=True, help="UTC, e.g. ...T14:00:00Z")
    parser.add_argument("--end", type=parse_time, required=True)
    parser.add_argument("--rules-dir", default=None)
    parser.add_argument("--read-role", default="api_ro", choices=("api_ro", "detect"))
    args = parser.parse_args(argv)
    if not args.start < args.end <= args.start + MAX_WINDOW:
        parser.error(f"--end must be after --start and at most {MAX_WINDOW} later")
    rules, problems = load_rules_report(args.rules_dir)
    by_id = {r.rule_id: r for r in rules}
    unknown = [r for r in args.rule if r not in by_id]
    if unknown:
        parser.error(f"unknown or invalid rule(s): {', '.join(unknown)} ({len(problems)} problems)")
    rules_client, read_client = connect("rules_ro"), connect(args.read_role)
    for rule_id in args.rule:
        for line in run(
            by_id[rule_id],
            args.start,
            args.end,
            rules_client=rules_client,
            read_client=read_client,
        ):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

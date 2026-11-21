"""Shared helpers for ExtorQ scenario scripts (owner C2).

Scenario scripts (bash, under simulations/<area>/) use this module through the CLI
(``uv run python simulations/lib/simlib.py <command>``) or ``simulations/lib/lib.sh``:

* ``new-run-id``                 a fresh simulation run id (12 hex chars, CSPRNG)
* ``marker RUN_ID``              the telemetry marker ``extorq-sim-<run_id>``
* ``wait-alert --rule R --run-id ID [--timeout S]``
                                 poll (read-only) until an alert of rule R carries the run
                                 id in ``simulation_run_ids``; exit 0 found / 1 timeout
* ``tagged --run-id ID``         telemetry tagged with the run id, per source/event type

Every query is a static, parameterised SELECT executed with the read-only ClickHouse
identity ``extorq_api_ro`` (A's ``extorq.storage.clickhouse.get_client("api_ro")``; on
the Mac this reaches ClickHouse through the debug proxy 127.0.0.1:18123, compose
profile ``debug``). Nothing here writes to ClickHouse or touches lab assets.

Output is plain text. Every value that comes from telemetry is untrusted and is
sanitised (control/format characters removed, truncated) before printing.
"""

from __future__ import annotations

import argparse
import random
import re
import secrets
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

RUN_ID_RE = re.compile(r"^[a-z0-9]{8,32}$")
RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,15}-[0-9]{3}$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
MARKER_PREFIX = "extorq-sim-"
#: Labels that mark synthetic test data (never real telemetry).
SYNTHETIC_LABELS = ("extorq.fixture", "synthetic")

ALERTS_FOR_RUN_SQL = (
    "SELECT alert_id, rule_id, rule_version, severity, confidence, asset_id, summary, "
    "first_seen, last_seen, event_count, evidence_event_ids, evidence_truncated, "
    "simulation_run_ids, service_ids, created_at, updated_at "
    "FROM alerts WHERE has(simulation_run_ids, {run_id:String}) "
    "AND ({rule_id:String} = '' OR rule_id = {rule_id:String}) "
    "ORDER BY updated_at DESC LIMIT 1 BY alert_id LIMIT 100"
)
EVIDENCE_IDS_SQL = (
    "SELECT event_id FROM alert_evidence WHERE alert_id = {alert_id:String} "
    "GROUP BY event_id ORDER BY event_id LIMIT 5000"
)
EVENTS_SQL = (
    "SELECT event_id, event_time, event_type, source_type, asset_id, collector_id, producer_id, "
    "parser, simulation_run_id, actor_name, src_ip, src_port, http_route, http_status, "
    "resource_path, resource_name, k8s_namespace, k8s_object_name, k8s_user, gh_repository, "
    "gh_commit_sha, service_name, labels "
    "FROM events WHERE event_id IN {ids:Array(String)} "
    "ORDER BY event_time, event_id LIMIT 1 BY event_id LIMIT 1000"
)
TAGGED_SQL = (
    "SELECT source_type, event_type, asset_id, producer_id, uniqExact(event_id) AS n, "
    "min(event_time) AS first_t, max(event_time) AS last_t "
    "FROM events WHERE simulation_run_id = {run_id:String} "
    "GROUP BY source_type, event_type, asset_id, producer_id "
    "ORDER BY first_t, source_type, event_type LIMIT 200"
)
SIM_RUN_SQL = (
    "SELECT run_id, argMax(scenario_id, row_version) AS r_scenario, "
    "argMax(asset_id, row_version) AS r_asset, argMax(status, row_version) AS r_status, "
    "min(started_at) AS r_started, argMax(tuple(finished_at), row_version).1 AS r_finished, "
    "argMax(expected_rule_ids, row_version) AS r_expected "
    "FROM simulation_runs WHERE run_id = {run_id:String} GROUP BY run_id"
)
CONTEXT_SQL = (
    "SELECT context_id, input_hash, created_at, evidence_count, related_count, direct_count, "
    "candidate_count, unestablished_count FROM investigation_contexts "
    "WHERE alert_id = {alert_id:String} ORDER BY created_at DESC, context_id DESC LIMIT 1"
)

_CONTROL_RE = re.compile(
    "[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u00ad\\u200b-\\u200f\\u2028-\\u202e"
    "\\u2060-\\u2064\\u2066-\\u2069\\ufeff\\U000e0000-\\U000e007f]"
)

#: ``select(sql, params) -> list[dict]``: the only database access this module needs.
Select = Callable[[str, dict[str, Any]], list[dict[str, Any]]]


class SimLibError(RuntimeError):
    pass


# ── run ids and markers ─────────────────────────────────────────────────────────


def new_run_id() -> str:
    """12 lower-case hex characters from the OS CSPRNG (matches SimulationRunId)."""
    return secrets.token_hex(6)


def validate_run_id(run_id: str) -> str:
    if not RUN_ID_RE.fullmatch(run_id or ""):
        raise SimLibError("run id must be 8-32 lower-case alphanumerics")
    return run_id


def marker(run_id: str) -> str:
    return MARKER_PREFIX + validate_run_id(run_id)


def clean(value: Any, limit: int = 120) -> str:
    """Printable, bounded rendering of an untrusted value."""
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S.") + f"{value.microsecond // 1000:03d}Z"
    text = _CONTROL_RE.sub("", str(value).replace("\r", " ").replace("\n", " "))
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ── database access ─────────────────────────────────────────────────────────────


def clickhouse_select(role: str = "api_ro") -> Select:
    """Read-only query function on A's client factory (password read from its file)."""
    from extorq.storage.clickhouse import get_client

    client = get_client(role)  # type: ignore[arg-type]

    def select(sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        result = client.query(sql, parameters=params or None)
        return [dict(zip(result.column_names, row, strict=True)) for row in result.result_rows]

    return select


def from_db_client(db: Any) -> Select:
    """Adapt an ``extorq.detection.clients.DbClient`` (used by the tests)."""

    def select(sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = db.select(sql, params).dicts()
        return rows

    return select


# ── queries ─────────────────────────────────────────────────────────────────────


@dataclass
class EvidenceEvent:
    event_id: str
    event_time: datetime
    event_type: str
    source_type: str
    asset_id: str
    collector_id: str
    producer_id: str
    synthetic: bool
    detail: str


@dataclass
class AlertReport:
    alert_id: str
    rule_id: str
    rule_version: str
    severity: str
    confidence: str
    asset_id: str
    summary: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    evidence_ids: list[str]
    evidence_truncated: bool
    service_ids: list[str]
    evidence: list[EvidenceEvent] = field(default_factory=list)
    stored_evidence: int = 0
    context: dict[str, Any] | None = None

    @property
    def by_source(self) -> dict[tuple[str, str, str], int]:
        counts: dict[tuple[str, str, str], int] = {}
        for e in self.evidence:
            key = (e.source_type, e.producer_id, e.collector_id)
            counts[key] = counts.get(key, 0) + 1
        return counts


def _detail(row: dict[str, Any]) -> str:
    parts: list[str] = []
    if row.get("actor_name"):
        parts.append(f"user={clean(row['actor_name'], 64)}")
    if row.get("src_ip"):
        port = f":{row['src_port']}" if row.get("src_port") is not None else ""
        parts.append(f"src={clean(row['src_ip'], 45)}{port}")
    if row.get("http_route"):
        parts.append(f"route={clean(row['http_route'], 80)} status={clean(row.get('http_status'))}")
    if row.get("resource_path") or row.get("resource_name"):
        parts.append(f"resource={clean(row.get('resource_path') or row.get('resource_name'), 100)}")
    if row.get("k8s_object_name"):
        parts.append(
            f"k8s={clean(row.get('k8s_namespace'), 40)}/{clean(row['k8s_object_name'], 80)} "
            f"by {clean(row.get('k8s_user'), 64)}"
        )
    if row.get("gh_commit_sha"):
        repo = clean(row.get("gh_repository"), 80)
        parts.append(f"repo={repo}@{clean(row['gh_commit_sha'], 12)}")
    if row.get("service_name"):
        parts.append(f"service={clean(row['service_name'], 40)}")
    if row.get("simulation_run_id"):
        parts.append(f"sim={clean(row['simulation_run_id'], 32)}")
    return " ".join(parts)


def _is_synthetic(row: dict[str, Any]) -> bool:
    labels = row.get("labels") or {}
    if isinstance(labels, dict) and any(k in labels for k in SYNTHETIC_LABELS):
        return True
    return str(row.get("producer_id") or "").startswith("fixture") or str(
        row.get("collector_id") or ""
    ).startswith("fixture")


def alerts_for_run(select: Select, run_id: str, rule_id: str = "") -> list[AlertReport]:
    validate_run_id(run_id)
    if rule_id and not RULE_ID_RE.fullmatch(rule_id):
        raise SimLibError("rule id must look like VM-001")
    reports: list[AlertReport] = []
    for row in select(ALERTS_FOR_RUN_SQL, {"run_id": run_id, "rule_id": rule_id}):
        reports.append(
            AlertReport(
                alert_id=str(row["alert_id"]),
                rule_id=str(row["rule_id"]),
                rule_version=str(row["rule_version"]),
                severity=str(row["severity"]),
                confidence=str(row["confidence"]),
                asset_id=str(row["asset_id"]),
                summary=str(row["summary"]),
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                event_count=int(row["event_count"]),
                evidence_ids=[str(x) for x in row["evidence_event_ids"]],
                evidence_truncated=bool(row["evidence_truncated"]),
                service_ids=[str(x) for x in row.get("service_ids") or []],
            )
        )
    reports.sort(key=lambda r: (r.rule_id, r.first_seen, r.alert_id))
    return reports


def load_evidence(select: Select, report: AlertReport, limit: int = 1000) -> None:
    stored = [str(r["event_id"]) for r in select(EVIDENCE_IDS_SQL, {"alert_id": report.alert_id})]
    report.stored_evidence = len(stored)
    ids = list(dict.fromkeys([*report.evidence_ids, *stored]))[:limit]
    ids = [i for i in ids if HEX32_RE.fullmatch(i)]
    if not ids:
        return
    for row in select(EVENTS_SQL, {"ids": ids}):
        report.evidence.append(
            EvidenceEvent(
                event_id=str(row["event_id"]),
                event_time=row["event_time"],
                event_type=clean(row["event_type"], 64),
                source_type=clean(row["source_type"], 64),
                asset_id=clean(row["asset_id"], 120),
                collector_id=clean(row["collector_id"], 64),
                producer_id=clean(row["producer_id"], 64),
                synthetic=_is_synthetic(row),
                detail=_detail(row),
            )
        )
    rows = select(CONTEXT_SQL, {"alert_id": report.alert_id})
    report.context = rows[0] if rows else None


def tagged_telemetry(select: Select, run_id: str) -> list[dict[str, Any]]:
    return select(TAGGED_SQL, {"run_id": validate_run_id(run_id)})


def simulation_run(select: Select, run_id: str) -> dict[str, Any] | None:
    rows = select(SIM_RUN_SQL, {"run_id": validate_run_id(run_id)})
    return rows[0] if rows else None


def wait_for_alert(
    select: Select,
    rule_id: str,
    run_id: str,
    *,
    timeout: float = 600.0,
    interval: float = 5.0,
    out: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> AlertReport | None:
    """Poll until an alert of ``rule_id`` carries ``run_id``; ``None`` on timeout.

    Database errors are retried with jittered backoff until the deadline (the stack or
    the debug proxy may be restarting); they are reported, never hidden.
    """
    deadline = clock() + timeout
    attempt = 0
    while True:
        attempt += 1
        try:
            found = alerts_for_run(select, run_id, rule_id)
            if found:
                return found[0]
            out(f"... waiting for a {rule_id} alert tagged {run_id} (attempt {attempt})")
            delay = interval
        except SimLibError:
            raise
        except Exception as exc:  # noqa: BLE001 - transient DB errors are retried, then reported
            out(f"... query failed ({type(exc).__name__}); retrying")
            delay = min(30.0, interval * 2 ** min(attempt, 4)) * random.uniform(0.5, 1.0)  # noqa: S311
        if clock() + delay > deadline:
            return None
        sleep(delay)


# ── rendering ───────────────────────────────────────────────────────────────────


def render_alert(report: AlertReport, *, max_events: int = 40) -> list[str]:
    lines = [
        f"  [{report.rule_id} v{report.rule_version}] alert {report.alert_id}",
        f"    severity={report.severity} confidence={report.confidence} asset={report.asset_id}",
        f"    {clean(report.summary, 400)}",
        f"    first_seen={clean(report.first_seen)} last_seen={clean(report.last_seen)} "
        f"event_count={report.event_count} evidence_ids={len(report.evidence_ids)}"
        f"{' (truncated)' if report.evidence_truncated else ''} "
        f"alert_evidence_rows={report.stored_evidence}",
    ]
    if report.service_ids:
        lines.append(f"    services: {', '.join(report.service_ids)}")
    lines.append("    evidence by source type / authenticated producer / collector:")
    for (source, producer, collector), n in sorted(report.by_source.items()):
        lines.append(f"      {source:<20} producer={producer:<24} collector={collector:<24} {n}")
    synthetic = sum(e.synthetic for e in report.evidence)
    lines.append(
        f"    evidence events read: {len(report.evidence)}; synthetic-labelled: {synthetic}"
        + ("  <-- NOT genuine telemetry" if synthetic else "")
    )
    for e in report.evidence[:max_events]:
        flag = " [SYNTHETIC]" if e.synthetic else ""
        lines.append(
            f"      {clean(e.event_time)} {e.event_type:<32} {e.source_type:<18} {e.detail}{flag}"
        )
    if len(report.evidence) > max_events:
        lines.append(f"      ... {len(report.evidence) - max_events} more")
    if report.context:
        c = report.context
        digest = str(c["input_hash"])[:16]
        lines.append(
            f"    investigation context {c['context_id']} (input_hash {digest}...): "
            f"direct={c['direct_count']} candidate={c['candidate_count']} "
            f"unestablished={c['unestablished_count']}"
        )
    else:
        lines.append("    investigation context: none stored yet")
    return lines


def render_tagged(rows: Sequence[dict[str, Any]]) -> list[str]:
    if not rows:
        return ["  (no events carry this simulation run id yet)"]
    return [
        f"  {clean(r['source_type'], 20):<20} {clean(r['event_type'], 34):<34} "
        f"{clean(r['asset_id'], 40):<28} producer={clean(r['producer_id'], 28):<24} "
        f"{int(r['n']):>4} events  {clean(r['first_t'])} .. {clean(r['last_t'])}"
        for r in rows
    ]


# ── CLI ─────────────────────────────────────────────────────────────────────────


def main(argv: Sequence[str] | None = None, select: Select | None = None) -> int:
    parser = argparse.ArgumentParser(prog="simlib", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("new-run-id")
    p_marker = sub.add_parser("marker")
    p_marker.add_argument("run_id")
    p_wait = sub.add_parser("wait-alert")
    p_wait.add_argument("--rule", required=True)
    p_wait.add_argument("--run-id", required=True)
    p_wait.add_argument("--timeout", type=float, default=600.0)
    p_wait.add_argument("--interval", type=float, default=5.0)
    p_tag = sub.add_parser("tagged")
    p_tag.add_argument("--run-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "new-run-id":
            print(new_run_id())
            return 0
        if args.command == "marker":
            print(marker(args.run_id))
            return 0
        db = select or clickhouse_select()
        if args.command == "tagged":
            print(f"telemetry tagged with simulation run {validate_run_id(args.run_id)}:")
            print("\n".join(render_tagged(tagged_telemetry(db, args.run_id))))
            return 0
        run_id = validate_run_id(args.run_id)
        report = wait_for_alert(db, args.rule, run_id, timeout=args.timeout, interval=args.interval)
        if report is None:
            print(f"timeout: no {args.rule} alert tagged {args.run_id} within {args.timeout:.0f}s")
            return 1
        load_evidence(db, report)
        print(f"{args.rule} alert found for simulation run {args.run_id}:")
        print("\n".join(render_alert(report)))
        return 0
    except SimLibError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

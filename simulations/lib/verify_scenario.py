"""Verify a scenario run end to end: telemetry -> alert -> evidence (owner C2).

Usage (from the repository root, stack + debug proxy running):

    uv run python simulations/lib/verify_scenario.py <run_id> [--expect VM-001 ...]
        [--wait SECONDS] [--max-events N]

Prints, using only read-only queries as ``extorq_api_ro``:

1. the SimulationRun record (scenario, asset, status, expected rules) if one was recorded
2. the telemetry carrying the run id (``events.simulation_run_id``), per source type,
   event type, asset and *authenticated producer* (set by the ingestion gateway from the
   producer's token, so it shows which collector delivered it)
3. every alert whose ``simulation_run_ids`` contains the run id, with its evidence events
   (source types, producers, collectors) and whether any evidence is synthetic-labelled
4. the result: which expected rules alerted

Exit status: 0 when every expected rule has an alert for the run (expected rules come
from ``--expect`` or the SimulationRun record), 1 when one is missing (or nothing is
expected and no alert exists), 2 on usage/connection errors. ``--wait`` keeps polling
until the expected rules alert or the time is up.
"""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from simlib import (
    RULE_ID_RE,
    AlertReport,
    Select,
    SimLibError,
    alerts_for_run,
    clean,
    clickhouse_select,
    load_evidence,
    render_alert,
    render_tagged,
    simulation_run,
    tagged_telemetry,
    validate_run_id,
)


def verify(
    select: Select,
    run_id: str,
    *,
    expect: Sequence[str] = (),
    wait: float = 0.0,
    max_events: int = 40,
    out: Callable[[str], None] = print,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    validate_run_id(run_id)
    for rule in expect:
        if not RULE_ID_RE.fullmatch(rule):
            raise SimLibError(f"invalid rule id {rule!r}")
    run = simulation_run(select, run_id)
    recorded = set(run.get("r_expected") or []) if run else set()
    expected = sorted(set(expect) if expect else recorded)
    deadline = clock() + max(0.0, wait)
    while True:
        alerts = alerts_for_run(select, run_id)
        alerted = {a.rule_id for a in alerts}
        missing = [r for r in expected if r not in alerted]
        satisfied = not missing and (bool(alerts) or not expected)
        if satisfied or clock() >= deadline:
            break
        out(f"... waiting for {', '.join(missing) or 'alerts'} (run {run_id})")
        sleep(min(10.0, max(0.5, deadline - clock())))

    out(f"Scenario run {run_id}")
    if run:
        out(
            f"  simulation_runs: scenario={clean(run.get('r_scenario'), 40)} "
            f"asset={clean(run.get('r_asset'), 80)} status={clean(run.get('r_status'), 20)} "
            f"started={clean(run.get('r_started'))} finished={clean(run.get('r_finished'))} "
            f"expected_rules={', '.join(clean(r, 16) for r in run.get('r_expected') or []) or '-'}"
        )
    else:
        out("  simulation_runs: no record for this run id (scenario did not record it)")
    out("  telemetry carrying the run id (simulation.run_id):")
    for line in render_tagged(tagged_telemetry(select, run_id)):
        out(line)
    out(f"  alerts carrying the run id: {len(alerts)}")
    reports: list[AlertReport] = []
    for report in alerts:
        load_evidence(select, report)
        reports.append(report)
        for line in render_alert(report, max_events=max_events):
            out(line)
    synthetic = sum(e.synthetic for r in reports for e in r.evidence)
    if synthetic:
        out(f"  WARNING: {synthetic} evidence event(s) are synthetic-labelled test data")
    missing = [r for r in expected if r not in {a.rule_id for a in alerts}]
    if expected:
        ok = [r for r in expected if r not in missing]
        out(
            f"  result: expected {', '.join(expected)}; alerted {', '.join(ok) or 'none'}; "
            f"missing {', '.join(missing) or 'none'}"
        )
        return 1 if missing else 0
    out(f"  result: no expected rules given; {len(alerts)} alert(s) found")
    return 0 if alerts else 1


def main(argv: Sequence[str] | None = None, select: Select | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verify_scenario", description="Show the alerts and evidence of a scenario run."
    )
    parser.add_argument("run_id")
    parser.add_argument("--expect", action="append", default=[], help="rule id (repeatable)")
    parser.add_argument("--wait", type=float, default=0.0, help="seconds to wait for alerts")
    parser.add_argument("--max-events", type=int, default=40)
    args = parser.parse_args(argv)
    try:
        db = select or clickhouse_select()
        return verify(
            db, args.run_id, expect=args.expect, wait=args.wait, max_events=max(1, args.max_events)
        )
    except SimLibError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - connection/config problems: say what failed
        print(
            f"error: cannot query ClickHouse ({type(exc).__name__}): is the stack and the "
            "debug proxy (127.0.0.1:18123) running?",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

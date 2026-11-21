"""simulations/lib (scenario helpers + verify_scenario) on a real ephemeral ClickHouse.

The VM-001 fixture used here is SYNTHETIC: the verifier must say so (it flags
synthetic-labelled evidence instead of presenting it as genuine telemetry).
"""

from __future__ import annotations

import sys
from datetime import timedelta
from pathlib import Path

import pytest

from extorq.contracts.ingest import RecordKind
from extorq.contracts.simulation import SimulationRun
from extorq.detection import harness
from extorq.detection.engine import DetectionEngine, EngineConfig
from extorq.detection.registry import load_rules_report

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "simulations" / "lib"))

import simlib  # noqa: E402
import verify_scenario  # noqa: E402

RULES = {r.rule_id: r for r in load_rules_report(REPO / "rules")[0]}
NAT_SIM = REPO / "rules" / "linux" / "tests" / "VM-001" / "positive_nat_gateway_sim.jsonl"
RUN_ID = "fixture0vm001"


@pytest.fixture
def scenario(clickhouse: harness.EphemeralClickHouse, to_row):
    clickhouse.truncate()
    records = harness.load_fixture(NAT_SIM)
    records = harness.shift_records(
        records, harness.day_offset(max(m.event_time for _, m in records))
    )
    first = min(m.event_time for _, m in records)
    run = SimulationRun(
        run_id=RUN_ID,
        scenario_id="VM-001",
        asset_id="linux:lab-vm-01",
        status="completed",
        started_at=first - timedelta(seconds=5),
        finished_at=first + timedelta(minutes=1),
        operator="fixture-synthetic",
        description="SYNTHETIC test record",
        expected_rule_ids=["VM-001"],
    )
    harness.insert_records(
        clickhouse.client("admin"), [*records, (RecordKind.SIMULATION_RUN, run)], to_row
    )
    now = max(m.event_time for _, m in records) + timedelta(seconds=60)
    DetectionEngine(
        [RULES["VM-001"]],
        rules_client=clickhouse.client("rules_ro"),
        read_client=clickhouse.client("detect"),
        write_client=clickhouse.client("detect"),
        config=EngineConfig(instance="rules-harness"),
    ).run_once(now=now, force=True)
    return simlib.from_db_client(clickhouse.client("detect"))


def test_verify_scenario_reports_alert_evidence_and_synthetic_flag(scenario) -> None:
    lines: list[str] = []
    rc = verify_scenario.verify(scenario, RUN_ID, out=lines.append)
    text = "\n".join(lines)
    assert rc == 0, text
    assert "scenario=VM-001" in text and "expected_rules=VM-001" in text
    assert "[VM-001 v1.0.0]" in text and "confidence=medium" in text
    assert "linux.journald" in text and "producer=fixture-synthetic" in text
    assert "synthetic-labelled: 18" in text and "WARNING: 18 evidence event(s)" in text
    assert "result: expected VM-001; alerted VM-001; missing none" in text


def test_verify_scenario_fails_when_an_expected_rule_did_not_alert(scenario) -> None:
    lines: list[str] = []
    rc = verify_scenario.verify(scenario, RUN_ID, expect=["K8S-001"], out=lines.append)
    assert rc == 1
    assert "missing K8S-001" in lines[-1]


def test_wait_alert_finds_alert_and_times_out_otherwise(scenario) -> None:
    report = simlib.wait_for_alert(scenario, "VM-001", RUN_ID, timeout=5, out=lambda _: None)
    assert report is not None and report.rule_id == "VM-001"
    ticks = iter(range(0, 1000, 10))
    missing = simlib.wait_for_alert(
        scenario,
        "GH-001",
        RUN_ID,
        timeout=30,
        interval=10,
        out=lambda _: None,
        sleep=lambda _: None,
        clock=lambda: float(next(ticks)),
    )
    assert missing is None


def test_simlib_cli_basics(capsys, scenario) -> None:
    capsys.readouterr()  # drop log lines written while the fixture ran the detector
    assert simlib.main(["new-run-id"]) == 0
    run_id = capsys.readouterr().out.strip()
    assert simlib.RUN_ID_RE.fullmatch(run_id) and len(run_id) == 12
    assert simlib.main(["marker", RUN_ID]) == 0
    assert capsys.readouterr().out.strip() == f"extorq-sim-{RUN_ID}"
    assert simlib.main(["marker", "Bad Id!"]) == 2
    assert simlib.main(["tagged", "--run-id", RUN_ID], select=scenario) == 0
    out = capsys.readouterr().out
    assert "auth.ssh.invalid_user" in out and "producer=fixture-synthetic" in out


def test_untrusted_values_are_sanitised_for_printing() -> None:
    assert simlib.clean("a\x1b[31mb\nc‮d") == "a[31mb cd"
    assert len(simlib.clean("x" * 500, 50)) == 50

"""Contract between C1's GitHub collector output and GH-001, on a real ClickHouse.

C1's fixtures (``tests/fixtures/github/``) are what the real collector code path emits for
the GH-001 scenario: baseline commit, escalation commit, cleanup commit (SYNTHETIC GitHub
API fake, events labelled ``extorq.fixture=synthetic``):

* ``gh001_collector_output.jsonl``: every version parses (structured analysis); GH-001 must
  raise exactly one HIGH alert, for the escalation commit
* ``gh001_lexical_fallback.jsonl``: the escalation version is unparseable and compared
  lexically (``analysis = lexical_fallback``); exactly one MEDIUM alert, for the escalation

and none for the baseline or cleanup commits. The rule's declared cases run on verbatim
copies (``rules/github/tests/GH-001/c1_*.jsonl``, visible to the detector container); this
test runs on C1's current files, so a collector change that alters the GH-001 verdict fails
here instead of going unnoticed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from extorq.contracts.event import SecurityEvent
from extorq.detection import harness
from extorq.detection.registry import RuleTestCase, load_rules_report

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "github"
RULES = {r.rule_id: r for r in load_rules_report(REPO / "rules")[0]}


@pytest.fixture
def clean(clickhouse: harness.EphemeralClickHouse) -> harness.EphemeralClickHouse:
    clickhouse.truncate()
    return clickhouse


@pytest.mark.parametrize(
    ("filename", "confidence"),
    [("gh001_collector_output.jsonl", "high"), ("gh001_lexical_fallback.jsonl", "medium")],
)
def test_c1_collector_output_alerts_exactly_the_escalation_commit(
    clean, to_row, filename: str, confidence: str
) -> None:
    source = FIXTURES / filename
    if not source.is_file():
        pytest.skip(f"C1's fixture {filename} is not present")
    case = RuleTestCase(
        name=f"c1-{filename}",
        fixture=source,
        expect="alert",
        alerts=1,
        confidence=confidence,
    )
    result = harness.run_case(clean, RULES["GH-001"], case, to_row)
    assert result.passed, result.message

    workflow = sorted(
        (
            m
            for _, m in harness.load_fixture(source)
            if isinstance(m, SecurityEvent) and m.event_type == "github.workflow.modified"
        ),
        key=lambda m: m.event_time,
    )
    assert len(workflow) == 3, "expected baseline, escalation and cleanup commits"
    baseline, escalation, cleanup = workflow
    assert escalation.github is not None and escalation.simulation is not None

    [alert] = harness.fetch_alerts(clean.client("admin"), "GH-001")
    assert alert["entities"]["commit_sha"] == escalation.github.commit_sha
    assert list(alert["evidence_event_ids"]) == [escalation.event_id]
    assert escalation.simulation.run_id in alert["simulation_run_ids"]
    assert baseline.event_id not in alert["evidence_event_ids"]
    assert cleanup.event_id not in alert["evidence_event_ids"]

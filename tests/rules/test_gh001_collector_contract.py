"""Contract between the GitHub collector's output and GH-001/GH-002, on a real ClickHouse.

The collector's fixtures (``tests/fixtures/github/``) are what its real code path emits for
a workflow-escalation commit series: a baseline commit, an escalation commit (write-all, a
pull_request_target trigger and a checkout of the pull request head) and a cleanup commit
(SYNTHETIC GitHub API fake, events labelled ``extorq.fixture=synthetic``):

* ``gh001_collector_output.jsonl``: every version parses (structured analysis)
* ``gh001_lexical_fallback.jsonl``: the escalation version is unparseable and compared
  lexically (``analysis = lexical_fallback``)

GH-001 (permission escalation) and GH-002 (privileged trigger + untrusted checkout) must
each raise exactly one alert, for the escalation commit (high for the structured series,
medium for the lexical one), and none for the baseline or cleanup commits. Running on the
collector's current files means a collector change that alters these verdicts fails here.
The files belong to the GitHub collector's owner; while they still hold records of an
older contract schema the test is skipped with that reason (never silently passed).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

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


def _load(source: Path) -> list:
    if not source.is_file():
        pytest.skip(f"the GitHub collector fixture {source.name} is not present")
    try:
        return harness.load_fixture(source)
    except harness.HarnessError as exc:
        if isinstance(exc.__cause__, ValidationError) and "schema_version" in str(exc.__cause__):
            pytest.skip(f"{source.name} still holds records of an older contract schema")
        raise


@pytest.mark.parametrize("rule_id", ["GH-001", "GH-002"])
@pytest.mark.parametrize(
    ("filename", "confidence"),
    [("gh001_collector_output.jsonl", "high"), ("gh001_lexical_fallback.jsonl", "medium")],
)
def test_collector_output_alerts_exactly_the_escalation_commit(
    clean, to_row, rule_id: str, filename: str, confidence: str
) -> None:
    source = FIXTURES / filename
    records = _load(source)
    case = RuleTestCase(
        name=f"collector-{filename}",
        fixture=source,
        expect="alert",
        alerts=1,
        confidence=confidence,
    )
    result = harness.run_case(clean, RULES[rule_id], case, to_row)
    assert result.passed, result.message

    workflow = sorted(
        (
            m
            for _, m in records
            if isinstance(m, SecurityEvent) and m.event_type == "github.workflow.modified"
        ),
        key=lambda m: m.event_time,
    )
    assert len(workflow) == 3, "expected baseline, escalation and cleanup commits"
    baseline, escalation, cleanup = workflow
    assert escalation.github is not None

    [alert] = harness.fetch_alerts(clean.client("admin"), rule_id)
    assert alert["entities"]["commit_sha"] == escalation.github.commit_sha
    assert list(alert["evidence_event_ids"]) == [escalation.event_id]
    assert baseline.event_id not in alert["evidence_event_ids"]
    assert cleanup.event_id not in alert["evidence_event_ids"]

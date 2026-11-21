"""Every rule's declared fixture tests (positive and negative) on a real ClickHouse."""

from __future__ import annotations

import pytest

from extorq.detection import harness
from extorq.detection.registry import load_rules_report

RULES, PROBLEMS = load_rules_report("rules")
CASES = [(rule, case) for rule in RULES for case in rule.tests]


def test_all_rules_valid() -> None:
    assert not PROBLEMS, "\n".join(str(p) for p in PROBLEMS)


def test_every_rule_has_positive_and_negative_fixtures() -> None:
    for rule in RULES:
        expects = {case.expect for case in rule.tests}
        assert expects == {"alert", "no_alert"}, f"{rule.rule_id} needs positive and negative tests"


@pytest.mark.parametrize(("rule", "case"), CASES, ids=[f"{r.rule_id}:{c.name}" for r, c in CASES])
def test_rule_case(
    clickhouse: harness.EphemeralClickHouse, to_row: harness.ToRow, rule, case
) -> None:
    result = harness.run_case(clickhouse, rule, case, to_row)
    assert result.passed, result.message

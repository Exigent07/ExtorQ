"""Every rule's declared fixture cases (positive and negative) on a real ClickHouse, plus the
catalogue-level guarantees of the detection-test matrix (docs/team/PLAN.md section 12)."""

from __future__ import annotations

from collections import Counter

import pytest

from extorq.contracts.event import SecurityEvent
from extorq.detection import harness
from extorq.detection.registry import load_rules_report

RULES, PROBLEMS = load_rules_report("rules")
CASES = [(rule, case) for rule in RULES for case in rule.tests]
#: Asset classes of the matrix and the minimum number of rules each must have.
MIN_RULES_PER_ASSET = {
    "linux_host": 5,
    "kubernetes_cluster": 5,
    "github_repository": 5,
    "macos_host": 5,
}
PROVENANCE = {"synthetic", "derived-captured"}


def test_all_rules_valid() -> None:
    assert not PROBLEMS, "\n".join(str(p) for p in PROBLEMS)


def test_every_rule_has_positive_and_negative_fixtures() -> None:
    for rule in RULES:
        expects = {case.expect for case in rule.tests}
        assert expects == {"alert", "no_alert"}, f"{rule.rule_id} needs positive and negative tests"


def test_every_rule_mirrors_its_matrix_test_and_negative_control() -> None:
    """Each rule has a fixture of the matrix positive and one of its negative control."""
    for rule in RULES:
        names = {case.name: case.expect for case in rule.tests}
        positives = [n for n, e in names.items() if n.startswith("matrix-") and e == "alert"]
        controls = [n for n, e in names.items() if n.startswith("matrix-control-")]
        assert positives, f"{rule.rule_id}: no matrix positive case (matrix-*)"
        assert controls, f"{rule.rule_id}: no matrix negative control case (matrix-control-*)"
        assert all(names[n] == "no_alert" for n in controls), rule.rule_id


def test_each_asset_class_has_at_least_five_rules() -> None:
    counts: Counter[str] = Counter()
    for rule in RULES:
        for asset_type in {a.value for a in rule.metadata.asset_types}:
            counts[asset_type] += 1
    for asset_type, minimum in MIN_RULES_PER_ASSET.items():
        assert counts[asset_type] >= minimum, f"{asset_type}: {counts[asset_type]} rules"


def test_rules_document_attack_false_positives_and_blind_spots() -> None:
    for rule in RULES:
        meta = rule.metadata
        assert meta.mitre_techniques, f"{rule.rule_id}: no ATT&CK technique"
        assert meta.blind_spots, f"{rule.rule_id}: no blind spots"
        assert meta.false_positives, f"{rule.rule_id}: no false positives"
        # Every false-positive entry says how it is handled (threshold, allowlist, ...).
        undocumented = [fp[:60] for fp in meta.false_positives if "Handling" not in fp]
        assert not undocumented, f"{rule.rule_id}: false positives without handling {undocumented}"
        assert "Confidence" in meta.description, f"{rule.rule_id}: confidence logic undocumented"


def test_fixture_events_carry_provenance_labels() -> None:
    for rule in RULES:
        for case in rule.tests:
            for _, record in harness.load_fixture(case.fixture):
                if isinstance(record, SecurityEvent):
                    label = record.labels.get("extorq.fixture")
                    assert label in PROVENANCE, f"{case.fixture.name}: label {label!r}"


@pytest.mark.parametrize(("rule", "case"), CASES, ids=[f"{r.rule_id}:{c.name}" for r, c in CASES])
def test_rule_case(
    clickhouse: harness.EphemeralClickHouse, to_row: harness.ToRow, rule, case
) -> None:
    result = harness.run_case(clickhouse, rule, case, to_row)
    assert result.passed, result.message

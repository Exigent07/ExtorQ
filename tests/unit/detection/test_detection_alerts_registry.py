"""Alert identity/merge logic, summary templates and the rule loader (pure logic).

Rows and alerts below are SYNTHETIC.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from extorq.contracts.alert import EvidenceConfidence
from extorq.contracts.common import AssetType
from extorq.contracts.identity import alert_id
from extorq.detection.alerts import (
    MAX_ALERT_EVIDENCE,
    RowError,
    RuleRow,
    decide,
    find_continuation,
    merge_features,
    parse_row,
    with_service_ids,
)
from extorq.detection.registry import load_rule_file, load_rules_report
from extorq.detection.templates import TemplateError, render_summary, validate_template

ROOT = Path(__file__).resolve().parents[3] / "rules"
RULES = {r.rule_id: r for r in load_rules_report(ROOT)[0]}
T0 = datetime(2026, 11, 20, 10, 0, tzinfo=UTC)


def ids(n: int, start: int = 1) -> list[str]:
    return [f"{i:032x}" for i in range(start, start + n)]


def row(evidence: list[str], **kw) -> RuleRow:
    base = {
        "group_key": "linux:lab-vm-01|203.0.113.45",
        "asset_id": "linux:lab-vm-01",
        "asset_type": AssetType.LINUX_HOST,
        "first_seen": T0,
        "last_seen": T0 + timedelta(seconds=50),
        "event_count": len(evidence),
        "evidence_event_ids": evidence,
        "entities": {"src_ip": "203.0.113.45"},
        "features": {"distinct_connections": 6, "usernames": ["admin"]},
        "confidence": EvidenceConfidence.MEDIUM,
        "simulation_run_ids": [],
        "bucket_start": T0,
    }
    base.update(kw)
    return RuleRow(**base)


def _decide(r: RuleRow, existing=None, stored=None, now=T0 + timedelta(minutes=2)):
    rule = RULES["VM-001"]
    return decide(
        rule,
        r,
        alert_id(rule.rule_id, r.group_key, r.bucket),
        existing=existing,
        stored_evidence=stored or {},
        window_start=T0 - timedelta(minutes=20),
        window_end=T0 + timedelta(minutes=1),
        now=now,
    )


def test_identity_excludes_rule_version_and_is_stable() -> None:
    a = alert_id("VM-001", "g", T0)
    assert a == alert_id("VM-001", "g", T0)
    assert a != alert_id("VM-001", "g", T0 + timedelta(minutes=5))
    assert a != alert_id("VM-002", "g", T0)


def test_new_alert_then_late_evidence_creates_a_new_version() -> None:
    first = _decide(row(ids(5)))
    assert first is not None and first.created
    alert = first.alert
    assert alert.event_count == 5 and alert.created_at == alert.updated_at
    assert "203.0.113.45" in alert.summary

    # Same row again: nothing new -> no version.
    assert _decide(row(ids(5)), existing=alert, stored=dict.fromkeys(ids(5), "trigger")) is None

    late = _decide(
        row(ids(7), confidence=EvidenceConfidence.HIGH, last_seen=T0 + timedelta(seconds=90)),
        existing=alert,
        stored=dict.fromkeys(ids(5), "trigger"),
        now=T0 + timedelta(minutes=4),
    )
    assert late is not None and not late.created
    assert late.alert.created_at == alert.created_at
    assert late.alert.updated_at > alert.updated_at
    assert late.alert.event_count == 7
    assert late.alert.confidence is EvidenceConfidence.HIGH
    assert [e.event_id for e in late.new_evidence] == ids(2, start=6)


def test_confidence_never_decreases_and_evidence_array_is_capped() -> None:
    big = _decide(row(ids(MAX_ALERT_EVIDENCE + 20), confidence=EvidenceConfidence.HIGH))
    assert big is not None
    assert len(big.alert.evidence_event_ids) == MAX_ALERT_EVIDENCE
    assert big.alert.evidence_truncated is True
    lower = _decide(
        row(ids(MAX_ALERT_EVIDENCE + 21), confidence=EvidenceConfidence.LOW),
        existing=big.alert,
        stored={},
    )
    assert lower is not None and lower.alert.confidence is EvidenceConfidence.HIGH


def test_service_ids_are_validated_unioned_and_sorted() -> None:
    alert = _decide(row(ids(3))).alert
    a, b = "b" * 32, "a" * 32
    updated = with_service_ids(alert, [a, b, "not-hex", a])
    assert updated.service_ids == [b, a]
    assert with_service_ids(updated, [b]) is updated
    merged = _decide(row(ids(4)), existing=updated, stored={}).alert
    assert merged.service_ids == [b, a]


def test_merge_features_is_monotone() -> None:
    merged = merge_features(
        {"n": 3, "flag": False, "users": ["a"], "s": "x"},
        {"n": 2, "flag": True, "users": ["b", "a"], "s": "y"},
    )
    assert merged == {"n": 3, "flag": True, "users": ["a", "b"], "s": "y"}


def test_find_continuation_merges_adjacent_buckets_only() -> None:
    alert = _decide(row(ids(3))).alert
    adjacent = row(
        ids(3, 10), first_seen=T0 + timedelta(minutes=5), bucket_start=T0 + timedelta(minutes=5)
    )
    far = row(
        ids(3, 20), first_seen=T0 + timedelta(minutes=30), bucket_start=T0 + timedelta(minutes=30)
    )
    assert find_continuation([alert], adjacent, gap_seconds=300, max_span_seconds=3600) is alert
    assert find_continuation([alert], far, gap_seconds=300, max_span_seconds=3600) is None


def test_parse_row_rejects_contract_violations() -> None:
    rule = RULES["VM-001"]
    good = {
        "group_key": "g",
        "asset_id": "linux:lab-vm-01",
        "asset_type": "linux_host",
        "first_seen": T0,
        "last_seen": T0,
        "event_count": 1,
        "evidence_event_ids": ids(1),
        "entities": {"src_ip": "1.2.3.4"},
        "features": '{"a": 1}',
        "confidence": "high",
        "simulation_run_ids": [],
        "bucket_start": T0,
    }
    assert parse_row(rule, good).features == {"a": 1}
    for change, message in [
        ({"asset_type": "kubernetes_cluster"}, "not declared"),
        ({"evidence_event_ids": ["nope"]}, "no valid evidence"),
        ({"confidence": "certain"}, "confidence"),
        ({"first_seen": T0.replace(tzinfo=None)}, "timezone-aware"),
        ({"features": "{broken"}, "not valid JSON"),
    ]:
        with pytest.raises(RowError, match=message):
            parse_row(rule, {**good, **change})


def test_templates_are_safe_and_bounded() -> None:
    assert validate_template("{a} and {b_c}") == ["a", "b_c"]
    for bad in ("{a.__class__}", "{0}", "{a!r}", "{a:>10}", "{", ""):
        with pytest.raises(TemplateError):
            validate_template(bad)
    text = render_summary(
        "user {u} list {l} none {missing}", {"u": "x\n‮y" * 100, "l": list("abcdefg")}
    )
    assert "\n" not in text and "‮" not in text
    assert "a, b, c, d, e (+2 more)" in text and "none unknown" in text


def test_registry_reports_invalid_rules(tmp_path: Path) -> None:
    (tmp_path / "XX-001.yaml").write_text(
        "rule_id: XX-001\nversion: 1.0.0\ntitle: t\ndescription: d\nseverity: low\n"
        "asset_types: [linux_host]\nrequires:\n  - source_type: linux.journald\n"
        "    event_types: [github.workflow.modified]\nschedule: {interval_seconds: 120, "
        "lookback_seconds: 60}\ndedup: {strategy: event}\ngroup_by: [a]\nquery: XX-001.sql\n"
        "query_sha256: abc\nunknown_key: 1\n"
    )
    (tmp_path / "XX-001.sql").write_text("SELECT * FROM alerts")
    rule, problems = load_rule_file(tmp_path / "XX-001.yaml", tmp_path)
    assert rule is None
    text = "\n".join(str(p) for p in problems)
    assert "unknown keys" in text
    assert "query_sha256 is computed by the loader" in text
    assert "does not emit github.workflow.modified" in text
    assert "lookback_seconds" in text
    assert "table alerts is not allowed" in text


def test_repository_rules_all_have_positive_and_negative_tests() -> None:
    assert {"VM-001", "VM-002", "K8S-001", "K8S-002", "GH-001", "CORR-002"} <= set(RULES)
    for rule in RULES.values():
        assert {c.expect for c in rule.tests} == {"alert", "no_alert"}, rule.rule_id
        assert rule.metadata.false_positives and rule.metadata.blind_spots, rule.rule_id


_VALID_RULE = (
    "rule_id: XX-002\nversion: 1.0.0\ntitle: t\ndescription: d\nseverity: low\n"
    "asset_types: [linux_host]\nrequires:\n  - source_type: linux.journald\n"
    "    event_types: [auth.ssh.login_failed]\nschedule: {interval_seconds: 60, "
    "lookback_seconds: 600}\ndedup: {strategy: event}\ngroup_by: [a]\nquery: XX-002.sql\n"
    "tests:\n"
)
_VALID_SQL = (
    "SELECT event_id AS signature FROM events "
    "WHERE event_time >= {window_start:DateTime64(3, 'UTC')} "
    "AND event_time < {window_end:DateTime64(3, 'UTC')}"
)


def _rule_with_case(tmp_path: Path, case: str):
    (tmp_path / "XX-002.yaml").write_text(_VALID_RULE + case)
    (tmp_path / "XX-002.sql").write_text(_VALID_SQL)
    (tmp_path / "f.jsonl").write_text("")
    return load_rule_file(tmp_path / "XX-002.yaml", tmp_path)


def test_test_cases_accept_feature_and_summary_expectations(tmp_path: Path) -> None:
    rule, problems = _rule_with_case(
        tmp_path,
        "  - name: c\n    fixture: f.jsonl\n    expect: alert\n"
        "    features: {persistence_units: [a.service], causation_established: false}\n"
        "    summary_contains: 'context only: a'\n",
    )
    assert problems == [] and rule is not None
    [case] = rule.tests
    assert case.features == {"persistence_units": ["a.service"], "causation_established": False}
    assert case.summary_contains == ("context only: a",)


def test_test_case_expectations_are_validated(tmp_path: Path) -> None:
    _, problems = _rule_with_case(
        tmp_path,
        "  - name: c\n    fixture: f.jsonl\n    expect: alert\n    features: {a: {nested: 1}}\n",
    )
    assert "features must map names to scalars or scalar lists" in "\n".join(map(str, problems))
    _, problems = _rule_with_case(
        tmp_path,
        "  - name: c\n    fixture: f.jsonl\n    expect: alert\n    summary_contains: [1]\n",
    )
    assert "summary_contains must be a string or list" in "\n".join(map(str, problems))


def test_harness_feature_comparison_is_exact() -> None:
    from extorq.detection.harness import _feature_problems

    alert = {"features": '{"units": ["a.service"], "n": 1, "flag": false}'}
    assert _feature_problems(alert, {"units": ["a.service"], "n": 1, "flag": False}) == []
    problems = _feature_problems(alert, {"units": ["b.service"], "missing": True})
    assert len(problems) == 2 and "<missing>" in problems[1]
    assert _feature_problems({"features": "not json"}, {"x": 1}) == [
        "alert features are not valid JSON"
    ]

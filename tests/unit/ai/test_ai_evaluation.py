"""Evaluation harness and deterministic baseline (fake Jev client, no network)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from ai_fakes import DATASET, answering_client, enabled_settings, jev_key, load_dataset_records

from extorq.ai import evaluation
from extorq.ai.baseline import baseline_prioritise
from extorq.ai.evaluation import (
    LABELS,
    build_report,
    compute_metrics,
    load_dataset,
    render_markdown,
    run_eval,
)
from extorq.ai.jev import JevTriageProvider
from extorq.ai.synthetic import SYNTHETIC_NOTICE, is_synthetic
from extorq.contracts.ai import TriageRecommendation
from extorq.contracts.context import InvestigationContext


def test_dataset_is_synthetic_balanced_and_valid() -> None:
    records = load_dataset_records()
    assert len(records) >= 24
    assert all(r["synthetic"] is True for r in records)
    cases = load_dataset(DATASET)
    for case in cases:
        assert is_synthetic(case.context)
        assert SYNTHETIC_NOTICE in case.context.limitations
        assert case.label in LABELS
    counts = Counter((c.domain, c.label) for c in cases)
    for domain in ("github", "ssh_http", "k8s"):
        for label in LABELS:
            assert counts[(domain, label)] >= 1, (domain, label)
    # IPs are documentation/private ranges only (never real third-party addresses).
    for case in cases:
        for event in case.context.evidence:
            if event.src_ip:
                assert event.src_ip.startswith(
                    ("192.0.2.", "198.51.100.", "203.0.113.", "10.", "172.", "192.168.", "127.")
                )


def test_dataset_file_is_reproducible(tmp_path: Path) -> None:
    import runpy

    out = tmp_path / "dataset.jsonl"
    module = runpy.run_path(str(DATASET.with_name("build_dataset.py")))
    assert module["main"](out) == 0
    assert out.read_text(encoding="utf-8") == DATASET.read_text(encoding="utf-8")


def test_non_synthetic_records_are_rejected(tmp_path: Path) -> None:
    record = load_dataset_records()[0]
    record["synthetic"] = False
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="synthetic=true"):
        load_dataset(bad)
    record["synthetic"] = True
    record["context"]["limitations"] = []
    bad.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not marked as SYNTHETIC"):
        load_dataset(bad)


def test_baseline_is_deterministic_and_uses_coverage(
    contexts: dict[str, InvestigationContext],
) -> None:
    for ctx in contexts.values():
        assert baseline_prioritise(ctx) == baseline_prioritise(ctx)
    assert (
        baseline_prioritise(contexts["SSH-I1"]).recommendation
        is TriageRecommendation.INSUFFICIENT_CONTEXT
    )


def _provider(**answers: Any) -> JevTriageProvider:
    client = answering_client(**answers)
    return JevTriageProvider(enabled_settings(), key=jev_key(), client_factory=lambda k, s: client)


def test_offline_run_reports_baseline_only() -> None:
    cases = load_dataset(DATASET)
    run = run_eval(cases, provider=None, settings=enabled_settings(), max_calls=0, raw_path=None)
    metrics = compute_metrics(run)
    assert "jev" not in metrics
    assert metrics["cases"] == len(cases)
    confusion = metrics["baseline"]["confusion"]
    assert sum(sum(row.values()) for row in confusion.values()) == len(cases)


def test_fake_run_metrics_cap_and_raw_reuse(tmp_path: Path) -> None:
    cases = load_dataset(DATASET)[:6]
    raw = tmp_path / "raw.jsonl"
    run = run_eval(
        cases, provider=_provider(sc=0.9), settings=enabled_settings(), max_calls=4, raw_path=raw
    )
    assert run.calls_made == 4
    statuses = Counter(r.jev_status for r in run.results)
    assert statuses["not_run"] == 2
    metrics = compute_metrics(run)
    jev = metrics["jev"]
    assert jev["answered"] == 4
    assert jev["order_consistency_rate"] == 1.0
    assert jev["tokens"]["input_total"] == 4 * 1234
    assert jev["models_reported"] == ["jev-1.14.0"]
    # Re-run: successful raw results are reused, only the remaining cases cost calls.
    rerun = run_eval(
        cases, provider=_provider(sc=0.9), settings=enabled_settings(), max_calls=4, raw_path=raw
    )
    assert rerun.calls_made == 2
    assert sum(r.reused for r in rerun.results) == 4


def test_report_rendering_is_honest_about_synthetic_data(tmp_path: Path) -> None:
    cases = load_dataset(DATASET)
    run = run_eval(
        cases, provider=_provider(sc=0.1), settings=enabled_settings(), max_calls=100, raw_path=None
    )
    report = build_report(run, dataset=DATASET, max_calls=100, date="2026-11-21")
    markdown = render_markdown(report)
    assert "SYNTHETIC" in markdown
    assert "Confusion matrix - Jev" in markdown
    assert report["notes"][0].startswith(("Jev outperformed", "Jev did NOT outperform", "Jev tied"))
    # Every case answered "insufficient": accuracy equals the insufficient share of labels.
    expected = sum(1 for c in cases if c.label == "insufficient_context") / len(cases)
    assert report["metrics"]["jev"]["accuracy"] == round(expected, 4)
    json.dumps(report)  # serialisable


def test_cli_offline_writes_outputs(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = evaluation.main(["--out-dir", str(tmp_path), "--date", "test-run", "--limit", "5"])
    assert code == 0
    assert (tmp_path / "results-test-run.json").is_file()
    assert (tmp_path / "results-test-run.md").is_file()
    assert "live calls this run: 0" in capsys.readouterr().out


def test_cli_live_requires_a_usable_key(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = evaluation.main(["--live", "--out-dir", str(tmp_path), "--max-calls", "1"])
    assert code == 2
    assert "JEV_API_KEY not configured" in capsys.readouterr().out


def test_pre_guard_label_reads_the_raw_priority_choice() -> None:
    from extorq.ai.evaluation import CaseResult, pre_guard_label

    downgraded = CaseResult(
        "X",
        "k8s",
        "likely_benign_maintenance",
        "priority_investigation",
        3.0,
        jev="routine_review",
        rationale_codes=[
            "context_sufficient",
            "priority_order_consistent",
            "priority_likely_benign_maintenance",
            "benign_conflicts_privilege_escalation",
        ],
    )
    assert pre_guard_label(downgraded) == "likely_benign_maintenance"
    insufficient = CaseResult(
        "Y", "k8s", "insufficient_context", "insufficient_context", 0.0, jev="insufficient_context"
    )
    assert pre_guard_label(insufficient) == "insufficient_context"
    assert pre_guard_label(CaseResult("Z", "k8s", "routine_review", "routine_review", 1.0)) is None

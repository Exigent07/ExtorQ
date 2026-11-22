"""scripts/demo_check.py: the pure checks (no stack, no docker, no network).

Covers the per-asset-class telemetry rules, the collector and ingest-problem checks and
the evaluation of detection-test reports (``var/reports/detection-tests-*.json`` written
by ``make test-detections``). Reports here are SYNTHETIC files in a temporary directory.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[3]


def _load() -> Any:
    spec = importlib.util.spec_from_file_location(
        "extorq_demo_check", REPO / "scripts" / "demo_check.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


dc = _load()


# ── telemetry per asset class ─────────────────────────────────────────


def test_asset_class_of_namespace() -> None:
    assert [dc.asset_class_of(n) for n in ("macos", "linux", "k8s", "github", "aws")] == [
        "macos",
        "linux",
        "kubernetes",
        "github",
        "other",
    ]


def test_fresh_telemetry_passes(capsys: pytest.CaptureFixture[str]) -> None:
    report = dc.Report()
    events = [["k8s", 20, 900], ["linux", 30, 400], ["macos", 4000, 3]]
    state = [["github", 600], ["k8s", 50], ["linux", 40], ["macos", 100]]
    seen = dc.check_telemetry(report, events, state)
    assert report.failures == []
    assert report.warnings == ["GitHub repository events"]  # only on repository activity
    assert seen["kubernetes"] == (20, 900) and seen["github"] == (None, 0)
    assert "[FAIL]" not in capsys.readouterr().out


def test_stale_or_missing_telemetry_fails() -> None:
    report = dc.Report()
    events = [["linux", 3600, 10]]  # Linux journald silent for an hour
    state = [["linux", 30], ["k8s", 9000]]  # Kubernetes inventory stale, macOS/GitHub absent
    dc.check_telemetry(report, events, state)
    assert set(report.failures) == {
        "Ubuntu VM events",
        "Kubernetes cluster (k8s:*) state records",
        "Kubernetes cluster events",
        "macOS host (macos:*) state records",
        "GitHub repository (github:*) state records",
    }


def test_unknown_asset_namespace_is_a_warning() -> None:
    report = dc.Report()
    dc.check_telemetry(report, [["aws", 10, 5]], [])
    assert "events of unknown asset classes" in report.warnings


# ── collectors and ingest problems ────────────────────────────────────


def _collector_row(collector_id: str, status: str, age: int, *, dead: int = 0) -> list[Any]:
    return [collector_id, "linux_ssh", status, "2026-11-22 10:00:00", age, 30, 0, "", 5, dead]


def test_collectors_ok_degraded_and_stale(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        dc, "enabled_host_collectors", lambda: {"a": 30, "b": 30, "c": 30, "missing": 30}
    )
    report = dc.Report()
    rows = [
        _collector_row("a", "ok", 20),
        _collector_row("b", "degraded", 20),
        _collector_row("c", "ok", 900),  # older than max(3 x 30 s, 180 s)
    ]
    dc.check_collectors(report, rows)
    assert report.warnings == ["b"]
    assert report.failures == ["c", "missing"]


def test_ingest_problems_are_warnings() -> None:
    report = dc.Report()
    dc.check_ingest_problems(
        report,
        [["linux-ssh-lab-vm-01", "semantics: event type not allowed", 3]],
        [["forbidden", "github-collector", "asset_not_allowed:github:x", 1]],
    )
    assert report.failures == []
    assert report.warnings == ["quarantined records", "refused requests (401/403)"]
    clean = dc.Report()
    dc.check_ingest_problems(clean, [], [])
    assert clean.warnings == [] and clean.failures == []


# ── detection-test reports ────────────────────────────────────────────


@pytest.mark.parametrize(
    ("item", "positive", "outcome"),
    [
        ({"kind": "positive", "status": "passed"}, True, "pass"),
        ({"polarity": "negative", "outcome": "PASS"}, False, "pass"),
        ({"type": "neg", "result": "failed"}, False, "fail"),
        ({"expect_alert": True, "passed": False}, True, "fail"),
        ({"expected_alert": False, "status": "skipped"}, False, "skip"),
        ({"status": "weird"}, None, "unknown"),
    ],
)
def test_normalise_result_variants(item: dict[str, Any], positive: Any, outcome: str) -> None:
    result = dc.normalise_result({"test_id": "t", "asset": "linux", "rule_id": "VM-001", **item})
    assert (result.positive, result.outcome) == (positive, outcome)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("linux", "linux"), ("k8s", "kubernetes"), ("k8s:extorq-lab", "kubernetes"), ("MAC", "macos")],
)
def test_normalise_asset(value: str, expected: str) -> None:
    assert dc.normalise_asset(value) == expected


def _results(asset: str, positives: int, negatives: int, **override: Any) -> list[dict[str, Any]]:
    items = [
        {"test_id": f"{asset}-p{i}", "asset": asset, "rule_id": "R-00" + str(i), "kind": "positive"}
        | {"status": "passed"}
        for i in range(positives)
    ] + [
        {"test_id": f"{asset}-n{i}", "asset": asset, "rule_id": "R-00" + str(i), "kind": "negative"}
        | {"status": "passed"}
        for i in range(negatives)
    ]
    for item in items:
        item.update(override.get(item["test_id"], {}))
    return items


def _write(directory: Path, name: str, results: list[dict[str, Any]], age: float = 0) -> Path:
    path = directory / f"detection-tests-{name}.json"
    controls = {(r["asset"], r["rule_id"]): r["status"] for r in results if r["kind"] == "negative"}
    tests = [
        {
            **r,
            "rule_version": "1.0.0",
            "cleanup_ok": True,
            "positive": {
                "outcome": r["status"],
                "alerts": [{"verified_evidence": {"a" * 32: "synthetic-producer"}}],
            },
            "negative": {
                "outcome": controls.get((r["asset"], r["rule_id"]), "passed"),
                "conclusive_run": "synthetic-rule-run",
            },
        }
        for r in results
        if r["kind"] == "positive"
    ]
    path.write_text(json.dumps({"schema": dc.REPORT_SCHEMA, "tests": tests}), encoding="utf-8")
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))
    return path


def test_all_assets_passing(tmp_path: Path) -> None:
    results = [r for a in dc.ASSET_CLASSES for r in _results(a, 5, 5)]
    _write(tmp_path, "all", results)
    report = dc.Report()
    dc.check_detection_tests(report, tmp_path)
    assert report.failures == [] and report.warnings == []


def test_failed_negative_and_skipped_positive_fail(tmp_path: Path) -> None:
    results = [r for a in dc.ASSET_CLASSES for r in _results(a, 5, 5)]
    results[0]["status"] = "skipped"  # macos positive not run
    for item in results:
        if item["test_id"] == "linux-n2":
            item["status"] = "failed"  # the rule alerted on its negative control
    _write(tmp_path, "all", results)
    report = dc.Report()
    dc.check_detection_tests(report, tmp_path)
    assert set(report.failures) == {"macos detection tests", "linux detection tests"}


def test_coverage_below_five_distinct_positives_fails(tmp_path: Path) -> None:
    results = [r for a in dc.ASSET_CLASSES for r in _results(a, 5 if a != "github" else 4, 4)]
    _write(tmp_path, "all", results)
    report = dc.Report()
    dc.check_detection_tests(report, tmp_path)
    assert report.failures == ["github test coverage"]


def test_newest_report_per_asset_is_used(tmp_path: Path) -> None:
    old = [r for a in dc.ASSET_CLASSES for r in _results(a, 5, 5)]
    for item in old:
        if item["asset"] == "linux":
            item["status"] = "failed"
    _write(tmp_path, "old-all", old, age=7200)
    _write(tmp_path, "new-linux", _results("linux", 6, 6), age=60)  # re-run of one asset
    report = dc.Report()
    dc.check_detection_tests(report, tmp_path)
    assert report.failures == []


def test_missing_or_stale_reports(tmp_path: Path) -> None:
    report = dc.Report()
    dc.check_detection_tests(report, tmp_path)
    assert report.failures == ["detection-test report"]
    _write(tmp_path, "linux", _results("linux", 5, 5), age=3 * 86400)
    (tmp_path / "detection-tests-broken.json").write_text("{not json", encoding="utf-8")
    report = dc.Report()
    dc.check_detection_tests(report, tmp_path)
    assert "linux report age" in report.warnings
    assert {"macos detection tests", "kubernetes detection tests", "github detection tests"} <= set(
        report.failures
    )


def test_report_time_prefers_the_report_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "detection-tests-x.json"
    path.write_text("{}", encoding="utf-8")
    stamp = dc.report_time({"finished_at": "2026-11-22T10:00:00Z"}, path)
    assert stamp == 1795341600.0
    assert dc.report_time({"finished_at": "garbage"}, path) == path.stat().st_mtime
    assert dc.report_results([{"test_id": "a"}, "junk"])[0].test_id == "a"
    assert dc.report_results({"tests": "not a list"}) == []

"""Evaluation of Jev triage against a deterministic baseline (``extorq ai eval``).

Input: ``eval/jev/dataset.jsonl`` - SYNTHETIC, author-labelled InvestigationContext
cases (see eval/jev/build_dataset.py). Every case must carry ``"synthetic": true``
and a context built by :mod:`extorq.ai.synthetic`; anything else is rejected.

Without ``--live`` only the baseline runs (no network). With ``--live`` each case
costs exactly one Jev call (all questions in one ``system_one`` request), capped
by ``--max-calls``. Raw assessments are appended to ``raw-<date>.jsonl`` and
reused on re-runs, so reporting can be regenerated without paying twice.

Outputs: ``results-<date>.json`` and ``results-<date>.md`` with accuracy,
confusion matrices, insufficient-context rate, order-consistency rate,
uncertainty rate, latency and token usage.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from extorq.ai.baseline import baseline_prioritise
from extorq.ai.jev import TRIAGE_PROMPT_VERSION, JevTriageProvider, question_set
from extorq.ai.projection import Domain, classify_domain
from extorq.ai.settings import AISettings, get_ai_settings, get_provider_key
from extorq.ai.synthetic import is_synthetic
from extorq.contracts.ai import AIAssessment, AIStatus, TriageRecommendation
from extorq.contracts.context import InvestigationContext

LABELS: tuple[str, ...] = tuple(r.value for r in TriageRecommendation)
JEV_INPUT_PRICE_PER_MTOK_USD = 0.042  # TypeSafe published price (output tokens currently free)
DEFAULT_DATASET = Path("eval/jev/dataset.jsonl")
DEFAULT_OUT = Path("eval/jev")


@dataclass(frozen=True)
class EvalCase:
    case_id: str
    domain: str
    label: str
    description: str
    context: InvestigationContext


def load_dataset(path: Path) -> list[EvalCase]:
    cases: list[EvalCase] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("synthetic") is not True:
            raise ValueError(f"line {number}: only records marked synthetic=true are accepted")
        if record.get("label") not in LABELS:
            raise ValueError(f"line {number}: unknown label {record.get('label')!r}")
        ctx = InvestigationContext.model_validate(record["context"])
        if not is_synthetic(ctx):
            raise ValueError(f"line {number}: context is not marked as SYNTHETIC")
        cases.append(
            EvalCase(
                record["case_id"], record["domain"], record["label"], record["description"], ctx
            )
        )
    if len({c.case_id for c in cases}) != len(cases):
        raise ValueError("duplicate case ids in dataset")
    return cases


@dataclass
class CaseResult:
    case_id: str
    domain: str
    label: str
    baseline: str
    baseline_score: float
    jev: str | None = None
    jev_status: str | None = None
    uncertain: bool | None = None
    order_consistent: bool | None = None
    sufficient_context: float | None = None
    rationale_codes: list[str] = field(default_factory=list)
    latency_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    model: str | None = None
    request_id: str | None = None
    error: str | None = None
    reused: bool = False


def _raw_key(case: EvalCase, settings: AISettings) -> str:
    qs = question_set(classify_domain(case.context))
    return f"{case.case_id}|{case.context.input_hash}|{qs.version}|{settings.jev_model}"


def _load_raw(path: Path) -> dict[str, AIAssessment]:
    reused: dict[str, AIAssessment] = {}
    if not path.is_file():
        return reused
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        reused[record["key"]] = AIAssessment.model_validate(record["assessment"])
    return reused


def _apply(result: CaseResult, a: AIAssessment) -> None:
    result.jev_status = a.status.value
    result.latency_ms = a.latency_ms
    result.input_tokens = a.input_tokens
    result.output_tokens = a.output_tokens
    result.model = a.model
    result.request_id = a.provider_request_id
    result.error = a.error
    if a.triage is not None:
        result.jev = a.triage.recommendation.value
        result.uncertain = a.triage.uncertain
        result.order_consistent = a.triage.order_consistent
        result.sufficient_context = a.triage.sufficient_context_probability
        result.rationale_codes = list(a.triage.rationale_codes)


@dataclass
class EvalRun:
    results: list[CaseResult]
    calls_made: int
    live: bool
    settings_model: str
    question_sets: dict[str, str]


def run_eval(
    cases: Sequence[EvalCase],
    *,
    provider: JevTriageProvider | None,
    settings: AISettings,
    max_calls: int,
    raw_path: Path | None,
) -> EvalRun:
    """Run the baseline on every case and (when ``provider`` is given) Jev, one call per case."""
    reused = _load_raw(raw_path) if raw_path is not None else {}
    results: list[CaseResult] = []
    calls = 0
    for case in cases:
        base = baseline_prioritise(case.context)
        result = CaseResult(
            case.case_id, case.domain, case.label, base.recommendation.value, base.score
        )
        if provider is not None:
            key = _raw_key(case, settings)
            previous = reused.get(key)
            if previous is not None and previous.status in (
                AIStatus.OK,
                AIStatus.INSUFFICIENT_CONTEXT,
            ):
                _apply(result, previous)
                result.reused = True
            elif calls >= max_calls:
                result.jev_status = "not_run"
                result.error = f"max_calls ({max_calls}) reached"
            else:
                assessment = provider.assess(case.context, requested_by="system:ai-eval")
                if assessment.status is not AIStatus.DISABLED:
                    calls += 1
                _apply(result, assessment)
                if raw_path is not None:
                    with raw_path.open("a", encoding="utf-8") as fh:
                        record = {"key": key, "assessment": assessment.model_dump(mode="json")}
                        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        results.append(result)
    return EvalRun(
        results=results,
        calls_made=calls,
        live=provider is not None,
        settings_model=settings.jev_model,
        question_sets={d.value: question_set(d).version for d in Domain},
    )


# ── metrics ───────────────────────────────────────────────────────────


def _confusion(
    pairs: list[tuple[str, str]], predicted_labels: Sequence[str]
) -> dict[str, dict[str, int]]:
    matrix = {gold: dict.fromkeys(predicted_labels, 0) for gold in LABELS}
    for gold, pred in pairs:
        matrix[gold][pred] = matrix[gold].get(pred, 0) + 1
    return matrix


def _rate(numerator: int, denominator: int) -> float | None:
    return None if denominator == 0 else round(numerator / denominator, 4)


def _percentile(values: list[int], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return float(ordered[index])


def compute_metrics(run: EvalRun) -> dict[str, Any]:
    results = run.results
    total = len(results)
    base_correct = sum(1 for r in results if r.baseline == r.label)
    metrics: dict[str, Any] = {
        "cases": total,
        "label_distribution": dict(Counter(r.label for r in results)),
        "baseline": {
            "accuracy": _rate(base_correct, total),
            "correct": base_correct,
            "insufficient_context_rate": _rate(
                sum(
                    1
                    for r in results
                    if r.baseline == TriageRecommendation.INSUFFICIENT_CONTEXT.value
                ),
                total,
            ),
            "confusion": _confusion([(r.label, r.baseline) for r in results], LABELS),
            "per_domain_accuracy": _per_domain(results, "baseline"),
        },
    }
    if not run.live:
        return metrics
    answered = [r for r in results if r.jev is not None]
    jev_correct = sum(1 for r in results if r.jev == r.label)
    latencies = [r.latency_ms for r in results if r.latency_ms is not None and not r.reused]
    all_latencies = [r.latency_ms for r in results if r.latency_ms is not None]
    in_tokens = [r.input_tokens for r in results if r.input_tokens is not None]
    out_tokens = [r.output_tokens for r in results if r.output_tokens is not None]
    confident = [r for r in answered if r.uncertain is False]
    status_counts = Counter(r.jev_status or "none" for r in results)
    agreement = Counter(
        ("jev_correct" if r.jev == r.label else "jev_wrong")
        + "/"
        + ("baseline_correct" if r.baseline == r.label else "baseline_wrong")
        for r in results
    )
    metrics["jev"] = {
        "accuracy": _rate(jev_correct, total),
        "correct": jev_correct,
        "answered": len(answered),
        "status_counts": dict(status_counts),
        "insufficient_context_rate": _rate(
            sum(1 for r in answered if r.jev == TriageRecommendation.INSUFFICIENT_CONTEXT.value),
            len(answered),
        ),
        "order_consistency_rate": _rate(
            sum(1 for r in answered if r.order_consistent), len(answered)
        ),
        "uncertain_rate": _rate(sum(1 for r in answered if r.uncertain), len(answered)),
        "confident_cases": len(confident),
        "accuracy_on_confident": _rate(
            sum(1 for r in confident if r.jev == r.label), len(confident)
        ),
        "confusion": _confusion(
            [(r.label, r.jev or (r.jev_status or "error")) for r in results],
            [*LABELS, "error", "timeout", "rate_limited", "invalid_output", "not_run"],
        ),
        "per_domain_accuracy": _per_domain(results, "jev"),
        "latency_ms": {
            "measured_calls": len(all_latencies),
            "mean": round(statistics.fmean(all_latencies), 1) if all_latencies else None,
            "p50": _percentile(all_latencies, 0.5),
            "p95": _percentile(all_latencies, 0.95),
            "max": max(all_latencies) if all_latencies else None,
            "calls_this_run": len(latencies),
        },
        "tokens": {
            "input_total": sum(in_tokens),
            "output_total": sum(out_tokens),
            "input_mean": round(statistics.fmean(in_tokens), 1) if in_tokens else None,
            "output_mean": round(statistics.fmean(out_tokens), 1) if out_tokens else None,
            "estimated_input_cost_usd": round(
                sum(in_tokens) * JEV_INPUT_PRICE_PER_MTOK_USD / 1e6, 6
            ),
        },
        "agreement_with_baseline": dict(agreement),
        "models_reported": sorted({r.model for r in results if r.model}),
    }
    return metrics


def _per_domain(results: list[CaseResult], which: str) -> dict[str, float | None]:
    out: dict[str, float | None] = {}
    for domain in sorted({r.domain for r in results}):
        subset = [r for r in results if r.domain == domain]
        correct = sum(1 for r in subset if getattr(r, which) == r.label)
        out[domain] = _rate(correct, len(subset))
    return out


# ── reporting ─────────────────────────────────────────────────────────


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _matrix_md(matrix: dict[str, dict[str, int]], columns: Sequence[str]) -> list[str]:
    used = [c for c in columns if any(row.get(c, 0) for row in matrix.values()) or c in LABELS]
    short = {
        "priority_investigation": "priority",
        "routine_review": "routine",
        "likely_benign_maintenance": "benign",
        "insufficient_context": "insufficient",
    }
    lines = [
        "| gold \\ predicted | " + " | ".join(short.get(c, c) for c in used) + " |",
        "|---|" + "---|" * len(used),
    ]
    for gold in LABELS:
        row = matrix.get(gold, {})
        lines.append(f"| {short[gold]} | " + " | ".join(str(row.get(c, 0)) for c in used) + " |")
    return lines


def render_markdown(report: dict[str, Any]) -> str:
    m = report["metrics"]
    meta = report["run"]
    lines = [
        f"# Jev triage evaluation - {meta['date']}",
        "",
        "**Dataset: SYNTHETIC, author-labelled** cases modelled on ExtorQ event-catalog shapes "
        f"(`{meta['dataset']}`, {m['cases']} cases). Not collected telemetry; small sample; "
        "labels are the author's judgement. Read results as indicative only.",
        "",
        f"- Live Jev calls this run: {meta['calls_made']} (cap {meta['max_calls']}); "
        f"requested model `{meta['requested_model']}`; prompt version `{TRIAGE_PROMPT_VERSION}`.",
        f"- Question sets: {', '.join(f'`{v}`' for v in meta['question_sets'].values())}",
        "",
        "## Summary",
        "",
        "| metric | Jev | deterministic baseline |",
        "|---|---|---|",
    ]
    base = m["baseline"]
    jev = m.get("jev")
    if jev is None:
        lines.append(
            f"| accuracy | not run | {_pct(base['accuracy'])} ({base['correct']}/{m['cases']}) |"
        )
        lines.append(
            f"| insufficient-context rate | not run | {_pct(base['insufficient_context_rate'])} |"
        )
    else:
        lat = jev["latency_ms"]
        tok = jev["tokens"]
        lines += [
            f"| accuracy (4 classes) | {_pct(jev['accuracy'])} ({jev['correct']}/{m['cases']}) | "
            f"{_pct(base['accuracy'])} ({base['correct']}/{m['cases']}) |",
            f"| insufficient-context rate | {_pct(jev['insufficient_context_rate'])} | "
            f"{_pct(base['insufficient_context_rate'])} |",
            "| order-consistency rate (priority asked twice) | "
            f"{_pct(jev['order_consistency_rate'])} | n/a |",
            f"| uncertain rate | {_pct(jev['uncertain_rate'])} | n/a |",
            "| accuracy on confident (not uncertain) answers | "
            f"{_pct(jev['accuracy_on_confident'])} "
            f"({jev['confident_cases']} cases) | n/a |",
            f"| latency ms mean / p50 / p95 / max | {lat['mean']} / {lat['p50']} / {lat['p95']} / "
            f"{lat['max']} | ~0 (local) |",
            f"| tokens input total / mean | {tok['input_total']} / {tok['input_mean']} | 0 |",
            f"| tokens output total / mean | {tok['output_total']} / {tok['output_mean']} | 0 |",
            f"| estimated input cost (USD) | {tok['estimated_input_cost_usd']} | 0 |",
            f"| provider statuses | {jev['status_counts']} | n/a |",
            f"| models reported by provider | {', '.join(jev['models_reported']) or 'n/a'} | n/a |",
        ]
    lines += ["", "## Per-domain accuracy", "", "| domain | Jev | baseline |", "|---|---|---|"]
    for domain, value in base["per_domain_accuracy"].items():
        jv = jev["per_domain_accuracy"].get(domain) if jev else None
        lines.append(f"| {domain} | {_pct(jv) if jev else 'not run'} | {_pct(value)} |")
    lines += ["", "## Confusion matrix - baseline", ""]
    lines += _matrix_md(base["confusion"], LABELS)
    if jev is not None:
        lines += ["", "## Confusion matrix - Jev", ""]
        lines += _matrix_md(
            jev["confusion"],
            [*LABELS, "error", "timeout", "rate_limited", "invalid_output", "not_run"],
        )
        lines += ["", "## Agreement", "", "| outcome | cases |", "|---|---|"]
        for key, value in sorted(jev["agreement_with_baseline"].items()):
            lines.append(f"| {key} | {value} |")
    lines += [
        "",
        "## Per case",
        "",
        "| case | domain | gold | baseline | Jev | sufficient_context | order consistent "
        "| uncertain | status |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in report["results"]:
        sc = "n/a" if r["sufficient_context"] is None else f"{r['sufficient_context']:.2f}"
        lines.append(
            f"| {r['case_id']} | {r['domain']} | {r['label']} | {r['baseline']} | "
            f"{r['jev'] or '-'} | "
            f"{sc} | {r['order_consistent']} | {r['uncertain']} | {r['jev_status'] or '-'} |"
        )
    lines += ["", "## Notes", ""]
    lines += [f"- {note}" for note in report["notes"]]
    return "\n".join(lines) + "\n"


def build_report(run: EvalRun, *, dataset: Path, max_calls: int, date: str) -> dict[str, Any]:
    metrics = compute_metrics(run)
    notes = [
        "The dataset is SYNTHETIC and labelled by the same engineer who wrote the question sets; "
        "this risks optimistic bias. It is a regression and sanity check, not a benchmark.",
        "One run, one call per case; Jev answers can vary between runs and model versions.",
        "The baseline only uses severity, asset criticality, evidence confidence, correlation "
        "counts and coverage gaps; it cannot see actors, review signals or maintenance context.",
        "Jev output is advisory: it never changes alert severity or suppresses alerts.",
    ]
    if run.live and metrics.get("jev"):
        jev_acc = metrics["jev"]["accuracy"] or 0.0
        base_acc = metrics["baseline"]["accuracy"] or 0.0
        verdict = (
            "Jev outperformed"
            if jev_acc > base_acc
            else "Jev did NOT outperform"
            if jev_acc < base_acc
            else "Jev tied"
        )
        notes.insert(
            0,
            f"{verdict} the deterministic baseline on this dataset "
            f"({_pct(jev_acc)} vs {_pct(base_acc)}).",
        )
    return {
        "run": {
            "date": date,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "dataset": str(dataset),
            "live": run.live,
            "calls_made": run.calls_made,
            "max_calls": max_calls,
            "requested_model": run.settings_model,
            "prompt_version": TRIAGE_PROMPT_VERSION,
            "question_sets": run.question_sets,
        },
        "metrics": metrics,
        "results": [asdict(r) for r in run.results],
        "notes": notes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="extorq ai eval", description=__doc__.split("\n\n")[0])
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--live", action="store_true", help="make real, budgeted Jev calls")
    parser.add_argument("--max-calls", type=int, default=30, help="hard cap on live Jev calls")
    parser.add_argument("--limit", type=int, default=None, help="evaluate only the first N cases")
    parser.add_argument("--date", default=datetime.now(UTC).date().isoformat())
    args = parser.parse_args(argv)

    cases = load_dataset(args.dataset)
    if args.limit is not None:
        cases = cases[: max(0, args.limit)]
    settings = get_ai_settings()
    provider: JevTriageProvider | None = None
    if args.live:
        key = get_provider_key("JEV_API_KEY")
        if not key.usable:
            print(f"error: --live requires a usable key ({key.describe()})")
            return 2
        # --live is the operator's explicit opt-in for this command only.
        provider = JevTriageProvider(settings.model_copy(update={"jev_enabled": True}), key=key)
        print(f"live evaluation: {len(cases)} cases, at most {args.max_calls} Jev calls")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    raw_path = args.out_dir / f"raw-{args.date}.jsonl" if args.live else None
    run = run_eval(
        cases, provider=provider, settings=settings, max_calls=args.max_calls, raw_path=raw_path
    )
    report = build_report(run, dataset=args.dataset, max_calls=args.max_calls, date=args.date)
    json_path = args.out_dir / f"results-{args.date}.json"
    md_path = args.out_dir / f"results-{args.date}.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    m = report["metrics"]
    summary = f"baseline accuracy {_pct(m['baseline']['accuracy'])}"
    if "jev" in m:
        summary = f"Jev accuracy {_pct(m['jev']['accuracy'])}, " + summary
    print(f"{summary}; live calls this run: {run.calls_made}; wrote {json_path} and {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

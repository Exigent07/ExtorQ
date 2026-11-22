"""Command line: ``uv run python -m detection_tests run|list|cleanup`` (repository root).

Exit status of ``run``: 0 when every selected test passed, 1 when any test failed, errored
or was blocked by a precondition, 2 on usage or setup errors (nothing was changed), 130
when interrupted (cleanup ran and the report was written).
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

from detection_tests import __version__
from detection_tests.api import DEFAULT_API_URL, DEFAULT_TOKEN_FILE, AnalystApi, ApiError
from detection_tests.matrix import ASSET_KEYS, build_suites, parse_only, select
from detection_tests.model import PreconditionFailed, TestStatus
from detection_tests.report import RunReport, write_reports
from detection_tests.runner import (
    AssetSuite,
    Clock,
    Output,
    Runner,
    RunOptions,
    TestContext,
    install_signal_handlers,
)
from detection_tests.settings import local_rule, source_interval
from detection_tests.windows import detection_timing, utc_now

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORT_DIR = "var/reports"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m detection_tests",
        description="ExtorQ detection tests: real activity on the monitored assets, verified "
        "by asset + rule + time window through the analyst API (docs/detection-tests.md).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="run detection tests and write a report")
    run_p.add_argument("--asset", required=True, choices=[*ASSET_KEYS, "all"])
    run_p.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="RULE",
        help="only tests of this rule id (repeatable or comma-separated, e.g. VM-001,K8S-003)",
    )
    run_p.add_argument("--skip-negatives", action="store_true", help="skip negative controls")
    run_p.add_argument(
        "--parallel",
        action="store_true",
        help="with --asset all: run the asset suites concurrently (one thread per asset)",
    )
    run_p.add_argument(
        "--api-url",
        default=os.environ.get("EXTORQ_API_URL", DEFAULT_API_URL),
        help=f"analyst API base URL (default {DEFAULT_API_URL}; plain HTTP only to loopback)",
    )
    run_p.add_argument(
        "--token-file",
        default=os.environ.get("EXTORQ_API_SERVICE_TOKEN_FILE", DEFAULT_TOKEN_FILE),
        help="file holding the API service token (read by path, never printed)",
    )
    run_p.add_argument("--report-dir", default=DEFAULT_REPORT_DIR)
    run_p.add_argument("--poll-seconds", type=float, default=10.0)
    run_p.add_argument("--clock-skew-seconds", type=int, default=30)
    run_p.add_argument("--min-margin-seconds", type=int, default=60)
    run_p.add_argument("--max-quiet-wait-seconds", type=int, default=1200)

    list_p = sub.add_parser("list", help="print the test matrix (no stack needed)")
    list_p.add_argument("--asset", default="all", choices=[*ASSET_KEYS, "all"])
    list_p.add_argument("--only", action="append", default=[], metavar="RULE")
    list_p.add_argument("--markdown", action="store_true", help="print a Markdown table")

    clean_p = sub.add_parser(
        "cleanup", help="remove leftovers (extorq-test-* artefacts) of interrupted runs"
    )
    clean_p.add_argument("--asset", required=True, choices=[*ASSET_KEYS, "all"])
    return parser


def _resolve(path: str) -> Path:
    candidate = Path(path)
    return candidate if candidate.is_absolute() else REPO_ROOT / candidate


def _estimated_bound(suite: AssetSuite) -> dict[str, str]:
    """Offline estimate of each test's bound from the local rule YAML and collector configs."""
    estimates: dict[str, str] = {}
    for test in suite.tests:
        rule = local_rule(REPO_ROOT, test.spec.rule_id)
        schedule = rule.get("schedule") if isinstance(rule, dict) else None
        interval = schedule.get("interval_seconds") if isinstance(schedule, dict) else None
        if not isinstance(interval, int):
            estimates[test.spec.test_id] = "rule not in rules/"
            continue
        resolved = source_interval(REPO_ROOT, test.spec.source)
        timing = detection_timing(
            source_seconds=resolved.source_seconds,
            loop_seconds=resolved.loop_seconds,
            cycles=test.spec.source.cycles,
            pipeline_seconds=test.spec.source.pipeline_seconds,
            rule_interval_seconds=interval,
        )
        estimates[test.spec.test_id] = f"{timing.bound_seconds} s"
    return estimates


def cmd_list(args: argparse.Namespace) -> int:
    suites = select(build_suites(REPO_ROOT, args.asset), parse_only(args.only))
    if args.markdown:
        print("| Asset | Rule | Positive (real activity) | Negative control | Cleanup | Bound |")
        print("|---|---|---|---|---|---|")
    for suite in suites:
        bounds = _estimated_bound(suite)
        if not args.markdown:
            print(f"{suite.asset.asset_id} ({suite.asset.label})")
        for test in suite.tests:
            spec = test.spec
            if args.markdown:
                cells = [
                    spec.asset.asset_id,
                    spec.rule_id,
                    spec.positive,
                    spec.negative,
                    spec.cleanup,
                    bounds[spec.test_id],
                ]
                print("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
                continue
            print(f"  {spec.rule_id:<9} {spec.title}")
            print(f"      positive: {spec.positive}")
            print(
                f"      negative: {spec.negative}{' (runs first)' if spec.negative_first else ''}"
            )
            print(f"      cleanup:  {spec.cleanup}")
            print(f"      expected: {spec.expected_alert}")
            print(f"      evidence: {spec.source.description}; bound ~{bounds[spec.test_id]}")
    return 0


def cmd_cleanup(args: argparse.Namespace) -> int:
    output = Output()
    clock = Clock()
    # The sweeps act on the assets only; the API object is never contacted here.
    api = AnalystApi(DEFAULT_API_URL, _resolve(DEFAULT_TOKEN_FILE))
    ok = True
    for suite in build_suites(REPO_ROOT, args.asset):
        out = output.scoped(f"{suite.asset.key} cleanup")
        ctx = TestContext(REPO_ROOT, api, clock, RunOptions(), out)
        try:
            checks = suite.check(ctx)
        except PreconditionFailed as exc:
            out(f"cannot reach the asset: {exc}")
            ok = False
            continue
        failed = [c for c in checks if not c.ok]
        if failed:
            out(
                "cannot reach the asset: "
                + "; ".join(f"{c.description}: {c.detail}" for c in failed)
            )
            ok = False
            continue
        for step in suite.sweep(ctx):
            out(f"{step.description}: {'ok' if step.ok else 'FAILED'} {step.detail}")
            ok = ok and step.ok
    return 0 if ok else 1


def cmd_run(args: argparse.Namespace, argv: Sequence[str]) -> int:
    try:
        suites = select(build_suites(REPO_ROOT, args.asset), parse_only(args.only))
        api = AnalystApi(args.api_url, _resolve(args.token_file))
    except (ValueError, ApiError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.parallel and args.asset != "all":
        print("error: --parallel needs --asset all", file=sys.stderr)
        return 2
    try:
        api.health()
    except ApiError as exc:
        print(
            f"error: {exc}. The analyst API verifies every detection: start the stack "
            "(`make up-full`) before running detection tests.",
            file=sys.stderr,
        )
        return 2
    options = RunOptions(
        skip_negatives=args.skip_negatives,
        poll_seconds=max(2.0, args.poll_seconds),
        clock_skew_seconds=max(0, args.clock_skew_seconds),
        min_margin_seconds=max(0, args.min_margin_seconds),
        max_quiet_wait_seconds=max(0, args.max_quiet_wait_seconds),
    )
    output = Output()
    clock = Clock()
    install_signal_handlers(clock, output)
    runner = Runner(root=REPO_ROOT, api=api, clock=clock, options=options, output=output)
    started = utc_now()
    total = sum(len(s.tests) for s in suites)
    output.line(
        "runner", f"{total} test(s) on {len(suites)} asset(s); report dir {args.report_dir}"
    )
    results = runner.run_suites(suites, parallel=args.parallel)
    report = RunReport(
        started_at=started,
        finished_at=utc_now(),
        command="uv run python -m detection_tests " + shlex.join(argv),
        api_url=api.base_url,
        options={
            "asset": args.asset,
            "only": parse_only(args.only),
            "skip_negatives": options.skip_negatives,
            "parallel": bool(args.parallel),
            "poll_seconds": options.poll_seconds,
            "clock_skew_seconds": options.clock_skew_seconds,
            "min_margin_seconds": options.min_margin_seconds,
            "max_quiet_wait_seconds": options.max_quiet_wait_seconds,
        },
        results=results,
        interrupted=clock.cancel.is_set(),
    )
    json_path, md_path = write_reports(report, _resolve(args.report_dir))
    for result in results:
        output.line(
            "result",
            f"{result.status.value.upper():<7} {result.spec.asset.asset_id} {result.spec.rule_id}: "
            f"{result.message}",
        )
    output.line("runner", f"report: {json_path} and {md_path}")
    if report.interrupted:
        return 130
    return 0 if results and all(r.status is TestStatus.PASSED for r in results) else 1


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    args = _parser().parse_args(arguments)
    if args.command == "list":
        try:
            return cmd_list(args)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    if args.command == "cleanup":
        return cmd_cleanup(args)
    return cmd_run(args, arguments)


if __name__ == "__main__":
    raise SystemExit(main())

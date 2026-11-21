"""Offline workflow analyser CLI (no network, no token).

Compares two versions of a GitHub Actions workflow exactly as the collector does for
``github.workflow.modified`` and prints the resulting event attributes as JSON::

    uv run python -m extorq_collectors.github.analyze \\
        --path .github/workflows/ci.yml --before old.yml --after new.yml --repo-default read

``--before none`` / ``--after none`` model an added / removed workflow. With
``--expect-escalation`` (or ``--expect-no-escalation``) the exit status is 0 only when
the expectation holds, which the GH-001 dry run uses as an offline self-check.
Exit codes: 0 ok, 1 expectation not met, 2 usage or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Literal

from extorq_collectors.github.workflow import (
    MAX_WORKFLOW_BYTES,
    WorkflowAnalysis,
    analyse_workflow,
    compare_workflows,
    is_workflow_path,
)


def _load(path_arg: str, workflow_path: str) -> WorkflowAnalysis | None:
    if path_arg.lower() == "none":
        return None
    file_path = Path(path_arg)
    if not file_path.is_file():
        raise SystemExit(f"error: {path_arg} is not a file")
    if file_path.stat().st_size > MAX_WORKFLOW_BYTES:
        return WorkflowAnalysis(
            path=workflow_path, ok=False, error=f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes"
        )
    return analyse_workflow(workflow_path, file_path.read_text(encoding="utf-8", errors="replace"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="extorq-github-analyze", description=__doc__.splitlines()[0]
    )
    parser.add_argument("--path", required=True, help="repository path of the workflow")
    parser.add_argument("--before", required=True, help="file with the previous version, or 'none'")
    parser.add_argument("--after", required=True, help="file with the new version, or 'none'")
    parser.add_argument(
        "--repo-default",
        choices=("read", "write", "unknown"),
        default="unknown",
        help="repository default GITHUB_TOKEN permission (GET /actions/permissions/workflow)",
    )
    parser.add_argument(
        "--previous-path", default=None, help="old path when the workflow was renamed"
    )
    expectation = parser.add_mutually_exclusive_group()
    expectation.add_argument("--expect-escalation", action="store_true")
    expectation.add_argument("--expect-no-escalation", action="store_true")
    args = parser.parse_args(argv)

    if not is_workflow_path(args.path):
        print("error: --path must be .github/workflows/<name>.yml|yaml", file=sys.stderr)
        return 2
    try:
        before = _load(args.before, args.previous_path or args.path)
        after = _load(args.after, args.path)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if before is None and after is None:
        print("error: --before and --after cannot both be 'none'", file=sys.stderr)
        return 2
    change_type: Literal["added", "modified", "removed", "renamed"]
    if before is None:
        change_type = "added"
    elif after is None:
        change_type = "removed"
    elif args.previous_path and args.previous_path != args.path:
        change_type = "renamed"
    else:
        change_type = "modified"
    default = None if args.repo_default == "unknown" else args.repo_default
    delta = compare_workflows(
        args.path,
        before,
        after,
        repo_default=default,
        change_type=change_type,
        previous_path=args.previous_path if change_type == "renamed" else None,
    )
    output = {
        "event_type": "github.workflow.modified",
        "summary": delta.summary(),
        "escalation": delta.escalation,
        "attributes": delta.to_attributes(),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    if args.expect_escalation and not delta.escalation:
        print("expectation failed: no escalation detected", file=sys.stderr)
        return 1
    if args.expect_no_escalation and delta.escalation:
        print("expectation failed: escalation detected", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

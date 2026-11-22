"""GH-001 workflow analysis and legacy script argument guards (offline)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from extorq_collectors.github.analyze import main as analyse

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "simulations/github/gh_001_workflow_permissions.sh"
CREATE = ROOT / "simulations/github/create_lab_repo.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None or shutil.which("uv") is None,
    reason="bash, git and uv are required",
)


def run(script: Path, *args: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "USER")}
    env["TMPDIR"] = str(tmp_path)
    return subprocess.run(
        ["bash", str(script), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        cwd=ROOT,
        env=env,
    )


def test_workflow_analyser_detects_escalation_and_clean_revert(
    capsys: pytest.CaptureFixture[str],
) -> None:
    path = ".github/workflows/ci.yml"
    baseline = str(ROOT / "lab/github-repo" / path)
    changed = str(SCRIPT.parent / "templates/ci-gh001.yml")
    args = ["--path", path, "--repo-default", "read"]
    assert analyse([*args, "--before", baseline, "--after", changed, "--expect-escalation"]) == 0
    out = capsys.readouterr().out
    assert '"write_all_added": true' in out
    assert '"untrusted_checkout_added": true' in out
    assert analyse([*args, "--before", changed, "--after", baseline, "--expect-no-escalation"]) == 0
    assert '"escalation": false' in capsys.readouterr().out


@pytest.mark.parametrize(
    "args",
    [
        ["--dry-run"],  # --repo is required
        ["--repo", "Example-Org/production-app", "--dry-run"],  # not a lab repository
        ["--repo", "bad repo", "--dry-run"],
        ["--repo", "Example-Org/extorq-lab", "--run-id", "UPPER"],
        ["--repo", "Example-Org/extorq-lab", "--cleanup"],  # cleanup needs the run id
        ["--repo", "Example-Org/extorq-lab", "--bogus"],
    ],
)
def test_unsafe_or_invalid_arguments_are_refused(args: list[str], tmp_path: Path) -> None:
    result = run(SCRIPT, *args, tmp_path=tmp_path)
    assert result.returncode != 0
    assert "error:" in result.stderr


def test_create_lab_repo_refuses_non_lab_names(tmp_path: Path) -> None:
    result = run(CREATE, "--repo", "Example-Org/not-a-lab", "--yes", tmp_path=tmp_path)
    assert result.returncode != 0 and "extorq-lab" in result.stderr


def _load_verify():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "verify_gh001", ROOT / "simulations/github/verify_gh001.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _EmptyResult:
    column_names: tuple[str, ...] = ()
    result_rows: list[tuple[object, ...]] = []


class _EmptyClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def query(self, sql: str, parameters: dict[str, object]) -> _EmptyResult:
        assert "{" in sql and "%" not in sql  # server-side parameters only
        self.calls.append(parameters)
        return _EmptyResult()


def test_verify_helper_validates_input_and_reports_missing_evidence() -> None:
    verify = _load_verify()
    assert verify.main(["--repo", "bad repo", "--run-id", "x"], client=_EmptyClient()) == 2
    client = _EmptyClient()
    assert (
        verify.main(["--repo", "Example-Org/extorq-lab", "--run-id", "gh001fixture"], client=client)
        == 1
    )
    assert {"asset": "github:example-org/extorq-lab", "run": "gh001fixture"} in client.calls

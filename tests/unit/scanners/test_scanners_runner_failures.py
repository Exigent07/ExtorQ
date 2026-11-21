"""Scan orchestration and failure-mode tests (ScanRunner with a fake Docker boundary).

All tool results here are SYNTHETIC (built in this module) except where a real
fixture is loaded explicitly. They prove that crashes, timeouts, non-zero exits
with unusable output, malformed or truncated output can only ever produce
``failed`` or ``partial`` ScanRuns, never ``succeeded``, and that failed scans
submit no findings.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from scanners_testlib import FIXTURES, REPO_ROOT, load_json, load_text

from extorq.contracts import HealthStatus, ScanRun, ScanStatus
from extorq.contracts.ingest import CollectorHealthRecord, FindingRecord, ScanRunRecord
from extorq_scanners.config import ScannersConfig
from extorq_scanners.docker import ContainerResult, ContainerSpec
from extorq_scanners.inventory import InventoryUnavailable
from extorq_scanners.runner import ScanRunner
from extorq_scanners.scope import scope_for
from extorq_scanners.sink import MemorySink
from extorq_scanners.state import StateStore
from extorq_scanners.status import ProcessOutcome

DIGEST = "@sha256:" + "a" * 64
NOW = datetime(2026, 11, 21, 15, 0, tzinfo=UTC)


class FakeDocker:
    """Docker boundary: returns programmed ContainerResults per container purpose."""

    docker = "docker"
    available = True

    def __init__(self, results: dict[str, ContainerResult | Exception]) -> None:
        self.results = results
        self.specs: list[ContainerSpec] = []

    def run(
        self,
        spec: ContainerSpec,
        *,
        timeout: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int = 1_000_000,
    ) -> ContainerResult:
        self.specs.append(spec)
        if spec.purpose.endswith("-version"):
            return ContainerResult(ProcessOutcome(0), b"Version: 9.9.9\n", "")
        result = self.results[spec.purpose]
        if isinstance(result, Exception):
            raise result
        return result

    def image_present(self, image: str) -> bool:
        return True

    def newest_image(self, repository: str) -> str | None:
        return None


def ok(stdout: bytes | str, code: int = 0, stderr: str = "") -> ContainerResult:
    data = stdout.encode() if isinstance(stdout, str) else stdout
    return ContainerResult(ProcessOutcome(code, duration_seconds=0.1), data, stderr)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / "lab" / "repo").mkdir(parents=True)
    (tmp_path / "lab" / "repo" / "app.py").write_text("print('synthetic')\n")
    (tmp_path / "manifests").mkdir()
    (tmp_path / "manifests" / "a.yaml").write_text(
        "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: x\n"
    )
    rules = tmp_path / "scanners" / "rules" / "gitleaks"
    rules.mkdir(parents=True)
    shutil.copy(REPO_ROOT / "scanners" / "rules" / "gitleaks" / "extorq-gitleaks.toml", rules)
    db = tmp_path / "var" / "cache" / "trivy" / "db"
    db.mkdir(parents=True)
    (db / "trivy.db").write_bytes(b"synthetic-db")
    downloaded = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    (db / "metadata.json").write_text(json.dumps({"Version": 2, "DownloadedAt": downloaded}))
    return tmp_path


def make_config(**target_overrides: Any) -> ScannersConfig:
    targets = [
        {
            "name": "lab-gitleaks",
            "kind": "gitleaks",
            "mode": "dir",
            "asset_id": "github:o/extorq-lab",
            "paths": ["lab/repo"],
        },
        {
            "name": "lab-trivy",
            "kind": "trivy",
            "mode": "fs",
            "asset_id": "github:o/extorq-lab",
            "paths": ["lab/repo"],
            "scanners": ["vuln", "misconfig"],
        },
        {
            "name": "kind-config",
            "kind": "trivy",
            "mode": "config",
            "asset_id": "k8s:extorq-lab",
            "paths": ["manifests"],
        },
        {
            "name": "vm-packages",
            "kind": "linux-packages",
            "mode": "sbom",
            "asset_id": "linux:lab-vm-01",
            "service_attribution": [{"packages": ["openssh-server"], "unit": "ssh.service"}],
        },
        {
            "name": "missing-skip",
            "kind": "gitleaks",
            "mode": "git",
            "asset_id": "github:o/extorq-lab",
            "paths": ["absent/repo"],
            "when_missing": "skip",
        },
        {
            "name": "missing-fail",
            "kind": "gitleaks",
            "mode": "dir",
            "asset_id": "github:o/extorq-lab",
            "paths": ["absent/dir"],
        },
    ]
    for target in targets:
        target.update(target_overrides.get(target["name"], {}))
    return ScannersConfig.model_validate(
        {
            "version": 1,
            "images": {
                "trivy": f"aquasec/trivy:0.76.2{DIGEST}",
                "gitleaks": f"ghcr.io/gitleaks/gitleaks:v8.30.1{DIGEST}",
                "semgrep": f"semgrep/semgrep:1.184.0{DIGEST}",
            },
            "targets": targets,
        }
    )


def runner(root: Path, docker: FakeDocker, **kwargs: Any) -> tuple[ScanRunner, MemorySink]:
    sink = MemorySink()
    clock_values = iter(NOW + timedelta(seconds=i) for i in range(10_000))
    scan_runner = ScanRunner(
        make_config(),
        root,
        sink,
        docker=docker,  # type: ignore[arg-type]
        allow_network=False,
        clock=lambda: next(clock_values),
        **kwargs,
    )
    return scan_runner, sink


def target(scan_runner: ScanRunner, name: str):  # type: ignore[no-untyped-def]
    return next(t for t in scan_runner.cfg.targets if t.name == name)


def scan_runs(sink: MemorySink) -> list[ScanRun]:
    return [r.data for r in sink.records if isinstance(r, ScanRunRecord)]


def findings(sink: MemorySink) -> list[Any]:
    return [r.data for r in sink.records if isinstance(r, FindingRecord)]


def final(sink: MemorySink) -> ScanRun:
    return scan_runs(sink)[-1]


# ── success paths on REAL tool output ──────────────────────────────────────────


def test_real_gitleaks_output_with_leak_exit_code_succeeds_and_orders_records(root: Path) -> None:
    docker = FakeDocker(
        {
            "gitleaks-dir": ok(
                json.dumps(load_json("gitleaks-dir-lab-repo.json")),
                42,
                load_text("gitleaks-dir-lab-repo.stderr.txt"),
            )
        }
    )
    scan_runner, sink = runner(root, docker)
    outcome = scan_runner.run_target(target(scan_runner, "lab-gitleaks"))
    assert outcome.status is ScanStatus.SUCCEEDED and outcome.findings == 1
    kinds = [type(r) for r in sink.records]
    # running ScanRun first, findings, terminal ScanRun LAST (before health)
    assert kinds == [ScanRunRecord, FindingRecord, ScanRunRecord, CollectorHealthRecord]
    running, done = scan_runs(sink)
    assert running.status is ScanStatus.RUNNING and done.status is ScanStatus.SUCCEEDED
    assert running.scan_run_id == done.scan_run_id
    assert done.scope == scope_for(target(scan_runner, "lab-gitleaks"))
    assert done.findings_count == 1
    assert done.attributes["exit_code"] == 42
    spec = docker.specs[-1]
    assert spec.network == "none"
    assert "--redact" in spec.args and "--ignore-gitleaks-allow" in spec.args
    assert all(m.read_only for m in spec.mounts)


def test_real_trivy_fs_output_succeeds(root: Path) -> None:
    docker = FakeDocker(
        {
            "trivy-fs": ok(
                (FIXTURES / "trivy-fs-lab-repo.json").read_bytes(),
                stderr=load_text("trivy-fs-lab-repo.stderr.txt"),
            )
        }
    )
    scan_runner, sink = runner(root, docker)
    outcome = scan_runner.run_target(target(scan_runner, "lab-trivy"))
    assert outcome.status is ScanStatus.SUCCEEDED
    assert outcome.findings == 38
    assert final(sink).coverage.checks_total == 27
    notes = " ".join(final(sink).coverage.notes)
    assert "embedded check bundle" in notes  # benign ERROR line recorded as a note
    args = docker.specs[-1].args
    for flag in (
        "--skip-db-update",
        "--offline-scan",
        "--disable-telemetry",
        "--skip-version-check",
    ):
        assert flag in args


# ── failure modes: never succeeded ─────────────────────────────────────────────


@pytest.mark.parametrize(
    ("result", "expected_error"),
    [
        (ok("panic: runtime error\n", 2), "unusable tool output (exit code 2): malformed JSON"),
        (ok("", 1), "unusable tool output (exit code 1): empty output"),
        (ok('{"SchemaVersion": 2, "Results": [', 0), "malformed JSON"),
        (ok('{"SchemaVersion": 3, "Results": []}', 0), "unsupported trivy SchemaVersion"),
        (
            ContainerResult(ProcessOutcome(None, timed_out=True), b'{"SchemaVersion": 2}', ""),
            "tool timed out",
        ),
        (
            ContainerResult(
                ProcessOutcome(0, output_truncated=True), b'{"SchemaVersion": 2, "Res', ""
            ),
            "exceeded the size limit",
        ),
        (
            ContainerResult(ProcessOutcome(None, start_error="No such image"), b"", ""),
            "tool could not be started",
        ),
        (ContainerResult(ProcessOutcome(137), b"", "Killed"), "exit code 137"),
    ],
)
def test_failure_modes_produce_failed_without_findings(
    root: Path, result: ContainerResult, expected_error: str
) -> None:
    # SYNTHETIC tool results
    scan_runner, sink = runner(root, FakeDocker({"trivy-fs": result}))
    outcome = scan_runner.run_target(target(scan_runner, "lab-trivy"))
    assert outcome.status is ScanStatus.FAILED
    done = final(sink)
    assert done.status is ScanStatus.FAILED
    assert expected_error in (done.error or "")
    assert done.findings_count == 0
    assert findings(sink) == []
    health = [r.data for r in sink.records if isinstance(r, CollectorHealthRecord)][-1]
    assert health.status is HealthStatus.FAILED and health.last_success_at is None


def test_usable_output_with_unexpected_exit_code_is_partial(root: Path) -> None:
    # SYNTHETIC: valid real report but a non-documented exit code
    docker = FakeDocker({"trivy-fs": ok((FIXTURES / "trivy-fs-lab-repo.json").read_bytes(), 1)})
    scan_runner, sink = runner(root, docker)
    outcome = scan_runner.run_target(target(scan_runner, "lab-trivy"))
    assert outcome.status is ScanStatus.PARTIAL
    assert "unexpected exit code 1" in (final(sink).error or "")
    assert len(findings(sink)) == 38  # partial results are stored (they never resolve anything)


def test_tool_error_log_lines_make_scan_partial(root: Path) -> None:
    stderr = (
        "2026-11-21T14:38:53Z\tERROR\t[misconfig] failed to parse manifests/a.yaml\n"  # SYNTHETIC
    )
    docker = FakeDocker(
        {"trivy-config": ok((FIXTURES / "trivy-config-kind.json").read_bytes(), 0, stderr)}
    )
    scan_runner, sink = runner(root, docker)
    outcome = scan_runner.run_target(target(scan_runner, "kind-config"))
    assert outcome.status is ScanStatus.PARTIAL
    assert "1 tool errors" in (final(sink).error or "")


def test_internal_error_closes_scan_as_failed(root: Path) -> None:
    docker = FakeDocker({"trivy-fs": RuntimeError("synthetic bug")})  # SYNTHETIC crash
    scan_runner, sink = runner(root, docker)
    outcome = scan_runner.run_target(target(scan_runner, "lab-trivy"))
    assert outcome.status is ScanStatus.FAILED
    assert final(sink).error == "internal error in scanner runner: RuntimeError"
    assert [r.status for r in scan_runs(sink)] == [ScanStatus.RUNNING, ScanStatus.FAILED]


def test_missing_target_skip_emits_nothing_and_fail_emits_failed(root: Path) -> None:
    scan_runner, sink = runner(root, FakeDocker({}))
    skipped = scan_runner.run_target(target(scan_runner, "missing-skip"))
    assert skipped.status is None and skipped.skipped_reason and sink.records == []
    failed = scan_runner.run_target(target(scan_runner, "missing-fail"))
    assert failed.status is ScanStatus.FAILED
    assert "does not exist" in (final(sink).error or "")


def test_interrupted_scan_is_reported_failed_on_next_run(root: Path) -> None:
    docker = FakeDocker({"trivy-fs": ok((FIXTURES / "trivy-fs-lab-repo.json").read_bytes())})
    state = StateStore(root / "var" / "state" / "scanners")
    scan_runner, sink = runner(root, docker, state=state)
    leftover = ScanRun(  # SYNTHETIC: a previous runner died after submitting "running"
        scan_run_id="f" * 32,
        scanner="trivy",
        scanner_version="0.76.2",
        asset_id="github:o/extorq-lab",
        scope=scope_for(target(scan_runner, "lab-trivy")),
        started_at=NOW - timedelta(hours=1),
        status=ScanStatus.RUNNING,
        producer_id="scanner-runner",
    )
    state.mark_inflight(leftover)
    assert scan_runner.recover_interrupted() == 1
    [recovered] = scan_runs(sink)
    assert recovered.scan_run_id == "f" * 32
    assert recovered.status is ScanStatus.FAILED
    assert "interrupted" in (recovered.error or "")
    assert state.interrupted() == []


def test_run_takes_the_lock(root: Path) -> None:
    from extorq_scanners.state import LockedError

    state = StateStore(root / "var" / "state" / "scanners")
    scan_runner, _sink = runner(root, FakeDocker({}), state=state)
    with state.lock(), pytest.raises(LockedError):
        scan_runner.run([])


# ── Linux packages (SBOM) ───────────────────────────────────────────────────────


def test_sbom_inventory_unavailable_fails(root: Path) -> None:
    def unavailable(_root: Path, _cfg: Any) -> Any:
        raise InventoryUnavailable("SSHConnectionError: ssh connection failed")  # SYNTHETIC

    scan_runner, sink = runner(root, FakeDocker({}), inventory_fetcher=unavailable)
    outcome = scan_runner.run_target(target(scan_runner, "vm-packages"))
    assert outcome.status is ScanStatus.FAILED
    assert "package inventory unavailable" in (final(sink).error or "")


def test_sbom_scan_with_real_inventory_and_service_attribution(root: Path) -> None:
    docker = FakeDocker({"trivy-sbom": ok((FIXTURES / "trivy-sbom-linux-vm.json").read_bytes())})
    scan_runner, sink = runner(
        root,
        docker,
        inventory_fetcher=lambda _r, _c: load_json("linux-packages-dispatch.json"),
        unit_fetcher=lambda _r, _c: load_json("linux-inventory-units.json"),
    )
    outcome = scan_runner.run_target(target(scan_runner, "vm-packages"))
    assert outcome.status is ScanStatus.SUCCEEDED
    done = final(sink)
    assert done.attributes["inventory_packages"] == 667
    assert done.attributes["service_units"] == ["ssh.service"]
    attributed = [f for f in findings(sink) if f.service_id]
    assert [f.package.name for f in attributed] == ["openssh"]
    # the generated SBOM was mounted read-only and removed afterwards
    sbom_mount = next(m for m in docker.specs[-1].mounts if m.target == "/sbom")
    assert sbom_mount.read_only and not sbom_mount.source.exists()


def test_sbom_unit_inventory_failure_keeps_scan_successful_without_attribution(root: Path) -> None:
    def no_units(_root: Path, _cfg: Any) -> Any:
        raise InventoryUnavailable("SSHTimeoutError: timeout")  # SYNTHETIC

    docker = FakeDocker({"trivy-sbom": ok((FIXTURES / "trivy-sbom-linux-vm.json").read_bytes())})
    scan_runner, sink = runner(
        root,
        docker,
        inventory_fetcher=lambda _r, _c: load_json("linux-packages-dispatch.json"),
        unit_fetcher=no_units,
    )
    outcome = scan_runner.run_target(target(scan_runner, "vm-packages"))
    assert outcome.status is ScanStatus.SUCCEEDED
    assert all(f.service_id is None for f in findings(sink))
    assert any("service attribution skipped" in n for n in final(sink).coverage.notes)


def test_trivy_db_missing_fails_offline(root: Path) -> None:
    shutil.rmtree(root / "var" / "cache" / "trivy" / "db")
    scan_runner, sink = runner(root, FakeDocker({}))
    outcome = scan_runner.run_target(target(scan_runner, "lab-trivy"))
    assert outcome.status is ScanStatus.FAILED
    assert "vulnerability DB not available" in (final(sink).error or "")

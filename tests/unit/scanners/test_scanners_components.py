"""Unit tests for scanner components: status decision, config + scopes, SBOM builder,
service evidence, Docker hardening and the SDK gateway sink.

Real fixtures are used where a real artefact exists (dispatch outputs, config);
everything else is SYNTHETIC and labelled.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from scanners_testlib import REPO_ROOT, load_json

from extorq.contracts import IngestResult, ScanStatus
from extorq.contracts.identity import service_id
from extorq.contracts.ingest import ScanRunRecord
from extorq_collectors.sdk.client import RetryableError
from extorq_scanners.config import ConfigError, ScannersConfig, load_config
from extorq_scanners.docker import ContainerSpec, DockerError, DockerRunner, Mount, parse_rfc3339
from extorq_scanners.sbom import (
    InventoryError,
    build_cyclonedx,
    inventory_from_dpkg_tsv,
    parse_inventory,
    purl,
    split_deb_version,
)
from extorq_scanners.scope import scope_for
from extorq_scanners.services import package_service_map, unit_states
from extorq_scanners.sink import GatewaySink
from extorq_scanners.status import ProcessOutcome, decide

DIGEST = "@sha256:" + "b" * 64

# ── status decision (pure) ──────────────────────────────────────────────────────


def _decide(process: ProcessOutcome, **kwargs: Any) -> Any:
    return decide(
        process, success_exit_codes={0}, parse_error=kwargs.pop("parse_error", None), **kwargs
    )


@pytest.mark.parametrize(
    ("process", "kwargs", "status"),
    [
        (ProcessOutcome(0), {}, ScanStatus.SUCCEEDED),
        (ProcessOutcome(None, start_error="x"), {}, ScanStatus.FAILED),
        (ProcessOutcome(None, timed_out=True), {}, ScanStatus.FAILED),
        (ProcessOutcome(0, output_truncated=True), {}, ScanStatus.FAILED),
        (ProcessOutcome(0), {"parse_error": "malformed"}, ScanStatus.FAILED),
        (ProcessOutcome(None), {}, ScanStatus.FAILED),
        (ProcessOutcome(0), {"nothing_scanned": True}, ScanStatus.FAILED),
        (ProcessOutcome(3), {}, ScanStatus.PARTIAL),
        (ProcessOutcome(0), {"tool_errors": ["e"]}, ScanStatus.PARTIAL),
        (ProcessOutcome(0), {"skipped": ["ruleset:x"]}, ScanStatus.PARTIAL),
        (ProcessOutcome(0), {"dropped_findings": 1}, ScanStatus.PARTIAL),
        # precedence: a truncated output is FAILED even with other problems
        (ProcessOutcome(3, output_truncated=True), {"tool_errors": ["e"]}, ScanStatus.FAILED),
    ],
)  # SYNTHETIC outcomes
def test_status_decision_matrix(
    process: ProcessOutcome, kwargs: dict[str, Any], status: ScanStatus
) -> None:
    verdict = _decide(process, **kwargs)
    assert verdict.status is status
    assert (verdict.error is None) == (status is ScanStatus.SUCCEEDED)


# ── configuration and lifecycle scopes ─────────────────────────────────────────


def test_repository_config_is_valid() -> None:
    cfg = load_config(REPO_ROOT / "config" / "scanners.yaml")
    assert cfg.producer_id == "scanner-runner"
    assert {t.name for t in cfg.targets} >= {
        "trivy-lab-repo",
        "gitleaks-lab-repo",
        "semgrep-lab-repo",
        "trivy-kind-config",
        "trivy-lab-portal-image",
        "trivy-otel-collector-image",
        "linux-vm-packages",
    }
    for image in (cfg.images.trivy, cfg.images.gitleaks, cfg.images.semgrep):
        assert "@sha256:" in image


def test_configured_scope_hashes_are_pinned() -> None:
    """Changing a scope silently orphans stored findings; update deliberately."""
    cfg = load_config(REPO_ROOT / "config" / "scanners.yaml")
    hashes = {t.name: scope_for(t).scope_hash for t in cfg.targets}
    assert hashes["trivy-lab-repo"] == "4e5f44be9b9ac2918f90bd5a59e51b52"
    assert hashes["gitleaks-lab-repo"] == "d496e0526e31bb6ab0f4ab039bc01576"
    assert hashes["semgrep-lab-repo"] == "782e10fe7c8a8369b0514b82be1e672e"
    assert hashes["trivy-lab-portal-image"] == "77ff937512614a951843a0e807c97b3c"
    assert hashes["trivy-otel-collector-image"] == "3eb6b8bd4e962ad14badaa8d5a446b21"
    assert hashes["linux-vm-packages"] == "7677cd388c4bedd4bca253fcff84c824"


def _cfg(
    target: dict[str, Any], *more: dict[str, Any], images: dict[str, str] | None = None
) -> ScannersConfig:
    return ScannersConfig.model_validate(
        {
            "version": 1,
            "images": images
            or {
                "trivy": f"t/t:1{DIGEST}",
                "gitleaks": f"g/g:1{DIGEST}",
                "semgrep": f"s/s:1{DIGEST}",
            },
            "targets": [target, *more],
        }
    )


BASE = {"name": "t1", "kind": "gitleaks", "mode": "dir", "asset_id": "github:o/r", "paths": ["lab"]}


@pytest.mark.parametrize(
    "change",
    [
        {"paths": ["/etc"]},
        {"paths": ["../outside"]},
        {"paths": ["a,b"]},
        {"paths": []},
        {"mode": "image"},
        {"interval_seconds": 7 * 86400},
        {"service_attribution": [{"packages": ["openssh-server"], "unit": "ssh.service"}]},
        {"asset_id": "Bad Asset"},
    ],
)  # SYNTHETIC invalid configs
def test_invalid_targets_are_rejected(change: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        _cfg({**BASE, **change})


def test_unpinned_images_are_rejected() -> None:
    with pytest.raises(ValueError, match="pinned"):
        _cfg(
            BASE,
            images={
                "trivy": "aquasec/trivy:latest",
                "gitleaks": f"g/g:1{DIGEST}",
                "semgrep": f"s/s:1{DIGEST}",
            },
        )


def test_two_targets_sharing_a_scope_are_rejected() -> None:
    with pytest.raises(ValueError, match="share one lifecycle scope"):
        _cfg(BASE, {**BASE, "name": "t2"})


def test_image_scope_is_the_repository() -> None:
    cfg = _cfg(
        {
            "name": "img",
            "kind": "trivy",
            "mode": "image",
            "asset_id": "k8s:c",
            "image": f"otel/collector:0.1{DIGEST}",
        }
    )
    target = cfg.targets[0]
    assert target.image_repository == "otel/collector"
    assert scope_for(target).targets == ["image:otel/collector"]
    with pytest.raises(ValueError, match="repository"):
        _cfg(
            {
                "name": "img",
                "kind": "trivy",
                "mode": "image",
                "asset_id": "k8s:c",
                "image": "x/y:tag",
                "image_select": "newest",
            }
        )


def test_select_by_kind_and_name() -> None:
    cfg = load_config(REPO_ROOT / "config" / "scanners.yaml")
    assert {t.kind for t in cfg.select("trivy")} == {"trivy"}
    assert [t.name for t in cfg.select("all", ["semgrep-lab-repo"])] == ["semgrep-lab-repo"]
    with pytest.raises(ConfigError):
        cfg.select("trivy", ["semgrep-lab-repo"])


# ── SBOM builder on the REAL dispatch output ───────────────────────────────────


def test_parse_real_packages_inventory() -> None:
    inventory = parse_inventory(load_json("linux-packages-dispatch.json"))
    assert (inventory.os_id, inventory.os_version) == ("ubuntu", "24.04")
    assert len(inventory.packages) == 667
    assert inventory.hostname == "lab-vm-01"
    assert not inventory.truncated and inventory.errors == []


def test_cyclonedx_has_os_component_and_trivy_conventions() -> None:
    inventory = parse_inventory(load_json("linux-packages-dispatch.json"))
    bom = build_cyclonedx(
        inventory, asset_id="linux:lab-vm-01", generated_at=datetime(2026, 11, 21, tzinfo=UTC)
    )
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    os_component = bom["components"][0]
    assert os_component["type"] == "operating-system"
    assert (os_component["name"], os_component["version"]) == ("ubuntu", "24.04")
    libs = {c["name"]: c for c in bom["components"][1:]}
    assert len(libs) == 667
    ssh = libs["openssh-server"]
    assert ssh["purl"].startswith("pkg:deb/ubuntu/openssh-server@9.6p1-")
    assert "distro=ubuntu-24.04" in ssh["purl"] and "epoch=1" in ssh["purl"]
    props = {p["name"]: p["value"] for p in ssh["properties"]}
    assert props["aquasecurity:trivy:SrcName"] == "openssh"
    assert props["aquasecurity:trivy:SrcEpoch"] == "1"
    assert props["aquasecurity:trivy:SrcVersion"] == "9.6p1"
    assert bom["dependencies"][1]["ref"] == os_component["bom-ref"]


@pytest.mark.parametrize(
    "doc",
    [
        {"schema": "other"},
        {
            "schema": "extorq.linux.packages.v1",
            "type": "packages",
            "os_release": {"ID": "debian", "VERSION_ID": "12"},
            "packages": [{"name": "a", "version": "1", "architecture": "all"}],
        },
        {
            "schema": "extorq.linux.packages.v1",
            "type": "packages",
            "os_release": {"ID": "ubuntu", "VERSION_ID": "24.04"},
            "packages": [],
        },
    ],
)  # SYNTHETIC invalid inventories
def test_unusable_inventories_are_rejected(doc: dict[str, Any]) -> None:
    with pytest.raises(InventoryError):
        parse_inventory(doc)


def test_deb_version_split_and_purl() -> None:
    v = split_deb_version("1:9.6p1-3ubuntu13.20")
    assert (v.epoch, v.upstream, v.revision) == (1, "9.6p1", "3ubuntu13.20")
    assert split_deb_version("3.137ubuntu1").revision is None
    doc = inventory_from_dpkg_tsv(
        "openssl\t3.0.13-0ubuntu3.5\tarm64\topenssl\t3.0.13-0ubuntu3.5\tii\n"
    )
    pkg = parse_inventory(doc).packages[0]  # SYNTHETIC single-line TSV
    assert purl(pkg, "ubuntu-24.04") == (
        "pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5?arch=arm64&distro=ubuntu-24.04"
    )


# ── service evidence ────────────────────────────────────────────────────────────


def test_unit_states_from_real_inventory() -> None:
    states = unit_states(load_json("linux-inventory-units.json"))
    assert {"ssh.service", "nginx.service", "auditd.service"} <= set(states)
    assert not states["ssh.service"].masked


def test_masked_or_missing_units_are_not_attributed() -> None:
    doc = {
        "type": "inventory",
        "systemd_units": [  # SYNTHETIC
            {
                "name": "nginx.service",
                "unit_dir": "/usr/lib/systemd/system",
                "role": "unit",
                "kind": "file",
            },
            {
                "name": "nginx.service",
                "unit_dir": "/etc/systemd/system",
                "role": "unit",
                "kind": "symlink",
                "symlink_target": "/dev/null",
            },
            {
                "name": "ssh.service",
                "unit_dir": "/usr/lib/systemd/system",
                "role": "unit",
                "kind": "file",
            },
        ],
    }
    states = unit_states(doc)
    assert states["nginx.service"].masked
    hints, notes = package_service_map(
        "linux:lab-vm-01",
        [
            (["nginx"], "nginx.service"),
            (["openssh-server"], "ssh.service"),
            (["vsftpd"], "vsftpd.service"),
        ],
        states,
    )
    assert set(hints) == {"openssh-server"}
    assert hints["openssh-server"].service_id == service_id(
        "linux:lab-vm-01", "host_service", "ssh.service"
    )
    assert any("masked" in n for n in notes) and any(
        "vsftpd.service not present" in n for n in notes
    )


# ── Docker hardening ────────────────────────────────────────────────────────────


def test_container_command_is_hardened(tmp_path: Path) -> None:
    image = f"aquasec/trivy:0.76.2{DIGEST}"
    runner = DockerRunner(allowed_images=[image], allowed_roots=[tmp_path])
    spec = ContainerSpec(image=image, args=["--version"], mounts=[Mount(tmp_path, "/src")])
    cmd = runner.command(spec, "extorq-c3-scan-test")
    joined = " ".join(cmd)
    for flag in (
        "--rm",
        "--pull never",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--pids-limit",
        "--memory",
        "--cpus",
    ):
        assert flag in joined
    assert f"--user {os.getuid()}:{os.getgid()}" in joined
    assert f"type=bind,source={tmp_path},target=/src,readonly" in cmd
    assert "/var/run/docker.sock" not in joined


@pytest.mark.parametrize(
    "spec_kwargs",
    [
        {"image": "aquasec/trivy:latest"},
        {"network": "host"},
        {"env": {"bad-key": "x"}},
        {"mounts": [Mount(Path("/etc"), "/src")]},
        {"mounts": [Mount(Path("relative"), "/src")]},
    ],
)  # SYNTHETIC invalid specs
def test_container_spec_validation(tmp_path: Path, spec_kwargs: dict[str, Any]) -> None:
    image = f"aquasec/trivy:0.76.2{DIGEST}"
    runner = DockerRunner(allowed_images=[image], allowed_roots=[tmp_path])
    spec = ContainerSpec(**{"image": image, "args": [], **spec_kwargs})
    with pytest.raises(DockerError):
        runner.command(spec, "extorq-c3-scan-test")


def test_symlink_mount_is_rejected(tmp_path: Path) -> None:
    image = f"aquasec/trivy:0.76.2{DIGEST}"
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    runner = DockerRunner(allowed_images=[image], allowed_roots=[tmp_path])
    with pytest.raises(DockerError, match="symlink"):
        runner.command(
            ContainerSpec(image=image, args=[], mounts=[Mount(tmp_path / "link", "/s")]), "n"
        )


def test_rfc3339_parsing() -> None:
    assert parse_rfc3339("2026-11-21T10:30:12.123456789Z") == datetime(
        2026, 11, 21, 10, 30, 12, 123456, tzinfo=UTC
    )
    assert parse_rfc3339("2026-11-21T16:00:12+05:30") == datetime(
        2026, 11, 21, 10, 30, 12, tzinfo=UTC
    )
    assert parse_rfc3339("yesterday") is None


# ── SDK gateway sink (fake gateway client at the boundary) ─────────────────────


class FakeGateway:
    def __init__(self, fail_first: int = 0) -> None:
        self.fail_first = fail_first
        self.batches: list[Any] = []

    def send(self, batch: Any) -> IngestResult:
        if self.fail_first:
            self.fail_first -= 1
            raise RetryableError("gateway unreachable (ConnectError)")  # SYNTHETIC outage
        self.batches.append(batch)
        return IngestResult(
            batch_id=batch.batch_id, accepted=len(batch.records), duplicates=0, rejected=0
        )

    def close(self) -> None:
        pass


def _running_record() -> ScanRunRecord:
    from extorq.contracts import ScanRun, ScanScope
    from extorq.contracts.identity import scope_hash

    return ScanRunRecord(
        data=ScanRun(  # SYNTHETIC record
            scan_run_id="c" * 32,
            scanner="trivy",
            scanner_version="0.76.2",
            asset_id="linux:lab-vm-01",
            scope=ScanScope(targets=["x"], scope_hash=scope_hash(["x"])),
            started_at=datetime(2026, 11, 21, tzinfo=UTC),
            status=ScanStatus.RUNNING,
            producer_id="scanner-runner",
        )
    )


def test_gateway_sink_delivers_in_order(tmp_path: Path) -> None:
    gateway = FakeGateway()
    sink = GatewaySink(
        state_path=tmp_path / "outbox.db", producer_id="scanner-runner", client=gateway
    )
    sink.submit([_running_record()])
    report = sink.close(5)
    assert (report.submitted, report.delivered, report.buffered) == (1, 1, 0)
    assert gateway.batches[0].producer_id == "scanner-runner"
    assert gateway.batches[0].records[0]["kind"] == "scan_run"


def test_gateway_sink_keeps_records_buffered_during_outage(tmp_path: Path) -> None:
    gateway = FakeGateway(fail_first=100)
    sink = GatewaySink(
        state_path=tmp_path / "outbox.db", producer_id="scanner-runner", client=gateway
    )
    sink.submit([_running_record()])
    report = sink.flush(0.5)
    assert report.buffered == 1 and report.delivered == 0
    assert any("unreachable" in e for e in report.errors)
    sink.store.close()
    # a later run delivers the durable outbox
    later = GatewaySink(
        state_path=tmp_path / "outbox.db", producer_id="scanner-runner", client=FakeGateway()
    )
    assert later.close(5).buffered == 0


def test_gateway_sink_requires_token_without_client(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="token_file"):
        GatewaySink(state_path=tmp_path / "o.db", producer_id="scanner-runner")

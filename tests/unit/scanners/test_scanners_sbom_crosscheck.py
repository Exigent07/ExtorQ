"""Cross-validation: the dpkg -> CycloneDX SBOM path finds exactly what Trivy's native
Ubuntu image detection finds (same vulnerability id, package, installed and fixed version).

Uses the locally present, pinned ``clickhouse/clickhouse-server:26.8.42.13`` image (Ubuntu
22.04) as the reference system: its dpkg database is read with ``dpkg-query`` in a
throwaway container, turned into an SBOM by ``extorq_scanners.sbom`` and scanned with
``trivy sbom``; the same image is scanned with ``trivy image``. Both scans run offline in the
pinned, hardened Trivy container against the same DB, so the comparison is deterministic.
Skipped when Docker, the images or the Trivy DB cache are not available locally (nothing is
pulled or downloaded).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from scanners_testlib import REPO_ROOT

from extorq_scanners.config import load_config
from extorq_scanners.docker import ContainerResult, ContainerSpec, DockerRunner, Mount
from extorq_scanners.sbom import build_cyclonedx, inventory_from_dpkg_tsv, parse_inventory
from extorq_scanners.trivydb import read_metadata

REFERENCE_IMAGE = "clickhouse/clickhouse-server:26.8.42.13"
TRIVY_CACHE = REPO_ROOT / "var" / "cache" / "trivy"
_FMT = (
    "${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\t"
    "${db:Status-Abbrev}\n"
)
_COMMON = [
    "--format",
    "json",
    "--cache-backend",
    "memory",
    "--disable-telemetry",
    "--skip-version-check",
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-vex-repo-update",
    "--offline-scan",
    "--no-progress",
    "--pkg-types",
    "os",
]


def _skip_reason() -> str | None:
    docker = shutil.which("docker")
    if docker is None:
        return "docker CLI not installed"
    if read_metadata(TRIVY_CACHE) is None:
        return "no Trivy DB in var/cache/trivy (run extorq-scan update)"
    trivy = load_config(REPO_ROOT / "config" / "scanners.yaml").images.trivy
    for image in (REFERENCE_IMAGE, trivy):
        probe = subprocess.run(
            [docker, "image", "inspect", image], capture_output=True, timeout=30, check=False
        )
        if probe.returncode != 0:
            return f"image {image} not present locally"
    return None


_SKIP = _skip_reason()
pytestmark = pytest.mark.skipif(_SKIP is not None, reason=_SKIP or "")


def _os_vulns(result: ContainerResult) -> tuple[set[tuple[str, str, str, str]], dict]:
    assert result.outcome.exit_code == 0, result.stderr[-500:]
    doc = json.loads(result.stdout)
    found = {
        (v["VulnerabilityID"], v["PkgName"], v["InstalledVersion"], v.get("FixedVersion") or "")
        for r in doc.get("Results") or []
        if r.get("Class") == "os-pkgs"
        for v in r.get("Vulnerabilities") or []
    }
    return found, doc


def test_sbom_path_matches_native_ubuntu_detection(tmp_path: Path) -> None:
    docker = shutil.which("docker") or "docker"
    tsv = subprocess.run(
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "dpkg-query",
            REFERENCE_IMAGE,
            "-W",
            f"-f={_FMT}",
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    ).stdout
    inventory = parse_inventory(inventory_from_dpkg_tsv(tsv, os_version="22.04"))
    sbom = build_cyclonedx(inventory, asset_id="linux:crosscheck", generated_at=datetime.now(UTC))
    (tmp_path / "inventory.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
    subprocess.run(
        [docker, "image", "save", "--output", str(tmp_path / "image.tar"), REFERENCE_IMAGE],
        capture_output=True,
        timeout=600,
        check=True,
    )

    trivy = load_config(REPO_ROOT / "config" / "scanners.yaml").images.trivy
    runner = DockerRunner(
        allowed_images=[trivy],
        allowed_roots=[TRIVY_CACHE.resolve(), tmp_path.resolve()],
        name_prefix="extorq-c3-crosscheck",
        memory="3g",
    )
    mounts = [Mount(TRIVY_CACHE.resolve(), "/cache"), Mount(tmp_path.resolve(), "/w")]
    native = runner.run(
        ContainerSpec(
            trivy,
            [
                "--cache-dir",
                "/cache",
                "image",
                "--input",
                "/w/image.tar",
                "--scanners",
                "vuln",
                *_COMMON,
            ],
            mounts,
            purpose="native",
        ),
        timeout=900,
        max_stdout_bytes=256 * 1024 * 1024,
    )
    via_sbom = runner.run(
        ContainerSpec(
            trivy,
            ["--cache-dir", "/cache", "sbom", *_COMMON, "/w/inventory.cdx.json"],
            mounts,
            purpose="sbom",
        ),
        timeout=900,
        max_stdout_bytes=256 * 1024 * 1024,
    )
    native_set, native_doc = _os_vulns(native)
    sbom_set, sbom_doc = _os_vulns(via_sbom)
    assert native_doc["Metadata"]["OS"] == sbom_doc["Metadata"]["OS"]
    assert native_doc["Metadata"]["OS"]["Family"] == "ubuntu"
    assert len(inventory.packages) > 50
    assert sbom_set == native_set

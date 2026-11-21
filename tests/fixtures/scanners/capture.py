"""Capture scanner test fixtures from REAL tool output (developer tool, owner: C3).

Usage (from the repository root, after a real run with raw output kept)::

    uv run extorq-scan run all --save-raw var/cache/scanners/raw
    uv run python tests/fixtures/scanners/capture.py var/cache/scanners/raw [--live-vm]

* Copies the newest raw stdout/stderr of every target into this directory.
* Large reports are TRIMMED by keeping a subset of whole, unmodified entries
  (vulnerabilities of selected source packages, the packages they reference):
  nothing is rewritten or invented. Trimming is recorded in ``manifest.json``.
* Every string goes through ``extorq.common.redaction.redact_text`` and the
  ExtorQ lab test-secret pattern before it is written (secret-shaped values are
  replaced by markers; gitleaks already ran with ``--redact``).
* Semgrep ``extra.lines`` (matched source lines) is replaced by a marker.
* ``--live-vm`` additionally fetches B1's ``packages`` dispatch output (full) and
  the ``inventory`` output reduced to ``type`` + ``systemd_units`` (process, user,
  cron and file lists are dropped) from the lab VM.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from extorq.common.redaction import redact_text

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
_LAB_SECRET = re.compile(r"EXTORQ_TEST_SECRET_[A-Z0-9]{24}")
_LINES_MARKER = "<source lines not stored in fixtures>"


def scrub(value: Any) -> Any:
    if isinstance(value, str):
        text, _ = redact_text(value)
        return _LAB_SECRET.sub("EXTORQ_TEST_SECRET_<redacted>", text)
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    return value


def latest(raw: Path, target: str, suffix: str) -> Path:
    files = sorted(raw.glob(f"{target}.*.{suffix}"), key=lambda p: p.stat().st_mtime)
    if not files:
        raise SystemExit(f"no raw {suffix} for {target} in {raw}")
    return files[-1]


def trim_os_report(report: dict[str, Any], keep: Callable[[str, str], bool]) -> dict[str, Any]:
    """Keep os-pkgs vulnerabilities whose (source, vuln id) passes ``keep`` + their packages."""
    for result in report.get("Results") or []:
        if result.get("Class") != "os-pkgs":
            continue
        sources = {p.get("ID"): p.get("SrcName") for p in result.get("Packages") or []}
        vulns = [
            v
            for v in result.get("Vulnerabilities") or []
            if keep(str(sources.get(v.get("PkgID")) or v.get("PkgName")), v["VulnerabilityID"])
        ]
        used = {v.get("PkgID") for v in vulns}
        result["Vulnerabilities"] = vulns
        result["Packages"] = [p for p in result.get("Packages") or [] if p.get("ID") in used]
    return report


def write_json(name: str, data: Any) -> None:
    path = HERE / name
    path.write_text(json.dumps(scrub(data), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")


def write_text(name: str, text: str) -> None:
    path = HERE / name
    path.write_text(scrub(text), encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")


def first_n_per_source(limits: dict[str, int]) -> Callable[[str, str], bool]:
    seen: dict[str, set[str]] = {}

    def keep(source: str, vid: str) -> bool:
        if source not in limits:
            return False
        ids = seen.setdefault(source, set())
        if vid in ids:
            return True  # same vulnerability for another binary of the source
        if len(ids) >= limits[source]:
            return False
        ids.add(vid)
        return True

    return keep


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    parser.add_argument("--live-vm", action="store_true")
    args = parser.parse_args()
    raw: Path = args.raw
    manifest: dict[str, Any] = {}

    def load(target: str) -> tuple[Any, str]:
        out = latest(raw, target, "stdout")
        err = latest(raw, target, "stderr")
        return json.loads(out.read_text(encoding="utf-8")), err.read_text(encoding="utf-8")

    # Trivy fs on the lab repository content (full).
    report, stderr = load("trivy-lab-repo")
    write_json("trivy-fs-lab-repo.json", report)
    write_text("trivy-fs-lab-repo.stderr.txt", stderr)
    manifest["trivy-fs-lab-repo.json"] = {"target": "trivy-lab-repo", "trimmed": False}

    # Trivy config on the applied kind manifests (full) + the line index of those files.
    report, stderr = load("trivy-kind-config")
    write_json("trivy-config-kind.json", report)
    write_text("trivy-config-kind.stderr.txt", stderr)
    from extorq_scanners.config import load_config
    from extorq_scanners.k8s_index import index_paths

    cfg = load_config(ROOT / "config" / "scanners.yaml")
    target = next(t for t in cfg.targets if t.name == "trivy-kind-config")
    index = index_paths(ROOT, target.paths, None)
    write_json(
        "trivy-config-kind.k8s-index.json",
        {path: [ref.__dict__ for ref in refs] for path, refs in sorted(index.items())},
    )
    manifest["trivy-config-kind.json"] = {"target": "trivy-kind-config", "trimmed": False}

    # Trivy image of the lab-portal image: keep 3 Debian source packages + all lang-pkgs.
    report, stderr = load("trivy-lab-portal-image")
    report = trim_os_report(report, first_n_per_source({"glibc": 6, "openssl": 6, "systemd": 4}))
    write_json("trivy-image-lab-portal.json", report)
    write_text("trivy-image-lab-portal.stderr.txt", stderr)
    manifest["trivy-image-lab-portal.json"] = {
        "target": "trivy-lab-portal-image",
        "trimmed": "os-pkgs vulnerabilities of sources glibc(6 ids), openssl(6), systemd(4) "
        "and the packages they reference; lang-pkgs result complete",
    }

    # Trivy image of the OTel collector: Go binary result, package list trimmed.
    report, stderr = load("trivy-otel-collector-image")
    for result in report.get("Results") or []:
        vulnerable = {
            v.get("PkgID") or v.get("PkgName") for v in result.get("Vulnerabilities") or []
        }
        pkgs = result.get("Packages") or []
        result["Packages"] = [
            p for i, p in enumerate(pkgs) if i < 10 or (p.get("ID") or p.get("Name")) in vulnerable
        ]
    write_json("trivy-image-otel.json", report)
    write_text("trivy-image-otel.stderr.txt", stderr)
    manifest["trivy-image-otel.json"] = {
        "target": "trivy-otel-collector-image",
        "trimmed": "Packages list cut to the first 10 + vulnerable ones; vulnerabilities complete",
    }

    # Trivy sbom of the Linux VM: kernel (4 ids), openssh (all), sudo/openssl/glibc (all).
    report, stderr = load("linux-vm-packages")
    limits = {"linux": 4, "openssh": 1000, "sudo": 1000, "openssl": 1000, "glibc": 1000}
    report = trim_os_report(report, first_n_per_source(limits))
    write_json("trivy-sbom-linux-vm.json", report)
    write_text("trivy-sbom-linux-vm.stderr.txt", stderr)
    manifest["trivy-sbom-linux-vm.json"] = {
        "target": "linux-vm-packages",
        "trimmed": "os-pkgs vulnerabilities of sources linux (first 4 ids, all binaries), "
        "openssh, sudo, openssl, glibc (all ids) and the packages they reference",
    }

    # Gitleaks dir scan of the lab repository (full; ran with --redact).
    report, stderr = load("gitleaks-lab-repo")
    write_json("gitleaks-dir-lab-repo.json", report)
    write_text("gitleaks-dir-lab-repo.stderr.txt", stderr)
    manifest["gitleaks-dir-lab-repo.json"] = {"target": "gitleaks-lab-repo", "trimmed": False}

    # Semgrep (full, matched source lines replaced).
    report, stderr = load("semgrep-lab-repo")
    for result in report.get("results") or []:
        extra = result.get("extra")
        if isinstance(extra, dict) and "lines" in extra:
            extra["lines"] = _LINES_MARKER
    write_json("semgrep-lab-repo.json", report)
    write_text("semgrep-lab-repo.stderr.txt", stderr)
    manifest["semgrep-lab-repo.json"] = {"target": "semgrep-lab-repo", "trimmed": False}

    if args.live_vm:
        from extorq_scanners.inventory import fetch_inventory, fetch_packages

        write_json("linux-packages-dispatch.json", fetch_packages(ROOT, cfg.inventory))
        inv = fetch_inventory(ROOT, cfg.inventory)
        unit_keys = ("name", "unit_dir", "role", "kind", "symlink_target", "exists")
        units = [
            {k: u.get(k) for k in unit_keys if k in u}
            for u in inv.get("systemd_units") or []
            if isinstance(u, dict)
        ]
        write_json("linux-inventory-units.json", {"type": inv.get("type"), "systemd_units": units})
        manifest["linux-packages-dispatch.json"] = {"source": "dispatch packages", "trimmed": False}
        manifest["linux-inventory-units.json"] = {
            "source": "dispatch inventory",
            "trimmed": "only type + systemd_units (name, unit_dir, role, kind, symlink_target, "
            "exists) kept",
        }

    old = HERE / "manifest.json"
    merged = json.loads(old.read_text()) if old.exists() else {}
    merged.update(manifest)
    old.write_text(json.dumps(merged, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

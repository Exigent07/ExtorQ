# Scanner test fixtures (owner: C3)

These files are **real tool output** captured on 2026-11-21 from the ExtorQ lab with
`tests/fixtures/scanners/capture.py` (see its docstring), not hand-written samples.
`manifest.json` records which raw run each file came from and how it was trimmed.

| File | Tool / source | Scope | Trimmed |
|---|---|---|---|
| `trivy-fs-lab-repo.json` (+ `.stderr.txt`) | Trivy 0.76.2 `fs --scanners misconfig,vuln` | `lab/github-repo` (lab repository content) | no |
| `trivy-config-kind.json` (+ `.stderr.txt`, `.k8s-index.json`) | Trivy 0.76.2 `config` | applied kind manifests (`var/kind` renders + plain manifests) and the lab-portal Dockerfile; the index is the manifest line index computed from those files at capture time | no |
| `trivy-image-lab-portal.json` (+ `.stderr.txt`) | Trivy 0.76.2 `image --input` | `extorq/lab-portal` image (Debian 13.7 + pip) | yes: OS vulnerabilities of sources glibc, openssl, systemd only (whole entries) |
| `trivy-image-otel.json` (+ `.stderr.txt`) | Trivy 0.76.2 `image --input` | `otel/opentelemetry-collector-contrib:0.165.0` (Go binary) | yes: package list cut; vulnerabilities complete |
| `trivy-sbom-linux-vm.json` (+ `.stderr.txt`) | Trivy 0.76.2 `sbom` | CycloneDX SBOM of the Ubuntu 24.04 VM (`linux:lab-vm-01`) | yes: sources linux (4 ids, all 7 binaries), openssh, sudo, openssl, glibc |
| `gitleaks-dir-lab-repo.json` (+ `.stderr.txt`) | Gitleaks 8.30.1 `dir --redact` | `lab/github-repo` | no |
| `semgrep-lab-repo.json` (+ `.stderr.txt`) | Semgrep 1.184.0 `scan` with registry pack `p/python` | `lab/github-repo` | no (`extra.lines` replaced by a marker) |
| `linux-packages-dispatch.json` | B1 dispatch command `packages` over SSH | lab VM, 667 dpkg packages, Ubuntu 24.04.5 LTS arm64 | no |
| `linux-inventory-units.json` | B1 dispatch command `inventory` | lab VM | yes: only `systemd_units` (name, dir, role, kind, symlink target, exists) |

## Secret handling

* Every string was passed through `extorq.common.redaction.redact_text` and the ExtorQ
  lab test-secret pattern before writing (secret-shaped values become markers).
* Gitleaks ran with `--redact`; Trivy ran without its secret scanner; Semgrep's matched
  source lines are not kept.
* The only secret-shaped value in the lab repository is the documented FAKE
  `EXTORQ_TEST_SECRET_...` string; it does not appear in any fixture.

## Synthetic data

Tests that need inputs no real run produced (non-zero exits, timeouts, malformed or
truncated JSON, unredacted gitleaks matches, Semgrep errors) build them inline in the test
module and label them `SYNTHETIC` there. Nothing synthetic is stored in this directory.

Re-capture after a real run: `uv run extorq-scan run all --save-raw var/cache/scanners/raw`
then `uv run python tests/fixtures/scanners/capture.py var/cache/scanners/raw --live-vm`
(test expectations derived from fixture contents may then need updating).

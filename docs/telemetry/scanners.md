# Security scanners and the findings lifecycle

Owner: C3. Code: `scanners/src/extorq_scanners/`, configuration: `config/scanners.yaml`,
gitleaks rules: `scanners/rules/gitleaks/extorq-gitleaks.toml`, lifecycle views:
`infra/clickhouse/migrations/0003_findings_views.sql` and `0005_findings_services.sql`,
tests: `tests/unit/scanners/`, real-output fixtures: `tests/fixtures/scanners/`.

ExtorQ runs three open-source scanners in pinned, hardened containers, normalises their
output into the versioned contracts (`ScanRun`, `PostureFinding`, `CollectorHealth`) and
submits it as producer `scanner-runner` through the collector SDK outbox to the ingest
gateway. Whether a finding is open, unverified or resolved is never asserted by a scanner:
ClickHouse derives it from the history of scans (section 7).

## 1. Tools, versions and execution

| Tool | Image (pulled once, scans use `--pull never`) | Version check |
|---|---|---|
| Trivy | `aquasec/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb` | `trivy --version` in the same image; `ScanRun.scanner_version` comes from the report (`Trivy.Version`) |
| Gitleaks | `ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` | `gitleaks version` |
| Semgrep (OSS) | `semgrep/semgrep:1.184.0@sha256:cc1b68266f267878b39739373ea9985b9a78e5d64497dd875c8de100b22695ed` (linux/amd64 only, emulated on Apple Silicon) | report `version` |

Every scan container (`extorq_scanners.docker.DockerRunner`) runs with: `--rm`,
`--pull never`, `--network none`, `--read-only` root filesystem plus a 512 MiB `noexec`
tmpfs on `/tmp`, `--cap-drop ALL`, `--security-opt no-new-privileges`, the invoking
non-root uid:gid, `--pids-limit 512`, `--memory 3g`, `--cpus 4`, and read-only bind mounts
created with `--mount` (which never creates missing host paths). Mount sources must be real
directories/files inside the repository root (symlinks and paths outside it are refused);
only the three configured digests may run. Output is read with hard byte caps; on timeout or
overflow the container is killed by name. The Docker socket is never mounted.

Network is used only by two explicit maintenance steps, never by a scan container:

* Trivy DB: `extorq-scan update` (or a run when `var/cache/trivy` is older than
  `trivy.db_max_age_hours`, 24 h) starts Trivy with `--download-db-only` on the bridge
  network, mounting only the cache directory (no scan target). Scans then use
  `--skip-db-update --skip-java-db-update --skip-vex-repo-update --offline-scan`.
* Semgrep rules: the registry pack `p/python` is fetched host-side over HTTPS
  (`https://semgrep.dev/c/p/python`, timeout 30 s, 3 jittered retries, no redirects,
  size cap 8 MiB, validated as a ruleset), cached with a SHA-256 sidecar in
  `var/cache/semgrep` (never committed: Semgrep Rules License) and refreshed after 168 h.
  The Semgrep container itself runs offline with `--metrics=off`. A failed refresh falls
  back to the cache and says so in the coverage notes.

Commands (container side):

```text
trivy --cache-dir /cache fs --scanners misconfig,vuln --format json --cache-backend memory \
      --disable-telemetry --skip-version-check --skip-db-update --skip-java-db-update \
      --skip-vex-repo-update --offline-scan --skip-check-update --no-progress --timeout 900s /src
trivy --cache-dir /cache config ... --skip-check-update --timeout 900s /src
trivy --cache-dir /cache image --input /images/image.tar --scanners vuln ... (offline flags)
trivy --cache-dir /cache sbom ... (offline flags) /sbom/inventory.cdx.json
gitleaks dir|git /src --config /config/extorq-gitleaks.toml --gitleaks-ignore-path /config \
      --ignore-gitleaks-allow --redact --no-banner --no-color --log-level info \
      --max-target-megabytes 10 --exit-code 42 --report-format json --report-path -
semgrep scan --config <cached p/python> --metrics=off --disable-version-check --disable-nosem \
      --json --timeout 30 --max-target-bytes 1000000 --jobs 4 /src
```

Trivy's secret scanner is never enabled (secrets are Gitleaks' job). Gitleaks ignores inline
`gitleaks:allow` and the scanned repository's `.gitleaks.toml`/`.gitleaksignore`; the runner
refuses to start if a `.gitleaksignore` sits next to the ExtorQ rule file. Semgrep ignores
`nosemgrep` comments (`--disable-nosem`), so a scanned repository cannot silence findings.

## 2. Targets (config/scanners.yaml)

| Target | Tool / mode | Asset | Scope (`ScanRun.scope.targets`) |
|---|---|---|---|
| `trivy-lab-repo` | Trivy `fs` (vuln + misconfig) | `github:exigent07/extorq-lab` | `fs:lab/github-repo` |
| `gitleaks-lab-repo` | Gitleaks `dir` | same | `dir:lab/github-repo` |
| `semgrep-lab-repo` | Semgrep `scan` (`p/python`, 151 rules) | same | `scan:lab/github-repo` |
| `gitleaks-lab-repo-history` | Gitleaks `git` (full history) | same | `git:var/cache/scanners/repos/extorq-lab` (**planned**: skipped until the real repository is cloned there) |
| `trivy-kind-config` | Trivy `config` | `k8s:extorq-lab` | the APPLIED kind manifests: `var/kind/{21-otel-daemonset,30-lab-portal,40-posture-lab}.yaml` (rendered by `infra/kind/kind.sh`), `infra/kind/manifests/{00,10,20}-*.yaml`, `infra/kind/apps/lab-portal/Dockerfile` |
| `trivy-lab-portal-image` | Trivy `image` | `k8s:extorq-lab` | `image:extorq/lab-portal` (newest local build; tags are content hashes) |
| `trivy-otel-collector-image` | Trivy `image` | `k8s:extorq-lab` | `image:otel/opentelemetry-collector-contrib` (pinned digest from kind.sh) |
| `linux-vm-packages` | Trivy `sbom` of the VM's dpkg inventory | `linux:lab-vm-01` | `sbom:linux:lab-vm-01:dpkg` |

The lab repository content is scanned from the ExtorQ working tree (`lab/github-repo`, the
source C1 pushes to GitHub) until the real repository exists and is cloned. Templated kind
manifests are not scanned because their placeholders (e.g. `__LAB_PORTAL_IMAGE__`) produced
artefacts such as KSV-0013 ":latest tag" that are not deployed. The diagnostic pod
`90-netcheck-pod` is excluded (kind.sh deletes it after use).

Image targets save the local image with `docker image save` (only the image's own
platform) to a 0700 work directory, scan the archive offline and delete it. Image scopes are
the repository, so a rebuilt or bumped image resolves the findings it no longer has; the
exact reference, Docker image id, platform and repo digests are kept in `ScanRun.attributes`.

### Linux VM packages (SBOM)

The package inventory comes from B1's restricted SSH dispatch command `packages`
(`extorq_collectors.linux.ssh.SSHDispatchClient`, host-key pinned, BatchMode, forced
command allow-list, key `var/vm/keys/extorq-collector`, known hosts `var/vm/known_hosts`,
`127.0.0.1:2222`; the key is passed to `ssh` by path and never read by ExtorQ code).
`extorq_scanners.sbom` builds a CycloneDX 1.6 SBOM with an `operating-system` component
(`ubuntu` / `24.04`) and one component per installed dpkg package with
`pkg:deb/ubuntu/<name>@<version>?arch=<arch>&distro=ubuntu-24.04[&epoch=N]` purls and Trivy's
source-package properties (`aquasecurity:trivy:SrcName/SrcVersion/SrcRelease/SrcEpoch`,
because Ubuntu advisories are keyed by source package). Packages that are not installed
(`config-files`, `not-installed`) are excluded; invalid entries make the scan `partial`.
The SBOM (0600) is mounted read-only into Trivy and deleted afterwards; a copy of the latest
one stays in `var/cache/scanners/sbom/` for inspection.

Cross-validation (`tests/unit/scanners/test_scanners_sbom_crosscheck.py`): for a local
Ubuntu 22.04 image (the pinned ClickHouse server image, 111 dpkg packages) the SBOM built
from its `dpkg-query` output and Trivy's native image detection yield identical OS
vulnerability sets (42 entries; same id, package, installed and fixed version).

## 3. Findings: identity, severity, content

Finding ids are `identity.finding_id(asset_id, scanner, check_id, resource_key, qualifier)`:

| Kind | check_id | resource_key |
|---|---|---|
| Vulnerability, language package | vulnerability id (CVE/GHSA/GO-...) | `lang-pkgs\|<lock file>\|<package>\|<installed>\|<pkg path>` |
| Vulnerability, OS package | vulnerability id | `os-pkgs\|os\|src:<source package>\|<full source version>\|` |
| Misconfiguration | Trivy check id (KSV-..., DS-...) | `<file>\|<kind/namespace/name>\|sha256(message)[:16]` + `#n` for the n-th identical failure in one object (line order) |
| Secret | `gitleaks:<rule id>` | gitleaks fingerprint `[<commit>:]<file>:<rule>:<line>` |
| Code (Semgrep) | rule id | `<path>:<line>:<col>:<end line>:<end col>` |

Image scans add the qualifier `image:<repository>`, so the same CVE in two images of one
asset are two findings. Misconfiguration ids do not depend on line numbers (stable across
unrelated edits; verified by a test that shifts every line).

OS-package vulnerabilities are grouped per (vulnerability, source package, source version):
Trivy repeats a source CVE for every binary package built from it (the VM kernel source
`linux` has 7 installed binary packages). One finding is kept per group with
`package.name = <source>`, `installed_version = <source version>` and the affected binary
packages in `attributes.binary_packages`. Real effect on the lab VM: 22,944 Trivy entries
become 3,359 findings with no information dropped. Language packages are never grouped.

Severity: Trivy `CRITICAL/HIGH/MEDIUM/LOW` map 1:1; `UNKNOWN` uses the CVSS v3 qualitative
scale when a score exists, else `info` (`attributes.severity_basis` = `scanner`, `cvss_v3` or
`unknown`; the original value is always in `attributes.source_severity`). Semgrep
`ERROR`/`WARNING`/`INFO` map to high/medium/low. Gitleaks findings are `high` by default,
`extorq-test-secret` is configured `medium` (`gitleaks.severity_overrides`). CVSS: v3 score
of the severity source, then NVD, GHSA, Red Hat, Ubuntu, Debian (v4 if no v3). CVE ids, fixed
versions (all distinct values of a group) and at most 10 http(s) references are kept.

Stored text is bounded and sanitised (`extorq.common.redaction.sanitize_untrusted` strips
control/bidi characters) and credential-shaped values are removed with `redact_text`. Trivy
code snippets (`CauseMetadata.Code`) and Semgrep matched lines are never stored (tests assert
it on the real fixtures).

## 4. Secret handling

* Gitleaks runs with `--redact`; the secret never leaves the container. Per leak ExtorQ keeps
  only: rule id, file, start/end line, commit (git mode, validated hex), the gitleaks
  fingerprint and the redacted match (`REDACTED`). Author, e-mail, date, message, entropy and
  columns are discarded.
* A leak whose `Match`/`Secret` is not redacted by gitleaks is still reported, but its match
  is replaced by `REDACTED` and the scan notes record it.
* `redact_text` runs over every stored free-text string (paths, descriptions, messages,
  attributes). Exception, documented in `sanitize.Verbatim`: identifiers composed only of
  components that were each validated or redacted (the gitleaks fingerprint and rule id) are
  stored after control-character sanitisation only, because generic `key: value` redaction
  turned `extorq-test-secret:9` into `[REDACTED:secret]` and destroyed the fingerprint.
* Custom rule `extorq-test-secret` matches the lab repository's documented FAKE value
  (`EXTORQ_TEST_SECRET_` + 24 upper-case alphanumerics).
* `--save-raw DIR` (debug only) keeps raw tool output with mode 0600 under `var/`; it is never
  committed. Fixtures are produced from it by `tests/fixtures/scanners/capture.py`, which
  scrubs every string again.
* The producer token is read from `var/secrets/tokens/scanner-runner.token` at runtime and
  never logged; the CLI summary contains no scanned content.

## 5. Scan status and coverage

`extorq_scanners.status.decide` (pure, unit-tested) decides the terminal status:

| Status | When |
|---|---|
| `failed` | tool could not start (Docker/image missing, invalid mount), timeout/kill, output over the size cap (truncated output is never parsed), empty/malformed/unsupported output (including non-zero exit with unusable output, e.g. OOM kill 137), unknown exit status, the tool reports it scanned nothing while logging errors (gitleaks "0 commits scanned"), a required input is missing (Trivy DB, VM inventory, target path), any internal error of the runner |
| `partial` | output usable but: undocumented exit code, tool error lines (Trivy `ERROR`/`FATAL`, gitleaks `ERR`, Semgrep errors), skipped checks/rulesets/inventory entries, findings that could not be represented |
| `succeeded` | everything else |

Findings of a `failed` scan are not submitted; findings of a `partial` scan are submitted
but can never resolve anything. Coverage (`ScanRun.coverage`): Trivy misconfiguration
checks evaluated/passed/failed (`MisconfSummary`), Semgrep rules run/total and skipped rules,
files scanned and Semgrep's own skip summary (e.g. `Files matching .semgrepignore
patterns: 1`: Semgrep's default ignore list excludes `tests/`), gitleaks bytes/commits
scanned, SBOM package counts, ruleset/config SHA-256 digests and the Trivy DB timestamp.

Each scan is submitted in order: `running` ScanRun, findings, terminal ScanRun last, then a
`CollectorHealth` (`collector_id = scanner.<target>`, ok/degraded/failed, last success).
A runner that dies mid-scan leaves an in-flight marker; the next run reports that scan as
`failed` ("runner interrupted"), and the lifecycle view treats any scan still `running`
after 6 hours as failed.

## 6. Service attribution (contract 1.1)

`PostureFinding.service_id` is set only with evidence: a rule in
`targets[].service_attribution` says the binary package ships a systemd unit
(`openssh-server`/`openssh-sftp-server` -> `ssh.service`, `nginx`/`nginx-common`/`nginx-core` -> `nginx.service`,
`auditd` -> `auditd.service`) AND the unit is present and not masked in the VM's unit list
fetched with B1's dispatch command `inventory` during the same scan. The id is
`identity.service_id('linux:lab-vm-01', 'host_service', '<unit>')`, the identity B1's
discovery assigns to a systemd unit service. It is labelled
`attributes.service_attribution = inferred:package-ships-unit` (a package shipping a unit
does not prove the vulnerable code is loaded by it). If the unit inventory is unavailable
the scan still succeeds without attribution and says so in its notes. Image, repository and
manifest findings have no service attribution yet (**planned**: Kubernetes workload
attribution once B2 publishes workload services).

## 7. Lifecycle views

`extorq.v_scan_runs_current` (0003): one row per `scan_run_id` (latest row version wins)
with `effective_status` (`running` older than 6 h -> `failed`).

`extorq.v_findings_current` (0003, recreated by 0005 with `service_id` appended last).
Grain: (asset_id, scanner, scope_hash, finding_id); `scope_hash` comes from the ScanRun that
produced the observation. Columns: finding_id, asset_id, scanner, scope_hash, check_id,
category, severity, title, resource_type, resource_name, resource_namespace, resource_path,
package_name, installed_version, fixed_version, cve_ids, accepted_risk_reason,
first_observed_at, last_observed_at, last_scan_run_id, last_success_at (Nullable),
latest_scan_status (Nullable), latest_scan_at (Nullable), state, service_id (0005).

| state | meaning (per asset, scanner, scope) |
|---|---|
| `open` | observed in the latest SUCCEEDED scan and no newer partial/failed attempt |
| `unverified` | observed in the latest succeeded scan but a newer attempt was partial/failed; or observed only in partial/failed scans with no later success; or its ScanRun is unknown |
| `resolved` | a SUCCEEDED scan of the same scope, newer than the last observation, did not observe it |

Partial and failed scans never resolve; a different scope never resolves; running scans do
not change state. Descriptive columns (and `service_id`) come from the most recent
observation, NULL included. Both views are `SQL SECURITY INVOKER` (readers need SELECT on
the base tables too) and avoid `SETTINGS` so `readonly=1` users can query them; results are
identical under `join_use_nulls` 0 and 1. 0005 also grants SELECT on `v_scan_runs_current`
to the detect, rules_ro and grafana roles (no widening because of INVOKER security).

## 8. Operation

```bash
uv run extorq-scan validate                 # check config/scanners.yaml
uv run extorq-scan list                     # targets, assets, scope hashes
uv run extorq-scan update                   # refresh Trivy DB + Semgrep pack (network)
uv run extorq-scan run all                  # or trivy | gitleaks | semgrep | linux-packages
uv run extorq-scan run trivy --target trivy-lab-repo --sink jsonl --output /tmp/x.jsonl
uv run extorq-scan flush                    # deliver records still in the outbox
```

`run` prints a JSON summary (status and severity counts per target, records submitted /
delivered / buffered); logs go to stderr. Exit codes: 0 all succeeded or skipped, 1 partial,
2 failed, 3 configuration error, 4 another run holds the lock, 5 records not delivered.
State: `var/state/scanners/` (lock, in-flight markers, last results, SDK outbox
`outbox.db`, all 0600/0700). Delivery is at least once; records stay in the outbox across
gateway outages and are sent by the next `run` or `flush`. Scans are run by an operator
(`make scan` is **planned** in A's Makefile); there is no scheduler, so `CollectorHealth`
(interval 86400 s) turns stale after 3 days without a run.

## 9. What is not covered

* Trivy misconfiguration checks come from the check bundle embedded in Trivy 0.76.2 (bundle
  downloads are disabled); Trivy has no checks for GitHub Actions workflows (C1's workflow
  analyser covers them) or for the kind cluster config.
* Ubuntu kernel images (`linux-image-*`, source `linux-signed`) have no advisories of their
  own in Trivy's DB; kernel CVEs are reported through the `linux` source packages
  (headers, modules, tools, libc-dev).
* Image scans cover the newest local `extorq/lab-portal` build and the pinned OTel image; they
  do not query the cluster for the image actually running.
* Semgrep runs only the `p/python` pack on the lab repository; its default ignore list skips
  test directories (reported in coverage). No other languages are scanned.
* Git history of the real lab repository is not scanned until it is cloned (target skipped).
* Accepted-risk exceptions are not produced by these scanners (always NULL here).

## 10. Verification (2026-11-21, real runs)

| What | Result |
|---|---|
| `uv run extorq-scan run all --drain-seconds 300` | 7 scans succeeded, 1 skipped (clone absent); lab repo: Trivy 38 (1 critical, 11 high), Gitleaks 1, Semgrep 1; kind: misconfig 27, lab-portal image 110, OTel image 2; VM: 3,359 (42 critical, 755 high); 3,559 records delivered, 0 buffered |
| ClickHouse (`extorq_api_ro`) | ScanRuns and findings by severity present for all three assets; openssh finding carries the `ssh.service` service id |
| Gateway unreachable (config copy with url `https://127.0.0.1:9`), then `extorq-scan flush` | run: 4 records buffered, exit 5; flush: 4 delivered, scan visible in `v_scan_runs_current` |
| Forced failure (Trivy OOM-killed with a 16 MiB memory limit, same scope) | ScanRun `failed` (`unusable tool output (exit code 137): empty output`), CLI exit 2; all 38 earlier findings `unverified`, none resolved; next normal run: all 38 `open` again |
| `uv run pytest tests/unit/scanners -q` | 159 passed, 5 skipped (0005-only checks on the 0003 variant); lifecycle scenarios run against both view definitions in ephemeral ClickHouse 26.8.42.13 containers; SBOM path = native Trivy detection on an Ubuntu 22.04 image (42 = 42) |

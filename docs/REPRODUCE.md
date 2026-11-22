# Reproducing ExtorQ end to end

This guide rebuilds the whole system on an Apple Silicon Mac and re-runs every detection
test against the four monitored assets. Every command below exists in this repository
(`make help` lists the targets). Nothing here prints a secret; secrets are passed by file path.

| Asset | ID | How it is monitored |
|---|---|---|
| macOS host (this Mac) | `macos:workstation-01` | native collector (unified log, launchd, listeners, apps, posture) |
| Ubuntu 24.04 VM (QEMU/HVF) | `linux:lab-vm-01` | agentless SSH collector via a forced read-only dispatcher; auditd, journald, nginx, web app |
| kind cluster `extorq-lab` | `k8s:extorq-lab` | OTel DaemonSet (API audit log + container logs) and a read-only inventory collector |
| GitHub repository | `github:exigent07/extorq-lab` | REST polling collector (commits, workflow analysis, runs, posture) |

## 0. Prerequisites

`docker` (Docker Desktop), `uv`, `pnpm`, `kind`, `kubectl`, `qemu-system-aarch64` (+ edk2
firmware from Homebrew `qemu`), `gh` (logged in), `openssl`, `python3`. `make bootstrap`
reports any that are missing by name. The repo's `.env` must contain `JEV_API_KEY`
(it is read only by `make jev-key`, never printed).

## 1. One-time setup

```bash
make bootstrap                # secrets, local CA + gateway cert, producer registry (idempotent)
make jev-key                  # copies JEV_API_KEY from .env to var/secrets/jev_api_key (0600)
```

**GitHub credential.** The collector reads a token *file* (never an environment value or the
`gh` CLI directly):

```bash
# Preferred: a fine-grained, read-only PAT scoped to Exigent07/extorq-lab
#   (Metadata, Contents, Actions, Administration, Dependabot alerts: Read)
umask 077; mkdir -p var/secrets/github; printf '%s' '<github_pat_...>' > var/secrets/github/readonly-pat

# Interim (what the reference run used): the broad token of your `gh` login.
umask 077; mkdir -p var/secrets/github; gh auth token > var/secrets/github/readonly-pat
```

The interim token is accepted only because `config/collectors/github.yaml` sets
`allow_broad_token: true`; the collector then reports **degraded** on every cycle
("broad OAuth/classic token") until a fine-grained PAT replaces it (remove the flag then).

## 2. Start everything

```bash
make up-full                  # clickhouse, migrate, ingest(8443), writer, detector,
                              # ai-worker (Jev ON, 300 calls/day cap), api(8000),
                              # console(3000), grafana(3001)
make up-debug                 # loopback-only ClickHouse proxy 127.0.0.1:18123 (for the checks below)
make vm-up                    # Ubuntu VM: SSH 127.0.0.1:2222, HTTP 127.0.0.1:8088
make kind-up                  # kind cluster extorq-lab (audit logging, PSA namespaces, OTel)
make collectors-start         # macOS, Linux, Kubernetes-inventory and GitHub collectors (background)
make collectors-status        # every collector: outbox=0, status ok (github: degraded, see above)
```

> After **any** code update, run `make collectors-stop && make collectors-start`. A runner
> started before an upgrade keeps old code in memory (see Troubleshooting: HTTP 422).

## 3. Verify the four assets and their telemetry

A collector reporting healthy is not proof of telemetry, so check the stored events.
Fresh `last10m` counts must appear for sources that emit continuously (k8s audit and container
logs, Linux journald, macOS unified log). Inventory, nginx, web-app and GitHub events are
emitted on change, so they can legitimately be quiet.

```bash
q() { curl -s -H "X-ClickHouse-User: extorq_api_ro" \
      -H "X-ClickHouse-Key: $(cat var/secrets/clickhouse/extorq_api_ro_password)" \
      --data-binary "$1" http://127.0.0.1:18123/; }

q "SELECT asset_id, source_type, uniqExact(event_id) total,
          countIf(ingested_time > now() - INTERVAL 10 MINUTE) last10m,
          dateDiff('second', max(ingested_time), now()) secs_since_last
   FROM extorq.events GROUP BY asset_id, source_type ORDER BY 1,2 FORMAT PrettyCompactMonoBlock"

q "SELECT asset_id, asset_type FROM extorq.v_assets ORDER BY 1 FORMAT TSV"   # expect 6 assets
q "SELECT collector_id, status, last_success_at FROM extorq.v_collector_latest FORMAT PrettyCompactMonoBlock"
```

Reachability spot checks:

```bash
make vm-status                 # VM running, SSH reachable
infra/kind/kind.sh status      # cluster and nodes ready
curl -s --cacert var/tls/ca.crt https://127.0.0.1:8443/healthz     # {"status":"ok"}
make demo-check                # read-only readiness report across stack, telemetry, rules, tests
```

Jev: `docker logs extorq-ai-worker-1 | tail` shows `ai_worker_starting` with
`jev_enabled: true`, then `jev_triage_complete` for each new alert's context (advisory only).

## 4. Run the detection tests

Each test performs a **real** action on an asset, waits for the detector to raise an alert for
the expected rule on the expected asset inside the test window, and runs a negative control that
must **not** alert. Verification is by asset + rule + time window + evidence resolution; nothing
is marked inside the telemetry.

```bash
make fast-on                   # TEST PROFILE: collectors poll every 10-15 s, rules run every 10 s
make test-detections           # ALL assets at once: every test concurrent, each negative-first
make test-detections-corr      # CORR-002 alone (needs 30 quiet minutes; run it BEFORE the batch)
make fast-off                  # back to the normal intervals when you are done
```

Per asset: `make test-detections-linux | -kubernetes | -github | -macos`. The old strict sequential
mode (one test at a time, 30+ minutes) is `make test-detections-slow`.

**Timing (what to expect).** With the fast profile an alert is found about 50-70 s after the
attack on Linux, Kubernetes and macOS and 80-100 s on GitHub (it polls an external API); the
whole concurrent run, including every negative control, takes about 6-10 minutes. Without
`make fast-on` collectors poll every 30-120 s and rules run every 60-120 s, so allow 3-5 minutes
per wave. A repeat run soon after another can wait for an earlier alert's episode to close
(K8S-003/K8S-004: 15 minutes) because new activity would otherwise be merged into the old alert.

Reports are written to `var/reports/detection-tests-<UTC>.md` and `.json` (mode 0600): per test the
action and window, rule version, alert IDs, the verified event IDs, producer and source, the
negative-control outcome and whether cleanup succeeded.

**Why each rule fires, and how to trigger each one by hand, step by step: [detection-tests.md](detection-tests.md)**
(23 tests; regenerate with `uv run python scripts/gen_detection_docs.py`).

Safety: Linux actions use the operator account over SSH and only touch `extorq-test-*` artefacts;
Kubernetes artefacts are `extorq-test-*` and deleted; GitHub changes happen only in
`Exigent07/extorq-lab` and are reverted by a new commit; macOS tests create unloaded
`com.extorq.test.*` plists, an unsigned dummy bundle and a short-lived listener, and send wrong
passwords to `sudo -S` (no privilege is ever obtained, no launch item is ever loaded).

## 5. Regression checks (no live assets needed)

```bash
make test                      # unit + security + rule harness
uv run extorq rules validate   # all rules load and validate
uv run extorq rules test       # every rule's positive/negative fixtures on a throwaway ClickHouse 26.8
make lint && make typecheck
```

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Collectors report `gateway HTTP 422: invalid batch envelope`, outboxes grow | A collector runner older than the schema-2.0 rollout. The gateway now upgrades legacy 1.x records (`contracts/compat.py`, counter `legacy_records_upgraded_total` in `/v1/status`), so nothing queued is lost; restart the runner (`make collectors-stop && make collectors-start`). |
| `github-repos` is `failed` with "requires a dedicated fine-grained GitHub PAT" | The token file holds a broad token but `allow_broad_token` is not set, or the file is missing. See section 1. |
| `github-repos` is `degraded` | Expected with the broad interim token, plus free-plan gaps (branch protection, rulesets, code scanning return 403). They are reported, not hidden. |
| `ai-worker` shows `jev_enabled: false` or key `missing` | Run `make jev-key`, then `docker compose --profile full up -d --no-deps ai-worker`. |
| A detection test times out | Check `uv run extorq-collect status` (outbox=0?) and `docker logs extorq-detector-1`; the bound in the report shows which stage is slow. |
| Leftovers after an interrupted run | `ls ~/Library/LaunchAgents \| grep extorq.test`; `kubectl --context kind-extorq-lab get pods,clusterrolebindings -A \| grep extorq-test`; on the VM `ls /etc/systemd/system /etc/cron.d \| grep extorq-test`; in the repo `gh api repos/Exigent07/extorq-lab/commits --jq '.[].commit.message'`. |

## 7. Results of the reference run (2026-11-22/23, clean database)

The database was cleared first (`make reset-data`, after a verified recovery bundle and pausing the
OTel collector), then re-baselined: 6 assets, 85 services, all four collectors healthy.

| Run | Command | Result | Wall clock |
|---|---|---|---|
| Pure run, full (negative controls included) | `make test-detections` | **22 / 22 passed**, every negative control silent, every cleanup verified | 5 min 12 s |
| One wave, every positive at once | `make test-detections-instant` | **22 / 22 passed** | **1 min 58 s** |

Time from the attack to the alert being found: median **40-60 s**, 17 of 22 within 60 s; Linux,
Kubernetes and macOS 40-70 s, GitHub 80-110 s (it polls an external API). Reports:
`var/reports/detection-tests-20261122T224158Z.*` (pure run) and `...T224722Z.*` (one wave).

Notes for reading the numbers honestly:

* Instant mode skips the negative controls (they need their own quiet window); they are proven by
  the full run. Run it right after another run and some rules are still inside their open episode,
  so the new activity *extends* the earlier alert; a positive is accepted only when that alert's
  **evidence contains this run's own events**, never merely because an alert exists.
* CORR-002 (the multi-stage correlation) is not part of the concurrent runs: it needs 30 minutes
  without HTTP probing, so it is run separately with `make test-detections-corr`. It was not
  executed in this reference run (rule logic is covered by the ClickHouse rule harness).
* The macOS unit test `test_shipped_config_loads_through_the_sdk` asserts the shipped 60 s
  intervals and fails while `make fast-on` is active; run `make fast-off` first.
* GitHub shows **ok** with the warning "broad token accepted by allow_broad_token" in its health
  details. Free-plan limits (branch protection, rulesets, security_and_analysis) are listed as gaps
  but do not degrade it.
* Jev AI triage is on by default. The 300/day cap was reduced to the remaining 172 for the rest of
  that UTC day because clearing `ai_assessments` also clears the usage counter (128 calls had been
  made); restore the default with `docker compose --profile full up -d --no-deps ai-worker`.

# Demo Runbook (15 minutes)

Owner: agent F. Status: **final** for the technical demonstration to a Security
Engineer on Monday 2026-11-23 (written in build session 3, 2026-11-22). Every
outcome quoted here comes from a recorded run (run id, alert id, command) in
`docs/team/status/<agent>.md` or from a read-only query of the live stack on
2026-11-22 between 01:40 and 02:05 IST; nothing is an expectation presented as
a result. Items marked **(verify)** have not been exercised end to end and must
be checked during pre-flight.

## 0. Ground rules

* Only genuine telemetry. If a live step does not produce its alert in time,
  say so and open the alert of the earlier verified run (section 1) with its
  run id and timestamp visible. Never show fixtures as live data.
* Never display secrets: no `cat` of anything under `var/` or `.env`. Log in by
  copying a password file to the clipboard (`pbcopy < var/secrets/analyst_password`),
  pasting, then clearing it (`pbcopy < /dev/null`).
* Confidence describes evidence completeness, not maliciousness; AI output is
  advisory. Correlation shows co-occurrence, never causation.
* Lab assets only. Never touch the `motorq-security` kind cluster.
* Times: ClickHouse and the console show UTC; IST = UTC + 5:30.

## 1. Verified reference runs (the safety net)

All on genuine telemetry, 2026-11-21 (UTC). Alert ids open directly in the
console at `http://127.0.0.1:3000/investigations/<alert_id>`.

| Scenario | Run id | Genuine telemetry (source) | Alert id | Severity / confidence | Recorded by |
|---|---|---|---|---|---|
| VM-001 SSH failure burst | `bace7dc4a3d2` | `linux.journald`: invalid_user 9, preauth_closed 8, max_auth_exceeded 2, all from `10.0.2.2` | `7763c537f998a058fb4ca13926dec7da` | medium / **medium** (9 connections; `src_ip_shared_nat: true`), 19 evidence events | B1, C2 |
| VM-002 systemd persistence | `b7a712bc786d` | `linux.inventory` unit_created + unit_enabled, `linux.auditd` `file.audit.watch` key `extorq_systemd` (writer `/usr/bin/dash`), sudo by `extorq-admin` | `5ac7d8f5a069eabf1f0468397d9327a9` | high / **high** (`audit_corroborated: true`, `ExecStart /bin/true`) | B1, C2 |
| K8S-001 privileged Pod denied | `bcfcb726ff01` | `k8s.audit`: create pods -> 403, `violates PodSecurity "baseline:latest": host namespaces (hostPID=true), privileged`, risk flags `host_pid`, `privileged` | `cfbff55664cf6d62121a96e4cbe6692a` | medium / **high** | B2, C2 |
| K8S-002 risky RBAC | `c9c96ff29f33` | `k8s.audit` create clusterrolebindings -> 201 (role_ref `ClusterRole/cluster-admin`, subject `ServiceAccount:extorq-apps/extorq-sim-c9c96ff29f33`) **and** `k8s.api_inventory` `k8s.resource.created`; objects deleted by the script | `afc76864b4200260d47959111b0fdf01` | high / **high** (sources audit + state) | B2, C2 |
| GH-001 workflow escalation | `8dwz3wf6zji4` | `github.api` `github.workflow.modified`: commit `bf4026a59b31139d3533401d8d79009cf2c77f30` changed `.github/workflows/ci.yml` from `contents:read` to `write-all` (14 write scopes) and added `pull_request_target` with an untrusted checkout, in the private lab repository `Exigent07/extorq-lab`; the baseline and cleanup commits produced **no** alert | `e70639259d3044a6da955d9bc79e48cd` | high / **high** | lead |
| HTTP-001 web probing | `8c8e999442ed` | `linux.nginx` 11 `http.request` (`/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin/`, `/server-status`, `/admin`) | `469374702a500e83756c08a1bf3054ce` | low / medium (NAT) | B1, C2 |
| APP-001 failed app logins | `8c8e999442ed` | `linux.app` 5 `app.auth.login_failed` for `lab-admin`, 1 `app.authz.denied` | `a94ee8dd2ab946a71245f2b43caeb4b8` | medium / medium | B1, C2 |
| MAC-001 LaunchAgent (extra) | `51ff258a3b7d` | `macos.launchd` `persistence.launchd.item_created` (never loaded; cleaned up) | `fe5a072442b438711726ed51a5597bfd` | medium / high | B3, C2 |
| CORR-002 ordered sequence | B1's runs above | probing (23 client errors, 6 probe routes) -> SSH failures (21 connections) -> systemd change, all from `10.0.2.2`; `causation_established: false`, `same_non_nat_source_ip: false` | `b46da3805d1c6f17b6c1ed363b49a777` | high / **low**, 73 evidence events across nginx, journald, auditd, inventory | C2 |
| Late data | `c7cbc976ecaf` | VM-001 burst ingested about 26 minutes after event time (collector backfill) | `76fec91ab730250b5e7d12cdffb071d5` | medium / medium; created by the detector's late-data catch-up, no duplicate alerts | C2 |

Also present in the Detections list (genuine, not simulation-tagged): K8S-001
and K8S-002 alerts from 2026-11-21 10:16-10:18 UTC (B2's session-1 tests and
kubeadm's bootstrap bindings, audit only, confidence medium for K8S-002: a
documented false-positive class), and an APP-001 on `k8s:extorq-lab`. Say so if
asked; they are real detections of real lab activity.

AI records (read from `ai_assessments` as `extorq_api_ro` on 2026-11-22 ~02:07
IST; calls made by E in build session 3 after fixing the projection, which had
dropped the evidence key fields of real contexts):

* Jev (`jev-1.14.0`, question set `triage-v2`): 17 real alerts triaged at
  2026-11-21 20:32 UTC, all `ok`, 284-461 ms each. Examples: VM-002
  `5ac7d8f5...` and VM-001 `7763c537...` `priority_investigation`, not
  uncertain; GH-001 `e7063925...` `priority_investigation`, not uncertain;
  K8S-002 `afc76864...` `priority_investigation`, uncertain; K8S-001
  `cfbff556...` and CORR-002 `b46da380...` `routine_review`, uncertain.
* Gemini (`gemini-3.6-flash`, prompt `summary-v3`): the first summaries of real
  lab alerts, GH-001 `e70639259d3044a6da955d9bc79e48cd` (22.9 s; 17 evidence
  ids cited, 17 verified, 0 rejected, 0 statements without evidence) and
  CORR-002 `b46da3805d1c6f17b6c1ed363b49a777` (25.9 s; 64 cited, 64 verified,
  0 rejected). Earlier Gemini runs were on synthetic contexts only.

## 2. Pre-flight checklist

Run from the repository root. Targets are in the `Makefile` (`make help`); A added
`make up-demo` and `make collectors-start|stop|status` in build session 3
(checked with `make -n` on 2026-11-22).

### 2.1 T-60 minutes: bring everything up

| # | Step | Command | Pass criterion |
|---|---|---|---|
| 1 | Decide on live AI (operator) | AI on: `make up-demo` (sets `EXTORQ_JEV_ENABLED=true` and `EXTORQ_GEMINI_ENABLED=true`: live, budgeted calls); AI off: `make up-full` | decision made; the keys stay in `.env` (never opened); `make up-full` switches AI off again |
| 2 | Platform stack incl. console and Grafana | `make up-demo` or `make up-full` (both wait up to 600 s for health) | `make ps`: clickhouse, ingest, writer, api, frontend, grafana healthy; detector and ai-worker running (all of them were up on 2026-11-22 02:01 IST) |
| 3 | Ubuntu VM | `make vm-up`, then `make vm-status` | running; SSH 127.0.0.1:2222 and HTTP 127.0.0.1:8088 answer |
| 4 | kind cluster | `make kind-up`, `make kind-status`, `infra/kind/kind.sh netcheck` | audit log active; `GET /healthz -> HTTP 200 (TLS verified with ExtorQ CA)` |
| 5 | Fresh inventory token (24 h lifetime) | `infra/kind/kind.sh token` | the token minted 2026-11-21 20:11 IST expires 2026-11-22 20:11 IST; without a fresh one the `k8s-inventory` collector fails with 401 and K8S-002 drops to audit-only (medium) |
| 6 | Host collectors in the background | `make collectors-start` (after a token renewal while it runs: `make collectors-stop && make collectors-start`) | `collectors started (pid ...)`; one runner for `macos-workstation-01`, `linux-ssh-lab-vm-01`, `k8s-inventory`, `github-repos`; log `var/log/collectors.log`. It refuses to start while another `extorq-collect run` is active. Start it early: the first cycles drain any backlog |
| 7 | Collector state | `make collectors-status` | `collectors runner: running`; every collector `status=ok`, `outbox=0`, `dead=0` |
| 8 | Readiness report | `make demo-check` | `DEMO READY: all checks passed` (services, gateway, API, console, Grafana datasource, migrations, the five mandatory scenarios with stored evidence, fresh host collectors, rules run in the last 15 min). Works without the debug proxy (queries run inside the `api` container); prints a WARN while the proxy is up |
| 9 | Security evidence for minute 12:45 | `make test-security`; then `make up-debug`, `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` | 296 passed, 32 deselected (2026-11-22 01:48 IST); live RBAC 32 passed (01:49 IST) |
| 10 | Debug proxy off (F-01) | `docker compose --profile debug stop clickhouse-debug` | `make ps` shows no `clickhouse-debug`; `make demo-check` shows no proxy WARN |
| 11 | Console smoke **(verify)** | `cd frontend && EXTORQ_SMOKE_ANALYST_PASSWORD_FILE=../var/secrets/analyst_password EXTORQ_SMOKE_VIEWER_PASSWORD_FILE=../var/secrets/viewer_password node scripts/smoke.mjs --base http://127.0.0.1:3000; cd ..` | 0 failed. On 2026-11-22 02:01 IST against the compose console: 98 passed, 5 failed; all 5 failing checks (Kubernetes node "workloads on node" view, detections rule and asset filters) were new in D2's in-progress script and the running image predated D2's latest changes: re-run after the final rebuild. Run it once only: it loads about 100 pages |
| 12 | AI services **(verify, only if enabled)** | `docker compose logs --tail 20 ai-worker` and the console Health page | worker cycles `ok`; Jev and Gemini shown enabled. Enabling Jev triages every stored context younger than 72 h without a current Jev result (6 of 23 alerts had none on 2026-11-22: APP-001, HTTP-001, MAC-001), at most 10 per 30 s cycle, daily cap 300 |
| 13 | Host hygiene | `stat -f '%Sp' .env` | `-rw-------`. It was `-rw-r--r--` on 2026-11-22 (F-09); `chmod 600 .env` is the operator's decision |
| 14 | Browser tabs | console `http://127.0.0.1:3000` as `analyst`; Grafana `http://127.0.0.1:3001` as `admin` (`var/secrets/grafana_admin_password`) | tabs: console Overview, Detections, Health; Grafana dashboards Security Overview, Linux Investigation, Kubernetes Investigation, GitHub Investigation, Collector & Pipeline Health; Grafana Explore with data source "ExtorQ ClickHouse" |
| 15 | Terminals | T1 Linux simulations, T2 Kubernetes simulations, T3 operations (collectors stop/start, curl checks); all in the repository root | large font, notifications off, commands of section 3 pre-typed |

### 2.2 T-10 minutes: go / no-go

* `make demo-check` once more: `DEMO READY`, no proxy WARN.
* Console Health: the four host collectors fresh, detector rule runs within the
  last two minutes, no unexpected quarantine spike.
* Do not run `make demo-check`, the smoke script or test suites while presenting:
  the API's ClickHouse identity has a quota of 1200 queries per minute, and on
  2026-11-22 ~02:01 IST it was exceeded (1374/1200) right after two consecutive
  smoke runs, so the API answered 503 until the minute ended.
* No-go handling: a stale collector means the runner is down
  (`make collectors-status`, then `make collectors-start`); a dead VM or cluster
  is not rebuilt in front of the audience (fallback table, section 4).

### 2.3 Expected latency

Not measured end to end. Components: Linux collector every 30 s (inventory diff
every 60 s), Kubernetes inventory every 60 s, OTel batching for audit and
container logs, GitHub polling every 120 s, rules every 60 s (CORR-002 and
GH-001 every 120 s). Plan for alerts 1 to 4 minutes after a simulation and start
every simulation in the first minute.

## 3. Minute-by-minute script

| Time | Segment | Do | Show | Expect |
|---|---|---|---|---|
| 0:00-0:30 | Kick-off | T1: Linux sequence; T2: Kubernetes (commands below) | the run ids the scripts print | scripts finish; K8S-002 keeps T2 busy for up to 240 s while it waits for evidence |
| 0:30-2:00 | Architecture | | `README.md` diagram or `docs/architecture.md` section 2 | narrative below |
| 2:00-3:30 | Live telemetry, four assets | | console Overview and Assets; Grafana Security Overview | four asset classes reporting; services with explicit coverage |
| 3:30-5:00 | VM-001 (+ HTTP-001, APP-001) | | console Detections -> new VM-001 -> Investigation; Grafana Linux Investigation | VM-001 confidence medium (shared NAT) |
| 5:00-6:15 | VM-002 | | Investigation of the new VM-002; Assets -> `linux:lab-vm-01` -> Services | VM-002 confidence high (auditd + inventory) |
| 6:15-7:45 | K8S-001, K8S-002 | read T2's output | Investigations; Grafana Kubernetes Investigation | K8S-001 high confidence; K8S-002 high with audit + state |
| 7:45-8:45 | GH-001 | T3: `make collectors-stop` (starts the outage for 11:30) | verified GH-001 alert; Grafana GitHub Investigation | alert from run `8dwz3wf6zji4` |
| 8:45-10:00 | Correlation | | new CORR-002 Investigation (or `b46da380...`) | confidence low: NAT, not causation |
| 10:00-11:30 | AI | optional "Generate overview" | Jev and Gemini panels | advisory only; ids verified |
| 11:30-12:45 | Failure handling | T3: `make collectors-start` at about 12:30 | console Health (stale), Grafana Collector & Pipeline Health | host collectors stale, Kubernetes logs still flowing, then fresh again |
| 12:45-14:00 | Security boundaries | live denials (commands below) | `make ps`, curl 401, Grafana Explore denial, RBAC probe output | every denial observed |
| 14:00-15:00 | Limitations and close | | `docs/known-limitations.md` | honest list |

### 0:00-0:30 Kick-off (start everything with latency first)

T1 (Linux: HTTP-001, APP-001, VM-001, VM-002 and, in this order, CORR-002):

```bash
make sim-http && make sim-vm-001 && make sim-vm-002
```

Each script prints its run id in its first `==> run <id>: ...` line (Kubernetes:
`==> K8S-00x run <id>: ...`); write down every run id for cleanup. Running the three in this order within 30 minutes is what CORR-002
looks for (HTTP probing, then SSH failures, then a systemd change on one host).

T2 (Kubernetes):

```bash
make sim-k8s-001 ARGS="--no-wait" && make sim-k8s-002
```

`sim-k8s-001` prints kubectl's genuine admission error, for example
`Forbidden: violates PodSecurity "baseline:latest": host namespaces (hostPID=true), privileged`;
no Pod is created. `sim-k8s-002` creates ServiceAccount
`extorq-apps/extorq-sim-<id>` and ClusterRoleBinding `extorq-sim-<id>` to
`cluster-admin`, waits until audit **and** inventory evidence are in ClickHouse,
then always deletes both and verifies they are gone.

### 0:30-2:00 Architecture

* Four asset classes and how each is collected: native macOS collector (operator
  user, no Full Disk Access); agentless SSH pull from the VM through a
  forced-command, read-only dispatcher; OTel DaemonSet (API audit and container
  logs) plus a read-only inventory collector for kind; GitHub REST polling.
* Ingest gateway on `127.0.0.1:8443`: TLS with a local CA, one bearer token per
  producer, per-record authorisation (kind, asset, source type), contract
  validation, secret redaction, quarantine, and a durable SQLite spool committed
  **before** `202`. Writer -> ClickHouse (at-least-once, deterministic ids,
  `ReplacingMergeTree`).
* Versioned SQL rules run by the detector as a read-only identity; alerts are
  written only by the detector; every alert gets a hashed InvestigationContext.
* AI is optional and advisory: Jev triage and Gemini summaries write only
  `ai_assessments`.
* Services: every host and node is broken into services and instances with
  explicit coverage; what ExtorQ cannot monitor is shown as unmonitored.

### 2:00-3:30 Live telemetry from four assets

* Console **Overview**: coverage lanes for the macOS host, the VM, the cluster and
  the GitHub repository with last-seen times; service coverage bar; collection
  health.
* **Assets -> `linux:lab-vm-01` -> Services**: ssh, nginx, lab-portal, systemd and
  auditd implemented and monitored; a DNS service with a **planned** adapter;
  services without an adapter listed as unsupported (on 2026-11-22: 5 monitored,
  1 planned, 16 without adapter). Port attribution is `confirmed` only with an
  observed socket owner (kernel cgroup of the socket), else `inferred` or
  `unknown`.
* **Assets -> `k8s:extorq-lab`**: node asset, workloads versus Kubernetes Service
  objects (never confused with host services), Pods and containers with Pod UID
  and container id.
* **Assets -> `macos:workstation-01`**: sshd and Screen Sharing adapters
  implemented but **unmonitored** because Remote Login and Screen Sharing are
  off; Homebrew Redis and MySQL shown with **planned** adapters.
* Grafana **Security Overview** -> "Event volume by source type": every source
  type with recent data. ClickHouse view (Grafana Explore, "ExtorQ ClickHouse",
  read-only `extorq_grafana`):

  ```sql
  SELECT asset_id, source_type, uniqExact(event_id) AS events, max(event_time) AS newest
  FROM extorq.events
  WHERE event_time > now() - INTERVAL 1 HOUR
  GROUP BY asset_id, source_type ORDER BY asset_id, source_type
  ```

### ClickHouse queries for any scenario (Grafana Explore)

Run as the read-only `extorq_grafana` identity through Grafana Explore (data
source "ExtorQ ClickHouse"); no debug proxy needed. These three queries and the
asset query of minute 2:00 were executed as `extorq_grafana` on 2026-11-22
~01:52 IST with run id `bace7dc4a3d2` (3 and 2 rows; the last one is refused,
as intended).

```sql
-- genuine telemetry of one run, per source and authenticated producer
SELECT source_type, event_type, producer_id, uniqExact(event_id) AS events
FROM extorq.events WHERE simulation_run_id = '<run_id>'
GROUP BY source_type, event_type, producer_id ORDER BY source_type, event_type;

-- alerts that carry the run id
SELECT rule_id, alert_id, severity, confidence, event_count
FROM extorq.v_alerts WHERE has(simulation_run_ids, '<run_id>');

-- column-level least privilege: refused for extorq_grafana
SELECT raw FROM extorq.events LIMIT 1;
```

### 3:30-5:00 VM-001 (with HTTP-001 and APP-001)

* Console **Detections** -> newest VM-001 (simulation badge with the run id) ->
  **Investigation**.
* Evidence: sshd lines for the non-existent user `extorq-sim-<run_id>`
  (`auth.ssh.invalid_user`, `preauth_closed`, `max_auth_exceeded`) from
  `10.0.2.2`, each from a different source port; lines are attributed to the ssh
  service only when journald's `_SYSTEMD_UNIT`/`_EXE` match.
* Point: confidence is **medium** because `10.0.2.2` is QEMU's NAT gateway: the
  burst is real, its origin is not attributable (feature `src_ip_shared_nat`).
  Reference: alert `7763c537...` (9 connections, 19 evidence events).
* HTTP-001 and APP-001 from the same probe: 11 nginx requests to probe-like
  routes (no query strings stored) and 5 failed logins for `lab-admin`;
  the app events link to the nginx lines through the propagated request id
  (DIRECT relationship).
* Grafana **Linux Investigation**: "SSH authentication failures by source IP",
  "Route probing: routes with client errors".

### 5:00-6:15 VM-002

* Investigation of the newest VM-002: unit
  `/etc/systemd/system/extorq-sim-<run_id>.service`, `ExecStart /bin/true`,
  sha256, `unit_created` and `unit_enabled` from the inventory diff, the auditd
  `file.audit.watch` (key `extorq_systemd`) on the same path, `sudo` by
  `extorq-admin`. Confidence **high** because two independent sources agree
  (`audit_corroborated: true`). Reference: alert `5ac7d8f5...`.
* **Services** view of the VM: the new unit appears as a discovered host service
  without an adapter (shown, not hidden).
* Grafana **Linux Investigation** -> "systemd persistence changes".

### 6:15-7:45 K8S-001 and K8S-002

* T2 output: the genuine `Forbidden ... violates PodSecurity "baseline:latest"`
  message. Namespace `extorq-restricted` enforces Pod Security **baseline**
  (F-11: say baseline, not restricted).
* K8S-001 Investigation: `k8s.api.request` create pods -> 403,
  `pod_security_violation`, risk flags `host_pid`, `privileged`, user
  `kubernetes-admin`, audit id; severity medium, confidence **high** (risk flags
  and violation text agree). Reference: `cfbff556...`.
* K8S-002 Investigation: audit (create clusterrolebindings -> 201, role_ref
  `ClusterRole/cluster-admin`) and inventory state (`k8s.resource.created`, risk
  flag `cluster_admin`) agree -> confidence **high**; T2 shows the objects were
  deleted and verified gone. Reference: `afc76864...`.
* Grafana **Kubernetes Investigation**: "Denied requests (403) by user",
  "RBAC changes".

### 7:45-8:45 GH-001 (and start the collector outage)

* First, if the VM-002 and CORR-002 alerts are already visible, T3:
  `make collectors-stop` (the background runner finishes its current cycle,
  commits and exits). If they are not visible yet, skip the live outage and tell
  only the recorded story at 11:30.
* GH-001 runs against the private lab repository and pushes a commit, so it is
  **not** re-run live by default: open the verified alert
  `e70639259d3044a6da955d9bc79e48cd` (run `8dwz3wf6zji4`, executed by the lead
  with the user's approval on 2026-11-21 19:59 UTC). Evidence: commit `bf4026a`
  changed `.github/workflows/ci.yml` from `contents:read` to `write-all` (14 write
  scopes), added `pull_request_target` with a checkout of the PR head; confidence
  high because both versions parsed and effective permissions are known. The
  baseline commit and the cleanup commit of the same run produced no alert
  (negative evidence).
* Grafana **GitHub Investigation** -> "Workflow modifications and permission
  deltas".
* Offline analyser, if asked: `make sim-gh-001 ARGS="--repo Exigent07/extorq-lab --dry-run"`
  (throwaway local repository, no network). A fresh live run
  (`make sim-gh-001 ARGS="--repo Exigent07/extorq-lab --execute"`) pushes to
  GitHub and needs the operator's explicit decision on the day.
* Honest gaps visible in the GitHub collector's health (2026-11-21 20:02 UTC):
  branch protection, branch rules and rulesets answer `HTTP 403: Upgrade to
  GitHub Pro or make this repository public`; code scanning is not enabled and
  secret scanning is disabled (`github-security-alerts` scan coverage); the token
  source is the gh CLI with a warning that its scopes (`repo`, `workflow`) are far
  broader than read-only.

### 8:45-10:00 Correlation: CORR-002 and NAT uncertainty

* Detections -> newest CORR-002 (or reference `b46da3805d1c6f17b6c1ed363b49a777`).
  Summary states the ordered sequence on `linux:lab-vm-01`: HTTP probing, then
  SSH failures, then a systemd change, within the 30-minute window.
* Confidence **low**: all three stages came from `10.0.2.2`;
  `same_source_ip: true` but `same_non_nat_source_ip: false`, and
  `causation_established: false` always. The verified reference even contains
  the lab operator's own failed key attempts in the SSH stage, which is exactly
  why a NAT address is never treated as an identity.
* Investigation timeline: relationship types **DIRECT** (shared request id, same
  unit path), **CANDIDATE** (non-NAT source IP, principal, simulation marker) and
  **UNESTABLISHED** (NAT-only IP match, temporal proximity); the simulation marker
  never makes a link DIRECT.
* Involved services: nginx, ssh, systemd and auditd with their coverage.

### 10:00-11:30 AI: advisory triage and evidence-grounded summary

* Investigation of GH-001 `e70639259d3044a6da955d9bc79e48cd` -> **Jev
  contextual assessment** (Advisory): typed probabilities; ExtorQ turns them into
  a recommendation deterministically (`priority_investigation`, not uncertain).
  Contrast with CORR-002 `b46da380...`: Jev says `routine_review`, uncertain,
  which matches the rule's own low confidence (NAT, co-occurrence only). Jev
  cannot change severity, state or alerts: `extorq_ai` has no INSERT on
  `alerts` and no SELECT on `events` (verified live).
* If Jev is enabled, the new demo alerts get their own Jev assessment within a
  worker cycle (30 s) after their context is stored.
* **Gemini overview** on the same two Investigations (stored, no new call):
  GH-001 cites 17 evidence ids and CORR-002 64, every one verified against the
  alert's evidence bundle, 0 rejected. Chips mark ids verified (jump to the
  evidence row), verified but not shown on the page, or **unverified (possibly
  invented)**. Only if AI is enabled and the operator wants a live call: press
  **Generate overview** on a new demo alert (analyst role) and wait up to 90 s
  (observed 22.9 s and 25.9 s on real alerts); one call per click, cooldown
  120 s per alert, cap 50 per day.
* If AI is off or the provider fails: the panels show the state honestly
  (disabled, rate limited, timeout); the deterministic context is the evidence.

### 11:30-12:45 Failure handling

* Collector outage (live): console **Health** and Grafana **Collector & Pipeline
  Health** -> "Collectors: last success and staleness". A source is stale when
  its last success is older than 3 x its interval, so after about 3.5 minutes
  `linux-ssh-lab-vm-01` (30 s), `macos-workstation-01` and `k8s-inventory`
  (60 s) are **stale**, while `github-repos` (120 s, stale after 360 s) may still
  be fresh. Kubernetes audit and container logs keep arriving: the OTel
  DaemonSet does not depend on the host runner (Grafana Security Overview,
  "Event volume by source type"). "No alerts" is not "no activity": staleness,
  rules' `missing_sources` and gap events are first-class data.
* At about 12:30, T3: `make collectors-start`. Each collector resumes from its
  committed checkpoint (journald cursor and audit offset on the VM, unified log
  window on the Mac with at most 900 s per cycle, inventory snapshots, GitHub
  ETags and commit checkpoints); an outage longer than 24 h on the Mac becomes an
  explicit gap event. Health turns fresh within one cycle.
* Recorded restart evidence (do not repeat live): Linux collector stopped with
  SIGTERM and restarted: 5283 -> 5295 unique events = rows, 0 re-ingested ids,
  journald resumed after the checkpoint (B1); OTel collector Pod deleted during
  marker traffic: each marker exactly one row, 0 duplicates (B2).
* ClickHouse outage story (recorded by A on 2026-11-21 with
  `uv run pytest -q -m failure tests/failure -s`; never run live, it stops shared
  services): ClickHouse stopped for 9.1 s while the gateway kept answering `202`
  from the spool, 100/100 buffered events delivered after the restart; `ingest`
  and `writer` restarted during a paced 800-record collector stream: 800/800
  delivered, 800 rows, 2 transient connection errors retried by the SDK. Scanner
  outbox: with the gateway unreachable 4 records stayed buffered and
  `extorq-scan flush` delivered them (C3).
* Late data: VM-001 run `c7cbc976ecaf` arrived 26 minutes late and was still
  alerted by the detector's catch-up without duplicating alerts (`76fec91a...`).
* Grafana panels: "Pipeline queue depth", "Oldest queued record age".

### 12:45-14:00 Security boundaries (live denials)

```bash
make ps                                                     # only 127.0.0.1 ports; ClickHouse publishes none
curl --cacert var/tls/ca.crt -s -o /dev/null -w '%{http_code}\n' \
  -X POST -H 'Content-Type: application/json' --data '{}' https://127.0.0.1:8443/v1/ingest   # 401 (no token)
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/v1/alerts                   # 401 (no service token)
```

Both denials observed on 2026-11-22 at about 01:44 IST (401 and 401); Grafana's
API answered 401 without a session.

* Grafana Explore as `extorq_grafana`: `SELECT raw FROM extorq.events LIMIT 1`
  is refused (column-level grant: no `raw`, `payload` or quarantine excerpts).
* Live RBAC probe output from pre-flight (32 passed): `default` user refused,
  `extorq_ai` and `extorq_api_writer` cannot INSERT alerts, `extorq_rules_ro`
  cannot read alerts or `system.users`, change settings or call `url()`.
* Gateway: per-producer tokens and per-record authorisation (403 + `ingest_audit`),
  forged service identities quarantined (`identity_mismatch`, F-19), secrets
  redacted before the spool. Grafana Collector & Pipeline Health -> "Ingest
  authentication/authorization decisions", "Quarantine reasons".
* VM: the collector key is bound to a forced-command dispatcher; anything outside
  its allow-list prints `denied`, exits 77 and becomes a `dispatch.denied` event
  (recorded by B1). Kubernetes: read-only inventory RBAC without secrets or
  configmaps; audit policy keeps secrets at Metadata level.
* Console: HttpOnly `SameSite=Strict` session, CSP nonce, API token only on the
  server, telemetry rendered as text. Live check:
  `curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://127.0.0.1:3000/assets`
  answers `303 http://127.0.0.1:3000/login?next=%2Fassets`, and `/login` sends a
  nonce-based `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and `nosniff` (observed 2026-11-22 ~02:05 IST).
* `make test-security`: 296 passed, 32 deselected (2026-11-22 01:48 IST).

### 14:00-15:00 Limitations and close

From [known-limitations.md](known-limitations.md): QEMU NAT hides origins
(`10.0.2.2`); agentless pull adds latency; no EDR or Endpoint Security telemetry
on macOS; GitHub polling, free-plan gaps on the private repository and the broad
gh CLI token; FTP, PostgreSQL, MySQL, DNS and Redis adapters are planned only;
Gemini quota and latency; Jev evaluated on 27 synthetic cases only;
at-least-once delivery on one laptop. Close on the principle: deterministic
evidence first, AI advisory, unknown stays unknown.

## 4. Fallbacks

| Problem | Fallback |
|---|---|
| A new alert has not appeared in time | keep talking over its raw events (Grafana Explore by `simulation_run_id`), then open the reference alert from section 1 with its run id and timestamp |
| Console down | Grafana dashboards and Explore show the same ClickHouse data read-only; do not call the API by hand on screen (it needs the service token) |
| VM down | `make vm-status`; do not rebuild live; show the VM reference alerts and point at the stale source on the Health page (that is the point of honest health) |
| kind down or OTel not delivering | `infra/kind/kind.sh status`; show K8S reference alerts `cfbff556...`, `afc76864...` |
| K8S-002 only medium | the inventory collector is not delivering (token expired: `infra/kind/kind.sh token`, then `make collectors-stop && make collectors-start`); audit-only evidence is correctly rated medium |
| Detections filters misbehave | open investigations by alert id (`/investigations/<alert_id>`, section 1); D2's smoke flagged the rule and asset filters on 2026-11-22 02:01 IST (new checks, image older than D2's latest changes) |
| API answers 503 | the `extorq_api_ro` per-minute query quota is exhausted (seen once after two smoke runs): wait one minute; stop any test or smoke run |
| GitHub collector failing | show GH-001 reference alert; `make collectors-status` and the health warning explain why |
| AI disabled, rate limited or slow | say so; show the stored Jev and Gemini assessments of GH-001 `e7063925...` and CORR-002 `b46da380...`; the deterministic context is the evidence |
| Stack component unhealthy | `make demo-check` names it; do not restart ClickHouse during the demo; tell the outage story from section 3 |

## 5. Cleanup (right after the demo)

```bash
make sim-cleanup SCENARIO=vm-002 RUN_ID=<vm-002 run id>     # disables and removes the unit, daemon-reload
make sim-cleanup SCENARIO=vm-001 RUN_ID=<vm-001 run id>     # nothing persistent; records cleaned_up
make sim-http ARGS="--cleanup --run-id <http run id>"       # nothing persistent; records cleaned_up
make sim-cleanup SCENARIO=k8s-001 RUN_ID=<k8s-001 run id>   # double-checks that no Pod exists
make sim-cleanup SCENARIO=k8s-002 RUN_ID=<k8s-002 run id>   # objects are already deleted; verifies
```

* GH-001, only if executed again: `make sim-gh-001 ARGS="--repo Exigent07/extorq-lab --cleanup --run-id <id>"`
  (`make sim-cleanup SCENARIO=gh-001` does not pass `--repo` and fails).
* MAC-001, only if run: `make sim-cleanup SCENARIO=mac-001 RUN_ID=<id>`.
* AI back to off: `make up-full` without the flags (recreates `ai-worker` and
  `api` with the defaults).
* Debug proxy off; collectors may keep running (`make collectors-stop` to stop
  them).
* Never `docker compose down -v` (deletes collected data) and never destroy the
  VM or the cluster without the operator's explicit decision.

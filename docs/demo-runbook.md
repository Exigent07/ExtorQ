# Demo Runbook (15 minutes): DRAFT

Owner: agent F. Status: **draft outline**, to be finalised after the
integration phase when every scenario has been verified end to end
([testing.md section 4](testing.md#4-scenario-verification-planned)). Items
marked *(verify)* must be checked on the demo machine before the demo.

Ground rules for the demo:
* Only genuine telemetry from scenario runs. No fixtures or screenshots shown as
  live data. If something does not work live, say so and show the result of an
  earlier real run with its timestamp and run id.
* Never display secrets: do not `cat` anything under `var/` or `.env`; log in to
  the console by pasting from the password file without showing it.
* AI output is labelled advisory; the deterministic evidence is the story.

## 1. Setup checklist (T-60 to T-10 minutes)

| # | Check | Command or place |
|---|---|---|
| 0 | Readiness report | `make demo-check` *(verify the script exists)* |
| 1 | Core and full stack healthy | `make ps` |
| 2 | Debug proxy **off** | `docker compose ps clickhouse-debug` shows nothing running |
| 3 | VM up, SSH and HTTP reachable | `infra/vm/vm.sh status` |
| 4 | kind cluster up, OTel can reach the gateway | `infra/kind/kind.sh status`, `infra/kind/kind.sh netcheck` |
| 5 | Collectors running and fresh (no stale sources) | `uv run extorq-collect status`; console health view |
| 6 | Detector running; last rule runs succeeded | console health or `v_rule_latest_run` |
| 7 | AI flags decided (on with budget, or off) and keys present | operator decision; never show the keys |
| 8 | GitHub: read-only token file configured (CLI fallback stays off) | `config/collectors/github.yaml` |
| 9 | Browser: console logged in as `analyst`, Grafana logged in | `http://127.0.0.1:3000`, `http://127.0.0.1:3001` |
| 10 | Security tests green; live RBAC probe output ready to show | `make test-security`; `uv run pytest tests/security/test_security_clickhouse_rbac_live.py -m integration -q` (needs the debug proxy: run it before the demo, then stop the proxy) |
| 11 | Terminal with the simulation commands below; notifications off | |

Latency budget *(verify)*: collector interval about 60 s plus rule interval
60 s plus ingest delay. Start VM-001 and VM-002 early (minute 1) so their alerts
are ready when shown.

## 2. Scenario order and what to show

| Time | Segment | Commands | What to show |
|---|---|---|---|
| 0:00-1:30 | Architecture and trust boundaries | | `docs/architecture.md` diagram: four assets, gateway, spool, ClickHouse, detector, AI boundary; loopback-only; per-service identities |
| 1:30 | Start background scenarios | `make sim-http`, `make sim-vm-001`, `make sim-vm-002` (this order also exercises CORR-002) | run ids printed by the scripts |
| 1:30-4:00 | Assets -> Services drill-down | console Assets -> `linux:lab-vm-01` -> Services | ssh, nginx, lab portal, systemd with coverage (monitored, degraded); port attribution `inferred`/`unknown` for root listeners and why; planned adapters shown as unmonitored (for example a Homebrew Redis or MySQL launch agent on the Mac, if present *(verify)*) |
| 4:00-6:00 | VM-001 | (already running) | alert -> evidence: sshd failure lines from `10.0.2.2`, sender verified via journald fields, confidence medium because of the shared NAT address; `extorq-sim-<run_id>` marker |
| 6:00-7:30 | VM-002 | cleanup afterwards: `--cleanup --run-id <id>` | alert with inventory and auditd agreement (high confidence); unit path and hash |
| 7:30-9:30 | K8S-001, K8S-002 | `make sim-k8s-001`, `make sim-k8s-002` (scripts by B2 *(verify present)*) | privileged Pod denied by Pod Security Admission (audit 403, PSA violation); risky RBAC binding with audit and state agreement |
| 9:30-11:00 | GH-001 | executed earlier with the operator's approval, or `--dry-run` clearly labelled | workflow `write-all` / `pull_request_target` detected from genuine GitHub telemetry; posture findings for the lab repository |
| 11:00-13:00 | Investigation and correlation | console Investigation for the VM alerts | timeline across nginx, sshd and systemd with relationship types (direct, candidate, unestablished) and bases; CORR-002 (experimental) shows the ordered sequence and says it is not causation; AI summary if enabled, with verified and unverified evidence ids |
| 13:00-14:00 | Honest health | stop one collector (or show a stale source) | stale and gap states in the console; "no alerts" is not "no activity" |
| 14:00-15:00 | Security posture of ExtorQ itself | | live RBAC probe results, security test suite, known limitations |

## 3. Fallbacks

| Problem | Fallback |
|---|---|
| A simulation's alert has not appeared yet | wait one more cycle while showing the raw events; otherwise show the alert from the earlier verified run (timestamp and run id visible) |
| VM or kind unavailable | show earlier real alerts and say which asset is down; the health view shows it as stale, which is the point |
| AI provider unavailable or disabled | say so; the deterministic InvestigationContext is the evidence |
| GitHub push not approved | GH-001 `--dry-run` output (offline analyser on a throwaway local repository), labelled as dry run |
| Console problem | Grafana dashboards and the API (`/api/v1/alerts`) show the same data |

## 4. After the demo

* Run every simulation's cleanup (`--cleanup --run-id <id>`).
* Leave the stack running unless the operator decides otherwise; never delete
  volumes without explicit authorisation.

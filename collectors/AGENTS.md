# collectors/AGENTS.md — conventions for `extorq_collectors`

Scoped guide for the collectors package (canonical rules: `/AGENTS.md`; ownership:
`docs/team/PLAN.md` §2). Owner of this file: B1. Collector owners send their section
through `docs/team/interface-changes/<agent>.md`; B1 merges it here.

## Package layout

| Path | Owner | Purpose |
|---|---|---|
| `sdk/` | A | `Collector`, `CollectorContext` (atomic `emit`, `diff_snapshot`, `discard_staged`), `asset_upsert`, runner, sender, gateway client, state store |
| `cli.py` | A | `extorq-collect run [--only a,b] [--once]`, `status`, `flush`, `sim-record` |
| `services/` | B1 (lead interface) | shared service model plumbing: `ServiceCandidate`, `ServiceAdapter`, registry, `classify_coverage`, `build_service`, `exposure_of`, `service_ref`, planned adapters |
| `linux/` | B1 | agentless Linux collector (SSH dispatch boundary), Linux adapters |
| `macos/` | B3 | native macOS collector |
| `kubernetes/` | B2 | Kubernetes inventory/posture collector |
| `github/` | C1 | GitHub collector |

## Rules for every collector

1. **Contracts only.** Emit `extorq.contracts` models through `ctx.emit(records,
   checkpoints)`; never a parallel format. Unknown values stay `None`.
2. **Atomicity.** Checkpoints (cursors, offsets, snapshot state) advance only inside the
   `ctx.emit` that carries the records they cover. If a step fails after
   `ctx.diff_snapshot`, call `ctx.discard_staged()` before the next emit, otherwise a later
   emit would commit the snapshot without its diff events.
3. **Deterministic identities.** `identity.event_id(source_type, asset_id, native_key)` with
   the most stable source-native key (journald cursor, audit serial, commit SHA, k8s
   `uid:resourceVersion`, snapshot-diff `<key>:<change>:<content sha256>`); never collection
   time. Re-reads must produce the same ids.
4. **Baselines.** The first snapshot of a category is a baseline: no change events (or
   `attributes.baseline=true` where a rule needs it, see C2-IC-1).
5. **Untrusted input.** Every log line, path, user agent, user name, k8s field and commit
   message is attacker-controlled: validate, bound, `sanitize_untrusted`, `redact_text`
   (count into `provenance.redaction_count`); never into SQL, shell or prompts. Verify
   claimed identities with fields the attacker cannot set (journald `_UID/_EXE/_SYSTEMD_UNIT`,
   kernel cgroups, k8s authenticated user) and mark contradictions instead of trusting them.
6. **Subprocesses** only with argument lists, absolute executables, minimal environment,
   timeouts and bounded output. Network calls: timeouts + bounded jittered retries.
7. **No secrets** in YAML (`config/collectors/*.yaml` is checked by the SDK), logs, events,
   fixtures or errors. Tokens/keys are referenced by path (0600).
8. **Self-activity** is recorded but labelled (`labels['extorq.self']='true'`); simulation
   markers `extorq-sim-<run_id>` set `event.simulation` (telemetry stays genuine).
9. **Health is telemetry.** Put per-step results in `ctx.health_details`, lag via
   `ctx.report_lag`, cursors in `ctx.checkpoint_summary`; raise when a step failed so the
   runner reports it.
10. **Tests** with real captures under `tests/fixtures/<platform>/` (synthetic variations
    labelled as such); test modules named `test_<platform>_*.py` (no `__init__.py` in test
    dirs; helpers in `<platform>_testlib.py`).

## Service model (contract 1.1, PLAN §10) — shared interface `services/`

* A service needs discovery evidence (`ServiceCandidate.evidence` is never empty). Never
  assume a process is a network service; attribute a port only with `PortAttribution`
  (`confirmed` = observed socket owner, `inferred` = configuration / well-known port,
  `unknown`) and record the basis.
* Register implemented adapters with `@register` in a platform module; an implemented
  adapter replaces a planned one with the same `adapter_id`. Keep matchers specific to
  your platform's naming (unit names, launchd labels); other platforms must not be claimed
  (B3-IC-4).
* Declare `collects` and `never_collects` on every adapter (both appear in docs/UI) and keep
  the promise: no credentials, FTP file contents, HTTP Authorization headers, query strings
  or database query text.
* Coverage: `classify_coverage(adapter, enabled=..., last_telemetry_at=<freshness of the
  source channel>, ...)`. Pass source freshness, not the time of the last event: an idle
  but watched service is `monitored`. `Service.last_telemetry_at` is the newest event the
  adapter genuinely attributed.
* `ServiceRef` on an event names the PRODUCING service; the subject of a record (unit being
  started, file being changed) goes to `resource.*` and `attributes.subject_service_id`.
* `ServiceInstance.asset_id` is mandatory in practice (the gateway quarantines instances
  without it).

## Linux collector (`extorq_collectors.linux`, owner B1)

* Agentless: `ssh` (argv, `-F /dev/null`, pinned `var/vm/known_hosts`,
  `StrictHostKeyChecking=yes`, `IdentitiesOnly`, no agent/forwarding, ControlMaster) as
  `extorq-collector` into the VM's dispatch boundary
  (`infra/vm/files/extorq-collect-dispatch`, deployed root-owned by cloud-init or
  `infra/vm/vm.sh redeploy`). New data needs a new allow-listed dispatch command or an
  additive field (bump `DISPATCHER_VERSION`, keep `PROTOCOL = 1` compatible, mirror the
  grammar in `linux/ssh.py:validate_command`, test in `test_linux_dispatcher.py`). Never add
  `Environment=` or file contents to the inventory.
* `SSHDispatchClient(SSHTarget.from_mapping(cfg["ssh"], base_dir=repo_root)).run(cmd)` is
  the supported way for other components (C3 `packages`) to read the VM.
* Steps per cycle (each with its own `ctx.emit`): inventory (60 s; packages hourly) →
  journal → audit → services → posture (15 min). Journald entries are routed by
  `SYSLOG_IDENTIFIER` to the adapter that owns them (ssh, nginx, apache, webapp-json,
  systemd), everything else to host parsers (sudo, su, PAM, account tools, dispatch
  denials). Records of disabled adapters are not collected.
* Parsers are pure functions over `JournalEntry` / audit bytes / documents with a
  `ParseContext`; build events only through `linux.common.build_event` (catalog check,
  redaction, sanitising, simulation tag, self label, service attachment).
* Docs: `docs/telemetry/linux.md`; VM: `infra/vm/README.md`; tests:
  `uv run pytest tests/unit/linux -q`; E2E check:
  `uv run python -m extorq_collectors.linux.verify --asset linux:lab-vm-01`.

### Kubernetes collector (`extorq_collectors.kubernetes`, owner B2)
- Host-native, read-only: kubeconfig `var/kube/extorq-inventory.kubeconfig` from
  `infra/kind/kind.sh token` (TokenRequest token, default 24 h, 0600). The client refuses
  client-certificate/inline-token/exec kubeconfigs and non-loopback or plain-HTTP servers, so it
  can never run with the cluster-admin kubeconfig. GET only; RBAC: get/list/watch on the kinds
  in `infra/kind/manifests/10-inventory-rbac.yaml` (no secrets, no configmaps, no exec/logs).
- One `ctx.emit` per cycle: object diffs (`k8s.resource.*`, InventoryItems), Services /
  ServiceInstances (`service.*`), `k8s.event.observed`, cluster + node assets, posture ScanRun +
  findings. A kind that fails to LIST is never diffed (no false deletions); 401 fails the cycle.
- Identities for services/instances/node assets/container ids MUST come from
  `extorq.ingest.otlp_k8s` helpers (shared with the OTLP normaliser), never be re-derived.
- Container logs and audit events are NOT collected here (OTel DaemonSet + `otlp_k8s`).
- Tests: `uv run pytest tests/unit/kubernetes -q` (real API/audit/OTLP captures in
  `tests/fixtures/kubernetes/`).

### macOS collector (owner B3)

* Native process on the host: `uv run extorq-collect run --only macos-workstation-01`
  (config `config/collectors/macos.yaml`, docs `docs/telemetry/macos.md`). Runs as the
  logged-in user; never sudo, never Full Disk Access, never a configuration profile.
* Commands only through `extorq_collectors.macos.commands.run_command`: absolute
  allow-listed executables, argv lists, minimal env, timeouts, bounded output, and a
  read-only sub-command policy (e.g. `launchctl` may only `print`). Add a new command
  by extending `ALLOWED_EXECUTABLES` *and* `check_read_only_policy`, with a test in
  `tests/unit/macos/test_macos_commands.py`.
* Six sources (unified_log 60 s, launchd 60 s, inventory+services 300 s, posture 300 s,
  applications 3600 s, asset 300 s), each committed by its own `ctx.emit`; a failing
  source calls `ctx.discard_staged()` and never advances a snapshot. One instance per
  state directory (flock).
* Unified-log predicates are fixed fragments in `unified_log.PRODUCERS`; configuration
  selects names only. `<private>` values are never recovered.
* Known platform behaviour (macOS 27): `netstat` returns an empty socket table to
  descendants of ad-hoc signed binaries (the uv CPython); the collector falls back to
  `lsof` (current user's processes only) and reports the gap. `proc_pidpath` and
  `launchctl print` work unprivileged.
* Fixtures (`tests/fixtures/macos/`) are real captures with the account name replaced by
  `testuser`; synthetic records are labelled `extorqSynthetic`; launchd `environment`
  blocks are removed from fixtures.
* MAC-001: `simulations/macos/mac_001_launchagent.sh` (never loads the job; cleanup
  verifies removal).

### GitHub collector (`extorq_collectors/github/`, owner C1)

- Read-only REST polling (`GET` only) of the repositories in `config/collectors/github.yaml`;
  producer `github-collector`, source type `github.api`, asset ids lower-case
  `github:<owner>` / `github:<owner>/<repo>`. Docs: `docs/telemetry/github.md`.
- Token: `EXTORQ_GITHUB_TOKEN_FILE` (fine-grained, read-only, 0600) > `EXTORQ_GITHUB_TOKEN` >
  `gh auth token` only when `gh_cli_token_fallback: true` (broad OAuth scopes; reported in
  health). Never log, print or put the token in errors, fixtures or docs.
- All GitHub text is attacker-controlled (commit messages, branch names, workflow YAML, alert
  titles): sanitise with `records.clean_text` / `clean_redacted`, never interpolate into SQL,
  shell or prompts. Workflow YAML only through `workflow.load_workflow_yaml` (SafeLoader,
  YAML 1.2 booleans so `on` stays a string, duplicate keys rejected, size/alias budgets).
- Unknown stays unknown: 403/404 = "feature unavailable or not authorised" (data gap, check
  skipped, never "no alerts"); transient errors never create change events.
- Checkpoints: one JSON per repository committed by `ctx.emit` with the records it produced;
  event ids are deterministic (commit SHA, `<sha>:<workflow path>`, `<run>:<attempt>:<status>`).
- Tests: `uv run pytest tests/unit/github -q` (synthetic API fake, no network). Offline workflow
  analysis: `uv run python -m extorq_collectors.github.analyze --help`.
- Never push, create repositories or change settings from code or tests; GH-001 `--execute`
  and `create_lab_repo.sh` require explicit user approval.

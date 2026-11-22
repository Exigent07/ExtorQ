# P (platform) interface notes, schema 2.0 stage

Audience: the lead, T (detection tests), UI (API/console), H (Linux + macOS), KG
(Kubernetes + GitHub), whoever owns the root docs. Status: what changed in platform
interfaces, plus proposals for files P does not own.

## P-IC-1 (all): platform interfaces after schema 2.0 (implemented)

* Gateway: accepts only `schema_version` `2.0` (`/v1/status` reports
  `accepted_schema_versions: ["2.0"]`). A 1.x envelope is a 422; a 1.x record or a
  `simulation_run` record is quarantined as `invalid_record` (never a 403).
* `extorq.storage.rows`: no `simulation_run` kind, no `events.simulation_run_id` /
  `scenario_id`, no `alerts.simulation_run_ids`. Works before and after migration 0008
  (ClickHouse fills the not-yet-dropped columns with NULL / `[]`).
* SDK: `extorq_collectors.sdk.simulation` and `extorq-collect sim-record` are deleted.
  New `extorq_collectors.sdk.baseline` (clean-slate re-baseline, see P-IC-5).
* Producer registry: `simulation-runner` removed from `scripts/bootstrap.py`. The gateway
  also drops retired kinds from an older `producers.json` (fail closed, logged), so the
  2.0 gateway starts even before `make bootstrap` is re-run.
* Settings: `Settings.gemini_api_key` and the unused `Settings.environment` are removed.
* Compose: no `gemini_api_key` secret, no `GEMINI_API_KEY_FILE` / `EXTORQ_GEMINI_ENABLED`,
  no `EXTORQ_ENVIRONMENT`; the `api` service is back on a read-only root filesystem.
  `make up-demo` only sets `EXTORQ_JEV_ENABLED=true` (ai-worker).
* Backend CLI: `extorq ai summary` removed; new `extorq data counts|reset --yes` and
  `extorq spool status|clear --yes` (clean slate, P-IC-5).

## P-IC-2 (T): detection-test report format read by `make demo-check`

`scripts/demo_check.py` reads `var/reports/detection-tests-*.json` (newest per asset class,
up to 50 files) and fails unless, per asset (`linux`, `kubernetes`, `github`, `macos`),
every result passed and there are at least 5 distinct positive tests. It parses
tolerantly, but please emit at least:

```json
{
  "finished_at": "2026-11-23T08:00:00Z",
  "results": [
    {"test_id": "linux-vm-001-ssh-burst", "asset": "linux", "rule_id": "VM-001",
     "kind": "positive", "status": "passed", "detail": "alert 3f2a... in window"},
    {"test_id": "linux-vm-001-key-logins", "asset": "linux", "rule_id": "VM-001",
     "kind": "negative", "status": "passed", "detail": "no VM-001 alert in window"}
  ]
}
```

* `kind`: `positive` (the rule must alert) or `negative` (the control must stay silent);
  `expect_alert: true|false` is accepted instead.
* `status`: `passed` / `failed` / `skipped` / `error` (`passed: true|false` accepted).
  A skipped test counts as not passed: demo readiness needs every test run.
* `asset`: the asset class (`k8s`/`kubernetes`, `mac`/`macos`, ... are normalised).
* Make targets call `uv run python -m detection_tests run --asset <all|linux|kubernetes|
  github|macos> $(ARGS)` (`make test-detections[-<asset>]`).

## P-IC-3 (UI): Jev status shown by the console

The `api` container gets no AI key and no AI flag (it never calls a provider), so the
AI configuration that `GET /api/v1/health` derives from the API process environment
reports Jev as not configured and disabled even while `make up-demo` runs triage in the
ai-worker. Proposal: show the ai-worker's own state instead (latest `pipeline_health`
row with `component = ai_worker`: `status` `disabled`/`ok`/`degraded`, `details.reason`,
`details.daily_cap`), which is the ground truth. If you prefer an environment flag in
the api, say so and P adds `EXTORQ_JEV_ENABLED` (non-secret) to the api service.

## P-IC-4 (lead): proposals for files P does not own

1. Migration `0009_api_writer_no_ai.sql` (least privilege): `REVOKE INSERT ON
   extorq.ai_assessments FROM extorq_role_api_writer;` Since schema 2.0 the API only
   reads assessments; the 0002 grant is unused.
2. `.env.example`: drop `GEMINI_API_KEY` and the `EXTORQ_GEMINI_ENABLED` comment
   (nothing reads them any more).
3. Root docs still describing removed platform features (owners: lead / docs):
   `AGENTS.md` lines about `GEMINI_API_KEY` (section 3), `make up-demo` "Jev and Gemini
   flags" and the `sim-*` targets (section 8), `EXTORQ_GEMINI_ENABLED` (section 9);
   `README.md` (`make sim-*`, "Jev and Gemini"); `docs/deployment.md` (Gemini key, `sim-*`,
   `sim-record`); `docs/security.md` (`simulation-runner` producer row, Gemini key row);
   `docs/demo-runbook.md` (`EXTORQ_GEMINI_ENABLED`, `make sim-*`); `docs/testing.md`;
   `docs/attack-scenarios.md` (T replaces it); `collectors/AGENTS.md` (`sim-record` in the
   `cli.py` row, simulation markers rule 8; owner H). Replacements: `make test-detections`,
   `make reset-data YES=1`, `make up-demo` = Jev only.
4. PLAN section 4.3 (producer table) still lists `simulation-runner`, section 4.5 the
   Gemini key and section 5 `extorq-collect sim-record`.
5. Verification order for the VERIFY stage: `make up-full` (rebuild: the reset commands
   live in the new backend image) -> `make migrate` (applies 0008) -> `make bootstrap`
   (rewrites `producers.json` without `simulation-runner`) -> `make test-integration`
   (writes labelled synthetic probes, so before the reset) -> `make reset-data YES=1` ->
   wait one collector cycle -> `make scan` -> `make test-detections` -> `make demo-check`.

## P-IC-5 (H, KG): clean-slate re-baseline of your collector state

`make reset-data YES=1` re-baselines each stopped collector's state DB with a policy in
`extorq_collectors.sdk.baseline.POLICIES` (documented in `docs/collectors.md` section 6):
outbox and snapshots are cleared, cursors kept. Please check the rows for your collectors
and tell P when you add state keys:

* Linux: drops `linux.last_run.*`, `linux.inventory.last_full`, `linux.services.last_event`;
  keeps `journal.cursor`, `audit.inode`, `audit.offset`, `linux.runtime`,
  `linux.services.first_seen`, `linux.services.known_units`.
* macOS: drops `macos.sources`, `macos.full_inventory`, `macos.adapter_last_event`; keeps
  `unified_log.window`.
* Kubernetes: keeps the `k8s-events` snapshot (Event uids already emitted: without it
  every Event still within its TTL would be re-ingested) and `k8s.events_last_success`;
  drops `k8s.last_full_refresh` and all other snapshots (baseline records carry
  `attributes.baseline=true`).
* GitHub: rewrites each `github:repo:*` checkpoint (RepoState version 1): resets
  `settings`, `repo_meta`, `protection`, `branch_info`, `etags`, `last_posture_at`,
  `last_alerts_at`, `last_asset_at`, `inventory_workflows`, `inventory_branches`; keeps
  branch heads, run tracking, activity id, change sequence and commit retries. A test
  round-trips this through `RepoState.from_json`, so renaming a field fails it.

The reset relies on collectors/AGENTS.md rule 4: the first snapshot of a category is a
baseline and produces no change events (or events marked `baseline=true` that rules
ignore). Please keep that true for the new types (`software.installed` on a cleared
`applications` snapshot, listener/cron/account diffs).

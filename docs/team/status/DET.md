# DET status: detection and correlation (schema 2.0, detection-test matrix)

Owner paths: `rules/**`, `backend/src/extorq/{detection,correlation}/**`,
`tests/unit/{detection,correlation}/**`, `tests/rules/**`,
`docs/{detection-engine,detection-catalog,correlation}.md`, `rules/AGENTS.md`.

Last update: 2026-11-22 17:16Z UTC (milestone 2: fixtures generated, rule harness 116/116)

## Plan
1. Schema 2.0 in engine, harness, dry run and correlation: no `simulation_run_ids`, no
   `SIMULATION_RUN` basis, no simulation wording; harness applies 0006 + 0008.
2. Rules per asset (PLAN 12 matrix): Linux VM-001..004, HTTP-001, APP-001, CORR-002;
   Kubernetes K8S-001..005 + APP-001; GitHub GH-001..005; macOS MAC-001..005.
3. Positive and negative fixtures per rule mirroring the matrix negative controls,
   regenerated deterministically (schema 2.0, `extorq-test-` names, no `sim` markers).
4. Docs: per-asset catalogue, engine and correlation docs, docstrings.

## Dependencies observed (not mine)
- `extorq.storage.rows` (A) still imports `extorq.contracts.simulation`: the engine store,
  the harness and every ClickHouse test depend on it, so `uv run pytest tests/rules` cannot
  run until it is updated for schema 2.0.
- `extorq.ingest.otlp_k8s` (KG) and the Linux/macOS collectors (H) import `SimulationTag`:
  the K8S fixtures are produced with B2/KG's real normaliser, so they are regenerated once
  it imports again.
- Field requests to H and KG: `docs/team/interface-changes/DET.md`.

## Done
- Milestone 1 (17:40Z): engine/harness/dry run/sqlguard/correlation without simulation
  (`alerts.py` row contract, `classify.py` bases, `records.py` columns, `builder.py` linked
  query + limitations, `features.py`); harness applies 0006 + 0008; per-case `params`
  overrides in rule tests (`LoadedRule.with_params`) so allowlists are tested without test
  values in production rules. 24 rules written (VM-001..004, HTTP-001, APP-001, CORR-002,
  K8S-001..005, GH-001..005, MAC-001..005): static validation clean except fixtures, which
  are generated next. `extorq.storage.rows` (P) and the producers import again.

- Milestone 2: `tests/rules/fixture_builder.py` + `generate_fixtures.py` rewritten (schema 2.0,
  one builder per rule, matrix positive + matrix negative control per rule). Linux fixtures
  derived from the captured VM output with H's own parsers (journal, auditd, inventory diff:
  `derived-captured`); K8s fixtures from captured audit records through KG's OTLP normaliser;
  GitHub through the collector's workflow analyser; macOS launchd/unified-log fixtures
  through H's launchd and unified-log code on plists/log lines written here (`synthetic`).
  Cluster-birth capture converted to schema 2.0 (schema_version only). 15 stale fixtures
  (schema 1.x, simulation-tagged) deleted.

## Verified
| Claim | Command | Result |
|---|---|---|
| All 24 rules load, every fixture case passes (ephemeral ClickHouse, migrations 0001-0006 + 0008) | `uv run extorq rules test` | first run 113/116 (GH-004 fixture YAML invalid, two wrong expectations: fixed), then `--only VM-001 --only VM-003 --only GH-004` 17/17 |

## Not verified / open
- Live detection tests are out of scope for this stage (VERIFY stage).

## Release remediation, 2026-11-23

- Starting Git revision `023fdb63b6023143302a0733883c9749743835c3` with existing
  Contract 2.0 and remediation work in the working tree.
- Saturated rule windows stream bounded batches over the original SQL window. Window
  retries preserve the success watermark, and evidence checks asset, time, source and
  event type before writing alert links. The ClickHouse harness applies the additive
  evidence timestamp migration and includes a regression with a one-row batch size.
- Re-evaluation under a different rule version publishes current confidence and
  features with stable alert identity and historical evidence retained. Correlation
  coverage uses asset and source, with Kubernetes delivery scoped to the recorded node.
  Related activity uses cluster-scoped Kubernetes identifiers and repository-scoped
  GitHub run IDs. SSH and audit corroboration apply host and event-order checks.
- `.venv/bin/extorq rules validate` reported 22 valid rules. `.venv/bin/extorq rules test`
  exited 2 during `docker ps` because the Docker API socket denied access.
- `.venv/bin/pytest tests/rules -q -rs` reported 8 passed and 165 skipped. All skips
  required Docker and ClickHouse.
- `.venv/bin/pytest tests/unit/detection tests/unit/correlation tests/security -q`
  reported 405 passed, 3 skipped and 32 deselected. The skipped cases required Docker.
  The warning identified an intentionally weaker posture-test deployment in the lab.
- Scoped Ruff and mypy checks passed. No ClickHouse execution, native validation
  scenario, or deployed dashboard was verified in this session.

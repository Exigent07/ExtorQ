# KG status: Kubernetes + GitHub telemetry (schema 2.0 stage)

Scope (write access in this stage): `collectors/src/extorq_collectors/{kubernetes,github}/**`,
`backend/src/extorq/ingest/otlp_k8s.py`, `infra/kind/**`,
`config/collectors/{kubernetes,github}.yaml`, `tests/unit/{kubernetes,github}/**`,
`tests/fixtures/{kubernetes,github}/**`, `docs/telemetry/{kubernetes,github}.md`.
Proposals for other owners: `docs/team/interface-changes/KG.md`.

Last update: 2026-11-22 (milestone 0: started)

## Milestone 0: baseline
- Contracts are at schema 2.0 (lead commit 023fdb6). Every KG module that imported
  `SimulationTag` fails to import; `uv run pytest tests/unit/kubernetes tests/unit/github -q`
  -> 7 collection errors (ImportError `SimulationTag`, and `extorq.storage.rows` -> missing
  `extorq.contracts.simulation`, which is A's module).

## Plan
1. Remove simulation markers and dead code (otlp_k8s, k8s model/verify, github records/poller,
   tests, fixtures).
2. Kubernetes matrix fields (K8S-003 exec, K8S-004 secret enumeration scope, K8S-005 admitted
   pod flags + namespace Pod Security level).
3. GitHub matrix fields (GH-002, GH-003, GH-004 on `github.workflow.modified`; new
   `github.secret.exposed`).
4. Docs and docstrings.

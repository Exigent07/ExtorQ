# T status: detection tests (schema 2.0 stage)

Owner paths (this stage): `detection_tests/**` (new top-level package), `simulations/**`
(retired: ported, then deleted), `docs/attack-scenarios.md` (replaced by
`docs/detection-tests.md`), `tests/unit/detection_tests/**`.
Proposals for other owners: `docs/team/interface-changes/T.md`.

Last update: 2026-11-22 (milestone 0: survey done, plan fixed)

## Milestone 0: survey
- Read AGENTS.md, PLAN.md section 12 (matrix: Linux 7, Kubernetes 6, GitHub 5, macOS 5
  tests), contracts 2.0, `docs/team/interface-changes/DET.md` (fields each new rule reads),
  the old `simulations/**` scripts and the analyst API (alerts, events, rules, health).
- Verification channel chosen: the analyst API (`http://127.0.0.1:8000`, token read from
  `var/secrets/api_service_token` by path, role `viewer`); no debug proxy needed.

## Plan
1. Package `detection_tests/` (model, windows, api, proc, settings, report, runner, matrix,
   linux, kubernetes, github, macos, CLI `python -m detection_tests run|list|cleanup`).
2. Port the useful parts of `simulations/`, then delete it; replace
   `docs/attack-scenarios.md` with `docs/detection-tests.md`.
3. Unit tests for the pure parts (windows, report, command construction, matrix, runner with
   fakes). ruff check + format, mypy on the package, pytest.
4. No live detection tests in this stage (VERIFY runs them).

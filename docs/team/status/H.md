# H status: Linux + macOS telemetry (schema 2.0 stage)

Scope (write access in this stage): `collectors/src/extorq_collectors/{linux,macos,services}/**`,
`infra/vm/**`, `lab/apps/lab-portal/**`, `config/collectors/{linux,macos}.yaml`,
`tests/unit/{linux,macos}/**`, `tests/fixtures/{linux,macos}/**`,
`docs/telemetry/{linux,macos}.md`, `collectors/AGENTS.md`.
Proposals for other owners: `docs/team/interface-changes/H.md`.

Last update: 2026-11-22 (milestone 2: macOS matrix telemetry implemented)

## Milestone 0: baseline
- Contracts are at schema 2.0 (lead commit 023fdb6). `linux/common.py` and `macos/common.py`
  import `SimulationTag`, so both collectors fail to import:
  `uv run pytest tests/unit/linux tests/unit/macos -q -x` -> ImportError
  `cannot import name 'SimulationTag' from 'extorq.contracts'` (conftest collection error).

## Plan
1. Remove simulation markers (`extorq-sim-*`, `com.extorq.sim.*`, SimulationTag, `sim_texts`)
   and dead code; `linux/verify.py` loses its `simulation_run_id` queries (columns dropped by
   migration 0008).
2. Linux matrix telemetry verified on real VM output (read-only capture): users, cron,
   systemd + auditd, sshd, nginx, app auth.
3. macOS matrix telemetry: launchd attributes, listener exposure + owner, sudo failure from
   the unified log, `software.installed/removed` with bounded codesign checks.
4. Remove "lab" wording from display names; docs/docstrings for schema 2.0.

## Milestone 1: simulation markers removed (done)
- `linux/common.py`, `macos/common.py`: `SimulationTag`, `find_simulation`, `simulation_tag`,
  `launchd_simulation_tag`, the `extorq-sim-*` / `com.extorq.sim.*` patterns and every
  `sim_texts=` argument removed (18 call sites). Dead code removed: `service_records.iter_refs`,
  `inventory.services_by_unit`, auditd `raw_title`.
- `linux/verify.py`: no `simulation_run_id` / `simulation_runs` queries (dropped by 0008);
  verifies by asset + `--from/--to` event-time window (or `--since-minutes`), adds the
  producer's quarantine reasons. Ran read-only against the live stack:
  `uv run python -m extorq_collectors.linux.verify --since-minutes 30` -> event counts,
  26 services, posture scan succeeded (6 findings), health ok, 0 quarantined.
- Fixtures: the retired artefact prefix in the real 2026-11-21 captures was renamed
  `extorq-sim-` -> `extorq-test-` (plain and kernel hex encoding; JSON re-validated);
  macOS synthetic sshd line renamed likewise.
- `uv run pytest tests/unit/linux tests/unit/macos -q -p no:cacheprovider` -> 224 passed.

## Milestone 2: macOS matrix telemetry (implemented, unit-tested)
- MAC-002 (`launchd.py`): `program`, `program_arguments` (first 16, redacted),
  `program_arguments_count`, `program_exists`, `program_user_writable` (host facts SQL cannot
  derive), `run_at_load`, `scope`, `allowlisted`.
- MAC-003: new `listeners` source (60 s; was inside the 300 s inventory): `bind_address`,
  `exposure` (contract ServiceEndpoint vocabulary `any|loopback|private|unknown`),
  `processes`/`pids`/`users`, `process_attribution` (`lsof`/`netstat_last_pid`),
  `listener_method`; `process.{name,pid}` when one owner. Inventory/posture reuse the
  fresh snapshot (< 120 s).
- MAC-004 (`unified_log.py`): sudo sender verified (`/usr/bin/sudo` only, else notable
  `source_verified=false`), documented `ENV=... COMMAND=` form, `failed_attempts`,
  `failure_kind` (authentication -> outcome failure / policy -> denied). Predicate
  `process == "sudo"` runs (exit 0), but the reference Mac's whole log archive
  (2026-10-23..2026-11-22) holds NO sudo record (`log show --start "2026-10-23 00:00:00"
  --predicate 'process == "sudo" OR ...'` -> 4 records, all opendirectoryd); parser tested on
  sudoers(5) 1.9.17p2 formats in a labelled SYNTHETIC fixture. Linux sudo parser aligned.
- MAC-005: new `software` source (`software.py`, 60 s): /Applications + ~/Applications (top
  level + one folder deep), Info.plist only; `software.installed/removed`; bounded
  `codesign --verify --strict` + `codesign -dv --verbose=2` on NEW bundles only (count + time
  budget), `signed` true/false/"unknown", `signature_valid`, `signature_type`,
  `signature_team_id`, `signature_authority(ies)`, `notarization_ticket`; ctime settling +
  retry of "sealed resource" failures (mid-copy false positive), bounded deferral; version
  updates are not installs; replaced bundle ids are. Command policy admits only those two
  codesign forms on application-folder bundles. Real codesign outputs captured as fixtures.
- `uv run pytest tests/unit/macos -q -p no:cacheprovider` -> 135 passed.

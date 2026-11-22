# K-DATA status (acting for B2, Kubernetes telemetry)

Scope: `collectors/src/extorq_collectors/kubernetes/**`, `infra/kind/**`,
`tests/unit/kubernetes/**`, `docs/telemetry/kubernetes.md`. Nothing under `frontend/`.
Proposals for other owners: `docs/team/interface-changes/K-DATA.md`.

Last update: 2026-11-22T07:21Z (milestone 3: periodic refresh verified live; all tasks done)

## Tasks
1. D1-IC-8: Pod/container ServiceInstances stale in the console. **Fixed and verified live.**
2. Inventory token expiry before the demo (~2026-11-22T14:41Z). **Re-minted (48 h) and
   verified without a restart; minting and reload made robust.**
3. Verify fresh `observed_at` for running Pods/containers in ClickHouse. **Done.**

## Milestone 0: investigation
- Live data (api_ro via the debug proxy, 06:45Z): node instances (12 pods + 12 containers)
  all had `max(observed_at)` = 2026-11-21 15:07:50Z, although `k8s-inventory` reported `ok`
  every minute and its full refresh (`refresh_seconds` 900) re-sent every instance.
- Root cause: the gateway's dedup key for `service_instance`
  (`contracts/ingest.py:record_identity`) is `instance_id + state + present + content
  WITHOUT observed_at`, held for 168 h (`dedup_retention_hours`). A refreshed instance whose
  content did not change gets the same key and is dropped as a duplicate in the spool, so
  ClickHouse never saw the newer `observed_at`. Services refresh fine (their key includes
  `last_seen`), inventory items too (key includes `snapshot_id`).
- Same rule: an instance whose state flaps back to an earlier content (ready true -> false
  -> true) within 7 days is dropped on the way back, leaving the intermediate state current.
- Token: minted 2026-11-21 14:41Z with 24 h; `exp` 2026-11-22T14:41:28Z (decoded locally,
  never printed). kube-apiserver has no `--service-account-max-token-expiration`. The client
  already re-read the token file for every request.

## Milestone 1: code + tests
- `kubernetes/collector.py` (COLLECTOR_VERSION 1.1.0): every emitted ServiceInstance carries
  `attributes.snapshot_id` (= the cycle's inventory snapshot id, as on InventoryItems), so
  refreshes, flaps back and tombstones pass the gateway dedup; snapshot items and
  `instance_id`s unchanged. First cycle of every process is a full refresh. Health details
  `instances_sent`, `instances_removed`, `token_expires_at`, `token_reloads`. A token
  expiring within `token_warn_seconds` (default 7200, 0 disables) marks the cycle degraded.
- `kubernetes/api.py`: token file still read per request; on 401 it is read again and the
  request retried once if the token changed (re-mint race); otherwise fail fast with
  "token expired at <exp>" / "rejected before its expiry" (from the exp claim, never the token).
- `infra/kind/kind.sh token`: default 48 h, bounds 10m..168h validated before any cluster
  call, prints the real expiry from the exp claim, warns if the API server shortened it;
  `status` shows expiry and time left; main guarded so tests can source the helpers.
- Docs: `docs/telemetry/kubernetes.md` (sections 5, 6, 7, 9), `infra/kind/AGENTS.md`.

## Milestone 2: live (re-mint, redeploy, verification)
- 07:01:43Z `infra/kind/kind.sh token` -> "inventory token valid until
  2026-11-24T07:01:43Z" (48 h; covers the demo on 2026-11-23). Files 0600.
- Re-mint without a restart: the OLD runner (pid 59404, collector 1.0.0) reported
  `token_expires_in_seconds` 27600 at 07:01:27Z and 172754 at 07:02:28Z, status ok.
- 07:03:33-07:03:39Z `make collectors-stop` (pid 59404) / `make collectors-start` (pid 19371,
  all enabled collectors). Only my files changed under `collectors/` (git status checked);
  all four collector modules import.
- First cycle of the new code 07:03:34.592Z: collector 1.1.0, ok, `full_refresh` true,
  `instances_sent` 24; next cycle 07:04:34Z: no refresh, 0 sent, ok.
- ClickHouse (`v_service_instances_current`, k8s-inventory): node
  `k8s:extorq-lab/node/extorq-lab-control-plane` 12 pods + 12 containers, all `running`,
  `observed_at` 2026-11-22 07:03:34.561Z (was 2026-11-21 15:07:50Z), each with
  `attributes.snapshot_id` `k8s-20261122T070334Z`; 24 rows stored since the deploy;
  0 rows in `ingest_quarantine` for `k8s%` producers in the last 24 h.
- Analyst API `GET /api/v1/assets/k8s%3Aextorq-lab%2Fnode%2Fextorq-lab-control-plane/services`
  (viewer, one call): 11 hosted workloads, 24 instances, all `stale: false`.
- `infra/kind/kind.sh status`: "inventory token: valid until 2026-11-24T07:01:43Z (47 h 56 min
  left; ...)".

## Milestone 3: periodic refresh live (07:20Z)
- `collector_health` (k8s-inventory, since 07:03Z): 18 cycles, 18 ok; full refreshes at
  07:03:34.592Z (startup) and 07:18:36.452Z (900 s timer), each `instances_sent` 24,
  `instances_removed` 0.
- `v_service_instances_current`: 12 pods + 12 containers, `observed_at` 07:18:36.417Z for all
  (98 s old at 07:20:14Z). Stored rows per marker: `k8s-20261122T070334Z` 24,
  `k8s-20261122T071836Z` 24 (the gateway accepted every refresh; none deduplicated away).
- `make kind-status` (Makefile delegate, executes `main`) still works and shows the expiry.

## Verified (commands and observed results)
| Claim | Command | Result |
|---|---|---|
| k8s unit tests | `uv run pytest tests/unit/kubernetes -q` | 156 passed (was 124: +6 inventory, +4 api, +22 kind.sh) |
| new tests detect the old behaviour | HEAD `collector.py` restored temporarily, inventory tests run; HEAD `api.py` (+ helper shims) for api tests; files restored, `cmp` identical | 6 failed / 4 failed on old code; all pass on new code |
| lint / format / types | `uv run ruff check` + `ruff format --check` (k8s collector + tests); `uv run mypy collectors/src/extorq_collectors/kubernetes backend/src/extorq/ingest/otlp_k8s.py infra/kind/audit_check.py` | clean; "no issues found in 10 source files" |
| shell lint | `docker run --rm --network none -v "$PWD:/mnt:ro" -w /mnt koalaman/shellcheck:v0.10.0 -x infra/kind/kind.sh` | clean |
| security suites | `uv run pytest tests/security/test_security_python_static.py tests/security/test_security_lab_boundaries.py tests/security/test_security_service_adapters.py tests/security/test_security_secret_scan.py tests/security/test_security_repo_hygiene.py -q` | 151 passed, 1 failed: `test_no_secrets_in_git_history` (pre-existing finding in commit e243768, `tests/unit/ai/test_ai_sanitize.py:75`, not my files) |
| full default suite | `uv run pytest -q --deselect tests/security/test_security_secret_scan.py::test_no_secrets_in_git_history` | 1936 passed, 10 failed, all in `tests/unit/api/*` (overview/openapi) from another agent's uncommitted edits to `backend/src/extorq/api/schemas.py`/`settings.py` (not mine) |
| live: token, redeploy, freshness, API | see milestone 2 | as listed |

## Not verified
- A live 401 retry (re-mint racing a request): covered by unit tests only.
- The degraded warning live (needs a token with < 2 h left): unit test only.

## Other findings (not my scope, reported)
- Linux and macOS instances go stale for the same reason (K-DATA-IC-1): at 07:07Z
  `linux:lab-vm-01` 21 instances stored 06:07-06:10Z; `macos:workstation-01` 26 of 27 older
  than 1 h.
- Docs by F/B1/B2-config still say 24 h and "restart the collector" (K-DATA-IC-2).

## Next (for others; nothing open for K-DATA)
- Lead: optional contract fix K-DATA-IC-1. B1/B3: Linux/macOS instance refresh (same cause).
- F/B1/B2: stale "24 h" / "restart the collector" texts (K-DATA-IC-2).
- UI agents: Kubernetes Pods/containers are no longer stale in the API; recapture the node
  page screenshots if they still show "Stale".
- Before 2026-11-24T05:01Z (2 h before expiry) re-mint with `infra/kind/kind.sh token` if the
  lab keeps running; no restart needed.

# K-DATA interface notes (acting for B2, Kubernetes telemetry), 2026-11-22

Nothing here edits lead-owned or other agents' files; each item names who must act.

## K-DATA-IC-1 ServiceInstance dedup key ignores `observed_at` (owner: lead; A informed) - OPTIONAL

Root cause of D1-IC-8. `record_identity()` in `backend/src/extorq/contracts/ingest.py`
keys `service_instance` records on `instance_id + state + present + content excluding
observed_at`, remembered for 168 h (`dedup_retention_hours`). Consequences for every
producer of instances:

* a periodic re-send of an unchanged instance is dropped as a duplicate in the spool, so
  `service_instances.observed_at` never advances and the API marks the instance stale after
  `EXTORQ_API_SERVICE_STALE_SECONDS` (1 h) although it is running;
* an instance whose content returns to an earlier state within 7 days (readiness
  true -> false -> true) is dropped on the way back, so ClickHouse keeps the intermediate
  state as current.

Fixed for Kubernetes without a contract change: every instance record the k8s collector
emits carries `attributes.snapshot_id` (the emitting cycle), so each emission is distinct
(`docs/telemetry/kubernetes.md` section 6). Option for the lead: include `observed_at`
(or a time bucket) in the instance key under a new namespace (`rec.instance.v2`); replays
of one outbox record keep their key either way, so dedup of retries is unaffected.
`tests/unit/kubernetes/test_k8s_inventory.py::test_unmarked_instance_refreshes_would_be_dropped_by_the_gateway`
characterises the current rule and fails once it changes (then the marker is optional).
B1/B3: Linux and macOS instances are sent only on change and hit the same rule. Live check
2026-11-22 07:07Z (`v_service_instances_current`, api_ro): `linux:lab-vm-01` 21 present
instances, all stored 06:07:46-06:10:46Z (they cross the 1 h stale threshold at about
07:08-07:11Z); `macos:workstation-01` 27 present instances, 26 older than 1 h (oldest
2026-11-21 15:15Z). The console therefore shows those processes as stale too. The same
collector-side remedy works there (re-send on a refresh with a per-emission marker in
`attributes`), or the contract option above fixes all producers at once.

## K-DATA-IC-2 Inventory token: 48 h default, no restart after a re-mint (owners: F, B1, B2) - DOC UPDATES

`infra/kind/kind.sh token` now mints 48 h tokens by default (`EXTORQ_K8S_TOKEN_DURATION`,
10 min..168 h, validated before any cluster call) and prints the expiry. The collector reads
the token file for every request and re-reads it once on a 401, so a re-mint needs **no**
collector restart (verified live 2026-11-22 07:01-07:02Z on the unrestarted runner). It reports
`degraded` from 2 h before expiry. Current token: minted 2026-11-22T07:01Z, valid until
2026-11-24T07:01:43Z (covers the demo on 2026-11-23). Stale text to update:

| File (owner) | Now says | Should say |
|---|---|---|
| `docs/demo-runbook.md` row 5 (F) | 24 h lifetime; token minted 2026-11-21 20:11 IST expires 2026-11-22 20:11 IST | 48 h; minted 2026-11-22 07:01Z, valid until 2026-11-24 07:01Z |
| `docs/demo-runbook.md` troubleshooting "K8S-002 only medium" (F) | `kind.sh token`, then `make collectors-stop && make collectors-start` | `kind.sh token` (no restart; next cycle uses it) |
| `docs/known-limitations.md` C9 (F) | 24 hours by default | 48 hours by default; degraded 2 h before expiry; re-mint needs no restart |
| `docs/operations.md` 401 row (F) | the 24-hour token expired; then restart the collector | the 48-hour token expired; re-mint, no restart |
| `docs/deployment.md` (F) | valid for 24 hours by default | 48 hours by default (10 min..168 h) |
| `collectors/AGENTS.md` k8s section (B1) | default 24 h | default 48 h; re-mint picked up without restart |
| `config/collectors/kubernetes.yaml` header comment (B2) | (default 24 h) | (default 48 h); optional new setting `token_warn_seconds` (default 7200) |

## K-DATA-IC-3 D1-IC-8 closed (owners: D1, D2) - INFORMATIONAL

Kubernetes Pod/container instances are re-stored with a fresh `observed_at` on the first
cycle after a collector start and at least every 900 s afterwards; removed ones get one
`present = 0` tombstone. The console's "Stale" badges on Pods/containers were correct for
the old data and clear without any console change.

# Agent A interface notes and change proposals

Owner: A (platform & data). Proposals for lead-owned artefacts follow PLAN §8;
nothing here edits lead-owned files.

## A-IC-1 `extorq-selftest` producer (PLAN §4.3 addition; owner: lead to ratify)

**What.** `scripts/bootstrap.py` registers one extra producer:

| producer_id | kinds | source types | assets |
|---|---|---|---|
| `extorq-selftest` | `collector_health` | `extorq.pipeline` | `macos:workstation-01` |

**Why.** The SDK heartbeat example (`extorq_collectors.sdk.examples.heartbeat`)
proves the whole collector path (outbox -> sender -> HTTPS gateway -> spool ->
writer -> ClickHouse) without touching real telemetry. `CollectorHealth` needs
at least one source type that the producer is allowed to send. Borrowing a
telemetry producer (e.g. `macos-workstation-01`) would both mislabel the health
row (`macos.*` source types it does not collect) and give the self-test the
power to write macOS telemetry. A dedicated identity that can only write
collector health for `extorq.pipeline` is the least-privilege option.

**Affected.** lead (PLAN §4.3 table), D1/D2 (the collector shows up with
`collector_type = heartbeat`; treat as self-test), F (privilege audit).

## A-IC-2 Gateway policy for `ServiceInstance.asset_id = null` (informational; lead, B2)

The 1.1 contract allows `ServiceInstance.asset_id = None` ("not reported").
Per-record authorization checks the asset id against the producer's asset
patterns; an instance without one cannot be checked, and the gateway has no
service -> asset index to resolve it from `service_id`. The gateway therefore
**quarantines** such records (`asset_unattributable`), after checking that the
producer may send the kind at all (otherwise the batch is denied as usual).

Options for the lead if unscheduled Pods must be represented: (a) require
`asset_id` on ingest (contract change), or (b) let the k8s inventory producer
use the cluster asset id for instances not yet bound to a node (semantic
change: "where it is managed" instead of "where it runs").

## A-IC-3 Sender treats envelope-level 4xx as systemic (informational; all producers)

Since 2026-11-21T14:45Z the SDK keeps batches buffered (long backoff, error in
CollectorHealth) on 400/404/405/415/422 instead of dead-lettering them. The SDK
validates records with the same contracts as the gateway, so these answers mean
version skew or misconfiguration, never one bad record (bad records are
quarantined with 202). Observed trigger: a 1.1 client against a 1.0 gateway.
Dead letters can be re-queued with `extorq-collect flush --requeue-dead`.

## A-IC-4 Collector SDK additions, session 3 (informational; B3, C1, B1, B2)

Implemented in `extorq_collectors.sdk` (no contract change; tests in
`tests/unit/platform/test_platform_sdk.py`):

* `ctx.mark_degraded(reason: str)` (B3-IC-2, C1 3.3): the current cycle completed but only
  partly. Health `status=degraded`, `last_error = "degraded: <r1>; <r2>"`,
  `details.degraded_reasons = [...]` (redacted, sanitised, <= 8 distinct reasons);
  `last_success_at` still advances. Per cycle: call it every cycle while the condition
  lasts. A cycle that raises stays `failed`. Suggested uses: macOS source isolation
  (B3: a failing source), GitHub (C1: one repository failed, rate limited mid-cycle,
  `token_source=gh_cli`).
* `ctx.committed_snapshot(name) -> dict[str, dict]` (B3-IC-3): the last COMMITTED snapshot,
  parsed, as a fresh copy (staged items of this cycle are not included). Replaces
  `ctx.store.snapshot(name)` + `json.loads` in `macos/collector.py` (two call sites).
* Config secret check (C1 3.1): only STRING settings are checked (each with its key);
  `allow_gh_cli_token: true` loads. The error names the setting path, never the value
  (the loader used to embed pydantic's `input_value=...` in its message: fixed).

## A-IC-5 PLAN §5.1 wording (owner: lead)

PLAN §5.1 still says "Events with `event_time` > now+1d or older than 400d -> quarantine".
Implemented per §11: older than the `events` retention (90 d, `EXTORQ_EVENT_RETENTION_DAYS`,
pinned to the 0001 TTL by a unit test) -> quarantine reason `older_than_retention: ...`;
future check unchanged (`time: event_time_in_future`). Suggest updating §5.1 to match.

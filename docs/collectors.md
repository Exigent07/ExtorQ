# Collectors and the collector SDK

Owner of the SDK: agent A (`collectors/src/extorq_collectors/sdk/`,
`collectors/src/extorq_collectors/cli.py`). Platform collectors are owned by their
teams: Linux (B1), Kubernetes inventory (B2), macOS (B3), GitHub (C1); scanners (C3)
use the same outbox. Telemetry details per source: `docs/telemetry/*.md`.

## 1. Concepts

* A **collector** is a class with `collector_type`, `source_types` and
  `collect(ctx)`. The runner instantiates it with no arguments; settings come from
  YAML (`ctx.config`).
* Each collector has its own **state DB** `var/collectors/<collector_id>/state.db`
  (SQLite WAL, `synchronous=FULL`, 0600) holding the **outbox**, **checkpoints**, a
  small **KV** store and **snapshots** for inventory diffs.
* `ctx.emit(records, checkpoints)` is the only way records leave a collector: it is
  atomic with the checkpoints and snapshots it covers (section 4 of
  `docs/data-flow.md`).
* The **runner** delivers the outbox to the gateway at least once and reports
  `CollectorHealth` every cycle.

## 2. Configuration (`config/collectors/*.yaml`, no secrets)

```yaml
collectors:
  - collector_id: linux-lab-vm-01            # [a-z0-9][a-z0-9._-]{1,127}, unique
    producer_id: linux-ssh-lab-vm-01         # token: var/secrets/tokens/<producer_id>.token
    asset_id: linux:lab-vm-01
    module: extorq_collectors.linux.collector:LinuxSSHCollector
    interval_seconds: 60
    enabled: true
    settings: {ssh: {host: 127.0.0.1, port: 2222}}   # -> ctx.config
```

A file may hold one mapping, a list, or `{collectors: [...]}`. Values that look like
credentials are rejected at load time; reference secrets by file path
(`*_file` settings). Producer authorization (kinds, source types, asset patterns) is
enforced by the gateway from `var/secrets/producers.json` (PLAN §4.3; service kinds for
the macOS, Linux and Kubernetes-inventory producers since contract 1.1).

## 3. Writing a collector

```python
from typing import ClassVar
from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert

class ExampleCollector(Collector):
    collector_type: ClassVar[str] = "linux_ssh"
    source_types: ClassVar[tuple[str, ...]] = ("linux.journald",)  # all allowed for the producer

    def setup(self, ctx: CollectorContext) -> None:      # optional, once before the first cycle
        ...

    def collect(self, ctx: CollectorContext) -> None:
        cursor = ctx.checkpoints.get("journal.cursor")
        events, new_cursor, newest = read_source(cursor)  # SecurityEvent models
        added, changed, removed = ctx.diff_snapshot("units", current_units)  # dict[key, dict]
        asset = asset_upsert(ctx, asset_type="linux_host", name="lab-vm-01",
                             attributes={"os_version": "24.04"})
        ctx.emit([*events, *unit_records(added, changed, removed), *([asset] if asset else [])],
                 {"journal.cursor": new_cursor})
        ctx.report_lag(newest)                       # lag_seconds in CollectorHealth
        ctx.checkpoint_summary = "cursor ok"         # short, no secrets
        ctx.health_details = {"lines_read": 120}     # scalars / short lists

    def close(self) -> None:                         # optional, at shutdown
        ...
```

Rules:

* Records are contract models (`SecurityEvent`, `Asset`, `InventoryItem`,
  `PostureFinding`, `ScanRun`, `SimulationRun`, `Service`, `ServiceInstance`) or
  `{"kind": ..., "data": ...}` dicts. `emit` validates all of them **before**
  committing anything; one invalid record raises and nothing is written.
* Use deterministic ids (`extorq.contracts.identity`) from source-native identity;
  never derive ids from collection time.
* Unknown values stay `None`. Free text from sources is attacker-controlled: keep it
  bounded; the gateway redacts and sanitises again.
* Commit checkpoints **with** the records they cover. A snapshot staged by
  `diff_snapshot` is persisted only by the next `emit`; if the cycle fails it is
  discarded and the next cycle diffs again (nothing is lost or skipped).
* `ctx.state` (KV) is for small non-critical state and is not atomic with records.
* Raise on failure: the runner reports it (sanitised) and keeps the other collectors
  running. Long blocking calls need their own timeouts.

### Services (contract 1.1)

Host and Kubernetes inventory collectors report `Service` and `ServiceInstance`
records through the same `emit`. The shared discovery/adapter interface is
`extorq_collectors.services` (owner B1; `ServiceCandidate`, `ServiceAdapter`,
registry, `classify_coverage`, `build_service`, `service_ref`). Use
`diff_snapshot` over service keys to emit changes and tombstones (`present=False`).
Always set `ServiceInstance.asset_id` (host or node asset): the gateway quarantines
instances without it because it cannot authorize them.

### Asset upserts

`asset_upsert(ctx, asset_type=..., name=..., attributes=..., refresh_seconds=900)`
returns an `Asset` only when the content changed since the last **committed** upsert
or a refresh is due (keeps `last_seen` moving); `first_seen` is remembered in KV.
Include the returned record in your `emit` (or pass `emit=True`).

## 4. Running

```
uv run extorq-collect run                       # every enabled collector, one thread each
uv run extorq-collect run --only linux-lab-vm-01,github-lab
uv run extorq-collect run --once                # one cycle each, deliver, exit 0/1
uv run extorq-collect run --config path/to/file.yaml
uv run extorq-collect status [--json]           # outbox, dead letters, last health (read-only)
uv run extorq-collect flush [--requeue-dead]    # deliver buffered records without collecting
make collectors | collectors-once | collectors-status | collectors-flush | sdk-selftest
```

Paths resolve against `EXTORQ_HOME` or the repository root found from the current
directory. Relevant settings: `EXTORQ_GATEWAY_URL` (default `https://127.0.0.1:8443`),
`EXTORQ_TLS_CA_FILE` (`var/tls/ca.crt`), `EXTORQ_TOKENS_DIR`, `EXTORQ_COLLECTORS_STATE_DIR`,
`EXTORQ_COLLECTORS_CONFIG_DIR`.

## 5. Delivery and failure isolation

* One thread per collector; an exception or crash (including a failing import of the
  collector class) is caught, reported in that collector's `CollectorHealth` and never
  affects the others. `--once` exits non-zero if any collector failed or could not
  deliver its outbox within the drain deadline (default 60 s).
* Between cycles the runner retries buffered records with the sender's backoff, so a
  gateway outage only delays delivery. Batches: <= 500 records, gzip, `batch_id` reused
  across retries; outbox rows are deleted only after a 202 (a replayed 202 counts).
  Retry/backoff/dead-letter policy: `docs/data-flow.md` section 2.
* `CollectorHealth` status: `failed` when the cycle raised, `degraded` when delivery
  is failing or dead letters exist, otherwise `ok`. Collector-provided `health_details`
  are coerced into the contract shape (keys normalised, nested values serialised,
  strings redacted and bounded) so a bad detail never suppresses the health record.
* Stop with SIGTERM/SIGINT: threads finish their current step; nothing committed is lost.

## 6. Simulation runs (`sim-record`)

```
uv run extorq-collect sim-record --scenario VM-001 --asset linux:lab-vm-01 \
    --status started --run-id a1b2c3d4e5 --description "SSH brute force" --expected-rules VM-001
uv run extorq-collect sim-record --scenario VM-001 --asset linux:lab-vm-01 \
    --status completed --run-id a1b2c3d4e5
```

Producer `simulation-runner`; state `var/collectors/simulation-runner/state.db`.
Later statuses reuse the locally remembered `started_at`, description and expected
rules (or pass `--started-at`); reusing a run id for another scenario/asset is refused.
Exit codes: 0 delivered, 75 committed locally but still buffered (delivered by the next
`sim-record` or `flush`), 2 invalid input, 1 rejected.

## 7. The heartbeat example (SDK self-test)

`extorq_collectors.sdk.examples.heartbeat:HeartbeatCollector`
(`collectors/src/extorq_collectors/sdk/examples/heartbeat.yaml`) collects nothing,
advances a cycle checkpoint and lets the runner report CollectorHealth
(`collector_type=heartbeat`, source `extorq.pipeline`) under the least-privilege
producer `extorq-selftest` (may only send collector health). `make sdk-selftest` proves
the whole path: outbox -> HTTPS gateway -> spool -> writer -> `extorq.collector_health`.
It reports only while run, so it shows as stale afterwards; treat it as a self-test.

## 8. Tests

`tests/unit/platform/test_platform_sdk.py` (atomic emit, rollback, diffs, sender
retry/backoff/Retry-After, lost-202 replay, 403 bisection, systemic 422, dead-letter
requeue, runner isolation, health sanitisation, sim-record, asset upserts) with the
in-process fake gateway `tests/unit/platform/fake_gateway.py`;
`tests/failure/test_failure_durability.py` exercises a real outbox across gateway and
writer restarts.

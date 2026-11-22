# Collectors and the collector SDK

Owner of the SDK: platform (`collectors/src/extorq_collectors/sdk/`,
`collectors/src/extorq_collectors/cli.py`). The platform collectors (Linux VM, macOS
host, Kubernetes inventory, GitHub repository) are owned by their telemetry teams; the
scanners use the same outbox. Contract schema 2.0. Telemetry details per source:
`docs/telemetry/*.md`.

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
  - collector_id: linux-ssh-lab-vm-01        # [a-z0-9][a-z0-9._-]{1,127}, unique
    producer_id: linux-ssh-lab-vm-01         # token: var/secrets/tokens/<producer_id>.token
    asset_id: linux:lab-vm-01
    module: extorq_collectors.linux.collector:LinuxSSHCollector
    interval_seconds: 60
    enabled: true
    settings: {ssh: {host: 127.0.0.1, port: 2222}}   # -> ctx.config
```

A file may hold one mapping, a list, or `{collectors: [...]}`. String settings that
look like credentials are rejected at load time (each string is checked together with
its key, so `password: x` is refused); the error names the setting path, never the
value. Booleans, numbers, dates and nulls are outside the string credential check.
Reference secrets by file path (`*_file`
settings). Producer authorization (kinds, source types, asset patterns) is enforced by
the gateway from `var/secrets/producers.json` (PLAN §4.3; the macOS, Linux and
Kubernetes-inventory producers may also send `service` and `service_instance`).

## 3. Writing a collector

```python
from typing import ClassVar

from extorq_collectors.sdk import Collector, CollectorContext, asset_upsert


class ExampleCollector(Collector):
    collector_type: ClassVar[str] = "linux_ssh"
    source_types: ClassVar[tuple[str, ...]] = ("linux.journald",)  # all allowed for the producer

    def setup(self, ctx: CollectorContext) -> None:  # optional, once before the first cycle
        ...

    def collect(self, ctx: CollectorContext) -> None:
        cursor = ctx.checkpoints.get("journal.cursor")
        events, new_cursor, newest = read_source(cursor)  # SecurityEvent models
        added, changed, removed = ctx.diff_snapshot("units", current_units)  # dict[key, dict]
        asset = asset_upsert(
            ctx, asset_type="linux_host", name="lab-vm-01", attributes={"os_version": "24.04"}
        )
        ctx.emit(
            [*events, *unit_records(added, changed, removed), *([asset] if asset else [])],
            {"journal.cursor": new_cursor},
        )
        if packages_unavailable:  # this cycle succeeded only partly
            ctx.mark_degraded("package inventory unavailable: dpkg query timed out")
        ctx.report_lag(newest)  # lag_seconds in CollectorHealth
        ctx.checkpoint_summary = "cursor ok"  # short, no secrets
        ctx.health_details = {"lines_read": 120}  # scalars / short lists

    def close(self) -> None:  # optional, at shutdown
        ...
```

Rules:

* Records are contract models (`SecurityEvent`, `Asset`, `InventoryItem`,
  `PostureFinding`, `ScanRun`, `CollectorHealth`, `Service`, `ServiceInstance`) or
  `{"kind": ..., "data": ...}` dicts. `emit` validates all of them **before**
  committing anything; one invalid record raises and nothing is written.
* The first snapshot of a category is a **baseline**: emit the current items as
  inventory/service records but no change events (or mark them
  `attributes.baseline=true` where a rule needs to see them), so a new deployment or a
  clean-slate reset never raises "new persistence item" alerts for what already existed.
* Use deterministic ids (`extorq.contracts.identity`) from source-native identity;
  never derive ids from collection time.
* Unknown values stay `None`. Free text from sources is attacker-controlled: keep it
  bounded; the gateway redacts and sanitises again.
* Commit checkpoints **with** the records they cover. A snapshot staged by
  `diff_snapshot` is persisted only by the next `emit`; if the cycle fails it is
  discarded and the next cycle diffs again (nothing is lost or skipped).
* `ctx.committed_snapshot(name)` returns the last **committed** snapshot as
  `{item_key: item}` (a read-only copy; items staged by `diff_snapshot` in this cycle are
  not included until `emit`). Use it to carry over items of a source that could not be
  read this cycle, so "unreadable" never looks like "deleted".
* `ctx.state` (KV) is for small non-critical state and is not atomic with records.
* Raise on failure: the runner reports it (sanitised) and keeps the other collectors
  running. Long blocking calls need their own timeouts.
* Partial success: when `collect` completes but part of its work did not (one source or
  repository failed, rate limited, a broader credential than needed is in use), call
  `ctx.mark_degraded(reason)`. The cycle is reported `degraded` instead of `ok`, the
  reasons go to `last_error` (`degraded: <reason>; ...`) and
  `details.degraded_reasons` (redacted, sanitised, up to 8 distinct reasons), and
  `last_success_at` still advances. The hint applies to the current cycle only: call it
  again every cycle while the condition lasts. A cycle that raises stays `failed`.

### Services

Host and Kubernetes inventory collectors report `Service` and `ServiceInstance`
records through the same `emit`. The shared discovery/adapter interface is
`extorq_collectors.services` (`ServiceCandidate`, `ServiceAdapter`,
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
uv run extorq-collect run --only linux-ssh-lab-vm-01,github-repos
uv run extorq-collect run --once                # one cycle each, deliver, exit 0/1
uv run extorq-collect run --config path/to/file.yaml
uv run extorq-collect status [--json]           # outbox, dead letters, last health (read-only)
uv run extorq-collect flush [--requeue-dead]    # deliver buffered records without collecting
make collectors | collectors-once | collectors-flush | sdk-selftest
```

Continuous collection (demo and day-to-day): the host collectors (macOS, Linux VM over
SSH, Kubernetes inventory, GitHub) run as ONE background process:

```
make collectors-start            # all enabled collectors; ONLY=a,b to limit
make collectors-status           # runner pid + uptime, then outbox/dead letters/last health
make collectors-stop             # SIGTERM: the current cycle commits, then exit (SIGKILL after 90 s)
```

`scripts/collectors_ctl.py` starts `nohup uv run --frozen extorq-collect run` in its own
session (survives the terminal), with stdin `/dev/null`, output appended to
`var/log/collectors.log` (0600, rotated once at 50 MiB) and the pid in
`var/run/collectors.pid`. Starting twice is a no-op; it refuses to start while another
`extorq-collect run` is active (duplicate collection; `--force` overrides), and a stale
or recycled pid is never signalled. It installs no launchd job or other persistence and
does not restart a crashed runner: `make collectors-status` (and `make demo-check`, which
requires fresh `last_success_at` for every enabled collector) show it. Restart after
changing collector code or configuration: `make collectors-stop collectors-start`.

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
* `CollectorHealth` status: `failed` when the cycle raised; `degraded` when the
  collector called `ctx.mark_degraded(reason)`, delivery is failing or dead letters exist;
  otherwise `ok`. Collector-provided `health_details` are coerced into the contract shape
  (keys normalised, nested values serialised, strings redacted and bounded) so a bad
  detail never suppresses the health record.
* Stop with SIGTERM/SIGINT: threads finish their current step; nothing committed is lost.

## 6. Clean-slate re-baseline (`make reset-data`)

After the database is cleared (`make reset-data YES=1`, see
[data-model.md](data-model.md#61-clean-slate-make-reset-data-yes1)) every collector must
send its current state again, while log sources must not re-read old activity.
`extorq_collectors.sdk.baseline.rebaseline()` resets one stopped collector's state DB in
one transaction, with a policy chosen by the collector's `module`:

| Collector | Cleared (re-sent as a baseline) | Kept (cursors) |
|---|---|---|
| every collector | outbox and dead letters (records collected before the reset) | |
| Linux (`extorq_collectors.linux`) | all snapshots; `linux.last_run.*` (inventory, packages, posture schedules), `linux.inventory.last_full`, `linux.services.last_event` | `journal.cursor`, `audit.inode`, `audit.offset`; first-seen history, known units |
| macOS (`extorq_collectors.macos`) | all snapshots; `macos.sources` (per-source schedule), `macos.full_inventory`, `macos.adapter_last_event` | `unified_log.window` |
| Kubernetes (`extorq_collectors.kubernetes`) | object, service, instance and asset snapshots; `k8s.last_full_refresh` | `k8s-events` snapshot (Event versions already emitted), `k8s.last_cycle`, `k8s.events_last_success` |
| GitHub (`extorq_collectors.github`) | inside each `github:repo:*` checkpoint: settings, protection, branch info, inventory key lists, ETags, posture/alerts/asset schedules | branch heads (commits), workflow-run tracking, activity id, change sequence, commit retries |
| any other collector | all snapshots | checkpoints and KV |

A collector that adds state keys keeps its row of `POLICIES` in sync
(`tests/unit/platform/test_platform_reset.py`). `rebaseline` refuses while a collector
holds an instance lock (`*.lock` in its state directory) and never creates state.

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
requeue, runner isolation, health sanitisation, degraded hint, committed snapshots,
string-only config secret check, asset upserts) with the in-process fake
gateway `tests/unit/platform/fake_gateway.py`;
`tests/unit/platform/test_platform_reset.py` (re-baseline policies on real state DBs);
`tests/unit/platform/test_platform_collectors_ctl.py` (background runner start/stop/
status with a fake `uv`); `tests/failure/test_failure_durability.py` exercises a real
outbox across gateway and writer restarts.

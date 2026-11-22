# Detection engine

Owner: C2. Code: `backend/src/extorq/detection/`. Rules: `rules/`. Service: `extorq detector`
(compose service `detector`, profile `full`). Everything below describes implemented
behaviour; items marked **planned** are not built.

Deterministic collection and detection establish the evidence. The engine runs
versioned SQL rules over stored telemetry, writes alerts with explicit evidence, and
never uses AI.

## 1. Rule format

A rule is two files under `rules/<domain>/`:

* `<RULE-ID>.yaml`: metadata that maps 1:1 onto `contracts.alert.RuleMetadata` plus
  four loader keys.
* `<RULE-ID>.sql`: one ClickHouse `SELECT` (or `WITH ... SELECT`).

| YAML key | Meaning |
|---|---|
| `rule_id`, `version` (semver), `title`, `description`, `severity`, `status` | identity and presentation; `status` is `stable`, `experimental` or `deprecated` |
| `mitre_techniques`, `asset_types` | ATT&CK ids; asset types a result row may carry (other types are rejected) |
| `requires` | list of `{source_type, event_types, optional}`; every event type must be emitted by that source type according to `contracts/catalog.py` |
| `schedule` | `interval_seconds` (how often), `lookback_seconds` (window length), `late_tolerance_seconds` (extra overlap for late events) |
| `dedup` | `strategy: window_bucket` with `bucket_seconds` (threshold rules) or `strategy: event` (single-event rules) |
| `group_by`, `params`, `false_positives`, `blind_spots`, `references` | grouping documentation; SQL parameters; analyst guidance |
| `query` | SQL file name (must stay inside `rules/`) |
| `summary_template` | deterministic alert summary, `{placeholder}` syntax only (no attribute access, no format specs); values are sanitised and truncated |
| `tests` | fixture cases: `name`, `fixture` (JSONL inside `rules/`), `expect: alert|no_alert`, optional `alerts`, `confidence`, `entities`, `features` (exact expected feature values), `summary_contains` (substrings of every summary), `now`, `description` |
| `enabled` | optional, default `true`; disabled rules are registered with `enabled = 0` and never run |

`query_sha256` is computed by the loader from the SQL text and must not be written by
hand; it identifies exactly what ran (stored in `detection_rules` and in every
investigation context).

### SQL contract

* Parameters are ClickHouse server-side placeholders only. `{window_start:DateTime64(3, 'UTC')}`
  and `{window_end:DateTime64(3, 'UTC')}` are mandatory; `{bucket_seconds:UInt32}` is
  available to `window_bucket` rules; every other placeholder must be declared in `params`
  with a value of the matching type (`String`, `(U)Int*`, `Float*`, `Bool`, `Array(...)`).
* Tables include `events`, `assets`, `inventory_items`, `finding_observations`,
  `scan_runs` (optionally `extorq.`-qualified) and CTEs defined in the query.
* Output columns: `group_key String`, `asset_id String`, `asset_type String`,
  `first_seen`/`last_seen DateTime64(3, 'UTC')`, `event_count UInt64`,
  `evidence_event_ids Array(String)` (bounded, earliest first), `entities Map(String, String)`,
  `features String` (JSON object), `confidence` (`high|medium|low`, from evidence
  completeness), plus `bucket_start DateTime64(3, 'UTC')`
  (window_bucket) or `signature String` (event). Optional `supporting_event_ids` marks
  evidence with role `supporting` instead of `trigger`.
* Duplicate safety: de-duplicate inputs by `event_id` (`LIMIT 1 BY event_id`) and count
  with `uniqExact`. The table is a ReplacingMergeTree, so rows may be duplicated until a
  merge.
* Controlled validation activity uses the same native sources and rule predicates as other
  activity. Version 2 validation reports map action, verified event IDs and alert IDs.

### Static validation (`extorq rules validate`, `registry.py`, `sqlguard.py`)

All problems are collected and reported together: YAML shape, the `RuleMetadata`
contract, catalog membership of required event types, `schedule.lookback_seconds >=
interval_seconds + params.window_seconds`, dedup coherence, test fixture paths, unique
rule ids and the SQL guard. The guard is defence in depth (the authoritative boundary is
the readonly ClickHouse identity, section 2). It rejects:

* more than one statement, `;`, block or `#` comments, quoted identifiers, `$` heredocs,
  backslashes or non-ASCII outside string literals;
* statement and settings keywords (`INSERT`, `ALTER`, `DROP`, `SYSTEM`, `SETTINGS`,
  `INTO`, `FORMAT`, `SET`, `GRANT`, ...);
* table functions (`url()`, `file()`, `remote()`, `s3()`, `mysql()`, ...), dictionary
  access, `system.*`, other databases, tables outside the allow-list, comma joins, CTE
  names that shadow a database object;
* undeclared or mistyped parameters, or a top-level result cap.

## 2. Evaluation

`DetectionEngine.run_once(now)` evaluates every due rule (each on its own
`interval_seconds`). For one rule at time `now`:

```
window = [now - lookback_seconds - late_tolerance_seconds, now - ingest_delay)
```

`ingest_delay` (default 10 s, `EXTORQ_DETECTOR_INGEST_DELAY_SECONDS`) keeps batches that
are still being written out of the window. Consecutive windows overlap heavily
(`lookback >> interval`), so an event that arrives late is evaluated again by later runs.

**Late-data catch-up.** Telemetry can arrive long after it happened: a collector that
starts, recovers from an outage or backfills a journal (observed live: B1's collector
delivered sshd and nginx lines ~26 minutes after they were written, outside VM-001's
20-minute window). Before each evaluation the engine asks which events of the rule's
source types were *ingested* since the rule's last successful run (minus 300 s margin for
writer batching; on the first run after a start: the whole horizon) with an `event_time`
before the normal window. If there are any, that evaluation's window starts at
`earliest late event - lookback` (bounded by `EXTORQ_DETECTOR_CATCHUP_MAX_SECONDS`,
default 6 h; 0 disables). Alert identities do not depend on the window, so a longer
window never duplicates alerts. Consequence: a detector restart evaluates up to 6 hours
of telemetry that arrived while it was down (observed 2026-11-21 20:27Z: the restarted
detector re-evaluated the afternoon with the new rule versions; 0 alerts created, 0
updated). Regression test: `test_late_burst_ingested_after_its_window_alerts_exactly_once`
(the detector runs first, the burst is ingested 26 minutes late, six later runs: exactly one
alert creation, one stored version, the full evidence).

Identities and privileges:

| Step | ClickHouse identity |
|---|---|
| rule SQL | `extorq_rules_ro` (`readonly=1`, SELECT on the approved telemetry tables) |
| missing-source probe, existing alerts and evidence, service lookup | `extorq_detect` |
| writes: `alerts`, `alert_evidence`, `rule_runs`, `detection_rules`, `pipeline_health`, contexts | `extorq_detect` |

Every result row is validated (`alerts.parse_row`): asset id format, declared asset type,
aware timestamps, at least one valid 32-hex evidence id, JSON features, confidence value.
Before applying a batch, the detector resolves every cited ID to a single stored event
identity and checks its asset, event-time window, and declared source and event type.
Evidence associations retain the verified event timestamp. A malformed row, missing
output column, or unverifiable
evidence reference fails the run.

## 3. Alert identity, deduplication and late events

* `alert_id = identity.alert_id(rule_id, group_key, bucket_start | signature)`. The rule
  **version is deliberately excluded**, so upgrading a rule does not duplicate open alerts.
* Before writing, the engine loads the newest stored version of each candidate alert
  (`ORDER BY updated_at DESC LIMIT 1 BY alert_id`, duplicate-safe) and the full evidence
  set from `alert_evidence`.
* New identity: a new alert (`created_at = updated_at = now`).
* Existing identity with new evidence (late events, overlapping windows): a new version
  with `created_at` preserved, `updated_at` strictly increased, `first_seen`/`last_seen`
  widened, `event_count` never decreasing, confidence monotone within the same rule
  version, numeric features max,
  boolean features OR, lists unioned. Only evidence ids never stored before get new
  `alert_evidence` rows. A row that adds nothing writes nothing (re-running a window is
  idempotent).
* `window_bucket` continuity: a row whose activity is continuous with an existing alert of
  the same asset and group (gap <= `bucket_seconds`, total span <= `max_episode_seconds`, default
  3600 s) extends that alert, so a burst crossing a bucket boundary yields one alert.
* The alert array `evidence_event_ids` holds at most 500 ids (`evidence_truncated = true`
  beyond); `alert_evidence` holds the full set.
* `alert_evidence` rows are written before the alert version with its publication
  timestamp. If publishing the alert is interrupted, a matching subsequent evaluation
  reuses the stored associations and publishes the missing alert update.
* `service_ids` (contract 1.1): the services of the evidence events: the producing service
  (`events.service_id`, falling back to the validated `payload` JSON) and the subject
  service the record is about (`attributes.subject_service_id`, e.g. the unit's own service
  for a unit-file change produced by systemd). A reference is dropped when the only valid
  service records for that id belong to an unrelated asset (service-id shadowing, F-IC-6:
  a record is valid only if its id recomputes from `(asset_id, service_kind, service_key)`).
  The lookup never blocks an alert write.
* Summaries are rendered from `summary_template` with sanitised values (no AI).

### Rule upgrades and stored alerts

When a different rule version matches the same alert identity, the detector publishes
the confidence, features, and summary from that evaluation. The first creation time
and accumulated evidence associations preserve the alert history. The latest evidence
array prioritizes the events selected by the new version. Alerts that do not match
the new version retain their last published version. A dry run shows the evidence the
current rule would use. Explicit evidence roles for superseded references are **planned**.

### Dry run against stored telemetry

```bash
uv run python -m extorq.detection.dryrun --rule CORR-002 \
    --start 2026-11-21T14:00:00Z --end 2026-11-21T16:30:00Z
```

Evaluates the current rule definition over a historical window exactly as the engine does
(rule SQL as `extorq_rules_ro`, row validation, alert identity, window-bucket continuation)
and compares every row with the stored alert it would create (`NEW`) or extend (`STORED`):
the evidence this version produces, by event type and source type, and stored evidence it
no longer produces. Nothing is written (the store is wrapped in a client that refuses
writes); reads use `extorq_api_ro` (or `--read-role detect`); the window is limited to 7
days; telemetry values are sanitised. Use it before deploying a rule change and to explain
historical alerts after one.

## 4. Rule runs, health and failure handling

* Every evaluation writes a `rule_runs` row: status (`succeeded|failed`), rows matched,
  alerts created/updated, duration, sanitised error (single line, secrets redacted,
  bounded), and `missing_sources` = required source types (optional ones included) with
  no events at all in the window.
* A failing rule never stops the others (each evaluation is isolated).
* The engine probes up to one row beyond `MAX_ROWS_PER_RULE`. When the probe exceeds
  that size, a single full-window query streams the ordered result in bounded batches.
  SQL window functions and aggregates still see the original event window. Completed
  batches can publish alerts while the query is running. A stream or validation error
  records a failed run and preserves the last-success watermark. The running detector
  retries the same saturated window at the next scheduled evaluation. A process
  restart uses the configured late-data catch-up horizon. On large runs, alert update
  counts reflect versions written per batch.
* ClickHouse unavailability: queries retry transient errors with exponential backoff and
  full jitter (3 attempts), then the run fails with a sanitised error. Rule-run records
  are kept in a bounded in-memory backlog (1000) and flushed later; dropped ones are
  counted.
* `pipeline_health` (component `detector`, every 30 s): `ok`, `degraded` (some rules
  failing, backlog, invalid rules), `failed` (no rules or all failing), `unknown` (no cycle
  yet), with counters (runs, failures, alerts created/updated, contexts built/failed).
* `detection_rules` is populated on start; rules that disappeared are re-registered with
  `enabled = 0`.
* After alerts are created or updated, the correlation builder builds and stores an
  InvestigationContext per alert (at most 50 per evaluation). Correlation failures are
  logged and counted; they never fail detection.

## 5. Running it

```bash
uv run extorq rules validate                      # static validation of every rule
uv run extorq rules test                          # fixture harness (Docker, section 6)
uv run extorq detector --once                     # one forced evaluation of every rule
docker compose --profile full up -d --build --no-deps detector  # rebuild + recreate (owner C2)
docker compose --profile full restart detector    # rule-only changes (rules are bind-mounted)
uv run python -m extorq.detection.dryrun --rule <ID> --start <UTC> --end <UTC>  # read-only
uv run extorq context build <alert_id>            # (re)build + store a context
```

Settings (`EXTORQ_DETECTOR_*`, no secrets): `RULES_DIR`, `INGEST_DELAY_SECONDS`,
`MAX_ROWS_PER_RULE` (result batch size, 1000), `MAX_EPISODE_SECONDS`, `POLL_SECONDS`,
`HEALTH_INTERVAL_SECONDS`, `INSTANCE`, `CORRELATION_ENABLED`, `MAX_CONTEXTS_PER_RUN`,
`STARTUP_ATTEMPTS`. ClickHouse credentials come from A's settings (password files).

## 6. Rule test harness

`extorq rules test` and `uv run pytest tests/rules` start an ephemeral
`clickhouse/clickhouse-server:26.8.42.13` container `extorq-c2-rules-ch-<pid>-<random>` on a
random loopback port (throwaway admin password via a 0600 env file deleted after start;
the name is unique per run, so two sessions running the suite at once never touch each
other's container, and only leftovers of processes that no longer exist are removed), apply
migrations 0001, 0003–0006 and 0008–0009, create users mirroring `extorq_rules_ro` (readonly) and
`extorq_detect`, and for each declared test case:

1. truncate, load the JSONL fixture (validated by the contracts), shift it by whole days
   (bucket alignment preserved), insert through A's `extorq.storage.rows.to_row`;
2. run the real `DetectionEngine` for that rule at a fixed `now`;
3. assert the expectation (alert / no alert, count, confidence, entities, expected feature
   values, summary substrings) and integrity (evidence ids
   exist in `events`, `alert_evidence` holds the full set, `event_count >= evidence`).

The container is always removed. Engine properties are tested on the same server:
duplicate replay is idempotent for every rule, late events extend (not duplicate)
alerts, identities are stable across fresh detector state, a failing rule is recorded
and isolated, rule SQL cannot read `alerts` (privileges), missing sources are reported,
`service_ids` come from the evidence (and shadowing references are ignored), late
telemetry is caught up exactly once, a saturated result matches the original window,
and the dry run writes nothing.

Fixtures are synthetic and labelled (`labels: {"extorq.fixture": "synthetic"}`,
collector/parser `fixture-synthetic`, RFC 5737 addresses), regenerated deterministically
by `uv run python tests/rules/generate_fixtures.py [--only <builder>]`. Kubernetes
fixtures are derived from audit records captured from the real kind cluster by B2 and
normalised with B2's own normaliser (`derived-captured`); GitHub attributes are computed
by C1's workflow analyser. Two kinds of fixtures carry genuine data:

* `tests/rules/captures/k8s_cluster_birth_live.jsonl`: ten normalised audit events of the
  lab cluster's birth (2026-11-21 10:16Z), exported read-only from the live store with
  `raw` and client-certificate fingerprints removed (labelled `derived-captured`); the
  K8S-002 bootstrap fixtures are derived from it.
* `rules/github/tests/GH-001/c1_*.jsonl`: verbatim copies of C1's collector-output fixtures
  (real collector code path over a synthetic GitHub API fake);
  `tests/rules/test_gh001_collector_contract.py` runs GH-001 on C1's current files too.

## 7. Adding a rule

1. Check the event catalog (`contracts/catalog.py`) and the producer's interface notes
   (`docs/team/interface-changes/`) for the fields the source genuinely populates.
2. Write `rules/<domain>/<ID>.yaml` + `.sql` following sections 1 to 3; derive confidence
   from evidence completeness, never from a guess about maliciousness.
3. Add positive and negative fixtures (extend `tests/rules/generate_fixtures.py`), with
   false-positive and blind-spot notes in the YAML.
4. `uv run extorq rules validate && uv run pytest tests/rules -q`.
5. Document it in `docs/detection-catalog.md`; restart the detector
   (`docker compose --profile full restart detector`) to load it (rules are read at start).

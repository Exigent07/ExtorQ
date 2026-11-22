# ExtorQ data flow: from collection to visualisation

Owner: platform. Describes the implemented path and its exact guarantees (contract
schema 2.0). Code:
`collectors/src/extorq_collectors/sdk/`, `backend/src/extorq/ingest/`,
`backend/src/extorq/pipeline/`, `backend/src/extorq/storage/`.

```
collector (SDK) --emit--> SQLite outbox --HTTPS+token, gzip--> ingest gateway
  checkpoint+records          (per collector)                 validate, authorize,
  in ONE transaction                                          redact, dedup, quarantine
                                                                   |
                                         SQLite spool (WAL, synchronous=FULL) <- commit BEFORE 202
                                                                   |
                                                   writer --batched INSERT--> ClickHouse
                                                   (delete only after ack)        |
            detector (rules, correlation) <-------------------------------------+
            API / console / Grafana (read)  <-----------------------------------+
```

Kubernetes container logs and API audit logs take the same gateway path through the
OTel Collector DaemonSet (`POST /v1/otlp/v1/logs`, OTLP/HTTP JSON); its exporter
retries from a node-persistent sending queue. `POST /v1/otlp/v1/metrics` carries
the Collector's allow-listed delivery counters over a separate exporter. The
gateway records node and source health through the same durable spool. See
[Kubernetes telemetry](telemetry/kubernetes.md#31-delivery-health).

## 1. Collection (collector SDK)

* `ctx.emit(records, checkpoints)` validates **every** record against the contracts
  first, then commits outbox rows, checkpoint updates and snapshots staged by
  `ctx.diff_snapshot` in **one** SQLite transaction (`var/collectors/<id>/state.db`,
  WAL, `synchronous=FULL`, 0600).
  * Crash **before** the commit: nothing is recorded and the checkpoint did not move,
    so the next cycle re-reads the same source range.
  * Crash **after** the commit: the outbox is durable; it is sent later.
  * Re-reads produce the same deterministic ids, so repeats collapse downstream.
* A snapshot advances only with an explicit `emit`; after a failed cycle the runner
  discards staged snapshots, so a diff is never "consumed" without its records.
* CollectorHealth is emitted by the runner every cycle (also when `collect` fails):
  status, last attempt/success, lag, outbox depth, sanitised last error. Status is
  `failed` when `collect` raised, `degraded` when it completed but called
  `ctx.mark_degraded(reason)` (partial success, e.g. one source of several failed) or
  delivery is failing / records were dead-lettered, else `ok`. A degraded cycle still
  advances `last_success_at`; its reasons appear in `last_error` (`degraded: ...`) and
  `details.degraded_reasons`.
* Host collectors run continuously as one background process
  (`make collectors-start | collectors-stop | collectors-status`, see
  [collectors.md](collectors.md#4-running)).

## 2. Transport (SDK sender -> gateway)

* TLS 1.2+ to `https://127.0.0.1:8443` (`host.docker.internal` from kind pods,
  `10.0.2.2` from the VM), trust pinned to `var/tls/ca.crt` (system store not used),
  hostname verification on. Server side: ECDSA P-256 certificate, AEAD-only TLS 1.2
  suites.
* Bearer token per producer (`var/secrets/tokens/<producer_id>.token`); the gateway
  stores only SHA-256 digests and compares against **all** registered digests with
  `hmac.compare_digest` (no early exit).
* Batches of at most 500 records / ~3.5 MB JSON, gzip, `batch_id` assigned once and
  **reused on every retry** of the same rows.
* Delivery policy:

| Gateway answer | SDK behaviour |
|---|---|
| 202 (incl. `replayed=true`) | delete those rows from the outbox |
| timeout, connection error, 408, 429, 5xx, 503 | keep; exponential backoff 1 s -> 60 s, equal jitter, at least `Retry-After` (capped at 300 s) |
| 401 | keep everything; 60 s backoff; health shows the error |
| 400/404/405/415/422 (systemic: version skew or misconfiguration) | keep everything; 60 s backoff; health shows the error |
| 403 | bisect the batch; authorized halves flow; a single unauthorized record moves to `outbox_dead` |
| 413 | split the batch |
| 409 (batch id reused with other content) | re-issue batch ids |
| other 4xx | move the batch to `outbox_dead` (counted in health; `extorq-collect flush --requeue-dead`) |

## 3. Ingest gateway (`POST /v1/ingest`)

Order of checks (any failure before step 6 answers without storing records):

1. **Authentication** -> 401 (`WWW-Authenticate: Bearer`), audited in `ingest_audit`
   (rate-limited to 60 rows/min for unauthenticated attempts; excess counted).
2. **Content type** must be `application/json` -> 415; `Content-Encoding` identity or
   gzip -> 415 otherwise.
3. **Size**: `Content-Length` > 4 MiB -> 413 before reading; the body is read as a
   stream and rejected once it exceeds 4 MiB (chunked uploads included); gzip is
   inflated incrementally with a 4 MiB output cap (bomb guard; truncated, trailing or
   multi-member streams -> 400). Body read timeout 30 s -> 408.
4. **Backpressure**: spool depth >= `EXTORQ_SPOOL_MAX_RECORDS` (200 000) or free spool
   disk < 256 MiB -> **503 + `Retry-After: 30`** (checked before reading the body).
5. **Envelope**: strict JSON (`NaN`/`Infinity` tokens -> 400), `IngestBatch` validation
   -> 422 (including any `schema_version` other than `2.0`); > 1000 records -> 413;
   `producer_id` must equal the token's producer -> 403.
6. **Replay**: a known `(producer_id, batch_id)` with identical content returns the stored
   `IngestResult` with `replayed=true` (same content hash required, else 409).
7. **Per record**, in order: size <= 64 KiB; contract validation (a schema 1.x record
   or a record of a kind schema 2.0 removed, such as `simulation_run`, is quarantined as
   `invalid_record`); **authorization**
   (kind, asset pattern, source types; any unauthorized record -> **403 for the whole
   batch**, audited, nothing stored); catalog semantics; time sanity (`event_time`
   more than 1 day in the future -> `time: event_time_in_future`; `event_time` older
   than the `events` retention of 90 days -> **`older_than_retention: ...`**, because
   ClickHouse's TTL would delete such a row right after a 202; other kinds' timestamps in
   the future -> quarantine); **secret redaction** of free-text fields (event
   `message`/`raw`/`process.command_line`/`http.user_agent`/`http.route`/attribute and
   label strings; finding, scan, health and service free text) with the
   count added to `provenance.redaction_count`; storage compatibility (`to_row`);
   identity. Redaction is JSON-safe: key-based rules only replace string values in
   structured text, never `true`/`false`/`null` or (after a quoted key) numbers and
   arrays, so a JSON document stored in an attribute (e.g. a Kubernetes
   `request_summary` with `"automount_sa_token": false`) stays valid JSON. Service and
   instance ids must derive from the record's own fields (`identity_mismatch`
   otherwise, so a producer cannot publish rows under another asset's service id). A
   failure in any of these quarantines **only that record**; an unexpected exception in
   one record (identity, serialisation) is also quarantined, never a 500.
   A `service_instance` without `asset_id` is quarantined (`asset_unattributable`).
8. **Deduplication.** A security event receives a server-derived `accepted-event.v2`
   identity scoped to its authenticated producer, asset, source and event type. The
   gateway uses the stable native reference where available and otherwise the normalized
   evidence fingerprint. A matching key and fingerprint is a replay. A matching key
   with different evidence goes to quarantine as `event_identity_conflict`, with its
   canonical ID and payload digest. Non-event records retain the existing seven-day
   `(kind, record_identity)` index.
9. **Commit**: accepted records, quarantine rows (sanitised, redacted excerpt <= 4 KiB +
   SHA-256 of the original), identity receipts and the batch result go into the spool in **one
   transaction**; only then the gateway answers **202**.

The transaction enforces the queue-depth bound again after counting accepted and
quarantined rows. If the batch would exceed the bound, the transaction rolls back
and the gateway returns `503`. A later retry can submit the same batch.

The event fingerprint includes normalized evidence, the source observation time
(`event_time`), and raw evidence hashes when available. Collection time, reporter
and parser software identifiers, transport metadata and redaction counters do not
affect the digest. If a source cannot distinguish two byte-equivalent observations
at the same event time, the fallback collapses them. The identity ledger lives in
SQLite through the event retention horizon plus the configured future-time allowance.
Seed historical receipts before resuming producers on an existing database. See
[identity migration](deployment.md#event-identity-upgrade).

Why 403 for the whole batch: a producer sending records outside its registration is
misconfigured or compromised; accepting the rest would let it probe the boundary
silently. The SDK bisects so legitimate records still arrive.

`GET /healthz` (no auth, `{"status":"ok"}` only) and `GET /v1/status` (any producer
token; spool depth, oldest age, dead letters, counters, `schema_version` and
`accepted_schema_versions` (`["2.0"]`) and the acceptance window
`limits.max_future_seconds` / `limits.event_retention_days`) support operations. Every
30 s the gateway writes `PipelineHealth(component="ingest")`.

**Producer registry.** `var/secrets/producers.json` is rebuilt by `make bootstrap` from
`scripts/bootstrap.py` `PRODUCERS` only, so a retired producer (`simulation-runner`,
schema 2.0) is never authorized again even when its token file is left on disk
(bootstrap reports such files by id). A registry written before schema 2.0 still loads:
kinds the contracts no longer define are dropped and an entry left without kinds is
skipped (fail closed, logged as `producer_registry_entries_adjusted`).

The retention window is `EXTORQ_EVENT_RETENTION_DAYS` (default 90). It must equal the
`events` TTL in `0001_core_tables.sql`; `tests/unit/platform/test_platform_gateway.py`
parses the DDL and fails on drift. Other kinds keep their own TTL columns (`observed_at`,
`last_seen`, `reported_at`, ...) and are only refused for future timestamps.

## 4. Spool (`extorq.pipeline.spool`)

SQLite on the `spool` volume shared by gateway and writer: WAL journal,
`synchronous=FULL` (the WAL is fsynced on every commit), `busy_timeout` 10 s, short
transactions only (never held across network I/O). Tables: `records` (queue),
`batches` (idempotency results), `dedup` (record keys), `dead_letter`, `counters`.

`extorq spool status` prints the row count of each table; `extorq spool clear --yes`
empties all of them in one transaction (only with gateway and writer stopped; used by
`make reset-data`, see [data-model.md](data-model.md#61-clean-slate-make-reset-data-yes1)).
After a contract upgrade the spool must be drained or cleared before the new writer
runs: records spooled under an older schema can no longer be decoded and would be
dead-lettered.

## 5. Writer (`extorq writer`, identity `extorq_ingest`)

* Fetches up to 2000 ready records (~16 MiB), decodes each with `to_row`, groups by
  table and inserts each group.
* **Deletes spool rows only after ClickHouse acknowledged the INSERT** that contained
  them.
* **Transient** failures (connection errors, timeouts, memory/parts pressure,
  read-only, quota, authentication/authorization or missing-schema errors: a
  deployment problem, never the data's fault) consume **no** attempts: the writer drops
  the connection and backs off exponentially (0.5 s -> 30 s, equal jitter), keeping
  every record.
* **Data** errors bisect the batch; only records that fail alone consume an attempt;
  after `EXTORQ_WRITER_MAX_ATTEMPTS` (8) they move to `dead_letter` with a sanitised
  error and are counted in health (`dead_letter_total`, status `degraded`).
* Every 30 s: `PipelineHealth(component="writer")` with queue depth, oldest queued
  age, written/error/dead-letter counters and last write time. A heartbeat file feeds
  the container healthcheck.

## 6. Guarantees

| Property | Guarantee |
|---|---|
| Acknowledgement | 202 means the records are durably committed to the spool (survives process crash and power loss of the Docker VM, given fsync honoured by the storage). |
| Delivery to ClickHouse | **At least once.** A crash between the INSERT acknowledgement and the spool delete re-inserts rows. **Not exactly-once.** |
| Duplicates | Logical duplicates share deterministic ids: the gateway drops repeats within 7 days, `ReplacingMergeTree` collapses them at merge time, and queries are duplicate-safe (`uniqExact`, `argMax`, `FINAL`, `v_*` views). |
| ClickHouse outage | No loss: the gateway keeps accepting (it never talks to ClickHouse), the spool grows, the writer retries without consuming attempts. Bounded by spool capacity (503 + Retry-After beyond it; collectors keep buffering). |
| Gateway outage | Collectors keep records in their outboxes and retry with backoff. |
| Ordering | Not guaranteed across batches or producers; consumers use `event_time`. |
| Poison records | Isolated by bisection; dead-lettered after 8 attempts; visible in health. |
| Unauthorized/forged records | Never stored; 401/403 audited in `ingest_audit`. |
| Retention-aligned acceptance | A 202 never covers an event the `events` TTL would expire at once: events older than 90 days (and more than 1 day in the future) are quarantined with a reason visible to the producer (`IngestResult.quarantined`) and in `ingest_quarantine`. |
| Record integrity under redaction | Redaction replaces secret string values only; JSON booleans, numbers and nulls are never rewritten, so structured attributes stay parseable. |
| Partial collector failures | Visible as `degraded` (reasons in `last_error` and `details.degraded_reasons`), never reported as `ok`. |

Verified (commands and results in `docs/team/status/A.md` and `docs/team/status/P.md`):
`tests/failure/test_failure_durability.py` (ClickHouse stopped: 100/100 buffered events
delivered after restart; gateway and writer restarted during an 800-record stream:
800/800 delivered), `tests/integration/platform/test_platform_live.py` (round trip,
replay/dedup counts, 401/403 audit, RBAC matrix, retention quarantine and JSON-safe
redaction on the deployed gateway), and the unit suites under `tests/unit/platform/`.

## 7. Downstream (owned by other teams)

* **Detection**: versioned SQL rules run by the detector as `extorq_rules_ro`,
  alerts written as `extorq_detect` only; correlation builds InvestigationContexts.
* **AI**: Jev triage in the ai-worker writes advisory `ai_assessments` only; disabled
  unless the operator enables it (`make up-demo`). There is no other AI provider.
* **API** reads as `extorq_api_ro` and writes analyst state as `extorq_api_writer`;
  the **console** talks only to the API; **Grafana** reads as `extorq_grafana`
  (no `events.raw`/`payload`).

## 8. Observability of the pipeline

`extorq.pipeline_health` / `v_pipeline_latest` (ingest, writer, detector, ai-worker),
`extorq.collector_health` / `v_collector_latest`, `extorq.ingest_quarantine`,
`extorq.ingest_audit`, `GET /v1/status`, `make collectors-status` (background runner +
local outboxes, read-only) and `make demo-check`, a read-only readiness report: compose
services and endpoints, telemetry per asset class (fresh state records for the macOS
host, the Ubuntu VM, the Kubernetes cluster and the GitHub repository; fresh events where
the sources never go quiet: Linux journald, Kubernetes audit), collector health and
freshness, rule runs (every rule ran in the last 15 min, no failure in 24 h), quarantined
records and refused requests (warnings), and the newest detection-test report per asset
(`var/reports/detection-tests-*.json`: every positive test alerted, every negative
control stayed silent, at least five distinct tests per asset). It works without the
debug proxy by querying inside the `api` container.

STACK READY 2026-11-21T10:36:49Z - gateway https://127.0.0.1:8443 (CA var/tls/ca.crt), producer tokens var/secrets/tokens/<producer_id>.token, ClickHouse debug proxy 127.0.0.1:18123 (profile debug; users per PLAN 4.4, passwords var/secrets/clickhouse/)

# Agent A status (Platform & Data)

Last update: 2026-11-21T10:36:49Z

## How to use the stack (for other agents)
- Core stack is running: `docker compose ps` (clickhouse, migrate, ingest, writer; plus
  clickhouse-debug from profile `debug`). Do not stop/restart services you do not own.
- Gateway: `POST https://127.0.0.1:8443/v1/ingest` (IngestBatch JSON, gzip ok),
  `Authorization: Bearer <contents of var/secrets/tokens/<producer_id>.token>`, CA `var/tls/ca.crt`.
  Responses per PLAN 5.1; 403 rejects the WHOLE batch when any record is outside the producer's
  kinds/source types/assets (audited in `extorq.ingest_audit`).
- OTLP: `POST https://127.0.0.1:8443/v1/otlp/v1/logs` (OTLP/HTTP JSON only, gzip ok, token of
  `k8s-otel-extorq-lab`). Returns 503 until B2's `extorq/ingest/otlp_k8s.py` exists AND the
  image is rebuilt (`docker compose up -d --build ingest` is run by A on request).
- ClickHouse from the Mac: `127.0.0.1:18123` (HTTP, debug proxy). In Python:
  `extorq.storage.clickhouse.get_client("<role>")` reads `var/secrets/clickhouse/<user>_password`
  (defaults: host 127.0.0.1, port 18123, database extorq). Roles: admin (migrations only), ingest,
  detect, rules_ro, ai, api_ro, api_writer, grafana.
- Grafana user cannot read `events.raw` / `events.payload` (so no `SELECT *` on events) nor
  `ingest_quarantine.payload_excerpt`.
- clickhouse-connect returns DateTime64(3,'UTC') values as naive datetimes that are UTC.
- Synthetic platform test events carry `labels['synthetic'] = 'true'` (event type
  system.log.notable, asset macos:workstation-01); dashboards/rules may filter them.
- Gap events: `extorq.collector.gap_detected` (source extorq.pipeline) are accepted from a producer
  when `attributes.source_type` is one of ITS allowed source types (see interface-changes/A.md).

## Done
- bootstrap (secrets, TLS CA + gateway cert, producers.json), extorq.common (config, logging,
  redaction), ClickHouse config + RBAC migration 0002 + migration runner, rows mapping,
  ingest gateway (HTTPS, auth, authz, limits, validation, redaction, quarantine, dedup, replay,
  durable spool, OTLP endpoint), writer, compose (core + full + debug profiles), backend image,
  root CLI.

## Verified
- `uv run python scripts/smoke_ingest.py` -> gateway HTTP 202 accepted=1; event read back from
  ClickHouse as extorq_api_ro via 127.0.0.1:18123 (round trip 0.66 s).
- `docker compose ps` -> clickhouse/ingest/writer healthy, migrate exited 0 (0001, 0002, 0003 applied).
- unauthenticated GET /v1/status -> 401 and an `ingest_audit` row (decision unauthenticated).

## Not verified
- unit/integration/failure test suites (being written now), SDK (next), Makefile, CI, docs.

## Blockers
- none

## Next
- Collector SDK (B1, B2, B3, C1, C3 are waiting), Makefile, unit tests, integration + failure tests,
  CI, docs.

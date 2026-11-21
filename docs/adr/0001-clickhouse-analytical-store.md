# ADR 0001: ClickHouse as the analytical store

Status: accepted, implemented (`compose.yaml`, `infra/clickhouse/`). Date: 2026-11-21.

## Context
Security telemetry is append-heavy and read by time window and asset:
detections count distinct connections per source in sliding windows, analysts
filter by asset, service and time, and dashboards aggregate over days. ExtorQ
runs on one laptop, rule SQL must be reviewable and parameterised, and
different consumers need different privileges (Grafana must not read raw log
payloads).

## Decision
One ClickHouse server (`clickhouse/clickhouse-server:26.8.42.13`, pinned by
digest) on the internal compose `data` network. Events go to a `MergeTree`
table with a 90-day TTL; latest-state data (assets, alerts, services, health)
goes to `ReplacingMergeTree` tables read through `v_*` views. Each service has
its own user and role (`0002_rbac.sql`): rule SQL runs as `extorq_rules_ro`
(`readonly=1`), the API reads as `extorq_api_ro`, Grafana has column-level
grants without `events.raw`/`payload`. Queries use server-side parameters
(`{name:Type}`).

## Consequences
* Fast window aggregations and ordered-sequence functions (`windowFunnel`)
  for rules; strong compression; SQL rules are reviewable text.
* Column-level grants and settings profiles give least privilege per consumer.
* Merges are eventual: duplicates are visible until merged, so reads use
  `FINAL`, `argMax` and `uniqExact(event_id)` (ADR 0008). Sorting keys are not
  unique keys.
* No transactions or foreign keys; updates are new versions of a row.
* Memory pressure on a laptop (3 GiB container limit, memory ratio caps).

## Alternatives considered
* PostgreSQL/TimescaleDB: transactions and simple updates, but slower large
  scans and weaker compression for this workload.
* Elasticsearch/OpenSearch: strong full-text search, but a heavy JVM footprint
  and a less reviewable query language for detections.
* SQLite only: no concurrent analytical access.
* Loki: cheap log storage, but no relational SQL for detections and joins.

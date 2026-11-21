# ADR 0008: Deterministic identities with ReplacingMergeTree (at-least-once delivery)

Status: accepted, implemented (`backend/src/extorq/contracts/identity.py`,
`infra/clickhouse/migrations/`). Date: 2026-11-21.

## Context
Collectors re-read sources after crashes, outboxes retry, the writer may insert
a batch twice, and rule windows overlap so late events are re-evaluated.
Exactly-once delivery across these hops is impractical on one laptop.

## Decision
Every record has a deterministic identity derived from its natural key
(`event_id(source_type, asset_id, native_key)`, `finding_id`,
`alert_id(rule_id, group_key, bucket)`, `context_id`, `assessment_id`, and in
1.1 `service_id(asset_id, kind, key)` and `instance_id(service_id, kind, key)`),
using namespaced, versioned hashes (`*.v1`). Latest-state tables are
`ReplacingMergeTree` keyed on these identities; readers use `v_*` views,
`FINAL`, `argMax` and `uniqExact(event_id)`. Delivery is at-least-once.

## Consequences
* Replays and retries are harmless: duplicates collapse, alerts are not
  inflated, re-running a rule window is idempotent.
* Queries must be duplicate-safe; a naive `count()` over raw tables is wrong.
* Identity changes need a new namespace version (`*.v2`), never an in-place edit.
* Identity parts are joined with an unescaped separator; safe today because at
  most one free-text part is adjacent to constrained parts (F-IC-4).

## Alternatives considered
* Exactly-once with transactional outbox to ClickHouse: not supported end to end.
* Random UUIDs plus deduplication tables: more state, no natural idempotency.

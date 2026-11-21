# ADR 0002: SQLite durable spool instead of Kafka or Redis

Status: accepted, implemented (`backend/src/extorq/pipeline/spool.py`,
`writer.py`, `collectors/src/extorq_collectors/sdk/state.py`). Date: 2026-11-21.

## Context
The gateway must acknowledge (`202`) only what is durably stored, and no data
may be lost while ClickHouse restarts or is unavailable. Volume is lab-scale
and everything runs on one host.

## Decision
A SQLite database in WAL mode with `synchronous=FULL` on a named volume shared
by the gateway and the writer. The gateway commits accepted records,
quarantine rows, dedup index entries and the batch idempotency result in one
transaction before answering. The writer deletes records only after ClickHouse
acknowledged the insert, defers on transient errors without consuming
attempts, bisects poison batches and moves records that keep failing to a
dead-letter table. Collectors use the same pattern locally: a SQLite outbox
whose records and checkpoints commit in one transaction.

## Consequences
* No extra service, credential or cluster to operate; survives process crashes
  and container restarts; easy to inspect.
* Single-writer locking: every access is a short transaction, never held across
  network I/O.
* Bounded by one host's disk; a full spool returns `503` with `Retry-After`,
  and collectors keep buffering in their outboxes.
* At-least-once delivery (ADR 0008), not exactly-once.

## Alternatives considered
* Kafka/Redpanda: replayable durable log and consumer groups, but heavy for a
  laptop and another stateful service with its own security configuration.
* Redis Streams: fast, but durability depends on AOF fsync policy, and it adds a
  network service and a secret.
* Direct inserts into ClickHouse: loses data or blocks producers during outages.

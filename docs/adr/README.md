# Architecture Decision Records

Short records (context, decision, consequences, alternatives). Owner: agent F.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-clickhouse-analytical-store.md) | ClickHouse as the analytical store | implemented |
| [0002](0002-sqlite-durable-spool.md) | SQLite durable spool instead of Kafka or Redis | implemented |
| [0003](0003-agentless-ssh-linux-collection.md) | Agentless SSH collection for Linux; compiled agent as future path | implemented (agent planned) |
| [0004](0004-native-macos-collector-without-fda-esf.md) | Native macOS collector without Full Disk Access or Endpoint Security | implemented |
| [0005](0005-otel-daemonset-for-kubernetes-logs.md) | OpenTelemetry Collector DaemonSet for workload and audit logs | implemented |
| [0006](0006-github-polling-not-webhooks.md) | GitHub REST polling instead of webhooks | implemented |
| [0007](0007-ai-advisory-boundaries.md) | AI boundaries: advisory triage, on-demand summaries, no authority | implemented |
| [0008](0008-deterministic-identities-replacingmergetree.md) | Deterministic identities with ReplacingMergeTree | implemented |
| [0009](0009-compose-networks-and-loopback-exposure.md) | Compose networks and loopback-only exposure | implemented |
| [0010](0010-service-model-and-adapter-registry.md) | Service model and adapter registry | implemented |

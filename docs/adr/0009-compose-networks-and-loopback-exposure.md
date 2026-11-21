# ADR 0009: Compose networks and loopback-only exposure

Status: accepted, implemented (`compose.yaml`). Date: 2026-11-21.

## Context
All platform services run on the operator's laptop. The database must never
be reachable from untrusted networks, internet egress should be limited to the
services that need it, and the gateway (the only endpoint producers talk to)
should not have a direct path to the database.

## Decision
* Two networks: `data` (`internal: true`, no egress) for ClickHouse, writer,
  detector and migrate; `edge` for the gateway, API, console, Grafana and
  ai-worker. Services that need both (API, Grafana, ai-worker) join both.
* The gateway is on `edge` only; its only link to the data plane is the spool
  volume (ADR 0002).
* Every published port binds `127.0.0.1`: gateway 8443, API 8000, console 3000,
  Grafana 3001; ClickHouse is never published except through the `debug`
  profile's socat proxy on `127.0.0.1:18123`.
* Containers run as non-root with all capabilities dropped,
  `no-new-privileges`, read-only root filesystems where possible, memory and
  pids limits; secrets are compose file secrets.

## Consequences
* Nothing listens on the Mac's external interfaces; ClickHouse has no egress.
* Loopback is not isolation from the lab: the VM reaches host loopback as
  `10.0.2.2` and kind pods through `host.docker.internal` (F-01, threat model
  T18), so every published service authenticates and the debug profile stays
  off during demos.

## Alternatives considered
* A single network: simpler, but gives the gateway and every service a path to
  ClickHouse and egress for the database.
* Publishing on all interfaces with a host firewall: more moving parts, easy to
  misconfigure on a laptop.

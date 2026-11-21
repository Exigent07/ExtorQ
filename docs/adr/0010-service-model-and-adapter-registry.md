# ADR 0010: Service model and adapter registry

Status: accepted, implemented (contracts, migration `0004_services.sql`, shared
interface, Linux, macOS and Kubernetes discovery and adapters; PLAN section 10).
Date: 2026-11-21.

## Context
A host or Kubernetes node runs many services. Treating all host telemetry as
one stream hides which service produced an event, which services are watched at
all, and where coverage is missing. The lab must monitor SSH, nginx, the lab web
application and systemd now, and leave room for FTP, databases, DNS and Redis
without pretending to monitor them.

## Decision
* Model **Asset -> Service -> ServiceInstance** in the contracts (schema 1.1):
  `ServiceKind` distinguishes host services, applications, Kubernetes workloads
  and logical Kubernetes Services; instances are processes, containers or Pods.
  Identities are deterministic: `service_id(asset_id, kind, key)`,
  `instance_id(service_id, kind, key)`.
* A service exists only with discovery evidence (`DiscoveryEvidence`); ports are
  attributed with explicit confidence (`PortAttribution`); a process is never
  assumed to be a network service.
* Coverage is two explicit fields: `adapter_support` (implemented, planned,
  none) and `monitoring_status` (monitored, degraded, unmonitored), computed by
  one deterministic function (`classify_coverage`).
* Service-specific telemetry comes from `ServiceAdapter` classes registered in a
  registry keyed by `adapter_id`. Implemented registrations replace planned
  ones; matching prefers implemented adapters and never uses ports alone.
  Planned adapters are real objects that recognise a service and collect
  nothing, so they appear honestly as "planned, unmonitored".
* Adapters declare `collects` and `never_collects`; data minimisation is part of
  the interface and is checked by `tests/security/test_security_service_adapters.py`.
* Events reference their service through `SecurityEvent.service` only when the
  adapter can genuinely attribute them; findings and alerts carry `service_id`(s).

## Consequences
* The console can drill down Asset -> Services -> Telemetry -> Findings ->
  Alerts -> Investigation and show unmonitored services transparently.
* New protocols are additive: a new adapter class, catalog types and tests.
* Coverage and attribution are only as good as the collector's privileges and
  the asset's honesty (known limitations S3 to S6, threat model T22, T23).
* The gateway must bind service records to authorised assets (F-19), and the
  API must join by service id and asset scope.

## Alternatives considered
* Tags on events only (no service entities): no place for coverage, instances
  or unmonitored services.
* Inferring services from well-known ports: wrong for forwarded ports and
  non-standard configurations; rejected.
* One monolithic parser per host: no per-service coverage and no clean extension
  point.

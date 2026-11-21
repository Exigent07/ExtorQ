# ADR 0004: Native macOS collector without Full Disk Access or Endpoint Security

Status: accepted, implemented (`collectors/src/extorq_collectors/macos/`).
Date: 2026-11-21.

## Context
The Mac is both a monitored asset and the operator's workstation, the trust
anchor of the whole lab. Endpoint Security requires an Apple entitlement and a
system extension; Full Disk Access grants broad access to personal data.
ExtorQ must not weaken host security.

## Decision
A native collector that runs as the operator user and uses only read-only
system tools with fixed argument vectors: `/usr/bin/log show` for the unified
log (authentication, sudo, Gatekeeper, XProtect), launchd plist inventory, `ps`,
`netstat` with an `lsof` fallback, `system_profiler`, and posture commands
(SIP, FileVault, Gatekeeper, firewall, software update, remote login). No sudo,
no Full Disk Access, no configuration profiles, no kernel or system extensions.
Process arguments are off by default and redacted when enabled.

## Consequences
* The host's security posture is untouched and the collector needs no special
  privileges.
* Visibility is limited: no Endpoint Security process or file events, no
  TCC-protected data, root-owned listeners are invisible in `lsof` mode; checks
  that cannot be evaluated report `error` (unknown), never `pass`.

## Alternatives considered
* Endpoint Security system extension: rich events, but needs an Apple
  entitlement, notarisation and a privileged extension on the operator's Mac.
* osquery with Full Disk Access: broad visibility, broad privilege.
* A commercial EDR: out of scope and not inspectable.

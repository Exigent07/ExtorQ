# ADR 0003: Agentless SSH collection for Linux, with a future compiled-agent path

Status: accepted, implemented (`infra/vm/`, `collectors/src/extorq_collectors/linux/`).
Date: 2026-11-21.

## Context
The Ubuntu VM is the attack target of the lab. Anything stored on it must be
assumed compromised. ExtorQ needs journald, auditd, nginx and lab-portal logs,
inventory, packages and posture from it.

## Decision
Pull over SSH from the Mac. A dedicated collector key is bound to a forced
command (`restrict,command=` in a root-owned authorized keys file plus sshd
`Match User` / `ForceCommand`) that runs `extorq-collect-dispatch`
(`python3 -I`): a strict grammar of six read-only commands (`version`,
`journal`, `audit`, `inventory`, `packages`, `posture`), fixed argument
vectors, a minimal environment, timeouts and bounded output; denials are logged
by hash. The collector account is unprivileged (groups `adm`,
`systemd-journal`), password-locked and not in sudo. Cursors and offsets are
checkpoints kept on the Mac; the VM host key is pinned.

## Consequences
* No producer token and no ExtorQ secret on the VM; compromising it yields no
  ingestion credential.
* Detection latency is at least the polling interval; when SSH is down the
  collector reports failure and gaps.
* Unprivileged view: socket owners of root's listeners and executable paths of
  other users' processes are not visible (known limitations S3, S4); process
  argument prefixes are visible to the collector (F-17).
* Root on the VM can still replace the dispatcher or tamper with logs before
  collection (threat model T01).

## Future path (planned, not built)
A compiled agent (Go or Rust) for real fleets: streaming instead of polling,
local durable buffer, its own producer identity (mutual TLS), signed updates and
the same read-only, allow-listed collection scope.

## Alternatives considered
* Run the Python collector on the VM: puts a producer token on the target.
* Remote syslog/journal forwarding to the gateway: push latency is better, but
  it needs a listener and per-host credentials and moves parsing into the
  gateway.
* osquery or Fluent Bit on the VM: capable, but another agent and attack
  surface on the target.

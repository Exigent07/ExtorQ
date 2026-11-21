# ADR 0005: OpenTelemetry Collector DaemonSet for workload and audit logs

Status: accepted, implemented (`infra/kind/otel/collector.yaml`,
`infra/kind/manifests/2*-otel-*.yaml`, `backend/src/extorq/ingest/otlp_k8s.py`).
Date: 2026-11-21.

## Context
ExtorQ needs Kubernetes API audit events (K8S-001, K8S-002) and container
logs (lab portal) from the kind cluster. The audit log is a root-owned file on
the control-plane node; container logs live under `/var/log/pods`.

## Decision
Run the OpenTelemetry Collector (contrib, pinned by digest) as a DaemonSet in
`extorq-system`: `filelog` receivers for `/var/log/pods/*/*/*.log` and the
audit log (read-only host mounts, checkpoints in a `file_storage` extension),
the `k8sattributes` processor (read-only `get/list/watch` on pods, namespaces,
nodes and replicasets), a persistent sending queue, and OTLP/HTTP JSON export to
the gateway (`https://host.docker.internal:8443/v1/otlp/v1/logs`) with the
`k8s-otel-extorq-lab` bearer token and the ExtorQ CA. The gateway normalises
audit lines and container logs into `SecurityEvent`s. Cluster state comes from a
separate read-only inventory collector with a short-lived service-account token.

## Consequences
* Standard, vendor-neutral pipeline with buffering and Pod metadata enrichment.
* The collector runs as UID 0 (needed for the 0600 audit log) with all
  capabilities dropped, no privilege escalation, a read-only root filesystem
  and `RuntimeDefault` seccomp; this is a documented accepted risk.
* The OTel token lives in the cluster (readable by cluster-admin or node root)
  and can forge events within its scope (`k8s.audit`, `k8s.container_log`).
* Depends on Docker Desktop's `host.docker.internal` route to host loopback.

## Alternatives considered
* API server audit webhook backend: push from the API server, but needs
  API-server configuration, a reachable endpoint and TLS trust inside kind.
* Fluent Bit: lighter, but the OTLP semantics and enrichment were more direct
  with the OTel Collector.
* Polling `kubectl logs`: misses rotations and does not scale.

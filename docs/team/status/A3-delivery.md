# Kubernetes delivery remediation

Source work was performed on the working tree based on `023fdb6`. The OTel
configuration removes the in-memory batch processors, caps outbound requests
after durable enqueue, and pauses upstream file reads on downstream rejection.
Active and retained audit logs and container logs have explicit file patterns.
The gateway converts allow-listed OTel metrics into node- and source-scoped
`CollectorHealth` only for the configured OTel producer. It confirms freshness
using actual newly accepted, attributed native records. The API exposes expired
reports as unavailable. Effective coverage of Kubernetes workloads uses health
from their running Pods' hosting nodes. Audit events carry the emitter node.

## Verified locally

| Command | Result |
|---|---|
| `.venv/bin/pytest -q --tb=short tests/unit/kubernetes tests/unit/api/test_api_services.py tests/unit/platform/test_platform_gateway.py tests/unit/platform/test_platform_bootstrap_migrate.py tests/security/test_security_lab_boundaries.py` | 271 passed. One expected warning describes the deliberately weak posture fixture. |
| `.venv/bin/ruff check backend/src/extorq/ingest/{otlp_health,otlp_k8s,app,registry}.py backend/src/extorq/api/{service,repository}.py collectors/src/extorq_collectors/kubernetes/{collector,hierarchy}.py scripts/bootstrap.py tests/unit/kubernetes/{test_otlp_delivery_health,test_otlp_k8s}.py tests/unit/{api/test_api_services,platform/test_platform_bootstrap_migrate}.py` | All checks passed. |
| `.venv/bin/mypy backend/src/extorq/ingest/{otlp_health,otlp_k8s,app,registry}.py backend/src/extorq/api/{service,repository}.py collectors/src/extorq_collectors/kubernetes/{collector,hierarchy}.py` | No issues in eight source files. |
| Pinned `docker run ... validate` command in the [Kubernetes runbook](../../telemetry/kubernetes.md#32-isolated-validation-and-rollout) | Blocked before container startup by access denied on the Docker Desktop Unix socket. No pinned-binary validation or live Collector deployment occurred. |

The health tests use synthetic OTLP and a temporary SQLite spool with the actual
gateway app. They verify source and identity scoping, valid gateway
acknowledgement, metric replay, health expiry, queue saturation and failed sends.
Existing normalized native capture tests verify audit emitter-node attribution.

## Outstanding runtime evidence

The current image configuration, actual metric labels, compressed CRI rotation,
audit rotation, crash recovery, queue behavior and expiry after exporter retries
need a disposable live run. Permanent-failure metrics can show a drop. A
retried attempt or an exporter timeout requires the terminal Collector diagnostic
to establish the number of drops. Native files that expire before being read and
unflushed CRI partial records remain unobservable from transport counters. The
gateway refreshes its in-process delivery corroboration after a restart. Existing
data, Kubernetes and Docker services were untouched.

# Kubernetes telemetry (cluster `extorq-lab`, asset `k8s:extorq-lab`)

Owner: B2. Cluster: `infra/kind/` (lifecycle `infra/kind/kind.sh`, guide
`infra/kind/AGENTS.md`). Normaliser: `backend/src/extorq/ingest/otlp_k8s.py`.
Inventory/posture collector: `collectors/src/extorq_collectors/kubernetes/`
(config `config/collectors/kubernetes.yaml`). Simulations: `simulations/k8s/`.
Tests: `tests/unit/kubernetes/` with real captures in `tests/fixtures/kubernetes/`.

Two independent paths feed ExtorQ:

```
kind node extorq-lab-control-plane
 ├─ kube-apiserver ──audit log──┐
 ├─ containers ──/var/log/pods──┤  OTel Collector DaemonSet (extorq-system)
 │                              └─ file_log -> k8s_attributes -> otlp_http (JSON, TLS, bearer)
 │                                   -> https://host.docker.internal:8443/v1/otlp/v1/logs
 │                                   -> otlp_k8s.normalize_otlp_logs -> spool -> ClickHouse
 └─ API server (127.0.0.1:<port> on the Mac)
      <- extorq-collect (k8s-inventory, read-only token) -> /v1/ingest -> ClickHouse
```

| Source type | Producer | Event types |
|---|---|---|
| `k8s.audit` | `k8s-otel-extorq-lab` (OTLP) | `k8s.api.request` |
| `k8s.container_log` | `k8s-otel-extorq-lab` (OTLP) | `k8s.container.log`; lab-portal: `app.auth.login_failed`, `app.auth.login_succeeded`, `app.authz.denied`, `http.request` |
| `k8s.api_inventory` | `k8s-inventory-extorq-lab` | `k8s.resource.created/updated/deleted`, `service.discovered/removed/exposure.changed`, InventoryItems, Services, ServiceInstances, assets |
| `k8s.events` | `k8s-inventory-extorq-lab` | `k8s.event.observed`, `extorq.collector.gap_detected` |
| `k8s.posture` | `k8s-inventory-extorq-lab` | ScanRun `extorq-posture-k8s` + PostureFindings |

## 1. The cluster

`infra/kind/kind.sh up|deploy|status|down|load-images|token|netcheck|audit-check|kubeconfig`.
Every `kind` call passes `--name extorq-lab`; every `kubectl` call passes
`--kubeconfig var/kube/extorq-lab-admin.kubeconfig --context kind-extorq-lab`
(0600, gitignored). `~/.kube/config` and any other cluster (e.g. `motorq-security`)
are never read or changed.

* Node image `kindest/node:v1.37.0@sha256:a1ed56cf...` (digest from the kind v0.33.0
  release notes), single control-plane node, API server on 127.0.0.1 (random port).
* kubeadm `v1beta4` patch (extraArgs is a list of `{name, value}`):
  `--audit-policy-file=/etc/kubernetes/policies/audit-policy.yaml`,
  `--audit-log-path=/var/log/kubernetes/audit/kube-apiserver-audit.log`,
  `--audit-log-format=json`, rotation `--audit-log-maxsize=50` (MB),
  `--audit-log-maxbackup=5`, `--audit-log-maxage=7` (days): at most ~300 MB on the node.
  `kind.sh up` fails if the flags are not in the static pod manifest.
* `extraPortMappings`: NodePort 30080 -> `127.0.0.1:8089` on the Mac (loopback only).
* Images: public images are pulled BY DIGEST by the node's containerd (`crictl pull`);
  lab-portal is built locally (`infra/kind/apps/lab-portal/Dockerfile`, tag = content hash)
  and loaded with `kind load docker-image`.

### Namespaces and Pod Security Admission

| Namespace | enforce | warn / audit | Purpose |
|---|---|---|---|
| `extorq-system` | privileged | baseline | OTel DaemonSet (hostPath mounts). Accepted risk annotated on the namespace and the workload. |
| `extorq-apps` | baseline | restricted | lab-portal (restricted-compliant: UID 10001, read-only root FS, all capabilities dropped, seccomp RuntimeDefault, no SA token, default-deny egress NetworkPolicy). |
| `extorq-restricted` | **baseline** | restricted | K8S-001 target. Despite its name it enforces *baseline*, which already denies privileged and host-namespace pods (review finding F-11). |
| `extorq-posture-lab` | privileged | baseline | `weak-log-reader`: deliberately weak but harmless (root, no limits, SA token mounted, no seccomp, writable root FS, read-only hostPath to an empty dedicated directory `/var/log/extorq-posture-lab`, not `/var/log`, review finding F-10). Its findings stay open on purpose. |

## 2. Audit policy (`infra/kind/audit-policy.yaml`)

`omitStages: [RequestReceived]`; first matching rule wins.

| # | Rule | Level | Why |
|---|---|---|---|
| 1 | `/healthz*`, `/livez*`, `/readyz*`, `/version` | None | probes every few seconds, no security value |
| 2 | API discovery GETs by authenticated users | None | kubectl/controller caches; unauthenticated discovery still logged (rule 13) |
| 3 | `coordination.k8s.io/leases` | None | leader election + node heartbeats (~every 10 s) |
| 4 | `secrets`, `configmaps`, `serviceaccounts/token`, `tokenreviews` | **Metadata** | credentials: who/what/when only, **never bodies**; placed before the system-read exclusions so every secret access is kept |
| 5 | get/list/watch by `system:nodes`, scheduler, controller-manager, kube-proxy, apiserver, `system:serviceaccounts:kube-system` | None | high-volume control-plane reads |
| 6 | reads of endpoints, endpointslices, events | None | high volume, low value |
| 7 | Event writes by kubelets and kube-system controllers | None | Events are collected through the Events API instead |
| 8 | RBAC writes (roles, rolebindings, clusterroles, clusterrolebindings) | **RequestResponse** | who granted what to whom (K8S-002) |
| 9 | pod create/update/patch, `pods/ephemeralcontainers` | **Request** | privileged/host-namespace specs and PSA denials (K8S-001) |
| 10 | `pods/exec`, `pods/attach`, `pods/portforward` (all verbs: WebSocket GET and SPDY POST) | Request | interactive access |
| 11 | self/subject access reviews, selfsubjectreviews, CSRs | Metadata | authentication/authorization probing |
| 12 | all other writes | Metadata | |
| 13 | everything else (non-system reads, anonymous, proxies) | Metadata | |

`infra/kind/kind.sh audit-check` re-checks these guarantees against the real log (active
file + rotated backups) and prints counts and violations, never bodies. Verified
2026-11-21 on 2,579 lines: no violations (secrets/configmaps/token requests at Metadata
without bodies, RBAC writes at RequestResponse, pod writes and exec at Request, no
RequestReceived stage, no lease or system-read records).

## 3. OTel Collector DaemonSet

Image `otel/opentelemetry-collector-contrib:0.165.0@sha256:e40d61f1...` (stable release,
verified on Docker Hub). Config `infra/kind/otel/collector.yaml` (ConfigMap
`extorq-system/extorq-otel-config`; the pod template carries its SHA-256, so a config
change rolls the pods). Validated with the pinned binary
(`otelcol-contrib validate`, plus a negative control that rejects an unknown key).

* Receivers: `file_log/containers` (`/var/log/pods/*/*/*.log`, CRI `container` parser,
  partial-line recombination, 16 KiB max line, the collector's own logs excluded) and
  `file_log/audit` (`kube-apiserver-audit*.log`, active file + rotated backups, 256 KiB max).
* Processors: `memory_limiter` (200 MiB), `k8s_attributes` (pod name/uid, namespace, node,
  Deployment/ReplicaSet/DaemonSet/StatefulSet/Job/CronJob, `container.id`,
  `container.image.name/tags`; `wait_for_metadata: true`, node-local filter), a `resource`
  processor setting `extorq.source = container | audit`, cluster and node names, `batch`
  (100 records: the gateway allows 1000 records / 4 MiB per request).
* Exporter: `otlp_http`, `encoding: json`, gzip, `logs_endpoint
  https://host.docker.internal:8443/v1/otlp/v1/logs`, TLS 1.2+ verified against the ExtorQ CA
  (ConfigMap `extorq-gateway-ca` built from `var/tls/ca.crt`), bearer token from the Secret
  `extorq-otel-token` built at deploy time from `var/secrets/tokens/k8s-otel-extorq-lab.token`
  by file path (server-side apply, never printed or committed).
* Durability: `file_storage` in the hostPath `/var/lib/extorq-otel` keeps the file offsets AND
  the exporter's persistent sending queue (`retry_on_failure` up to 2 h, then the batch is
  dropped and counted in `otelcol_exporter_send_failed_log_records`). Verified: after deleting
  the collector pod, the new pod logged "Resuming from previously known offset(s)", five marker
  requests sent before/during/after the restart each arrived exactly once, and the
  post-restart batches contained 0 duplicates.
* Connectivity (verified, `kind.sh netcheck`): pods resolve `host.docker.internal` to Docker
  Desktop's host gateway (192.168.65.254) and reach the gateway on 8443 with the certificate
  verified against the ExtorQ CA (the gateway certificate carries `DNS:host.docker.internal`).
  Fallback if a Docker runtime lacks `host.docker.internal`: set `EXTORQ_K8S_GATEWAY_URL`
  for netcheck and change `logs_endpoint` to a name the node can reach (e.g. connect the
  `ingest` container to the `kind` Docker network and use its container name, which then
  must be in the gateway certificate's SANs). **Planned**, not needed on this host.

Privileges: ServiceAccount `extorq-otel-collector` with a ClusterRole of get/list/watch on
pods, namespaces, nodes and replicasets (k8s_attributes), nothing else. The pod runs as
UID 0 because the audit log is `root:root 0600`; all capabilities are dropped,
`allowPrivilegeEscalation: false`, read-only root FS, seccomp RuntimeDefault, hostPath mounts
read-only except the checkpoint directory. This is a documented accepted risk
(`extorq.io/accepted-risk` on the DaemonSet, pod template and namespace).

## 4. Normalisation (`otlp_k8s.py`, PARSER_VERSION 1.1.x)

All telemetry is untrusted: strings are sanitised (control characters removed), redacted
(`redact_text`) and bounded; nothing is used to build queries or commands; unknown values
stay `None`. Per-record failures are returned as `(index, reason)` and quarantined by the
gateway with secret-free reasons.

### Audit -> `k8s.api.request`

* Stages ResponseComplete and Panic only (plus ResponseStarted with HTTP 401: failed
  authentications are only audited at that stage). `event_id =
  event_id("k8s.audit", "k8s:extorq-lab", "<auditID>:<stage>")`.
* `kubernetes.*`: verb, resource, subresource, api_group, namespace, object_name, user,
  user_groups, source_ips, user_agent, response_code, audit_id, stage, service_account.
  `actor` (type user/service_account/system, authenticated), `network.src_ip` = the last
  `sourceIPs` entry, `outcome` success (<400) / denied (401, 403) / failure.
* `attributes.request_summary`: canonical JSON of security-relevant fields ONLY (never env,
  args, annotations or full bodies): pods (privileged containers, hostPID/Network/IPC,
  hostPath paths, added capabilities, runAsUser 0, allowPrivilegeEscalation, images, service
  account), workload templates, JSON patches (paths + detected keys), RBAC objects (rules with
  verbs/resources/apiGroups/nonResourceURLs incl. wildcards, `role_ref`, `subjects`). RBAC
  writes summarise the response object (post-change state).
* `attributes.risk_flags` (shared with the inventory collector): `privileged`, `host_pid`,
  `host_network`, `host_ipc`, `host_path`, `host_path_root`, `added_capabilities`,
  `dangerous_capabilities`, `run_as_root`, `allow_privilege_escalation`, `wildcard_verbs`,
  `wildcard_resources`, `wildcard_api_groups`, `full_wildcard_rule`, `escalation_verbs`,
  `secrets_access`, `pod_exec`, `wildcard_non_resource_urls`, `cluster_admin`,
  `binds_anonymous`, `binds_unauthenticated`, `binds_authenticated`,
  `binds_all_service_accounts`, `binds_default_service_account`.
* `attributes.pod_security_violation` (403 + "violates PodSecurity"), PSA annotations
  (`pod_security_enforce_policy`, `..._audit_violations`), `authz_decision`/`authz_reason`,
  `denied_by` (authentication / authorization / pod_security / admission), `dry_run`,
  impersonation, credential ids; `metadata_only_change` + `metadata_fields_changed` when a
  patch only touches metadata (e.g. `kubectl annotate`).
* `service`: the node's `kube-system/kube-apiserver-<node>` workload (adapter `k8s-audit`).

### Container logs

* `event_id` per the identity docstring:
  `<pod_uid>:<container>:<stream>:<timestamp_ns>:<sha256(line)>`.
* `kubernetes.*`: namespace, pod name/uid, container, `container_id` (bare 64-hex runtime id),
  node, workload kind/name (top-level controller from k8s_attributes; static pods: the pod
  itself, detected by the kubelet config-hash UID); `attributes.stream`, `log_level` (klog,
  JSON or logfmt), `container_image`, `container_restart_count`, `static_pod`.
* lab-portal (`extorq-apps`/`lab-portal` container, stdout, schema `lab-portal.log.v1`, exact
  key set) -> `app.auth.*`, `app.authz.denied`, `http.request` with `actor.name`,
  `network.src_ip`, `http.*`, `attributes.reason`; the request id is only used as
  `http.request_id` when propagated by a trusted proxy. Lines from any other pod are never
  parsed as application security events (no forging by look-alike JSON).
* `service`: workload service + container instance (pod instance when the container id is
  unknown), adapter `webapp-json` for lab-portal events, `k8s-container-log` otherwise. API
  pods without controller metadata stay unattributed (absence of metadata is not evidence).
* Lines are bounded (16 KiB at the collector, 2 KiB message, 16 KiB raw excerpt).

## 5. Inventory, Events and posture collector (`k8s-inventory`)

Runs on the Mac: `uv run extorq-collect run --only k8s-inventory [--once]` (interval 60 s).
Identity: ServiceAccount `extorq-system/extorq-inventory`, ClusterRole
`extorq-inventory-reader`: get/list/watch on namespaces, pods, serviceaccounts, events,
nodes, services, deployments, daemonsets, statefulsets, replicasets, jobs, cronjobs, roles,
rolebindings, clusterroles, clusterrolebindings, networkpolicies. **No secrets, no
configmaps, no pods/exec, pods/log or nodes/proxy, no write verb** (checked with
`kubectl auth can-i --list`). Token: `infra/kind/kind.sh token` uses the TokenRequest API
(`kubectl create token`, default 24 h, audience-bound, never stored in a Secret object) and
writes `var/kube/extorq-inventory.token` + a kubeconfig referencing it by `tokenFile`
(both 0600). The client refuses client-certificate, inline-token and exec kubeconfigs,
plain HTTP, non-loopback servers and `insecure-skip-tls-verify`; it only sends GET.
Health reports `token_expires_in_seconds`; an expired token fails the cycle with a hint.

Each cycle (one atomic `ctx.emit`):

1. Paginated LIST of 16 kinds (`limit` 500 + `continue`; 410 Gone -> relist, max 3);
   bounded retries with jittered backoff for 5xx/429/transport errors; timeouts 15 s.
   A kind that cannot be listed is reported in health and NOT diffed (a failed list never
   produces deletions); the posture scan is then PARTIAL.
2. Snapshot diff per kind -> `k8s.resource.created|updated|deleted` (`resource.type` = plural
   API resource, `attributes.risk_flags`, `object_summary`, `changed_fields`,
   `previous_risk_flags`, `risk_flags_added`, `baseline` on the first snapshot,
   `field_managers`, `time_source`) + InventoryItems (`<Kind>/<ns>/<name>`, tombstones on
   deletion). Only content changes count as updates (status, scheduling and derived fields
   never do). `event_time` = creationTimestamp for creations, the newest `managedFields`
   time for updates, observation time for deletions. Names containing
   `extorq-sim-<run_id>` (object, owner or binding subjects) set `event.simulation`.
3. Service hierarchy (below) -> Service / ServiceInstance records (changed ones each cycle,
   all every `refresh_seconds` = 900 s, tombstones on removal) and `service.*` events.
4. core/v1 Events -> `k8s.event.observed` (deduplicated by uid + occurrence count; Warning ->
   `severity_hint` low). The API server deletes Events after its `--event-ttl` (default
   1 h): if the previous successful poll is older than `event_ttl_seconds`, an
   `extorq.collector.gap_detected` (`gap_reason: poll_gap_exceeds_event_ttl`) is emitted.
5. Assets: `k8s:extorq-lab` (kubernetes_cluster, version, node/namespace counts) and
   `k8s:extorq-lab/node/<node>` (kubernetes_node: kubelet/runtime/kernel/OS versions, roles,
   readiness, internal IP).
6. Posture scan `extorq-posture-k8s` -> ScanRun (scope `cluster:extorq-lab` + every scanned
   namespace, stable scope hash) + PostureFindings (`finding_id(asset, scanner, check,
   "<Kind>/<ns>/<name>")`, `service_id` of the workload or Service).

| Check | Severity | Evaluated on |
|---|---|---|
| K8S-POD-001 privileged container | critical | top-level workload templates, bare and static pods |
| K8S-POD-002 host namespaces | high | " |
| K8S-POD-003 hostPath (high under /, /etc, /proc, /sys, /var/log, kubelet/containerd paths, sockets) | medium/high | " |
| K8S-POD-004 dangerous capabilities | high | " |
| K8S-POD-005 runAsUser 0 | medium | " |
| K8S-POD-006 runAsNonRoot not enforced | low | " |
| K8S-POD-007 privilege escalation not disabled | low (medium if explicitly true) | " |
| K8S-POD-008 no CPU+memory limits | low | " |
| K8S-POD-009 SA token automounted | low | " |
| K8S-POD-010 no seccomp profile | low | " |
| K8S-POD-011 writable root FS | low | " |
| K8S-RBAC-001..008 cluster-admin binding, wildcards, escalate/bind/impersonate, secrets read, anonymous/unauthenticated, all-authenticated/all-SA, default SA, pods/exec | critical..medium | all RBAC objects except Kubernetes defaults (`kubernetes.io/bootstrapping=rbac-defaults`, `system:*`) |
| K8S-NS-001 no PSA enforce or privileged | medium | namespaces |
| K8S-NS-002 pods but no NetworkPolicy | low | namespaces |
| K8S-SVC-001 NodePort/LoadBalancer/externalIPs | low | Services |

Workload, namespace and Service checks skip `kube-system`, `kube-public`, `kube-node-lease`,
`local-path-storage` (recorded in every ScanRun's coverage notes). `accepted_risk` comes from
the `extorq.io/accepted-risk` annotation of the object (or pod template); the finding stays
visible, marked accepted. Accepted in this lab: the OTel DaemonSet and `extorq-system`
namespace, the lab-portal NodePort, and two kubeadm bootstrap bindings annotated by
`kind.sh` (`kubeadm:cluster-admins` -> cluster-admin for the operator kubeconfig group;
`kube-public/kubeadm:bootstrap-signer-clusterinfo` -> anonymous read of the public
cluster-info ConfigMap).

## 6. Service hierarchy (contract 1.1, PLAN section 10)

| Level | Record | Identity |
|---|---|---|
| cluster | Asset `k8s:extorq-lab` (kubernetes_cluster) | |
| node | Asset `k8s:extorq-lab/node/<node>` (kubernetes_node, parent the cluster) | |
| workload | Service `k8s_workload`, name `<ns>/<name>` | `service_id(cluster, "k8s_workload", "<ns>/<Kind>/<name>")`; Kind = top-level controller (Deployment via ReplicaSet owner, CronJob via Job owner, DaemonSet, StatefulSet, standalone ReplicaSet/Job) or `Pod` for bare/static pods |
| Kubernetes Service | Service `k8s_service`, name `<ns>/<name>` | `service_id(cluster, "k8s_service", "<ns>/<name>")`; a logical API object, never a host OS service |
| Pod | ServiceInstance `pod`, asset = node | `instance_id(service, "pod", <pod UID>)`; static pods use the kubelet config hash (`kubernetes.io/config.hash`), which is also the UID in node log paths |
| container | ServiceInstance `container`, parent = pod instance | `instance_id(service, "container", <bare container id>)`; runtime in `attributes.runtime` |

Coverage: workloads have an implemented adapter (`webapp-json` for lab-portal, `k8s-audit`
for kube-apiserver, `k8s-container-log` otherwise) and are `monitored` when the log agent is
Ready on every node running an instance, `degraded` when it is not, `unmonitored` without
running instances; the agent itself is `unmonitored` (own logs excluded). Kubernetes
Services are `adapter_support: none`, `unmonitored` (no per-connection telemetry); their
ClusterIP and NodePort endpoints are attributed `inferred` (declared by the Service spec;
kube-proxy implements them with packet rules, there is no socket owner to observe).
Verified live: container-log events join their container instances (186/186 kindnet
events), static-pod logs their pod instance (13/13 etcd events), audit events the
kube-apiserver service.

## 7. Identities and privileges

| Identity | Where | Can do |
|---|---|---|
| `kind-extorq-lab` admin (client cert, group `kubeadm:cluster-admins`) | `var/kube/extorq-lab-admin.kubeconfig` (0600) | cluster-admin; used only by `kind.sh` and the simulations, never by collectors |
| SA `extorq-system/extorq-inventory` | TokenRequest token in `var/kube/` (0600, 24 h) | get/list/watch on the 16 kinds above; no secrets/configmaps/exec/logs |
| SA `extorq-system/extorq-otel-collector` | in-cluster token (automounted) | get/list/watch pods, namespaces, nodes, replicasets |
| SA `extorq-apps/lab-portal` | no token mounted | nothing |
| SA `extorq-posture-lab/default` | token mounted (deliberate finding) | only the default discovery permissions |
| gateway producers `k8s-otel-extorq-lab`, `k8s-inventory-extorq-lab` | `var/secrets/tokens/*.token`; the OTel token is a Secret in `extorq-system` | events (k8s.audit, k8s.container_log) / inventory kinds (k8s.api_inventory, k8s.events, k8s.posture), assets `k8s:extorq-lab*` only |

## 8. Simulations (`simulations/k8s/`)

* `k8s_001_privileged_pod_denied.sh [--run-id ID] [--wait S]`: `kubectl create` of a
  privileged + hostPID pod `extorq-sim-<run_id>` in `extorq-restricted` -> HTTP 403 from
  Pod Security, no pod created. Evidence: `k8s.api.request` create pods -> 403,
  `pod_security_violation`, `risk_flags [host_pid, privileged]`, `simulation_run_id`.
  Verified run `bcfcb726ff01`; C2's K8S-001 SQL matched it (confidence high).
* `k8s_002_risky_rbac.sh [--run-id ID] [--wait S] [--collect-once]`: ServiceAccount and
  ClusterRoleBinding `extorq-sim-<run_id>` -> `cluster-admin`; waits for audit + inventory
  evidence, then ALWAYS deletes both (EXIT trap too) and verifies they are gone;
  `--cleanup --run-id ID` cleans a previous run. Only objects with that exact name AND label
  `extorq.io/simulation=<run_id>` are touched. Verified run `c9c96ff29f33` (audit 201 with
  `role_ref ClusterRole/cluster-admin`, inventory created + deleted, K8S-002 confidence high).
* Both record the SimulationRun (`extorq-collect sim-record`) and check evidence read-only:
  `uv run python -m extorq_collectors.kubernetes.verify --scenario K8S-00x --run-id ID`.

## 9. What is NOT monitored (limitations)

* **No runtime security telemetry**: process execution, file access and network connections
  inside containers or on the node are not observed (that needs eBPF / Falco- or
  Tetragon-class instrumentation). Only logs that containers write and API activity are seen.
* **Events expire** after the API server's event TTL (about 1 h): Events emitted while the
  inventory collector is down for longer are lost (reported as a gap, not recovered).
* **Audit log rotation**: 50 MB x 5 backups, 7 days. The OTel receiver also reads rotated
  backups, but if the collector is down long enough for data to rotate past the last backup,
  that audit data is lost. The audit log is on the node only (no remote audit webhook).
* **Client IPs behind NodePort are not real**: kube-proxy SNATs NodePort traffic, so
  lab-portal records the node's pod-network gateway address as `src_ip` (observed:
  `10.244.0.1` for every request), not the client's address; the kind port mapping
  (`127.0.0.1:8089`) adds Docker Desktop's port-forwarding hop in front of that. Rules must
  not treat k8s lab-portal `src_ip` as an attacker address.
* Static pods are not associated by k8s_attributes: their logs have no container id (the
  pod instance is still attributed via the kubelet config hash).
* API pods without a controller are not service-attributed in container-log events (the
  inventory still models them as `<ns>/Pod/<name>` services).
* kubelet, containerd and systemd logs inside the node container are not collected; the
  node's journald is not shipped.
* NetworkPolicy objects are inventoried and checked for presence; whether the CNI (kindnet)
  enforces them is not verified by ExtorQ.
* Posture is declarative (object specs), not runtime; image vulnerabilities are C3's Trivy
  scans, not this collector.
* Pod-level metrics, resource usage and traces are out of scope.

## 10. Verification commands

```
infra/kind/kind.sh status          # nodes, pods, PSA labels, audit log, token, lab-portal
infra/kind/kind.sh audit-check     # audit policy guarantees on the real log
infra/kind/kind.sh netcheck        # pod -> gateway TLS reachability
uv run extorq-collect run --only k8s-inventory --once
uv run pytest tests/unit/kubernetes -q
simulations/k8s/k8s_001_privileged_pod_denied.sh
simulations/k8s/k8s_002_risky_rbac.sh --wait 240
```

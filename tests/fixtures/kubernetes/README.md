# Kubernetes test fixtures (owner: B2)

All fixtures were **captured from the real `extorq-lab` kind cluster** (Kubernetes
v1.37.0, kind v0.33.0) on 2026-11-21. They are byte-for-byte copies of what the
cluster produced; nothing was edited. They contain no credentials: the audit
policy never logs secret/token bodies, and the files were checked for JWTs and
secret values before being committed.

## `audit/*.json`: one kube-apiserver audit line each

Copied from `/var/log/kubernetes/audit/kube-apiserver-audit.log` inside the node
(`docker exec extorq-lab-control-plane cat ...`). The activity that produced them
was a manual fixture run with objects named `b2-fixture-*` (all deleted afterwards):

| file | activity |
|---|---|
| `psa_denied_privileged_pod` | `kubectl apply` of a privileged + hostPID/hostNetwork + hostPath `/` pod into `extorq-restricted` -> PodSecurity 403 |
| `psa_denied_dry_run` | same pod with `kubectl create --dry-run=server` -> 403 |
| `psa_denied_ephemeral_container` | `kubectl debug --profile=sysadmin` (privileged ephemeral container) -> 403 |
| `rbac_crb_cluster_admin_create` / `_patch_subjects` / `_delete` | ClusterRoleBinding to `cluster-admin`, merge patch adding `system:authenticated`, delete |
| `rbac_role_wildcard_create` | Role with `*` verbs on `*.*` |
| `rbac_rolebinding_anonymous_create` | RoleBinding to `system:anonymous` and `system:unauthenticated` |
| `rbac_clusterrole_escalate_create` | ClusterRole with `escalate`/`bind`/`impersonate` and `nonResourceURLs: ["*"]` |
| `rbac_clusterrole_aggregation_patch` | clusterrole-aggregation-controller patch at cluster bootstrap |
| `pod_create_allowed` / `pod_patch_json` / `pods_exec` (+`_response_started`) | restricted-compliant pod, JSON patch, `kubectl exec` |
| `secret_create_metadata` / `token_request` / `serviceaccount_create` | Metadata-only secret write, TokenRequest, ServiceAccount |
| `forbidden_impersonated_secret_list` | `kubectl get secrets --as=system:serviceaccount:extorq-system:extorq-inventory` -> RBAC 403 |
| `anonymous_forbidden_secret_list` / `unauthenticated_401` | anonymous request -> 403; invalid bearer token -> 401 (audited only at stage ResponseStarted) |
| `watch_response_started` | an in-progress watch (stage ResponseStarted; skipped by the normaliser) |
| `bootstrap_mirror_pod_admission_denied` / `bootstrap_rbac_forbidden` / `metadata_list_nodes` | cluster bootstrap traffic (admission and RBAC denials, kind's readiness polling) |

**Synthetic content inside genuine records:** the privileged pod spec carries an
environment variable `FIXTURE_FAKE_PASSWORD=synthetic-not-a-secret-123`. The value
is fake and exists so the tests can prove request bodies (env values, the
`last-applied-configuration` annotation) never reach normalised events.

## `otlp/*.json`: OTLP/JSON `ExportLogsServiceRequest` documents

Produced by the real collector image (`otel/opentelemetry-collector-contrib:0.165.0`)
running in the cluster with the receivers and processors of
`infra/kind/otel/collector.yaml`, but writing to a `file` exporter (JSON encoding,
the same OTLP/JSON encoding the `otlp_http` exporter sends). Records were selected
from the capture; their content and wrapping are unmodified.

* `audit_sample.json`: five audit records (list nodes, the PSA denial, the
  cluster-admin binding, the 401, an in-progress watch).
* `containers_sample.json`: control-plane container logs (coredns, kube-apiserver,
  etcd, kube-scheduler, kindnet, local-path-provisioner) plus six lines from a
  throwaway pod `b2-fixture-logger` whose output is **synthetic and labelled
  `SYNTHETIC FIXTURE`** (control characters, a 20 000-character line recombined from
  CRI partial lines, and a fake bearer token/password to exercise redaction).
* `lab_portal_sample.json`: real lab-portal (B1's app) output from deployment
  `extorq-apps/lab-portal` after a scripted run of failed logins, an unknown user,
  `/admin` without a session, a successful login, and a 404.

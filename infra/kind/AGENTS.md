# infra/kind/AGENTS.md — ExtorQ lab cluster `extorq-lab` (owner: B2)

Scoped guide for agents and engineers changing the Kubernetes lab. The canonical
project guide is `/AGENTS.md`; telemetry details are in `docs/telemetry/kubernetes.md`.

## Hard rules

* Only ever touch the cluster **`extorq-lab`**. Use `infra/kind/kind.sh` or pass
  `--name extorq-lab` to `kind` and
  `--kubeconfig var/kube/extorq-lab-admin.kubeconfig --context kind-extorq-lab` to
  `kubectl`. Never use `~/.kube/config`; never touch `motorq-security` or any other cluster.
* Secrets move by **file path only**: the OTel producer token
  (`var/secrets/tokens/k8s-otel-extorq-lab.token`) becomes the Secret
  `extorq-system/extorq-otel-token` via `kubectl create secret --from-file ... | kubectl apply
  --server-side` (no `last-applied` annotation copy); the lab-portal demo password is random,
  lives in `var/kube/lab-portal/` (0600) and only its PBKDF2 hash enters the cluster. Never
  print, commit or put them in manifests.
* Collectors use least-privilege identities (`10-inventory-rbac.yaml`, `20-otel-rbac.yaml`).
  Never grant secrets, configmaps, `pods/exec`, `pods/log`, `nodes/proxy` or write verbs to
  them. The admin kubeconfig is for `kind.sh` and simulations only; the inventory collector
  refuses it by design.
* Anything deliberately weak (posture lab) must stay harmless: no privileged mode, no host
  namespaces, no capabilities, no RBAC bindings, hostPath only to the dedicated empty
  `/var/log/extorq-posture-lab`.
* Pin every image by digest (`kind.sh` constants); OTel releases must be stable tags
  (never nightly) and pass `otelcol-contrib validate` with the pinned binary.

## Files

| File | Purpose |
|---|---|
| `kind.sh` | lifecycle: `up` (create + verify audit flags + deploy), `deploy`, `status`, `down`, `load-images`, `token` (TokenRequest token + read-only kubeconfig, 0600), `netcheck` (pod -> gateway TLS), `audit-check` (policy guarantees on the real log), `kubeconfig` |
| `cluster.yaml` | kind config (rendered to `var/kind/`): node image digest, kubeadm v1beta4 audit flags (extraArgs is a list of `{name, value}`), policy mount, NodePort 30080 -> 127.0.0.1:8089 |
| `audit-policy.yaml` | audit policy (rule rationale in docs/telemetry/kubernetes.md) |
| `audit_check.py` | stdin audit-log checker used by `kind.sh audit-check` (prints counts/violations, never bodies) |
| `manifests/00-namespaces.yaml` | namespaces + PSA labels (+ accepted-risk annotation on `extorq-system`) |
| `manifests/10-inventory-rbac.yaml` | read-only identity of the inventory collector |
| `manifests/20-otel-rbac.yaml`, `21-otel-daemonset.yaml` | OTel collector identity and DaemonSet |
| `otel/collector.yaml` | collector config (ConfigMap `extorq-otel-config`) |
| `manifests/30-lab-portal.yaml`, `apps/lab-portal/Dockerfile` | lab web app (B1's source), hardened pod, NodePort, NetworkPolicy |
| `manifests/40-posture-lab.yaml` | deliberately weak, harmless posture target |
| `manifests/90-netcheck-pod.yaml` | short-lived connectivity check pod |

## Changing things

* **Audit policy**: kube-apiserver reads it at start. Edit `audit-policy.yaml`, then recreate
  the cluster (`kind.sh down && kind.sh up`) and run `kind.sh audit-check`. Keep secrets,
  configmaps, token requests and token reviews at `Metadata` (rule 4 stays above the
  system-read exclusions), RBAC writes at `RequestResponse`, pod writes at `Request`.
  Update the rule table in `docs/telemetry/kubernetes.md` and the normaliser tests.
* **OTel config**: edit `otel/collector.yaml`, validate with the pinned image
  (`docker run --rm --network none --tmpfs /var/lib/extorq-otel -e POD_IP=127.0.0.1
  -e K8S_NODE_NAME=x -v $PWD/infra/kind/otel/collector.yaml:/conf/collector.yaml:ro
  <image> validate --config=/conf/collector.yaml`), then `kind.sh deploy` (the config hash
  annotation rolls the pod; file offsets and the queue survive in `/var/lib/extorq-otel`).
  Component names in 0.165 are snake_case (`file_log`, `k8s_attributes`, `otlp_http`).
  Resource attributes the normaliser relies on: `extorq.source`, `k8s.pod.uid`,
  `k8s.container.name`, `k8s.namespace.name`, `k8s.pod.name`, `k8s.node.name`,
  `container.id`, `k8s.<controller>.name`; change them only together with `otlp_k8s.py`.
* **Normaliser** (`backend/src/extorq/ingest/otlp_k8s.py`) runs inside the gateway image:
  after a change, ask A to rebuild/recreate `ingest` and verify the source hash in the
  container. Bump `PARSER_VERSION` when output changes.
* **Identities**: service, instance, node-asset and container ids are derived only through
  the helpers in `otlp_k8s.py` (`workload_service_id`, `k8s_service_service_id`,
  `pod_instance_id`, `container_instance_id`, `node_asset_id`, `canonical_container_id`).
  Changing them breaks the join between OTLP events and inventory records.
* **Accepted risks**: annotate the object with `extorq.io/accepted-risk: <reason>`; the
  posture finding stays visible and is marked accepted. Annotate kubeadm-owned objects
  through `kind.sh annotate_once` (patches only when missing: each patch of a risky binding
  is a genuine RBAC write that K8S-002 sees).

## Verify after any change

```
infra/kind/kind.sh status && infra/kind/kind.sh audit-check && infra/kind/kind.sh netcheck
uv run pytest tests/unit/kubernetes -q
uv run pytest tests/security/test_security_lab_boundaries.py -q
uv run extorq-collect run --only k8s-inventory --once
```

# Genuine captures used to derive rule fixtures (owner DET)

Files here are **real telemetry** of the ExtorQ lab, exported read-only (identity
`extorq_api_ro`) from `extorq.events.payload` and validated as contract `SecurityEvent`s.
They are labelled `extorq.fixture=derived-captured`. Before export, `raw` and the
`credential_id` attribute (client-certificate fingerprints) were removed: no rule reads
them. Nothing secret is contained.

| File | Content | Exported | Used by |
|---|---|---|---|
| `k8s_cluster_birth_live.jsonl` | 10 kube-apiserver audit events of the `extorq-lab` cluster's birth, 2026-11-21 10:16:01-10:16:04Z: `system:apiserver` creating `kube-system` (the birth anchor), kubeadm's refused admin attempt (403), `kubernetes-super-admin` creating `kubeadm:cluster-admins`, `kubernetes-admin` creating `kube-public/kubeadm:bootstrap-signer-clusterinfo` and non-risky bootstrap bindings (`kubeadm:get-nodes`, `kubeadm:kubelet-bootstrap`, `kubeadm:node-proxier`, `system:coredns`, `kindnet`), and the API server's own `cluster-admin` binding | 2026-11-22 (C2, session 3), selected by `k8s_audit_id` | K8S-002 fixtures (`tests/rules/generate_fixtures.py`, builder `k8s002`) |

Contract schema 2.0 (2026-11-22): the only change to the exported records is
`schema_version` `1.0` -> `2.0` (none of them carried a field that 2.0 removed).

Derived fixtures that edit these records (other times, names, identities, subjects) are
labelled `synthetic`. To refresh a capture, export the same audit ids again with a read-only
identity and re-run `uv run python tests/rules/generate_fixtures.py --only k8s002`.

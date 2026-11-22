# AI test fixtures (owner: E)

## `context_k8s001_real.json`: REAL stored InvestigationContext (not synthetic)

* **What:** the `body` of the newest `extorq.investigation_contexts` row for alert
  `cfbff55664cf6d62121a96e4cbe6692a` (rule K8S-001, privileged pod denied by Pod Security
  admission), built by the correlation builder `extorq-correlation/0.1.0` on 2026-11-21 from
  genuine telemetry of the kind cluster `extorq-lab` (scenario run `bcfcb726ff01`, a real
  PodSecurity 403 recorded in the API server audit log).
* **How it was captured (2026-11-22):** loaded with C2's
  `extorq.correlation.store.load_latest_context` semantics as the least-privileged
  `extorq_ai` identity through the loopback debug proxy, then written with
  `json.dumps(body, indent=1, sort_keys=True, ensure_ascii=True)`. The content is
  **unmodified**: `extorq.correlation.builder.compute_input_hash(data)` still equals the stored
  `input_hash` (`b26c2d7c3c1f...`), and the regression test checks this.
* **Review before committing (data minimisation, AGENTS.md invariants 1 and 6):** no secrets
  (the only credential-shaped content is the gateway's own `[REDACTED:secret]` marker), no
  personal data: identities are cluster-generated (`kubernetes-admin`,
  `system:serviceaccount:...`, `system:node:extorq-lab-control-plane`), addresses are the
  Docker bridge (`172.18.0.x`) and the Service CIDR, names are lab namespaces and
  `extorq-sim-*` objects, and findings are public CVE titles of lab images. No host user
  names, home paths, e-mail addresses, GitHub handles or LAN addresses (pattern scan), and the
  pinned gitleaks image with `tests/security/gitleaks.toml` reports no leaks.
* **Why:** regression test for review finding E-HIGH (session 3): the AI projection dropped
  every evidence key field because the builder keys them by dotted catalog path
  (`kubernetes.verb`, `attributes.request_summary`). See
  `tests/unit/ai/test_ai_projection.py::test_real_stored_context_keeps_every_evidence_key_field`.

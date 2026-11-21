# Interface-change proposals from agent F (security assurance)

Each proposal names the owner who must make the change. F does not edit
lead-owned or other agents' files.

## F-IC-1 Reject NaN/Infinity in contracts (owner: lead; affects A, all producers)

**What.** Add `allow_inf_nan=False` to `ContractModel.model_config`
(`backend/src/extorq/contracts/common.py`), and have the gateway parse request
bodies with `json.loads(..., parse_constant=_reject)` (or pydantic JSON mode)
so the non-standard tokens `NaN`, `Infinity`, `-Infinity` are refused.

**Why (verified 2026-11-21).** `json.loads('{"a": NaN}')` returns `nan`;
`INGEST_RECORD_ADAPTER.validate_python` and `.validate_json` both accept
`attributes={"x": nan, "y": inf}` on a SecurityEvent. `canonical_json` then
raises `ValueError: Out of range float values are not JSON compliant`, and
`record_identity()` raises the same error for an InventoryItem with a NaN
attribute; `model_dump_json()` silently rewrites NaN to `null`. A producer can
therefore send records that validate but fail later (gateway 500 for the whole
batch if not caught per record, or a poison row in the spool/writer) or whose
stored value differs from what was validated. Minimal reproduction
(synthetic data):

```python
from extorq.contracts import INGEST_RECORD_ADAPTER, record_identity
rec = INGEST_RECORD_ADAPTER.validate_python({"kind": "inventory_item", "data": {
    "asset_id": "linux:lab-vm-01", "item_type": "package", "item_key": "openssl",
    "attributes": {"v": float("nan")}, "snapshot_id": "s1",
    "observed_at": "2026-11-21T12:00:00+00:00", "collector_id": "probe-f"}})
record_identity(rec)   # ValueError: Out of range float values are not JSON compliant
```

**Affected.** lead (contract), A (gateway JSON parsing; per-record exception
handling around `record_identity`/`to_row`). F will add a regression test once
merged.

## F-IC-2 Extend `.gitignore` for key material outside `var/` (owner: lead)

**What.** Add:

```gitignore
id_rsa*
id_ecdsa*
id_ed25519*
!*.pub
*kubeconfig*
*.kubeconfig
```

**Why (verified).** `git check-ignore` reports `id_ed25519`,
`infra/vm/id_ed25519` and a bare `kubeconfig` as NOT ignored. B1 generates an
SSH key pair for the collector and B2 handles a kind kubeconfig (cluster-admin
client certificate). Today both are written under `var/` (ignored), so this is
defence in depth against a future path change.
`tests/security/test_security_repo_hygiene.py::test_no_secret_named_or_runtime_files_are_committable`
already fails if such a file becomes committable.

## F-IC-3 Fix stale protocol references in contracts docstrings (owner: lead)

`contracts/__init__.py` and `contracts/catalog.py` say changes follow
`docs/team/INTERFACE_CHANGES.md`; PLAN section 8 uses
`docs/team/interface-changes/<agent>.md`. Documentation-only.

## F-IC-4 (informational) Identity part separator is not escaped (owner: lead)

`identity.stable_id` joins parts with `\x1f` without escaping. If two adjacent
parts were attacker-controlled, `("G\x1fX", "Y")` and `("G", "X\x1fY")` would
collide (verified). Today every identity has at most one free-text part next to
fixed or regex-constrained parts (rule id, asset id, ISO bucket, hex ids), so
this is not exploitable; keep it in mind for a `.v2` namespace (length-prefix
parts or reject control characters in identity inputs). No change requested now.

## F-IC-5 Reviewed-exception pragmas for security scans (owner: F, informational)

The security suite recognises two inline markers. Owners add them only after
a review; reasons are mandatory and greppable:

* Python SQL built from validated pieces:
  `# extorq: sql-reviewed <reason, >= 10 chars>` on the call line(s).
* Frontend raw-HTML sink (developer-controlled content only):
  `// extorq: html-reviewed <reason, >= 10 chars>` on the line or up to two lines above.

Secret-scan allowlist entries live in `tests/security/gitleaks.toml` (F-owned);
request additions here.

## F-IC-6 Bind service identities to the authorised asset (owners: A gateway, D1 API)

**What.** (A) In `prepare_batch`, quarantine (`identity_mismatch`) a `service` record
whose `service_id != identity.service_id(asset_id, service_kind, service_key)` and a
`service_instance` whose `instance_id != identity.instance_id(service_id,
instance_kind, instance_key)`. (D1) Read a service's instances and events by
`service_id` **and** the service's asset scope (`asset_id = <service asset>` or, for a
cluster, `startsWith(asset_id, <cluster> || '/node/')`), and resolve `GET
/services/{id}` to the row whose recomputed id matches.

**Why (verified 2026-11-21, review finding F-19).** Service ids are computable from
public facts and are not recomputed at the gateway. A synthetic probe through
`prepare_batch` with a producer authorised only for `linux:lab-vm-01` accepted a
`Service` (asset `linux:lab-vm-01`) carrying the macOS host's ssh `service_id` and an
instance attached to it. The API selects services, instances and events by
`service_id` alone (`SERVICE_GET_SQL ... ORDER BY last_seen DESC LIMIT 1`), so a
compromised or buggy producer could shadow another asset's service and inject
instances or events into its view. Legitimate collectors already derive ids with the
same helpers (`ServiceCandidate.service_id`, `make_instance_id`), so the check rejects
nothing valid.

**Affected.** A (gateway), D1 (API queries), B1/B2/B3 (no change expected).
F adds a regression case to `tests/security/test_security_ingest_redaction.py`'s
sibling suite once merged.

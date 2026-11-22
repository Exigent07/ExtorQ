# Correlation and investigation contexts

Owner: C2. Code: `backend/src/extorq/correlation/`. Contract:
`backend/src/extorq/contracts/context.py` (`InvestigationContext`, schema 1.1).

Correlation gathers what stored telemetry says around an alert and states **how** each
other event is linked to the alert's evidence. It describes co-occurrence and shared
attributes. **It never asserts causation**: a relationship says what is shared, not that
one event caused another or that one actor performed both.

```python
from extorq.correlation.builder import ContextBuilder
from extorq.correlation.store import save_context, load_latest_context
ctx = ContextBuilder(read_client).build(alert_id)   # raw clickhouse-connect client or DbClient
save_context(write_client, ctx)                     # insert-only (detector or API writer)
load_latest_context(read_client, alert_id)          # newest, validated, hash-checked
```

The detector builds and stores a context for every alert it creates or updates; the API
(`GET /api/v1/alerts/{id}/context`) serves the newest stored one or builds one on demand;
the AI worker reads the stored context (it is the only input AI receives). CLI:
`uv run extorq context build <alert_id>`.

## 1. What a context contains

| Section | Content |
|---|---|
| `alert`, `rule` | newest alert version; rule metadata of the version that wrote it (from `detection_rules`, else the loaded rules) |
| `asset` | asset record (name, criticality, environment); contract defaults with a stated limitation when no record exists |
| `window_start/end` | rule-family window: `[first_seen - before, last_seen + after]`; VM, HTTP, K8S, MAC: 15/15 min; CORR: 30/15 min; GH: 60/60 min |
| `evidence` | evidence events (full `alert_evidence` set plus the alert array; up to 100 shown, earliest and latest kept when truncated) as `EventSummary` (incl. `service_id`, `service_name`) |
| `relationships` | other events with type, bases, strength, time delta to `first_seen`, explanation (section 2); up to 250 |
| `timeline` | evidence and related events in time order (max 300) |
| `services` | services of the evidence (`role: evidence`) and of related events (`role: related`) with kind, category, adapter support, monitoring status |
| `related_assets` | other assets with related activity (cross-asset links, section 2.3) |
| `features` | deterministic aggregates (section 3) |
| `findings` | open and unverified posture findings of the asset from C3's `v_findings_current` (fallback: raw `finding_observations` shown as unverified) |
| `coverage` | per required/evidence source type: collector, status, last success, lag, `stale` (now - last_success > 3 x interval), `gap_during_window` (failed/degraded reports, reported telemetry gaps, or no report during the window) |
| `missing_telemetry` | required sources without events on the asset in the window; `rule_runs.missing_sources` of evaluations overlapping the alert |
| `limitations` | fixed statements (never causation, NAT sources, truncation, unreadable evidence, missing service/asset records, stale sources, simulation tag) |
| `truncated` | which sections were capped |
| `input_hash`, `context_id` | section 4 |

`missing_telemetry`, `limitations` and coverage notes are built only from fixed phrases and
validated identifiers (source types, rule ids, asset ids, IP addresses): no telemetry text
ever enters them. Summaries and key fields of events are sanitised (control and format
characters removed) and truncated; telemetry is untrusted input.

## 2. Relationship classification

For every candidate event the builder collects **bases** (contract `RelationshipBasis`)
against the alert's evidence profile, then derives the type and strength.

### 2.1 Types

| Type | Criteria | Strength |
|---|---|---|
| **DIRECT** | a verified shared identifier: propagated HTTP request id (`shared_request_id`), Kubernetes pod uid (`shared_pod_uid`), kube-apiserver audit id (`shared_audit_id`), commit SHA in the same repository (`shared_commit_sha`), GitHub workflow run (`shared_workflow_run`), the same resource on the same asset: file path, systemd unit, Kubernetes object, workflow file (`shared_resource`) | strong |
| **CANDIDATE** | plausible but inferred: same asset and context window plus a shared non-identifying attribute: a source IP that is **not** a shared NAT address (`shared_source_ip`), a principal name (`shared_principal`), the same ExtorQ simulation marker (`simulation_run`) | moderate with a non-NAT IP or two attributes; weak otherwise |
| **UNESTABLISHED** | considered and shown for completeness, no supported link: an IP match only through a shared NAT/gateway/loopback address (`shared_nat_source_ip`), or temporal proximity on the same asset only (`same_asset_time_window`), possibly with service topology bases | weak |

The simulation marker (`extorq-sim-<run_id>`) is a lab scenario tag carried in
attacker-controllable text (user names, user agents, object names); it never makes a link
DIRECT.

### 2.2 Service-aware bases (contract 1.1)

They describe topology and never upgrade a relationship by themselves. An event's services
are its producing service (`events.service_id`) and, when present, the service it is about
(`attributes.subject_service_id`, e.g. a unit-file change produced by systemd about the
unit's own service); both count for `same_service` and for `InvestigationContext.services`
(subject services of evidence events get role `evidence`).

* `same_service`: the event comes from a service of the evidence;
* `same_service_instance`: the same process, container or Pod instance;
* `cross_service_same_asset`: another service on the alert's asset (e.g. nginx and sshd on
  the VM). Such a link is CANDIDATE only with a shared attribute and DIRECT only with a
  shared identifier (e.g. nginx `$request_id` propagated to the lab app);
* `cross_asset`: another asset (section 2.3).

Service references are only trusted when consistent: a `services` record counts if its id
recomputes from `(asset_id, service_kind, service_key)`, and an event's service reference is
not trusted when the only valid records for that id belong to an unrelated asset
(service-id shadowing; the context then shows the service as unknown and says so).

### 2.3 Cross-asset links

Events on other assets are considered only with **identity evidence**: a source IP that is
not a shared NAT address, an authenticated principal (Kubernetes user, GitHub login, or a
host user name from a *successful* login; names submitted in failed logins are attacker
chosen and are never used across assets), or a shared identifier (e.g. a pod uid seen by
the audit log of the cluster and a node's container log). Through a shared NAT address a
cross-asset link stays UNESTABLISHED. Principal names are not globally unique; the
explanation says so.

### 2.4 Shared NAT / gateway addresses

`EXTORQ_CORRELATION_SHARED_NAT_IPS` (JSON list), default `10.0.2.2` (QEMU SLIRP gateway:
every connection from the Mac to the lab VM), `172.18.0.1` (Docker `kind` network gateway:
kubectl and NodePort traffic, observed in the captured audit records), `10.244.0.1` (kind
pod-network gateway: NodePort traffic to lab pods, observed in the live lab-portal logs),
`127.0.0.1`, `::1`.

### 2.5 Selection and bounds

1. **Linked events** (all assets, within the window): shared request id, pod uid, audit id,
   commit, workflow run, source IP, simulation run, authenticated principal; on the alert's
   asset also principal names, resource paths/names and evidence services (max 1000 rows).
2. **Temporal neighbours**: the 40 nearest other events on the alert's asset.

Relationships are ranked (DIRECT, CANDIDATE, UNESTABLISHED; then strength; then closeness to
`first_seen`; then id) and capped at 250 (`truncated.related`).

## 3. Aggregated features (deterministic)

Common: relationship counts per type, source types, number of evidence/related services,
`cross_service_activity`, number of related assets, `simulation_tagged`,
`causation_established: false`.
SSH: failure events, distinct user names and connections, `ssh_success_after_failures` (a
successful login from a failing source after the first failure) with the user names,
`sudo_after_login`. HTTP: 4xx/5xx counts, distinct 4xx routes, probe-like routes, distinct
user agents, application login failures and authorization denials. Kubernetes: Pod
Security denials, cluster-admin grants, other 403s, actors, namespaces. GitHub: actors,
added write scopes, write-all added, workflow runs of the changed commit, branch protection
and settings changes. Persistence: changes, units, auditd corroboration and writers, unit
state changes, package changes. Values are computed only from the events in the context.

auditd corroboration (`auditd_corroborated`, `auditd_writers`) counts only **successful
create/modify syscalls** whose written path is one of the changed unit paths (the shared
definition in `extorq.detection.linux_audit`, identical to the VM-002 / CORR-002 rule
parameters and checked by a unit test). Removals of those paths (for example a cleanup's
`unlinkat` by `rm`) are counted separately as `auditd_removals` and never corroborate a
change; failed attempts, xattr or timestamp changes and numeric (non-enriched) syscall
values count as neither.

## 3a. Correlation rule CORR-002 (ordered multi-stage pattern)

CORR-002 (`rules/correlation/`, catalog entry in `docs/detection-catalog.md`) is a detection
rule that correlates three services of one Linux host in order: HTTP probing, SSH
authentication failures, then a systemd persistence change, all within 30 minutes. It
states ordered co-occurrence only (`features.causation_established` is always false; never
high confidence). Since v1.2.0 the persistence stage requires **creation or modification
evidence**: an inventory diff (unit created, modified or enabled) or a successful auditd
create/modify syscall on a unit file. Deletions are context only (`context_unit_removals`,
`context_removal_events`), and the features separate units whose new content the inventory
confirmed (`persistence_units_inventory_confirmed`) from units only auditd saw written
(`persistence_units_audit_only`, e.g. an unchanged unit re-installed by `install`).
Observed live: v1.0.0 counted the VM-002 simulation's cleanup (`unlinkat` by `/usr/bin/rm`)
as the persistence stage of alert `b46da3805d1c6f17b6c1ed363b49a777`; the chain is still
valid on the unit creation at 15:07:11Z (verified with the dry run,
`docs/detection-engine.md`), but the stored alert keeps the evidence v1.0.0 attached
(append-only evidence).

## 4. Hashing, identity and storage

* `input_hash` = SHA-256 of the canonical JSON (`identity.canonical_json`) of the context
  without `context_id`, `created_at` and `input_hash`; `context_id =
  identity.context_id(alert_id, input_hash)`. Same stored data and build time give the same
  hash (verified by tests). Late events, new collector health reports or a newer rule
  version change the bundle and therefore the hash. Coverage staleness depends on the build
  time by design.
* `save_context` writes `context_relationships` first, then the `investigation_contexts`
  row (`body` = canonical JSON). It refuses a context whose hash does not match. It is
  insert-only, so the API writer identity (no SELECT) can use it.
* `load_latest_context` serves the newest row (`created_at`, then `context_id`), validates
  it against the contract and recomputes the hash from the stored JSON; a mismatch raises
  `ContextIntegrityError` instead of serving altered evidence.

## 5. Failure behaviour

The alert, its rule metadata and its evidence are mandatory (`AlertNotFound`,
`ContextBuildError`). Asset, services, findings, coverage and missing-telemetry sections
degrade to an explicit limitation when their query fails. In the detector, a context
failure is logged and counted (`context_failures_total`) and never fails detection.

## 6. Limitations

* Correlation is bounded by retention (events: 90 days), the context window and the caps
  above; absence of related events is not evidence of absence, especially with stale or
  gapped sources (stated in `limitations`).
* Shared identifiers are only as good as their propagation (e.g. the lab app's own request
  ids are not correlation keys; only nginx-propagated ids are).
* IP addresses identify network paths, not people; NAT, proxies and DHCP break that link.

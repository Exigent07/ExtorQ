# ExtorQ remediation and validation status

This report follows the [independent baseline audit](independent-release-audit.md). The user approved source changes for A1, A4, A5, A6 and A7, isolated design/verification for A2 and A3, and backup/reset design and disposable testing for A8. The local HEAD during work was `023fdb63b6023143302a0733883c9749743835c3`, with pre-existing uncommitted development. Patches were applied to the current source after rechecking the findings. The approval does not extend to deployed migrations, existing runtime data or Git publication.

**Release verdict is NOT READY.** Local regression coverage improved substantially. ClickHouse SQL execution, VM dispatcher rollout, current GitHub credential grants, live four-asset detections, retained evidence integrity, ingestion durability and dashboard behavior remain release gates.

## Approved implementation

| Batch | Changes | Validation and limits |
| --- | --- | --- |
| A1 | Changed the existing `.env` mode from 0644 to 0600 using metadata only. The GitHub collector configuration now requires a dedicated token-file path and disables GitHub CLI fallback. | 20 targeted credential/collector tests passed. The credential itself and its effective repository permissions were not inspected. Collection will report a failure if the configured token file is absent. |
| A4 | Removed the terminal cap from 21 rule SQL files and made the SQL guard reject top-level caps. The engine fetches a sentinel row and fails an incomplete result before applying alerts or advancing the last-success watermark. The runner now requires action-linked evidence from the deployed rule version and the expected authenticated producer. | Static registry validation passed for all 22 rules. Offline tests cover result overflow, watermark retention, wrong version/actor/producer, incomplete control windows and demo checks. The current SQL limit design retries on the normal schedule. It does not paginate a window that remains saturated. ClickHouse execution was blocked. |
| A5 | VM-002 v1.4.0 requires an audit write on the same asset and path in the preceding 120 seconds for high confidence. K8S-002 v1.3.0 requires the same reported object UID and resource version across audit and inventory. Typed portal logs require Deployment metadata and a Pod UID. ReplicaSet/Job ownership includes the UID in its lookup. Service findings are scoped to the owning asset and its descendants. Unknown service filters return 404. | Offline parser, API and owner-replacement tests passed. Historical K8S-002 fixtures lacking matching revisions now expect medium. Reported Pod-to-controller metadata is stronger, and final top-level controller authenticity still depends on the collector and available Kubernetes metadata. Existing stored alerts may retain prior confidence and evidence under the alert merge policy. New confidence behavior must be checked on fresh alerts before deployment. |
| A6 | Dispatcher 1.2.0 replaces arbitrary process arguments with kernel executable paths where available. The collector ignores legacy process-argument payloads. Linux auditd and Linux/macOS sudo records retain source identity and relevant outcomes while omitting arbitrary arguments from normalized and raw event fields. GitHub workflow-run polling fetches each page in its bounded scan and keeps the last complete timestamp on truncation. | Offline tests verified redaction/minimization, parsing, and a mocked later-page transition. The VM dispatcher remains to be deployed and checked on the dedicated VM. Very high GitHub run volume can still exceed the page or lookback bound, and the collector emits a gap. Systemd unit command configuration and explicitly opted-in macOS inventory argument collection have separate source contracts. Existing historical evidence was preserved. |
| A7 | Updated stale 2.0 contract, authorization, GitHub and Kubernetes tests. Kept retired-input quarantine and viewer authorization assertions. Replaced an obsolete scenario dry-run assertion with static positive/revert workflow-analysis checks and kept legacy argument guard coverage. Changed a macOS output-bound test to use an approved executable available in this environment. | Full default-suite run and machine-readable checks listed below. The collector-control lifecycle test runs where `ps` inspection is available. This session cannot inspect processes. No frontend source change was needed for this batch. The deployed UI still needs revision and authenticated smoke verification. |

### Provenance retained for controlled validation

Version 2 validation reports in `var/reports/` record action/window, rule version, alert IDs and exact verified event IDs, expected producer and source. They preserve the source-native reference when one is available and explicitly label the derived event reference otherwise. This makes validated activity identifiable without reviving a Simulations navigation category. Reports are written locally with mode 0600. The demo check requires v2 evidence-linked positive cases and completed negative controls. Older reports remain historical. A matching rule ID or an unresolved reference cannot establish a pass.

For actions using shared identities or NAT, verified producer/source, event shape and time identify the matching observations, while attribution to a person remains unknown. Controlled tests with no telemetry or an ambiguous alert yield an inconclusive negative result. Native source excerpts still need to be collected from each approved asset before source-to-dashboard acceptance.

### Remaining defects and operational follow-ups

- EXT-02 remains in the current deployed design. A2 is an isolated design only.
- EXT-03 and EXT-06 remain. The deployed OTel batch pipeline and correlation health scope were left at their prior implementation under the A3 approval gate.
- EXT-13 still needs a retention policy and live evidence age assessment. Reset design is separate from retention.
- High-confidence alert history is historical. The detector's cross-version merge can retain a previous confidence when an already-existing alert is extended. Review a migration/version-boundary policy before treating a previously stored alert as an example of current VM-002 or K8S-002 semantics.
- New GitHub credential provisioning, dispatcher rollout and all four current telemetry paths need operator evidence. The final Console/Grafana views and five historical UI smoke checks remain unverified.
- Captured evidence and validated scenarios still need live operator-approved targets, current native timestamps, a controlled test identity per run where practical, and matching evidence in ClickHouse.

## Semantic audit of all 22 rules

For each rule I compared the metadata, source/event predicates, alert evidence selection and declared fixture cases. A script checked that every declared event type appears as a literal in that rule's SQL and enumerated event types present in its JSONL fixtures. Every rule declares at least one alert case and one no-alert case. The table records static observations, so fixture counts are not measured positives or negatives. Rule execution, replay and late-arrival SQL checks require ClickHouse.

| Rule version | Static review of predicate and evidence | Declared + / − cases | Remaining coverage or qualification |
| --- | --- | --- | --- |
| APP-001 1.1.0 | Per-user guessing and per-source spraying aggregate cited application failures, with deduplicated input and NAT confidence. | 3 / 2 | Successful logins are not counted. Independently check both app source paths and service attribution. |
| CORR-002 1.3.0 | Ordered window requires HTTP, SSH and a systemd change on one asset. Supporting evidence is kept separate from a causal conclusion. | 4 / 7 | No literal fixture event for SSH max-auth failures or modified-unit branch. Shared source identity and ordered timing remain inferential. |
| GH-001 2.0.0 | Permission increase uses specific commit/workflow identity. Lexical fallback lowers confidence. | 3 / 4 | Privileged trigger alone is tested as a negative. Isolated native commit evidence still required. |
| GH-002 1.0.0 | Requires a privileged trigger plus untrusted checkout evidence, scoped to one workflow change. | 2 / 2 | Static comparison establishes workflow content, while actual execution remains unknown. |
| GH-003 1.0.0 | Detects newly added unpinned third-party actions and cites the workflow change. | 1 / 2 | Verify pinned and first-party exceptions with ClickHouse SQL cases. |
| GH-004 1.0.0 | Detects a newly added workflow expression in a script context and cites the workflow change. | 1 / 2 | Static expression finding does not establish execution. |
| GH-005 1.0.0 | Rule consumes credential-shaped added-line observations with commit/path and a redacted match. | 2 / 1 | Title should be read as a credential-shaped match. A provider-shaped example can still match, and the collector does not verify credential validity. |
| HTTP-001 1.1.0 | Qualifying HTTP client errors and diverse probe routes form a source/asset burst. | 2 / 3 | Shared addresses lower confidence. Ordinary errors and slow probing have controls. |
| K8S-001 1.1.0 | Requires Pod Security denial tied to the audit ID and privilege flags or violation text. | 3 / 3 | Verify distinct denied and admitted controls and the dry-run flag. |
| K8S-002 1.3.0 | Successful risky audit write and/or risky inventory difference. High confidence requires an exact object revision across both. | 11 / 6 | No literal inventory-updated row. A synthetic exact-revision and different-revision pair extend the historical fixtures. Their SQL results still need execution. |
| K8S-003 1.0.0 | Human interactive request rule uses accepted session response and Pod identity. Evidence shows the request. | 2 / 2 | Audit data does not show actions performed inside the session. |
| K8S-004 1.0.0 | Successful cluster-wide or multi-namespace enumeration can be linked to actor and audit request. | 2 / 2 | Audit records establish access metadata. Returned secret values are excluded from telemetry. |
| K8S-005 1.0.0 | Successful workload admission combines risk flags and inventory confirmation where available. | 2 / 2 | No literal inventory-updated record. Object-version precision merits a separate review. |
| VM-001 1.1.0 | Five connections or ten attempts share asset/source within five minutes. Evidence is sshd failures, with NAT-qualified confidence. | 5 / 4 | Verify genuine journald events, unique grouping and benign below-threshold behavior. |
| VM-002 1.4.0 | Eligible created/modified unit or enable-only signal. Audit write supports confidence only within the preceding two minutes. | 5 / 2 | Existing captures cover a close write and unrelated syscall/cleanup paths. Added a synthetic same-path out-of-window case. Its SQL result still needs execution. |
| VM-003 1.0.0 | Account snapshot transition is the trigger. Audit identity-file activity is supporting evidence. | 3 / 2 | Path/time correlation alone does not establish a specific account writer if multiple accounts change. |
| VM-004 1.0.0 | Cron configuration change and corresponding audit writes. | 3 / 2 | Prior Phase A summary table mislabeled this as an authorized-key rule. The actual rule is cron persistence. |
| MAC-001 2.0.0 | Launchd inventory path/digest changes drive the alert, including parse-quality confidence. | 4 / 1 | Verify bounded native filesystem observation and cleanup on an authorized user-level fixture. |
| MAC-002 1.0.0 | Launch item configured with a qualifying executable path or program type. | 2 / 1 | No literal item-modified fixture. A risky configuration does not establish launch execution. |
| MAC-003 1.0.0 | New wildcard TCP listener and verified executable when available. | 2 / 1 | Verify source visibility for the collector's configured permissions. |
| MAC-004 1.0.0 | Authentication-failure counts and optional second-system corroboration qualify confidence. | 2 / 1 | Verify redacted counts and same-account/time linkage with native Unified Logs. |
| MAC-005 1.0.0 | Unsigned or ad-hoc-signed application observation with path/version and signing evidence. | 2 / 1 | Installation and execution are distinct. Verify an appropriate benign signed control. |

## A2 design gate — canonical event identity

### Proposed compatibility and rollout

1. Introduce a versioned server-owned identity for accepted events using the authenticated producer, authorized asset/source and an explicitly stable native key. Keep v1 historical event rows and their alert IDs intact. Add a gateway-owned mapping from producer plus legacy event ID to canonical event ID for upgrade replays. Source types without usable native IDs need a reviewed stable per-source fallback before participation.
2. Preserve producer-scoped batch replay. For event-level replay, record a canonical content digest next to the canonical ID. Treat a matching digest as replay. Quarantine a different digest for the same canonical identity and keep both producer provenance and a sanitized conflict reason. Comment and test which transport/enrichment fields are excluded from the digest so delayed sends do not become false conflicts.
3. Proposed affected files are `contracts/identity.py`, `ingest/processing.py`, `pipeline/spool.py`, gateway batch handling, producer SDK/adapters for native-key completeness, and any API/evidence path that needs the versioned lookup. The existing ClickHouse string event-ID columns can hold v2 IDs. Add only an additive migration if identity-version metadata needs a dedicated column after the isolated storage test. Never edit applied migrations or rewrite the historic event ID in place.
4. Before cutover, export the ClickHouse evidence/reference tables and back up the gateway spool and collector outboxes. Pause relevant writers, verify matching schema/image versions, and introduce tolerant readers before the first v2 writes. Run shadow resolution for event/evidence references, then enable v2 for one producer on disposable storage. Finish rollout only after replay, orphan checks and negative controls pass. Legacy conflicts that discarded an original row cannot be repaired by changing the namespace.

### Rollback and isolated evidence

Before enabling v2 writes, rollback is selecting the previous image/config while the additive reader and schema remain compatible. After v2 writes, pause producers and keep v2-capable readers. Restore a pre-cutover snapshot only under a separately accepted data-loss decision. Otherwise retain v2 IDs and reconcile any queued mixed-version records through the stored mapping before rolling forward or disabling v2 for new writes. Do not drop mappings until outstanding outboxes and evidence refs reconcile.

In a scratch Python check, the candidate deterministic key was repeatable for one producer, distinct across two independent source/asset producers and distinct from the v1 namespace. This was a key-model check. SQLite migration/restart, ClickHouse writer replay, historical and mixed-version evidence retrieval still require a real isolated migration rehearsal. Deployment against persistent data is gated.

## A3 design gate — Kubernetes delivery and health

### Proposed canary and rollback

1. Validate configuration with the pinned OTel image in a disposable ExtorQ environment. Remove the two pipeline-level memory batch processors in the canary configuration, retaining verified file checkpoints, the node-persistent exporter queue, user/network controls and gateway acknowledgment after durable spool commit. Only use exporter batch settings if verified with the actual pinned release. Size logging requests against the gateway's limits of 1,000 records and 4 MiB decompressed.
2. Exercise active and retained rotated log filenames with source-native sequences. Include process termination before enqueue, after persistent enqueue and after gateway durability, worker/control-plane restart, queue saturation, a bounded exporter outage, renewal/rejection, and an outage longer than the retry budget. Feed per-node queue size/capacity, accepted/sent/failed/enqueue-failed records and delivery lag into health. Verify drops and unobservable gaps are visible.
3. In the correlation builder, select health only from the alert's actual asset or an explicitly related collector with known source coverage. Scope gap events by matching asset and source. Keep missing data unknown. Verify background events and collector reports from a separate asset do not affect the same rule's investigation.
4. A production-like canary needs exclusive ownership of each node's checkpoint and queue directories. Preserve copies of configuration, file offsets, queue data and native retained logs. Roll one node at a time while measuring count reconciliation. For rollback, stop the canary before starting the previous version, retain an isolated copy of both state generations, and replay only through a compatible state or a reconciled native range. Never run old and new services concurrently against the same node storage.

Proposed files are `infra/kind/otel/collector.yaml`, the OTel DaemonSet/configuration and health exporter, plus `backend/src/extorq/correlation/builder.py` and corresponding health projections. Current source and upstream durability documentation were reviewed. The pinned image could not run in this session. Upstream queue documentation alone cannot establish pinned-version behavior. No A3 deployment or OTel process fault test occurred. [OpenTelemetry Collector resiliency](https://opentelemetry.io/docs/collector/resiliency/)

## A8 design gate — clean-room validation and reset recovery

Use a new named Compose project, state path and ClickHouse/spool volumes for the acceptance environment. Before deployment, verify project and volume IDs, service bindings, persistent mounts and roles. Review the fresh migration ledger, including 0008, before routing agreed test producers. Existing queues and native cursors must stay paired. Retained native files can replay on a fresh receiver, so isolate the validation source cutoff and record the first accepted source IDs.

For an approved in-place reset, first quiesce all writers including the analyst mutation API, external OTel senders and scanners, then capture transactionally consistent ClickHouse and SQLite backups. Preserve source offsets and pending exporter state in the same recovery manifest. Record row counts and migration checksums. Run a restore rehearsal, validate evidence refs and quarantine counts, then request approval for that exact destructive target, table list, downtime and recovery point. A partial failure leaves writers stopped until restoration or an explicit resume decision.

Executed a scratch SQLite WAL-mode test of backup, local clearing, and restore to another scratch database. `integrity_check` passed and the queued record and checkpoint were recovered together. Existing reset/rebaseline unit tests also ran. A ClickHouse and OTel restore rehearsal is pending. No real database, queue, collector checkpoint or historical evidence was changed.

## Test and delivery log

| Check | Result |
| --- | --- |
| A1 targeted GitHub collector and token tests | 20 passed. |
| Targeted API, detection, security, Kubernetes, Linux, GitHub and macOS suites | 1,254 passed, 3 skipped, 32 deselected at the combined checkpoint. A subsequent focused run with the added detection and attribution unit regressions had 358 passes. |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider --tb=no` | Final run had **1,960 passed, 235 skipped and 247 deselected**, with two pre-existing hardening warnings. Process-lifecycle coverage was skipped here because process inspection is denied. Docker-backed coverage was not exercised. |
| `.venv/bin/ruff check --no-cache backend/src collectors/src scanners/src tests scripts eval detection_tests` | Passed. |
| `.venv/bin/ruff format --no-cache --check backend/src collectors/src scanners/src tests scripts eval detection_tests` | 349 formatted files, check passed. |
| `.venv/bin/python -m mypy --cache-dir /dev/null` and `.venv/bin/python -m mypy --cache-dir /dev/null scripts/*.py detection_tests` | Passed, 196 platform files and 20 operator/validation files. |
| `.venv/bin/python -m extorq.cli rules validate` | All 22 rules valid. The fixture model check independently validated 740 event rows across 118 unique fixture files. |
| `.venv/bin/python -m extorq.cli rules test` | Docker socket denied. ClickHouse SQL, the synthetic revision/window assertions and replay remain unverified. |
| `.venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/platform/test_platform_reset.py tests/unit/platform/test_platform_reset_data.py tests/unit/platform/test_platform_collectors_ctl.py --tb=no` | 55 passed, 1 environment-specific skip. The disposable SQLite backup/restore check also passed independently. |
| `.venv/bin/python -m detection_tests list` and `git diff --check` | Both passed. The list path did not run detection actions. |

No services were restarted. No real secret contents were read. No credential was provisioned or sent to GitHub. The existing ClickHouse store, its queues, collector cursors and historical evidence were preserved. No change was made to the deployed pipeline, Git configuration or Git history. No commit or push was attempted.

## Release gates and approval requests

1. Run the ClickHouse harness and restore rehearsal in a verified new disposable environment with Docker access. Confirm the reported failure status, the close-write and matching-revision cases, fixture replay and late arrival. A repeatedly saturated window needs a decision on fair, bounded evaluation without compromising event windows.
2. Confirm the exact authorized validation assets and bounded state-changing actions before triggering live tests. A fresh GitHub credential and a checked VM dispatcher revision are required for their current validation paths. Collect native evidence, controls and four-asset joins, then run authenticated Console/Grafana checks on the same pinned deployment.
3. Review the A2 and A3 plans only after their isolated migration and pinned-image fault tests pass. Applying either to existing persistent data requires separate approval.
4. Use a new isolated store by default. An in-place reset, history rewrite, new remote or push requires its own review. Formal event and alert retention policy remains a separate decision.

# GitHub repository security telemetry

Owner: C1. Code: `collectors/src/extorq_collectors/github/`. Config:
`config/collectors/github.yaml`. Tests: `tests/unit/github/` (synthetic API fake).
Lab content: `lab/github-repo/`. Scenario: `simulations/github/` (GH-001).

This page describes implemented behaviour. Items marked **planned** do not exist yet.

## 1. What is collected

The collector polls the GitHub REST API (`api_poll`, API version `2022-11-28`) for each
configured repository and sends records through the ingest gateway as producer
`github-collector` (source type `github.api`).

| Record | Content | Cadence |
|---|---|---|
| Asset `github:<owner>` (`github_account`) and `github:<owner>/<repo>` (`github_repository`, parent = owner) | visibility, default branch, archived, fork, allow_forking, default workflow token permission, default-branch protection flag, secret scanning / push protection status, Dependabot alert status, whether the token has admin | first poll, on settings change, every `posture_interval_seconds` |
| `github.commit.observed` | one per commit on a monitored branch: SHA, branch, pusher or author, changed-file count, workflow files touched, signature verification, push time, sanitised commit message | every poll (new commits since the checkpoint) |
| `github.workflow.modified` | one per (commit, workflow file) touched: before/after permission analysis (section 5) and a redacted unified diff | with the commit |
| `github.workflow_run.observed` | one per run state change: run id, attempt, head SHA, event, status, conclusion, actor / triggering actor, head repository (fork) | every poll |
| `github.repo.settings_changed` | security-relevant repository or Actions settings changed between polls (`changed_fields`, previous / current values) | on change |
| `github.branch_protection.changed` | default-branch protection or applicable ruleset rules changed between polls | on change |
| `extorq.collector.gap_detected` | genuine telemetry gaps (section 8) | when detected |
| ScanRun `extorq-posture-github` + PostureFindings | repository posture checks (section 6) | every `posture_interval_seconds` (900 s) and immediately after any settings, protection or workflow change |
| ScanRun `github-security-alerts` + PostureFindings | open Dependabot, code scanning and secret scanning alerts (section 7) | every `security_alerts_interval_seconds` (1800 s) |
| InventoryItems `github_workflow`, `github_branch` | workflow files at the default-branch head (triggers, declared and effective permissions, unpinned actions, blob SHA) and monitored branches (head, protection state); tombstones (`present=false`) for removed workflows and deleted or unmonitored branches | with each posture scan |
| CollectorHealth (runner) | token source and kind, warnings, data gaps, request count, 304 count, rate-limit budget, per-repository result | every cycle |

Asset ids are lower-case (`github:exigent07/extorq-lab`); display names keep GitHub's case.
GitHub repositories have no host services: the collector emits no `service` /
`service_instance` records, `event.service` and `PostureFinding.service_id` stay empty,
and posture is repository-scoped (PLAN section 10).

Not collected: organisation audit logs (they require GitHub Enterprise Cloud and an
organisation owner; ExtorQ never claims this source), webhook deliveries, pull request
contents, issue or comment bodies, file contents other than workflow files, secret values
(secret scanning alerts are listed with `hide_secret=true`), Actions logs and artifacts.

## 2. Endpoints and token permissions

All requests are `GET`. Required fine-grained personal access token permissions are taken
from GitHub's REST documentation; when GitHub answers 403/404 it may name the permission in
the `X-Accepted-GitHub-Permissions` header (fine-grained and App tokens only), which the
collector quotes in the data-gap reason.

| Endpoint | Used for | Fine-grained permission (read) | 403 / 404 handling |
|---|---|---|---|
| `GET /repos/{o}/{r}` | metadata, settings, `security_and_analysis` (admin only) | Metadata | 404: repository not found or not visible: cycle error for that repo |
| `GET /repos/{o}/{r}/actions/permissions/workflow` | default `GITHUB_TOKEN` permission, PR approval by Actions | Administration | data gap; dependent checks skipped |
| `GET /repos/{o}/{r}/actions/permissions` | Actions enabled, allowed actions, SHA pinning required | Administration | data gap |
| `GET /repos/{o}/{r}/vulnerability-alerts` | Dependabot alerts enabled (204) / disabled (404 with admin) | Administration | 404 without admin: "hidden" gap |
| `GET /repos/{o}/{r}/rulesets`, `GET .../rules/branches/{b}` | rulesets and rules applying to a branch | Metadata | data gap |
| `GET /repos/{o}/{r}/branches/{b}` | branch head and `protected` flag | Contents | default branch 404: empty repository |
| `GET /repos/{o}/{r}/branches/{b}/protection` | protection details | Administration | 404 + unprotected: no protection; 404 + protected or 403: "unknown", data gap |
| `GET /repos/{o}/{r}/commits`, `.../compare/{a}...{b}`, `.../commits/{sha}` | new commits since the checkpoint and their changed files | Contents | compare 404: checkpoint commit vanished (gap event) |
| `GET /repos/{o}/{r}/contents/{path}?ref=` (raw, at most a 4 MiB prefix) | workflow file before / after a commit | Contents | 404: file absent at that ref; other errors: per-commit isolation (section 8) |
| `GET /repos/{o}/{r}/activity` | push time, pusher, force-push flag | Contents | data gap; `event_time` falls back to first observation |
| `GET /repos/{o}/{r}/actions/runs`, `.../runs/{run_id}` | workflow runs and tracked open runs absent from the listing | Actions | data gap |
| `GET /repos/{o}/{r}/git/trees/{sha}?recursive=1`, `.../git/blobs/{sha}` (raw, at most a 4 MiB prefix) | workflow inventory, CODEOWNERS presence | Contents | data gap; workflow checks skipped |
| `GET /repos/{o}/{r}/dependabot/alerts?state=open` | Dependabot alerts | Dependabot alerts | "feature unavailable or not authorised" |
| `GET /repos/{o}/{r}/code-scanning/alerts?state=open` | code scanning alerts | Code scanning alerts | same |
| `GET /repos/{o}/{r}/secret-scanning/alerts?state=open&hide_secret=true` | secret scanning alerts (no secret values) | Secret scanning alerts | same |

**Minimal recommended token**: a fine-grained personal access token restricted to the
monitored repositories, expiry of 30 days or less, repository permissions *Metadata: Read*
(mandatory), *Contents: Read*, *Actions: Read*, and optionally *Administration: Read*
(branch protection, Actions settings, Dependabot status), *Dependabot alerts: Read*,
*Code scanning alerts: Read*, *Secret scanning alerts: Read*. No write permission is used
by the collector. Every optional permission that is missing becomes a visible data gap.

### Provision the dedicated token

1. In GitHub, generate a fine-grained personal access token for the repository owner.
   Select **Only select repositories** and choose `Exigent07/extorq-lab` for the checked-in
   configuration. Set **Metadata**, **Contents**, and **Actions** to **Read**, with the
   optional read grants above if the API coverage is needed. Use a short expiry and obtain
   organisation approval if the resource owner requires it. [GitHub token settings guide](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
2. Run `install -d -m 0700 var/secrets/github` as the collector account. Put the token
   directly in `var/secrets/github/readonly-pat` using a secure local editor or password
   manager, then run `chmod 0600 var/secrets/github/readonly-pat`. The collector requires a
   regular, non-symlink file owned by the collector, in mode 0600 or 0400, at most 4 KiB.
   To use a different path, set `EXTORQ_GITHUB_TOKEN_FILE` or configure `settings.token_file`.
3. Run `uv run extorq-collect run --only github-repos --once`. In collector health verify
   `token_source=file`, `token_kind=fine_grained_pat`, repository success and each required
   source's gaps. The collector verifies token type and file security and uses only GET.
   GitHub's token settings determine effective repository scope and permission levels.

## 3. Client behaviour (`client.py`)

* Headers `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`,
  `User-Agent: extorq-github-collector/<version>`; raw content uses
  `application/vnd.github.raw+json`.
* Timeouts: `request_timeout_seconds` (default 20 s) read/write, connect and pool at most 10 s.
* Bounded retries (3 attempts) with jittered exponential backoff for network errors, 408 and
  5xx. 401 fails the cycle; 403/404/409 are typed errors handled per endpoint.
* Pagination follows `Link: rel="next"`; next links must stay on the configured API origin
  (a hostile or broken response cannot redirect the token elsewhere). Listings are bounded
  by `page_size` (default 50) and `max_pages` (default 10); truncation is reported.
* Conditional requests apply to repository, Actions settings and branch snapshots.
  Workflow-run polling fetches each page in its bounded scan because pages can change
  independently. A truncated scan records a gap and preserves the last complete listing
  timestamp. Up to ten tracked open runs absent from the listing are checked directly
  per poll, including after truncation or a listing failure other than auth and rate limits.
* Primary rate limit: `X-RateLimit-*` headers are tracked; requests known to exceed the
  limit are not sent. Secondary rate limits: `Retry-After` is honoured; 403/429 "secondary
  rate limit" responses without headers wait at least 60 s with exponential backoff. Any
  wait longer than `max_rate_limit_wait_seconds` (60 s) ends the cycle early instead of
  blocking; the next cycle resumes from the committed checkpoints. Optional phases (posture,
  alerts) are skipped when fewer than `rate_limit_reserve` (200) requests remain.
* Response bodies are streamed and capped (16 MiB) before parsing; an oversized JSON body is
  an error, never silently cut. Workflow files are read with `get_text_prefix`: at most the
  first 4 MiB (`MAX_LEXICAL_BYTES`) of the raw content, the rest is never read and the
  result is marked truncated (section 5, fail closed).

Budget measured on 2026-11-21 against two public repositories (section 11): first cycle
44 requests, following cycle 18 requests with four 304s, i.e. about 9 requests per
repository per steady-state cycle. At the default 120 s interval that is roughly 270
requests per repository per hour, plus the posture (every 15 min) and alert (every 30 min)
scans: well inside the 5,000/hour primary limit of a user token.

## 4. Restart safety and identities

Per repository, one JSON checkpoint (`github:repo:<owner>/<repo>`) holds the last processed
commit per branch, ETags, the last settings / protection snapshots, seen workflow-run
states, the last listing time and inventory keys. It is committed by `ctx.emit` in the same
SQLite transaction as the records derived from it, phase by phase (commits in chunks of 20).
A crash before a commit re-reads from the previous checkpoint; event identities are
derived from the commit SHA, the commit SHA plus workflow path, or the versioned workflow
run transition key (`workflow-run.v2` with run ID, attempt, status, conclusion and native
revision timestamp when available). The current collector can read old checkpoint run
signatures and skips unchanged states, so an upgrade with intact checkpoints does not
re-emit those states. Historical run events keep their original identities. If the old
checkpoint is lost, a re-observed historical run can have one legacy and one v2 event.
Corrupt or unknown checkpoint versions start a fresh baseline; all checkpoint collections
are bounded.

Time semantics: `event_time` of commit and workflow events is the push time from the
activity API (`attributes.time_basis=push_activity`, actor = pusher) when available, else
the first-observation time (`time_basis=first_observed`, actor = commit author account).
Git author / committer dates are attacker-controlled and are kept only as attributes.
Settings and protection changes use the observation time (`time_basis=observed`) and carry
`previous_observed_at`. Transient errors never produce change events: the previous known
values are carried forward.

The first poll of a branch processes the `initial_commit_backfill` (10) most recent commits
and flags them `initial_backfill=true` (also on their workflow events); later polls use the
compare API from the checkpoint. More than `max_commits_per_poll` (50) new commits are
processed over several polls (checkpoint advances per chunk).

## 5. Workflow analysis (`workflow.py`)

Workflow YAML is attacker-controlled. Parsing uses a `SafeLoader` subclass with YAML 1.2
booleans (so the key `on` stays `"on"`; documents loaded elsewhere with `True` keys are also
understood), rejects duplicate keys, and bounds size (512 KiB), aliases (100) and nodes
(50,000). Analyser version `1.1.0` (`attributes.analyzer_version`).

For each changed workflow file the collector fetches the file at the parent and at the
commit and compares:

* **Permissions**: workflow-level and job-level `permissions` (a job block replaces the
  workflow block), `read-all` / `write-all` / `{}` / per-scope maps; a missing block means
  the repository default from `/actions/permissions/workflow` applies (`write` = permissive:
  every scope writable; `read` = contents and packages read). Output: `permissions_before`,
  `permissions_after`, effective write scopes before/after (union over jobs),
  `write_all_added`, `added_write_scopes`, `effective_permissions_unknown` (default not
  visible), `permissions_block_removed`, `relies_on_repo_default_write`.
* **Triggers**: `triggers_added/removed`, `dangerous_triggers_added`
  (`pull_request_target`, `workflow_run`, `issue_comment`), and `untrusted_checkout_added`
  when a privileged trigger checks out untrusted code (`actions/checkout` with
  `ref: github.event.pull_request.head.sha|ref`, `github.head_ref`, `workflow_run.head_*`,
  `refs/pull/`, fork `repository:`, `allow-unsafe-pr-checkout: true`, or `gh pr checkout` /
  `git fetch` of PR refs in `run`).
* **Actions pinning**: third-party `uses:` (not `actions/*` or `github/*`) not pinned to a
  40-hex commit SHA, Docker actions without a digest, reusable workflows.
* **`secrets: inherit`** on reusable-workflow calls.
* **Script injection**: `${{ github.event.* }}` / `github.head_ref` expressions known to be
  attacker-controlled (titles, bodies, head refs, commit messages, author fields) inside
  `run` scripts or `actions/github-script` `script:`; other event expressions are recorded
  separately without being called injection.

`risk_flags` summarises everything (`write_all_added`, `scope_escalation:<scope>`,
`dangerous_trigger_added:<t>`, `privileged_trigger_untrusted_checkout`, ...). The GH-001
rule (C2) reads `write_all_added`, `added_write_scopes`, `triggers_added`,
`dangerous_triggers_added`, `untrusted_checkout_added` and the parse/unknown flags.

Offline use (no token, no network; files are read as a bounded prefix like the collector):
`uv run python -m extorq_collectors.github.analyze --path .github/workflows/ci.yml --before old.yml --after new.yml --repo-default read [--expect-escalation]`.

### 5.1 Fail closed: lexical fallback for unanalysable workflows

A workflow version that exists but cannot be analysed (over a budget, invalid YAML,
duplicate keys, not a mapping) is never treated as absent: otherwise an attacker could hide
an escalation by padding the file or adding aliases. Every analysis carries a bounded
lexical scan of the raw text (`workflow.lexical_scan`), and when either version is
unanalysable both versions are compared lexically (like with like). The event then has
`attributes.analysis = "lexical_fallback"` (otherwise `"structured"`),
`effective_permissions_unknown = true`, the parser error in `parse_error_before/after` and
the risk flag `analysis_lexical_fallback`.

The scan (outside full-line comments; `\x`/`\u` escapes, escaped line breaks and scalar
anchors/aliases resolved) looks for exactly the GH-001 indicators:

* `write-all` anywhere (block, flow, quoted, anchored) -> `write_all_added`;
* `<write-capable scope>: write` pairs in block, flow or JSON style (tags and explicit keys
  allowed) -> `added_write_scopes` (with repository default `write` and no `permissions` key
  at all, the permissive default is assumed, flag `relies_on_repo_default_write`);
* the privileged triggers `pull_request_target`, `workflow_run`, `issue_comment`, except
  when only named inside a one-line `${{ }}` expression or as a property
  (`github.event.workflow_run.*`) -> `triggers_added` / `dangerous_triggers_added`;
* checkout of untrusted code: `ref:` / `repository:` using the pull request or workflow_run
  head expressions, `refs/pull/`, `gh pr checkout`, `git fetch|checkout ... pull/${{`,
  `allow-unsafe-pr-checkout` -> `untrusted_checkout_added` (with a privileged trigger),
  evidence labels in `lexical_evidence` (fixed text, never attacker input).

It cannot tell which job a declaration belongs to and over-approximates (a mention in a
trailing comment or script also counts); indicators present in both versions cancel out.
Checks it does not cover are reported as unknown (`null`): `unpinned_actions_added/after`,
`script_injection_added`, `secrets_inherit_added`. Bounds: 4 MiB of text, 100,000 matches
per pattern, 20,000 alias substitutions; all patterns are linear (measured on the lab Mac
on 2026-11-21: 0.2-0.7 s for each of seven 4 MiB hostile inputs such as 4 million empty
lines, 400,000 `git fetch` lines or 400,000 alias keys; the unit test bounds a mixed hostile
input at 10 s). Text beyond 4 MiB is not examined: `lexical_truncated = true`,
flag `lexical_scan_truncated`, and `workflow_sha256_*` is `null` (a prefix hash is not the
file hash); the collector never claims an escalation it did not see. Versions larger than
512 KiB are not diffed (`raw` says so) because `difflib` is superlinear.

GH-001 (C2) fires on such events: v1.1.0 reads `analysis` and gives lexical-fallback
evidence confidence `medium` (feature `analysis_methods`); see
`docs/team/interface-changes/C1.md` section 7.1 for the verification.

## 6. Posture checks (`posture.py`, scanner `extorq-posture-github`)

| Check id | Severity | Finding when | Inputs (skipped when unavailable) |
|---|---|---|---|
| `github.actions.default_token_write` | medium | default `GITHUB_TOKEN` permission is write | Actions workflow settings |
| `github.actions.can_approve_pull_requests` | medium | Actions may create/approve PRs | same |
| `github.actions.allowed_actions_unrestricted` | low | any action may run | Actions permissions |
| `github.actions.sha_pinning_not_required` | low | SHA pinning not enforced | same (field may be absent on older APIs: skipped) |
| `github.secret_scanning.disabled` | medium | `security_and_analysis.secret_scanning` not enabled | admin-visible settings |
| `github.secret_scanning.push_protection_disabled` | medium | push protection not enabled | same |
| `github.dependabot.security_updates_disabled` | low | Dependabot security updates not enabled | same |
| `github.dependabot.alerts_disabled` | medium | `/vulnerability-alerts` 404 for an admin-visible repository | Administration |
| `github.repo.private_fork_allowed` | low | private repository allows forking | metadata |
| `github.repo.codeowners_missing` | low | no CODEOWNERS in `.github/`, root or `docs/` | tree |
| `github.branch.unprotected` | medium | default branch unprotected and no ruleset rules apply | branch + protection + rules |
| `github.branch.force_push_allowed` | medium | protection allows force pushes and no `non_fast_forward` rule | protection details |
| `github.branch.no_required_reviews` | low | no required reviews and no `pull_request` rule | protection details |
| `github.workflow.write_all` | high | a workflow (or job) declares `write-all` | workflow files |
| `github.workflow.unpinned_third_party_action` | medium | third-party actions not pinned to a full SHA | workflow files |
| `github.workflow.privileged_untrusted_checkout` | high | privileged trigger checks out untrusted code | workflow files |
| `github.workflow.script_injection` | high | untrusted expression interpolated into a script | workflow files |
| `github.workflow.secrets_inherit` | low | `secrets: inherit` | workflow files |
| `github.workflow.unparseable` | low; medium / high from the lexical scan | workflow cannot be analysed; evidence and `attributes.lexical_*` carry the lexical indicators: high for write-all or privileged trigger + untrusted checkout, medium for write scopes or privileged triggers | workflow files (oversized blobs read as a 4 MiB prefix) |
| `github.workflow.relies_on_default_write` | medium | no permissions block while the repository default is write | workflow files + Actions settings |

Lifecycle (contracts `scan.py`): checks whose input is permanently unavailable (403/404)
are excluded from the scan scope and listed in `coverage.skipped`; transient failures keep
the check in scope and make the scan `partial`, so nothing is resolved by an incomplete
scan. Finding identities are stable per (asset, scanner, check, resource).

## 7. Security alerts (`alerts.py`, scanner `github-security-alerts`)

Open Dependabot alerts (package, manifest, GHSA/CVE, severity, CVSS v4/v3, first patched
version), code scanning alerts (tool, rule, location; `security_severity_level` mapped to
ExtorQ severity) and secret scanning alerts (type, validity, push-protection bypass; the
secret value is never requested or stored) become findings. A feature that answers 403/404
is recorded as "feature unavailable or not authorised" in `coverage.skipped` and in health,
and excluded from the scope: it is never reported as "no alerts". When no feature is
accessible the scan is `partial` with `findings_count = null`.

Feature availability (GitHub documentation at the time of writing; plans change, the
collector reports whatever GitHub answers): Dependabot alerts are free but must be enabled
by an administrator, and reading them needs the Dependabot alerts permission and a
qualifying role; code scanning alerts on private repositories need GitHub Code Security;
secret scanning and push protection on private repositories need GitHub Secret Protection;
branch protection and rulesets on private repositories need a paid plan (Pro / Team);
organisation audit logs need Enterprise Cloud. Unavailable features surface as data gaps.

## 8. Gaps (never silent)

* **Coverage gaps** (permission or plan): per-feature reasons in CollectorHealth
  `details.gaps` and in ScanRun `coverage.skipped`.
* **`extorq.collector.gap_detected` events** (source `github.api`, `attributes.gap_reason`):
  `checkpoint_commit_not_found` (force push + garbage collection; commits pushed and rewritten
  between polls may be missing), `history_rewritten` (branch rewritten since the last poll),
  `commit_files_truncated` (more than 3,000 files in one commit), `workflow_runs_truncated`
  (listing exceeded `max_pages`), `workflow_runs_outside_lookback` (no successful listing for
  longer than `runs_lookback_hours`), `record_build_failed` (an upstream item could not be
  converted to a valid record; it is skipped so one malformed item cannot stall the
  collector, and only the exception type is reported because validation messages can echo
  attacker-controlled input), `commit_unavailable` (below).
* **Per-commit isolation** (`commit_unavailable`): one commit whose detail or workflow
  content cannot be read never blinds the repository. 401 and rate limits still end the
  cycle (they affect every request). Permanent errors (for example 422 "diff taking too
  long", 404, 403, an oversized or malformed response) produce a gap event at once and the
  branch checkpoint moves past the commit. Transient errors (5xx, 408, network, after the
  client's 3 in-request attempts) put the commit in a bounded retry set in the checkpoint
  (at most 32 commits) while the checkpoint moves on; it is retried once per later poll with
  its genuine push time and pusher, and after 3 polls it becomes the same gap event. The gap
  event names the repository (`github.repository`), the commit (`github.commit_sha`,
  message) and `attributes.{http_status, error_type, endpoint, branch, attempts,
  transient}`. A commit's records are all-or-nothing, so a retry never duplicates part of it.
* **Per-branch isolation**: when listing a branch's new commits fails (compare API), that
  branch keeps its checkpoint and is retried next poll, while other branches and the runs,
  posture and security-alert phases still run; the poll is reported `incomplete`.
* A finding that fails contract validation (e.g. an out-of-range score) is never dropped
  from a successful scan: its check is marked failed, stays in scope and the scan becomes
  `partial`, so the lifecycle view cannot wrongly resolve it.

Known limitations:

* Polling latency up to `interval_seconds` (120 s) plus processing; states shorter than one
  interval (e.g. a workflow pushed and reverted between polls) are seen only through the
  commit history, which is complete unless force-pushed away (then a gap event is emitted).
* Workflow re-runs keep the original `created_at`. Routine listings revisit a rolling 6 h
  window and use up to `runs_lookback_hours` for catch-up and open-run coverage. Known open
  runs absent from listing are tracked separately. A re-run of a previously completed run
  outside the current listing window can be missed. GitHub provides the current run state,
  so intermediate states between polls can be missed too.
* Only the default branch plus up to 10 configured branches are monitored; workflow files
  are analysed as of each commit on those branches. Reusable workflows in other
  repositories are classified by reference only.
* Platform retention: the `events` table keeps 90 days (`TTL event_time + 90 DAY`).
  Backfilled commits whose real push time is older than that were accepted and then dropped
  by the TTL (observed 2026-11-21 with `actions/hello-world-javascript-action`, pushed
  2026-02-18). Since the lead's decision in PLAN section 11 the gateway quarantines such
  events visibly with reason `older_than_retention` (A's code in
  `backend/src/extorq/ingest/processing.py`; not re-tested by C1).
* The lexical fallback (section 5.1) is a heuristic: it cannot attribute declarations to
  jobs, so effective permissions stay unknown and it over-reports; content beyond 4 MiB is
  not examined (reported as `lexical_scan_truncated`). Commits whose detail stays unreadable
  are skipped with a `commit_unavailable` gap; their workflow changes are not analysed.

## 9. Polling instead of webhooks

Webhooks need a publicly reachable HTTPS receiver (or a third-party relay), a webhook
secret and repository admin rights to register them (a write action on the repository).
The lab runs on a laptop with every service bound to 127.0.0.1. Polling needs only a
read-only token, survives collector downtime (checkpoints, bounded catch-up) and is cheap
with conditional requests. Webhook ingestion is **planned**, not implemented.

## 10. GH-001 validation

Use `uv run python -m detection_tests list` to inspect the current validation matrix.
The authorised GitHub validation uses a dedicated private repository and a write identity
separate from the collector's read-only token. See the [demo runbook](../demo-runbook.md)
for release evidence requirements and scope.

`tests/rules/test_gh001_collector_contract.py` tests synthetic collector output against
GH-001 through the isolated ClickHouse harness. The historical results below predate the
current token-file policy and workflow-run identity format.

## 11. Verification record (2026-11-21)

| Claim | Command | Result |
|---|---|---|
| Unit tests (client, analyser, token, records, poller, posture, collector via SDK, simulation) | `uv run pytest tests/unit/github -q` | 176 passed |
| Collector output satisfies GH-001 | C2 harness `run_case` with synthetic collector output, ephemeral ClickHouse `extorq-c1-gh001-ch` | 1 alert, confidence high, escalation commit only; historical `verify_gh001.py` exit 0 for `executed` and `cleaned` on the same data |
| Lab repository CI would pass | `python:3.12-slim-bookworm` container: `pip install -r requirements.txt -r requirements-dev.txt && pytest -q` | 9 passed |
| Offline GH-001 dry run | `simulations/github/gh_001_workflow_permissions.sh --repo Exigent07/extorq-lab --dry-run` | escalation detected (write-all, 14 write scopes, `pull_request_target`, untrusted checkout); cleanup: no escalation; marker parsed |
| Live read-only collection through the SDK runner and gateway | `uv run extorq-collect run --config <scratch config: octocat/Hello-World + actions/hello-world-javascript-action, page_size 2> --once` (twice) | cycle 1: 44 requests, 6 events, 4 scan runs, 4 findings, 8 inventory items, 15 permission gaps, health ok; cycle 2: 18 requests, 4 not-modified, 0 new events |
| Records land in ClickHouse | queries as `extorq_api_ro` via 127.0.0.1:18123 | 4 assets, 3 commit events (unique ids), 4 scan runs (posture succeeded, alerts partial with 3 skipped features), 8 inventory items |

Session 3 (2026-11-21, UTC; review fixes and the live lab repository):

| Claim | Command | Result |
|---|---|---|
| Unit tests incl. lexical fallback (oversized, alias bomb, malformed, duplicate key, escapes, aliases, truncation, hostile-input timing) and per-commit isolation (422 gap, 502 retried then gap, recovery with push time, compare failure, 401 / rate limit propagate) | `uv run pytest tests/unit/github -q` | 204 passed |
| Lint, format, types | `uv run ruff check` / `uv run ruff format --check` on the package, tests and fixtures; `uv run mypy collectors/src/extorq_collectors/github` | clean; mypy: no issues in 13 files |
| Security suite still green | `uv run pytest tests/security -q` | 296 passed, 32 deselected |
| GH-001 fires on lexical-fallback evidence | C2 harness `run_case`, ephemeral ClickHouse `extorq-c1-gh001-ch` (removed), both fixtures, assertions of C2's collector contract test | GH-001 v1.1.0: structured 1 alert, high; lexical fallback 1 alert, medium, `analysis_methods=[lexical_fallback]`, `effective_permissions_unknown=true`; evidence = the escalation event only; no alert for baseline or cleanup (v1.0.0 earlier the same evening: high / low) |
| Live collection of the lab repository with the new code, twice | `uv run extorq-collect run --only github-repos --once` at 20:28:09 and 20:28:13 (a continuous `extorq-collect run` started by someone else had already polled at 20:25:12 and 20:27:16 with the same code) | both: status ok, 9 requests, 5 answered 304 (ETag), 0 events, 0 errors, `token_source=gh_cli`; runner's first cycle: posture scan succeeded (5 findings), workflow inventory `analyzer_version=1.1.0`, `analysis=structured` |
| No duplicates, three workflow events, one alert | queries as `extorq_api_ro` | `github.workflow.modified` 3 unique ids in 3 stored rows: `572f066` added (contents:read), `bf4026a` write-all added, `b464b80` back to contents:read; `github.commit.observed` 3/3; GH-001 alerts: exactly 1 (`e70639259d3044a6da955d9bc79e48cd`, high, commit `bf4026a`, run `8dwz3wf6zji4`) |
| Coverage gaps reported honestly on the live private repository | CollectorHealth details | branch protection, branch rules and rulesets: HTTP 403 "Upgrade to GitHub Pro or make this repository public"; `security_and_analysis` not visible to the token |

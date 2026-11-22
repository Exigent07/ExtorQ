# ADR 0006: GitHub REST polling instead of webhooks

Status: accepted, implemented (`collectors/src/extorq_collectors/github/`).
Date: 2026-11-21.

## Context
GH-001 needs workflow changes, commits, workflow runs and repository settings
from the lab repository. ExtorQ has no internet-facing listener and should not
get one.

## Decision
Poll the GitHub REST API from the Mac (default every 120 s) with a read-only
token loaded from a file, using pagination, ETags, rate-limit handling and
checkpoints. Unavailable features are recorded as gaps, never assumed. Workflow
YAML is parsed with a hardened safe loader (YAML 1.2 booleans, duplicate keys
rejected, size, alias and node budgets).

## Consequences
* No inbound endpoint: nothing to authenticate, nothing exposed.
* Latency is at least the polling interval; API rate limits bound frequency.
* The token can be fine-grained and read-only. An optional GitHub CLI token
  fallback exists and is off by default in code because its OAuth scopes are
  broader (F-14).
* Update 2026-11-22: for the lab demo the committed configuration enables the
  fallback (`gh_cli_token_fallback: true`) with the user's explicit approval
  (PLAN 11); the collector reports `token_source=gh_cli` and the broad scopes
  (`repo`, `workflow`) as a health warning. The decision itself is unchanged:
  a fine-grained read-only token remains the intended setup.
* Plan limits surface as gaps: on the private free-plan lab repository branch
  protection, rules and rulesets answer 403 and code and secret scanning are
  unavailable (observed 2026-11-21, known limitations C7).

## Alternatives considered
* Webhooks: near-real-time, but need a public endpoint or relay, webhook secret
  management and inbound exposure.
* GitHub audit log streaming: requires GitHub Enterprise.

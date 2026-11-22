"""GitHub repository security collector (SDK adapter).

Configured in ``config/collectors/github.yaml`` with
``module: extorq_collectors.github.collector:GitHubCollector``. Each cycle:

1. validates the settings and resolves the token (token.py; never logged);
2. polls every configured repository with :class:`RepoPoller`, committing each
   phase's records together with that repository's checkpoint via ``ctx.emit``;
3. publishes health details: token source/kind, data gaps (features unavailable or
   not authorised), transient errors, warnings, rate-limit budget.

A 401 (bad/expired token) or an unusable configuration fails the cycle (the runner
reports FAILED). A rate limit stops the cycle early; the next cycle resumes from the
committed checkpoints.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, ClassVar

import httpx

from extorq_collectors import __version__
from extorq_collectors.github.client import (
    GitHubClient,
    GitHubRateLimited,
    GitHubUnauthorized,
)
from extorq_collectors.github.config import GitHubCollectorConfig
from extorq_collectors.github.poller import PollReport, RepoPoller
from extorq_collectors.github.records import clean_text, iso, parse_time
from extorq_collectors.github.state import RepoState, checkpoint_key
from extorq_collectors.github.token import resolve_token
from extorq_collectors.github.workflow import WorkflowAnalysis
from extorq_collectors.sdk.base import Collector, CollectorContext

MAX_HEALTH_ITEMS = 32
_RATE_LIMIT_CHECKPOINT = "github:rate_limited_until"


def _bounded(items: list[str]) -> list[str]:
    return [clean_text(item, 500) for item in items[:MAX_HEALTH_ITEMS]]


#: Fragments of GitHub's own messages when a feature is unavailable for the repository's plan
#: or not enabled; such gaps are permanent facts, not degraded collection.
_PLAN_LIMIT_MARKERS = (
    "upgrade to github",
    "make this repository public",
    "is not enabled",
    "not enabled for this repository",
    "enable code scanning",
    "advanced security must be enabled",
    # GitHub omits security_and_analysis for repositories without Advanced Security (free plan).
    "security_and_analysis not visible",
)


def _is_plan_limit(gap: str) -> bool:
    text = gap.lower()
    return any(marker in text for marker in _PLAN_LIMIT_MARKERS)


class GitHubCollectorError(RuntimeError):
    """Cycle-level failure with a sanitised, secret-free message."""


class GitHubCollector(Collector):
    collector_type: ClassVar[str] = "github"
    source_types: ClassVar[tuple[str, ...]] = ("github.api",)
    collector_version: ClassVar[str] = __version__

    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self._workflow_cache: dict[str, WorkflowAnalysis] = {}
        #: Test seam (httpx.MockTransport); production uses the default HTTPS transport.
        self._transport = transport

    def setup(self, ctx: CollectorContext) -> None:
        GitHubCollectorConfig.from_mapping(ctx.config)  # fail fast on invalid settings

    def collect(self, ctx: CollectorContext) -> None:
        cfg = GitHubCollectorConfig.from_mapping(ctx.config)
        details: dict[str, Any] = {"repos_configured": len(cfg.repos)}
        if not cfg.repos:
            details["note"] = "no repositories configured in config/collectors/github.yaml"
            ctx.health_details = details
            return
        token = resolve_token(
            config_token_file=cfg.token_file, allow_broad_token=cfg.allow_broad_token
        )
        warnings: list[str] = []
        details.update({"token_source": token.source, "token_kind": token.kind})
        if token.kind == "broad_token":
            # The operator opted in (allow_broad_token), so this is a standing WARNING in the
            # health details, not a degraded collection: it keeps nagging until a fine-grained
            # read-only PAT replaces the token.
            warnings.append(
                "GitHub token is a broad OAuth/classic token (write-capable), accepted by "
                "allow_broad_token; use a fine-grained read-only PAT"
            )
        retry_at = parse_time(ctx.checkpoints.get(_RATE_LIMIT_CHECKPOINT))
        if retry_at is not None and retry_at > datetime.now(UTC):
            ctx.health_details = {**details, "requests": 0, "rate_limited_until": iso(retry_at)}
            ctx.mark_degraded("GitHub API backoff is active")
            return
        reports: list[PollReport] = []
        failure: str | None = None
        rate_limited_until: float | None = None
        timeout = cfg.request_timeout_seconds
        with GitHubClient(
            token.value,
            base_url=cfg.api_base_url,
            timeout=httpx.Timeout(timeout, connect=min(10.0, timeout), pool=min(10.0, timeout)),
            max_rate_limit_wait=cfg.max_rate_limit_wait_seconds,
            transport=self._transport,
        ) as client:
            for repo_cfg in cfg.repos:
                key = checkpoint_key(repo_cfg.full_name)
                state = RepoState.from_json(ctx.checkpoints.get(key))

                def emit(records: list[Any], st: RepoState, key: str = key) -> None:
                    ctx.emit(records, {key: st.to_json()})

                poller = RepoPoller(
                    client=client,
                    repo_cfg=repo_cfg,
                    cfg=cfg,
                    collector_id=ctx.collector_id,
                    producer_id=ctx.producer_id,
                    state=state,
                    emit=emit,
                    workflow_cache=self._workflow_cache,
                )
                try:
                    reports.append(poller.poll())
                except GitHubUnauthorized as exc:
                    failure = f"GitHub rejected the token (HTTP 401: {exc.message})"
                    break
                except GitHubRateLimited as exc:
                    rate_limited_until = exc.retry_at
                    reports.append(poller.report)
                    warnings.append(f"rate limited during {repo_cfg.full_name}: {exc.message}")
                    break
            limit = client.rate_limit
            details.update(
                {
                    "requests": client.request_count,
                    "not_modified": client.not_modified_count,
                    "rate_limit_remaining": limit.remaining,
                    "rate_limit_limit": limit.limit,
                    "rate_limit_reset_at": iso(datetime.fromtimestamp(limit.reset_at, UTC))
                    if limit.reset_at
                    else None,
                    "secondary_rate_limit_hits": limit.secondary_hits,
                    "token_expires": client.token_expiration,
                }
            )
        if rate_limited_until is not None:
            retry_at_text = iso(datetime.fromtimestamp(rate_limited_until, UTC))
            details["rate_limited_until"] = retry_at_text
            ctx.emit([], {_RATE_LIMIT_CHECKPOINT: retry_at_text})
        gaps = [
            f"{r.repo}: {name}: {reason}"
            for r in reports
            for name, reason in sorted(r.gaps.items())
        ]
        errors = [f"{r.repo}: {error}" for r in reports for error in r.errors]
        warnings.extend(f"{r.repo}: {w}" for r in reports for w in r.warnings)
        details.update(
            {
                "repos_polled_ok": sum(1 for r in reports if r.completed),
                "events": sum(r.events for r in reports),
                "findings": sum(r.findings for r in reports),
                "scan_runs": sum(r.scan_runs for r in reports),
                "gaps": _bounded(gaps),
                "errors": _bounded(errors),
                "warnings": _bounded(warnings),
            }
        )
        ctx.health_details = details
        newest = [r.newest_source_time for r in reports if r.newest_source_time is not None]
        ctx.report_lag(max(newest) if newest else None)
        ctx.checkpoint_summary = clean_text(
            ", ".join(f"{r.repo}:{'ok' if r.completed else 'incomplete'}" for r in reports), 256
        )
        if failure is not None:
            raise GitHubCollectorError(failure)
        if rate_limited_until is not None:
            ctx.mark_degraded("GitHub API rate limit stopped the cycle")
        # Permanent plan/feature limits (free plan: branch protection, rulesets, code scanning)
        # are listed in ``gaps`` but are not a collection problem; everything else is.
        actionable_gaps = [g for g in gaps if not _is_plan_limit(g)]
        if errors or actionable_gaps or len(reports) != len(cfg.repos):
            ctx.mark_degraded("GitHub API collection has incomplete source coverage")
        if reports and not any(r.completed for r in reports) and rate_limited_until is None:
            # Records of the phases that did run were committed; the cycle still counts as
            # failed so the incomplete coverage is visible in health.
            raise GitHubCollectorError(
                "no repository was polled completely: "
                + "; ".join(errors[:3] or ["see health details"])
            )

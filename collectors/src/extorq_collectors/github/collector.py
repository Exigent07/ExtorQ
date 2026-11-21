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

from extorq_collectors import __version__
from extorq_collectors.github.client import (
    GitHubClient,
    GitHubRateLimited,
    GitHubUnauthorized,
)
from extorq_collectors.github.config import GitHubCollectorConfig
from extorq_collectors.github.poller import PollReport, RepoPoller
from extorq_collectors.github.records import clean_text, iso
from extorq_collectors.github.state import RepoState, checkpoint_key
from extorq_collectors.github.token import resolve_token, scope_warnings
from extorq_collectors.github.workflow import WorkflowAnalysis
from extorq_collectors.sdk.base import Collector, CollectorContext

MAX_HEALTH_ITEMS = 32


def _bounded(items: list[str]) -> list[str]:
    return [clean_text(item, 500) for item in items[:MAX_HEALTH_ITEMS]]


class GitHubCollectorError(RuntimeError):
    """Cycle-level failure with a sanitised, secret-free message."""


class GitHubCollector(Collector):
    collector_type: ClassVar[str] = "github"
    source_types: ClassVar[tuple[str, ...]] = ("github.api",)
    collector_version: ClassVar[str] = __version__

    def __init__(self) -> None:
        self._workflow_cache: dict[str, WorkflowAnalysis] = {}

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
            config_token_file=cfg.token_file,
            allow_gh_cli=cfg.allow_gh_cli_token,
            gh_hostname=cfg.gh_hostname,
        )
        warnings: list[str] = list(token.warnings)
        details.update({"token_source": token.source, "token_kind": token.kind})
        reports: list[PollReport] = []
        failure: str | None = None
        rate_limited_until: float | None = None
        with GitHubClient(
            token.value,
            base_url=cfg.api_base_url,
            max_rate_limit_wait=cfg.max_rate_limit_wait_seconds,
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
            warnings.extend(scope_warnings(client.token_scopes))
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
            details["rate_limited_until"] = iso(datetime.fromtimestamp(rate_limited_until, UTC))
        gaps = [f"{r.repo}: {name}: {reason}" for r in reports for name, reason in sorted(r.gaps.items())]
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
        if reports and not any(r.completed for r in reports) and rate_limited_until is None:
            raise GitHubCollectorError(
                "no repository could be polled: " + "; ".join(errors[:3] or ["see health details"])
            )

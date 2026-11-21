"""Validated configuration of the GitHub collector (``config/collectors/github.yaml``).

The file holds no secrets: the token comes from ``EXTORQ_GITHUB_TOKEN_FILE`` /
``EXTORQ_GITHUB_TOKEN`` (see token.py). ``token_file`` may name a *path* only.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from extorq_collectors.github.records import RepoRef, clean_text

_BRANCH_FORBIDDEN = set(" ~^:?*[\\") | {chr(c) for c in range(0x20)} | {"\x7f"}


def valid_branch_name(name: str) -> bool:
    """Conservative subset of git check-ref-format rules."""
    if (
        not name
        or len(name) > 255
        or name.startswith(("/", "-"))
        or name.endswith(("/", ".", ".lock"))
    ):
        return False
    if ".." in name or "//" in name or "@{" in name:
        return False
    return not any(ch in _BRANCH_FORBIDDEN for ch in name)


class RepoConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    full_name: str
    #: Extra branches to monitor for commits/protection; the default branch is always monitored.
    branches: tuple[str, ...] = ()

    @field_validator("full_name")
    @classmethod
    def _full_name(cls, value: str) -> str:
        RepoRef.parse(value)
        return value.strip()

    @field_validator("branches")
    @classmethod
    def _branches(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > 10:
            raise ValueError("at most 10 extra branches per repository")
        for branch in value:
            if not valid_branch_name(branch):
                raise ValueError(f"invalid branch name {clean_text(branch, 80)!r}")
        return value

    @property
    def ref(self) -> RepoRef:
        return RepoRef.parse(self.full_name)


class GitHubCollectorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    repos: tuple[RepoConfig, ...] = ()
    api_base_url: str = "https://api.github.com"
    interval_seconds: int = Field(default=120, ge=30, le=3600)
    #: Path to the token file (only used when EXTORQ_GITHUB_TOKEN_FILE is unset). Never a token.
    token_file: str | None = None
    allow_gh_cli_token: bool = False
    page_size: int = Field(default=50, ge=1, le=100)
    max_pages: int = Field(default=10, ge=1, le=50)
    max_commits_per_poll: int = Field(default=50, ge=1, le=500)
    initial_commit_backfill: int = Field(default=10, ge=0, le=200)
    runs_lookback_hours: int = Field(default=24, ge=1, le=24 * 30)
    posture_interval_seconds: int = Field(default=900, ge=60, le=86400)
    security_alerts_interval_seconds: int = Field(default=1800, ge=60, le=86400)
    collect_security_alerts: bool = True
    collect_push_activity: bool = True
    request_timeout_seconds: float = Field(default=20.0, gt=0, le=120)
    max_rate_limit_wait_seconds: float = Field(default=60.0, ge=0, le=900)
    #: Keep at least this many primary-rate-limit requests in reserve; optional phases
    #: (posture, security alerts) are skipped when the remaining budget is lower.
    rate_limit_reserve: int = Field(default=200, ge=0, le=5000)

    @field_validator("repos", mode="before")
    @classmethod
    def _repos(cls, value: Any) -> Any:
        if value is None:
            return ()
        if not isinstance(value, list | tuple):
            raise ValueError("repos must be a list")
        items: list[Any] = []
        for item in value:
            items.append({"full_name": item} if isinstance(item, str) else item)
        return items

    @field_validator("api_base_url")
    @classmethod
    def _base_url(cls, value: str) -> str:
        parts = urlsplit(value)
        if (
            parts.scheme != "https"
            or not parts.netloc
            or parts.query
            or parts.fragment
            or parts.username
        ):
            raise ValueError(
                "api_base_url must be an https:// URL without credentials, query or fragment"
            )
        return value.rstrip("/")

    @field_validator("token_file")
    @classmethod
    def _token_file(cls, value: str | None) -> str | None:
        if value is not None and (not value.strip() or len(value) > 1024 or "\x00" in value):
            raise ValueError("token_file must be a non-empty path")
        return value

    @model_validator(mode="after")
    def _unique_repos(self) -> GitHubCollectorConfig:
        names = [r.full_name.lower() for r in self.repos]
        if len(names) != len(set(names)):
            raise ValueError("duplicate repository in repos")
        if len(names) > 50:
            raise ValueError("at most 50 repositories per collector")
        return self

    @property
    def gh_hostname(self) -> str:
        host = urlsplit(self.api_base_url).hostname or "github.com"
        return "github.com" if host == "api.github.com" else host

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> GitHubCollectorConfig:
        return cls.model_validate(dict(data or {}))

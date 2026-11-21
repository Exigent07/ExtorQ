"""Builders for ExtorQ contract records from GitHub API data.

All GitHub-sourced text (commit messages, branch names, workflow names, logins,
alert titles) is attacker-controlled: it is stripped of control characters,
bounded and passed through secret redaction before it enters a record. Unknown
values stay ``None``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts import (
    Actor,
    ActorType,
    Asset,
    AssetType,
    CollectionMethod,
    GitHubInfo,
    Outcome,
    Provenance,
    Resource,
    SecurityEvent,
    SimulationTag,
    SourceInfo,
    SourceType,
)
from extorq.contracts.catalog import EVENT_CATALOG
from extorq.contracts.identity import event_id, iso_utc, sha256_hex
from extorq_collectors import __version__

PARSER_ID = "github-api"
COLLECTOR_VERSION = __version__

_SIM_RE = re.compile(r"extorq-sim[- ]([a-z0-9]{8,32})(?![a-z0-9])")
_OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:\[bot\])?$")
#: The deliberately fake, secret-shaped lab string (docs/team/interface-changes/C1.md).
#: It is not a credential, but it is redacted like one to exercise the redaction path.
_LAB_FAKE_SECRET_RE = re.compile(r"\bEXTORQ_TEST_SECRET_[A-Z0-9]{24}\b")


def redact(text: str) -> tuple[str, int]:
    """Redact secret-shaped substrings (platform redactor + lab fake secret pattern)."""
    text, count = redact_text(text)
    text, extra = _LAB_FAKE_SECRET_RE.subn("[REDACTED:lab_fake_secret]", text)
    return text, count + extra


def clean_text(value: object, limit: int, *, single_line: bool = True) -> str:
    """Strip control/format characters and ANSI sequences, bound to ``limit`` characters."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    if single_line:
        text = " ".join(sanitize_untrusted(text, max(limit * 2, 64)).split())
        return text if len(text) <= limit else sanitize_untrusted(text, limit)
    return sanitize_untrusted(text, limit, keep_newlines=True)


def clean_redacted(value: object, limit: int, *, single_line: bool = True) -> tuple[str, int, bool]:
    """Redact, then clean; returns (text, redactions, truncated)."""
    raw = value if isinstance(value, str) else ("" if value is None else str(value))
    redacted, count = redact(raw)
    cleaned = clean_text(redacted, limit, single_line=single_line)
    return cleaned, count, len(redacted) > limit


def as_dict(value: object) -> dict[str, Any]:
    """``value`` when it is a JSON object, else an empty dict (API data is untrusted)."""
    return value if isinstance(value, dict) else {}


def simulation_run_id(*texts: object) -> str | None:
    """Return the run id of an ``extorq-sim-<run_id>`` / ``[extorq-sim <run_id>]`` marker."""
    for text in texts:
        if isinstance(text, str):
            match = _SIM_RE.search(text[:20000])
            if match:
                return match.group(1)
    return None


def parse_time(value: object) -> datetime | None:
    """Parse a GitHub ISO-8601 timestamp into aware UTC (None when absent/invalid)."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def now_utc() -> datetime:
    now = datetime.now(UTC)
    return now.replace(microsecond=(now.microsecond // 1000) * 1000)


def valid_owner(owner: str) -> bool:
    return bool(_OWNER_RE.match(owner))


def valid_repo_name(name: str) -> bool:
    return bool(_REPO_RE.match(name)) and name not in (".", "..")


@dataclass(frozen=True)
class RepoRef:
    owner: str
    name: str

    @classmethod
    def parse(cls, full_name: str) -> RepoRef:
        owner, sep, name = full_name.strip().partition("/")
        if not sep or not valid_owner(owner) or not valid_repo_name(name):
            raise ValueError(
                f"invalid repository name {clean_text(full_name, 120)!r} (expected owner/repo)"
            )
        return cls(owner, name)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"

    @property
    def asset_id(self) -> str:
        return f"github:{self.owner.lower()}/{self.name.lower()}"

    @property
    def owner_asset_id(self) -> str:
        return f"github:{self.owner.lower()}"

    @property
    def api_path(self) -> str:
        return f"/repos/{self.owner}/{self.name}"


def github_actor(login: object, user_id: object = None, user_type: object = None) -> Actor | None:
    if not isinstance(login, str) or not login:
        return None
    name = login if _LOGIN_RE.match(login) else clean_text(login, 100)
    is_bot = name.endswith("[bot]") or user_type == "Bot"
    return Actor(
        type=ActorType.GITHUB_APP if is_bot else ActorType.GITHUB_USER,
        name=name,
        id=str(user_id) if isinstance(user_id, int) else None,
        authenticated=True,
    )


@dataclass(frozen=True)
class EventBuilder:
    collector_id: str
    repo: RepoRef

    def build(
        self,
        *,
        event_type: str,
        native_key: str,
        event_time: datetime,
        observed_time: datetime,
        action: str,
        outcome: Outcome = Outcome.SUCCESS,
        actor: Actor | None = None,
        resource: Resource | None = None,
        github: GitHubInfo | None = None,
        message: str | None = None,
        attributes: Mapping[str, Any] | None = None,
        raw: str | None = None,
        raw_source: str | bytes | None = None,
        truncated: bool = False,
        redactions: int = 0,
        sim_run_id: str | None = None,
    ) -> SecurityEvent:
        spec = EVENT_CATALOG[event_type]
        return SecurityEvent(
            event_id=event_id(SourceType.GITHUB_API.value, self.repo.asset_id, native_key),
            event_type=event_type,
            category=spec.category,
            asset_id=self.repo.asset_id,
            asset_type=AssetType.GITHUB_REPOSITORY,
            source=SourceInfo(
                source_type=SourceType.GITHUB_API,
                collector_id=self.collector_id,
                collector_version=COLLECTOR_VERSION,
                collection_method=CollectionMethod.API_POLL,
                source_native_id=clean_text(native_key, 256),
            ),
            event_time=event_time,
            observed_time=observed_time,
            action=action,
            outcome=outcome,
            actor=actor,
            resource=resource,
            github=github,
            message=clean_text(message, 2000) if message else None,
            attributes=dict(attributes or {}),
            raw=raw,
            provenance=Provenance(
                parser=PARSER_ID,
                parser_version=COLLECTOR_VERSION,
                raw_sha256=sha256_hex(raw_source) if raw_source is not None else None,
                truncated=truncated,
                redaction_count=redactions,
            ),
            simulation=SimulationTag(run_id=sim_run_id) if sim_run_id else None,
        )


def owner_asset(
    repo: RepoRef,
    *,
    owner_login: str,
    owner_type: str | None,
    first_seen: datetime,
    last_seen: datetime,
    observed_by: str,
) -> Asset:
    attributes: dict[str, Any] = {"owner_type": clean_text(owner_type, 40) if owner_type else None}
    return Asset(
        asset_id=repo.owner_asset_id,
        asset_type=AssetType.GITHUB_ACCOUNT,
        name=repo.owner.lower(),
        display_name=clean_text(owner_login, 100),
        attributes=attributes,
        first_seen=first_seen,
        last_seen=last_seen,
        observed_by=observed_by,
    )


def repo_asset(
    repo: RepoRef,
    *,
    display_name: str,
    attributes: Mapping[str, Any],
    first_seen: datetime,
    last_seen: datetime,
    observed_by: str,
) -> Asset:
    return Asset(
        asset_id=repo.asset_id,
        asset_type=AssetType.GITHUB_REPOSITORY,
        name=repo.full_name.lower(),
        display_name=clean_text(display_name, 200),
        parent_asset_id=repo.owner_asset_id,
        attributes=dict(attributes),
        first_seen=first_seen,
        last_seen=last_seen,
        observed_by=observed_by,
    )


# ── Settings / protection normalisation and diffing ─────────────────────────────


def _bool(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _status(container: object, key: str) -> str | None:
    if not isinstance(container, Mapping):
        return None
    item = container.get(key)
    if isinstance(item, Mapping) and isinstance(item.get("status"), str):
        return clean_text(item["status"], 40)
    return None


def normalize_repo_settings(repo: Mapping[str, Any]) -> dict[str, Any]:
    """Security-relevant repository settings; ``None`` = not visible to this token."""
    sa = repo.get("security_and_analysis")
    visibility = repo.get("visibility")
    branch = repo.get("default_branch")
    return {
        "visibility": clean_text(visibility, 20) if isinstance(visibility, str) else None,
        "private": _bool(repo.get("private")),
        "default_branch": clean_text(branch, 255) if isinstance(branch, str) else None,
        "archived": _bool(repo.get("archived")),
        "disabled": _bool(repo.get("disabled")),
        "allow_forking": _bool(repo.get("allow_forking")),
        "web_commit_signoff_required": _bool(repo.get("web_commit_signoff_required")),
        "security_and_analysis_visible": isinstance(sa, Mapping),
        "advanced_security": _status(sa, "advanced_security"),
        "code_security": _status(sa, "code_security"),
        "secret_scanning": _status(sa, "secret_scanning"),
        "secret_scanning_push_protection": _status(sa, "secret_scanning_push_protection"),
        "secret_scanning_non_provider_patterns": _status(
            sa, "secret_scanning_non_provider_patterns"
        ),
        "secret_scanning_validity_checks": _status(sa, "secret_scanning_validity_checks"),
        "dependabot_security_updates": _status(sa, "dependabot_security_updates"),
    }


def normalize_actions_settings(
    workflow_perms: Mapping[str, Any] | None, actions_perms: Mapping[str, Any] | None
) -> dict[str, Any]:
    wp = workflow_perms or {}
    ap = actions_perms or {}
    default = wp.get("default_workflow_permissions")
    allowed = ap.get("allowed_actions")
    return {
        "actions.default_workflow_permissions": default if default in ("read", "write") else None,
        "actions.can_approve_pull_request_reviews": _bool(
            wp.get("can_approve_pull_request_reviews")
        ),
        "actions.enabled": _bool(ap.get("enabled")),
        "actions.allowed_actions": clean_text(allowed, 40) if isinstance(allowed, str) else None,
        "actions.sha_pinning_required": _bool(ap.get("sha_pinning_required")),
    }


def _enabled(container: Mapping[str, Any], key: str) -> bool | None:
    item = container.get(key)
    if isinstance(item, Mapping):
        return _bool(item.get("enabled"))
    return None


def normalize_protection(
    *,
    protected: bool | None,
    protection: Mapping[str, Any] | None,
    protection_status: str,
    protection_gap: str | None,
    rule_types: Sequence[str] | None,
    rulesets: Sequence[str] | None,
) -> dict[str, Any]:
    """Normalised default-branch protection state.

    ``protection_status``: ``present`` (details visible), ``absent`` (branch reported
    unprotected and protection endpoint 404), ``unknown`` (403, or 404 although the
    branch is protected: details hidden from this token).
    """
    p = protection or {}
    reviews = p.get("required_pull_request_reviews")
    reviews = reviews if isinstance(reviews, Mapping) else None
    checks = p.get("required_status_checks")
    checks = checks if isinstance(checks, Mapping) else None
    contexts: list[str] | None = None
    if checks is not None:
        raw_contexts = checks.get("contexts")
        if isinstance(raw_contexts, list):
            contexts = sorted({clean_text(c, 100) for c in raw_contexts if isinstance(c, str)})[:32]
    present = protection_status == "present"
    count = reviews.get("required_approving_review_count") if reviews else None
    return {
        "protected": protected,
        "protection_status": protection_status,
        "protection_gap": protection_gap,
        "required_reviews": (reviews is not None) if present else None,
        "required_approving_review_count": count if isinstance(count, int) else None,
        "dismiss_stale_reviews": _bool(reviews.get("dismiss_stale_reviews")) if reviews else None,
        "require_code_owner_reviews": _bool(reviews.get("require_code_owner_reviews"))
        if reviews
        else None,
        "require_last_push_approval": _bool(reviews.get("require_last_push_approval"))
        if reviews
        else None,
        "enforce_admins": _enabled(p, "enforce_admins") if present else None,
        "allow_force_pushes": _enabled(p, "allow_force_pushes") if present else None,
        "allow_deletions": _enabled(p, "allow_deletions") if present else None,
        "required_linear_history": _enabled(p, "required_linear_history") if present else None,
        "required_signatures": _enabled(p, "required_signatures") if present else None,
        "required_conversation_resolution": _enabled(p, "required_conversation_resolution")
        if present
        else None,
        "lock_branch": _enabled(p, "lock_branch") if present else None,
        "required_status_checks": contexts if present else None,
        "strict_status_checks": _bool(checks.get("strict")) if (present and checks) else None,
        "push_restrictions": (isinstance(p.get("restrictions"), Mapping)) if present else None,
        "rule_types": sorted(set(rule_types))[:64] if rule_types is not None else None,
        "rulesets": sorted(set(rulesets))[:64] if rulesets is not None else None,
    }


def diff_snapshots(
    before: Mapping[str, Any] | None,
    after: Mapping[str, Any],
    *,
    ignore: frozenset[str] = frozenset(),
) -> list[tuple[str, Any, Any]]:
    """Fields whose *known* value changed. Unknown (None) on either side is not a change:
    gaining or losing visibility is a coverage change, reported through health instead."""
    if before is None:
        return []
    changes: list[tuple[str, Any, Any]] = []
    for key in sorted(set(before) | set(after)):
        if key in ignore:
            continue
        old, new = before.get(key), after.get(key)
        if old is None or new is None or old == new:
            continue
        changes.append((key, old, new))
    return changes


def render_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + ",".join(str(v) for v in value) + "]"
    return str(value)


def change_attributes(changes: Sequence[tuple[str, Any, Any]]) -> dict[str, Any]:
    return {
        "changed_fields": [key for key, _, _ in changes][:64],
        "previous_values": [clean_text(f"{k}={render_value(o)}", 500) for k, o, _ in changes][:64],
        "current_values": [clean_text(f"{k}={render_value(n)}", 500) for k, _, n in changes][:64],
    }


def iso(value: datetime) -> str:
    return iso_utc(value)

"""Record builders, sanitisation, checkpoint state and configuration (synthetic data)."""

from __future__ import annotations

import json

import pytest

from extorq.contracts import SecurityEvent
from extorq_collectors.github.config import GitHubCollectorConfig, valid_branch_name
from extorq_collectors.github.records import (
    RepoRef,
    change_attributes,
    clean_redacted,
    clean_text,
    diff_snapshots,
    github_actor,
    normalize_protection,
    normalize_repo_settings,
    parse_time,
)
from extorq_collectors.github.state import MAX_ETAGS, RepoState, checkpoint_key


def test_repo_ref_asset_ids_are_lower_case_and_validated() -> None:
    ref = RepoRef.parse(" Exigent07/ExtorQ-Lab ")
    assert ref.full_name == "Exigent07/ExtorQ-Lab"
    assert ref.asset_id == "github:exigent07/extorq-lab"
    assert ref.owner_asset_id == "github:exigent07"
    assert ref.api_path == "/repos/Exigent07/ExtorQ-Lab"
    for bad in ("noslash", "a/b/c", "-bad/x", "own/..", "own/", "/repo", "o w/r"):
        with pytest.raises(ValueError):
            RepoRef.parse(bad)


def test_clean_text_strips_controls_and_bounds() -> None:
    assert clean_text("a\x1b[31mred\x00\nline", 100) == "ared line"  # ANSI sequence removed
    assert len(clean_text("x" * 500, 50)) <= 50
    assert clean_text(None, 10) == ""
    multi = clean_text("line1\nline2\x07", 100, single_line=False)
    assert "\n" in multi and "\x07" not in multi


def test_clean_redacted_removes_tokens_and_named_credentials() -> None:
    synthetic_pat = "ghp_" + "A1b2C3d4" * 4 + "Zz9Y"
    fake = "synthetic-credential-" + "X" * 17
    text, count, truncated = clean_redacted(f"leak {synthetic_pat} and password={fake}", 500)
    assert synthetic_pat not in text and fake not in text
    assert "[REDACTED:secret]" in text
    assert count >= 2 and truncated is False


def test_parse_time_requires_timezone() -> None:
    assert parse_time("2026-11-21T10:00:00Z").isoformat() == "2026-11-21T10:00:00+00:00"
    assert parse_time("2026-11-21T10:00:00") is None
    assert parse_time("garbage") is None
    assert parse_time(None) is None


def test_github_actor_types() -> None:
    bot = github_actor("dependabot[bot]", 49699333, "Bot")
    assert bot is not None and bot.type.value == "github_app" and bot.id == "49699333"
    user = github_actor("synthetic-dev", 1001, "User")
    assert user is not None and user.type.value == "github_user"
    assert github_actor(None) is None and github_actor("") is None


def test_settings_normalisation_and_diff_ignores_unknown() -> None:
    repo = {
        "visibility": "private",
        "private": True,
        "default_branch": "main",
        "allow_forking": True,
        "security_and_analysis": {"secret_scanning": {"status": "disabled"}},
    }
    before = normalize_repo_settings(repo)
    assert before["secret_scanning"] == "disabled"
    assert before["secret_scanning_push_protection"] is None
    assert before["security_and_analysis_visible"] is True
    after = normalize_repo_settings({**repo, "allow_forking": False, "security_and_analysis": None})
    changes = diff_snapshots(before, after)
    # allow_forking changed; secret_scanning became unknown (visibility loss) -> not a change;
    # security_and_analysis_visible true->false IS reported (both values known).
    keys = [key for key, _, _ in changes]
    assert "allow_forking" in keys and "secret_scanning" not in keys
    assert diff_snapshots(None, after) == []
    attrs = change_attributes(changes)
    assert "allow_forking=true" in attrs["previous_values"]
    assert "allow_forking=false" in attrs["current_values"]


def test_protection_normalisation_unknown_when_hidden() -> None:
    hidden = normalize_protection(
        protected=True,
        protection=None,
        protection_status="unknown",
        protection_gap="403",
        rule_types=None,
        rulesets=None,
    )
    assert hidden["enforce_admins"] is None and hidden["required_reviews"] is None
    present = normalize_protection(
        protected=True,
        protection={
            "required_pull_request_reviews": {"required_approving_review_count": 1},
            "allow_force_pushes": {"enabled": False},
        },
        protection_status="present",
        protection_gap=None,
        rule_types=["deletion"],
        rulesets=["r|branch|active|Repository"],
    )
    assert present["required_reviews"] is True
    assert present["required_approving_review_count"] == 1
    assert present["allow_force_pushes"] is False


def test_repo_state_roundtrip_and_corruption_tolerance() -> None:
    state = RepoState(repo_id=1, branch_heads={"main": "a" * 40})
    state.remember_etag("repo", 'W/"x"')
    state.inventory_workflows = [".github/workflows/ci.yml"]
    restored = RepoState.from_json(state.to_json())
    assert restored == state
    assert RepoState.from_json(None) == RepoState()
    assert RepoState.from_json("{not json") == RepoState()
    assert RepoState.from_json(json.dumps({"version": 999})) == RepoState()
    weird = json.loads(state.to_json())
    weird["etags"] = ["not", "a", "dict"]
    weird["inventory_workflows"] = "not-a-list"
    tolerant = RepoState.from_json(json.dumps(weird))
    assert tolerant.etags == {} and tolerant.inventory_workflows == []
    assert checkpoint_key("Exigent07/ExtorQ-Lab") == "github:repo:exigent07/extorq-lab"


def test_repo_state_is_bounded() -> None:
    state = RepoState()
    for i in range(MAX_ETAGS + 10):
        state.remember_etag(f"k{i}", f'W/"{i}"')
    assert len(state.etags) == MAX_ETAGS and "k0" not in state.etags
    state.runs_seen = {
        str(i): f"1:completed:success|2026-11-{(i % 20) + 1:02d}T00:00:00Z" for i in range(1500)
    }
    state.prune_runs("2026-11-15T00:00:00Z")
    assert all(v.rpartition("|")[2] >= "2026-11-15" for v in state.runs_seen.values())
    assert len(state.runs_seen) <= 1000
    state.settings = {"huge": "x" * 40_000}
    data = json.loads(state.to_json())
    assert data["settings"] is None and data["etags"] == {}  # never a 304 without snapshot


def test_config_validation() -> None:
    cfg = GitHubCollectorConfig.from_mapping(
        {
            "repos": [
                "Example-Org/extorq-lab",
                {"full_name": "example-org/other", "branches": ["release/1.x"]},
            ]
        }
    )
    assert [r.full_name for r in cfg.repos] == ["Example-Org/extorq-lab", "example-org/other"]
    assert cfg.repos[1].branches == ("release/1.x",)
    assert cfg.allow_gh_cli_token is False
    assert not GitHubCollectorConfig.from_mapping(
        {"gh_cli_token_fallback": False}
    ).allow_gh_cli_token
    with pytest.raises(ValueError):
        GitHubCollectorConfig.from_mapping({"gh_cli_token_fallback": True})
    assert GitHubCollectorConfig.from_mapping({}).repos == ()
    with pytest.raises(ValueError, match="duplicate"):
        GitHubCollectorConfig.from_mapping({"repos": ["a-b/c", "A-B/C"]})
    with pytest.raises(ValueError):
        GitHubCollectorConfig.from_mapping({"api_base_url": "http://api.github.com"})
    with pytest.raises(ValueError):
        GitHubCollectorConfig.from_mapping({"api_base_url": "https://user:pw@api.github.com"})
    with pytest.raises(ValueError):
        GitHubCollectorConfig.from_mapping({"repos": [{"full_name": "a/b", "branches": ["a..b"]}]})
    with pytest.raises(ValueError):
        GitHubCollectorConfig.from_mapping({"unknown_setting": 1})
    with pytest.raises(ValueError):
        GitHubCollectorConfig.from_mapping({"page_size": 1000})
    enterprise = GitHubCollectorConfig.from_mapping({"api_base_url": "https://ghe.example/api/v3"})
    assert enterprise.api_base_url == "https://ghe.example/api/v3"


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("main", True),
        ("release/1.x", True),
        ("feature-a_b", True),
        ("", False),
        ("-x", False),
        ("a..b", False),
        ("a b", False),
        ("x.lock", False),
        ("a@{b", False),
        ("a\x00b", False),
        ("/x", False),
        ("x/", False),
    ],
)
def test_branch_name_validation(name: str, ok: bool) -> None:
    assert valid_branch_name(name) is ok


def test_event_builder_produces_contract_valid_events() -> None:
    from datetime import UTC, datetime

    from extorq_collectors.github.records import EventBuilder

    builder = EventBuilder("github-repos", RepoRef.parse("Example-Org/extorq-lab"))
    now = datetime(2026, 11, 21, 10, 0, tzinfo=UTC)
    event = builder.build(
        event_type="github.commit.observed",
        native_key="a" * 40,
        event_time=now,
        observed_time=now,
        action="commit",
        message="Commit\x1b[2J aaaa [extorq-sim abc12345]",
    )
    assert isinstance(event, SecurityEvent)
    assert event.asset_id == "github:example-org/extorq-lab"
    assert event.category.value == "source_control"
    assert "simulation" not in event.model_dump()
    assert event.provenance.parser == "github-api"
    assert "abc12345" in (event.message or "")
    assert "\x1b" not in (event.message or "")
    again = builder.build(
        event_type="github.commit.observed",
        native_key="a" * 40,
        event_time=now,
        observed_time=now,
        action="commit",
    )
    assert again.event_id == event.event_id  # deterministic identity

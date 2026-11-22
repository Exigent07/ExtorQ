"""GitHubCollector through the real collector SDK (CollectorContext + SQLite StateStore).

The GitHub API is the SYNTHETIC fake (github_fakes.py); the token is a synthetic value in a
0600 temp file. Verifies that records land in the durable outbox together with the
per-repository checkpoint, that a second cycle is incremental, and that failures surface
as cycle errors with secret-free messages.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from github_fakes import FakeGitHub

from extorq.contracts import INGEST_RECORD_ADAPTER
from extorq_collectors.github.collector import GitHubCollector, GitHubCollectorError
from extorq_collectors.github.state import RepoState, checkpoint_key
from extorq_collectors.github.token import TOKEN_FILE_ENV, TokenUnavailable
from extorq_collectors.sdk.base import CollectorContext
from extorq_collectors.sdk.config import CollectorConfig
from extorq_collectors.sdk.state import StateStore

ROOT = Path(__file__).resolve().parents[3]
LAB_CI = (ROOT / "lab/github-repo/.github/workflows/ci.yml").read_text(encoding="utf-8")
TOKEN = "github_pat_" + "Z" * 40  # synthetic


def make_context(tmp_path: Path, settings: dict[str, Any]) -> tuple[CollectorContext, StateStore]:
    config = CollectorConfig(
        collector_id="github-repos",
        producer_id="github-collector",
        asset_id="github:example-org/extorq-lab",
        module="extorq_collectors.github.collector:GitHubCollector",
        interval_seconds=120,
        settings=settings,
    )
    store = StateStore(tmp_path / "state" / "state.db")
    return CollectorContext(config, store, collector_version="test"), store


def outbox(store_path: Path) -> list[tuple[str, dict[str, Any]]]:
    conn = sqlite3.connect(store_path)
    try:
        rows = conn.execute("SELECT kind, record FROM outbox ORDER BY seq").fetchall()
    finally:
        conn.close()
    return [(kind, json.loads(record)) for kind, record in rows]


@pytest.fixture
def token_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "readonly-pat"
    path.write_text(TOKEN, encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setenv(TOKEN_FILE_ENV, str(path))
    return path


def lab_fake() -> FakeGitHub:
    fake = FakeGitHub()
    fake.commit("Initial commit", {".github/workflows/ci.yml": LAB_CI, "README.md": "x\n"})
    return fake


def test_collect_writes_validated_records_and_checkpoint_atomically(
    tmp_path: Path, token_env: Path
) -> None:
    fake = lab_fake()
    ctx, store = make_context(tmp_path, {"repos": [fake.full_name]})
    collector = GitHubCollector(transport=fake.transport())
    collector.setup(ctx)
    ctx.begin_cycle()
    collector.collect(ctx)

    rows = outbox(tmp_path / "state" / "state.db")
    kinds = {kind for kind, _ in rows}
    assert {"asset", "event", "scan_run", "finding", "inventory_item"} <= kinds
    for kind, record in rows:
        parsed = INGEST_RECORD_ADAPTER.validate_python(record)
        assert parsed.kind == kind
    serialized = json.dumps([record for _, record in rows])
    assert TOKEN not in serialized

    state = RepoState.from_json(ctx.checkpoints.get(checkpoint_key(fake.full_name)))
    assert state.branch_heads["main"] == fake.branches["main"]
    details = ctx.health_details
    assert details["token_source"] == "file" and details["token_kind"] == "fine_grained_pat"
    assert details["repos_polled_ok"] == 1 and details["events"] >= 2
    assert details["errors"] == []
    assert TOKEN not in json.dumps(details)
    assert ctx.checkpoint_summary == "Example-Org/extorq-lab:ok"
    assert ctx.lag_seconds is not None

    # Second cycle: incremental (no new events for an unchanged repository).
    depth = store.outbox_depth()
    ctx.begin_cycle()
    collector.collect(ctx)
    new_rows = outbox(tmp_path / "state" / "state.db")[depth:]
    assert [kind for kind, _ in new_rows if kind == "event"] == []
    assert ctx.health_details["not_modified"] >= 3
    store.close()


def test_gh_cli_fallback_cannot_be_enabled(tmp_path: Path) -> None:
    fake = lab_fake()
    ctx, store = make_context(tmp_path, {"repos": [fake.full_name], "gh_cli_token_fallback": True})
    with pytest.raises(ValueError):
        GitHubCollector(transport=fake.transport()).setup(ctx)
    assert fake.requests == []
    store.close()


def test_no_repositories_is_reported_without_token_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(TOKEN_FILE_ENV, raising=False)
    ctx, store = make_context(tmp_path, {"repos": []})
    ctx.begin_cycle()
    GitHubCollector().collect(ctx)
    assert ctx.health_details["repos_configured"] == 0
    assert "no repositories configured" in ctx.health_details["note"]
    store.close()


def test_missing_token_fails_cycle_naming_settings_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(TOKEN_FILE_ENV, raising=False)
    ctx, store = make_context(tmp_path, {"repos": ["Example-Org/extorq-lab"]})
    ctx.begin_cycle()
    with pytest.raises(TokenUnavailable) as info:
        GitHubCollector(transport=lab_fake().transport()).collect(ctx)
    assert TOKEN_FILE_ENV in str(info.value)
    store.close()


def test_bad_credentials_fail_the_cycle(tmp_path: Path, token_env: Path) -> None:
    fake = lab_fake()
    fake.inject(r".*", 401, {"message": "Bad credentials"})
    ctx, store = make_context(tmp_path, {"repos": [fake.full_name]})
    ctx.begin_cycle()
    with pytest.raises(GitHubCollectorError, match="HTTP 401"):
        GitHubCollector(transport=fake.transport()).collect(ctx)
    assert store.outbox_depth() == 0
    store.close()


def test_inaccessible_repository_fails_cycle_with_reason(tmp_path: Path, token_env: Path) -> None:
    fake = lab_fake()
    ctx, store = make_context(tmp_path, {"repos": ["Example-Org/does-not-exist"]})
    ctx.begin_cycle()
    with pytest.raises(GitHubCollectorError, match="not found or not accessible"):
        GitHubCollector(transport=fake.transport()).collect(ctx)
    store.close()


def test_invalid_settings_fail_setup(tmp_path: Path) -> None:
    ctx, store = make_context(tmp_path, {"repos": ["not a repo"]})
    with pytest.raises(ValueError):
        GitHubCollector().setup(ctx)
    store.close()

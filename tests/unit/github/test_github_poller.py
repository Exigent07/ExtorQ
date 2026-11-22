"""RepoPoller end-to-end against the SYNTHETIC GitHub API fake (github_fakes.py).

Covers: baseline poll, conditional re-polls (ETag/304), the GH-001 commit flow with the
real lab workflow files, checkpoint behaviour (atomic emit, crash/restart, deferral),
history gaps, settings/protection diffs, transient-error handling, security-alert gaps,
workflow runs and inventory items. Every emitted record is validated against the
contracts with the SDK's own ``to_record_json``.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from github_fakes import FakeGitHub

from extorq.contracts import PostureFinding, ScanRun, ScanStatus, SecurityEvent, Severity
from extorq.contracts.asset import Asset, InventoryItem
from extorq.contracts.identity import event_id
from extorq.contracts.ingest import IngestRecord
from extorq_collectors.github import poller as poller_mod
from extorq_collectors.github.client import GitHubClient, GitHubRateLimited, GitHubUnauthorized
from extorq_collectors.github.config import GitHubCollectorConfig
from extorq_collectors.github.poller import PollReport, RepoPoller
from extorq_collectors.github.state import RepoState
from extorq_collectors.github.workflow import MAX_LEXICAL_BYTES, MAX_WORKFLOW_BYTES
from extorq_collectors.sdk.base import to_record_json

ROOT = Path(__file__).resolve().parents[3]
LAB_CI = (ROOT / "lab/github-repo/.github/workflows/ci.yml").read_text(encoding="utf-8")
GH001 = (ROOT / "simulations/github/templates/ci-gh001.yml").read_text(encoding="utf-8")
CI = ".github/workflows/ci.yml"
TOKEN = "ghp_" + "T" * 36  # synthetic
ASSET = "github:example-org/extorq-lab"


class SimulatedCrash(RuntimeError):
    pass


class Harness:
    """Drives RepoPoller like the SDK does: records + checkpoint committed per emit."""

    def __init__(self, fake: FakeGitHub, **settings: Any) -> None:
        self.fake = fake
        self.cfg = GitHubCollectorConfig.from_mapping({"repos": [fake.full_name], **settings})
        self.client = GitHubClient(
            TOKEN,
            transport=fake.transport(),
            sleep=lambda _s: None,
            rng=lambda: 0.5,
            max_rate_limit_wait=5,
        )
        self.state_json: str | None = None
        self.records: list[IngestRecord] = []
        self.emit_calls = 0
        self.fail_at_emit: int | None = None
        self.cache: dict[str, Any] = {}

    def emit(self, records: list[IngestRecord], state: RepoState) -> None:
        self.emit_calls += 1
        if self.fail_at_emit is not None and self.emit_calls == self.fail_at_emit:
            raise SimulatedCrash("crash before the outbox transaction committed")
        for record in records:
            to_record_json(record)  # contract validation, as ctx.emit does
        self.records.extend(records)
        self.state_json = state.to_json()

    def poll(self, *, now: datetime | None = None) -> tuple[PollReport, list[IngestRecord]]:
        when = now or (self.fake.clock + timedelta(minutes=1))
        poller = RepoPoller(
            client=self.client,
            repo_cfg=self.cfg.repos[0],
            cfg=self.cfg,
            collector_id="github-repos",
            producer_id="github-collector",
            state=RepoState.from_json(self.state_json),
            emit=self.emit,
            workflow_cache=self.cache,
            clock=lambda: when,
        )
        start = len(self.records)
        report = poller.poll()
        return report, self.records[start:]

    @property
    def state(self) -> RepoState:
        return RepoState.from_json(self.state_json)


def events(records: Sequence[IngestRecord], event_type: str | None = None) -> list[SecurityEvent]:
    return [
        r.data
        for r in records
        if isinstance(r.data, SecurityEvent)
        and (event_type is None or r.data.event_type == event_type)
    ]


def of_type(records: Sequence[IngestRecord], cls: type) -> list[Any]:
    return [r.data for r in records if isinstance(r.data, cls)]


def scans(records: Sequence[IngestRecord], scanner: str) -> list[ScanRun]:
    return [s for s in of_type(records, ScanRun) if s.scanner == scanner]


def lab_repo() -> FakeGitHub:
    fake = FakeGitHub()
    fake.commit(
        "Initial commit: ExtorQ lab inventory service",
        {CI: LAB_CI, "README.md": "# synthetic lab\n", "app/main.py": "print('x')\n"},
    )
    return fake


@pytest.fixture
def baseline() -> Harness:
    harness = Harness(lab_repo())
    report, _ = harness.poll()
    assert report.completed, report.errors
    return harness


# ── baseline and conditional re-polls ──────────────────────────────────────


def test_baseline_poll_emits_assets_commits_posture_and_inventory() -> None:
    harness = Harness(lab_repo())
    report, records = harness.poll()
    assert report.completed and not report.errors
    assets = {a.asset_id: a for a in of_type(records, Asset)}
    assert set(assets) == {"github:example-org", ASSET}
    repo_asset = assets[ASSET]
    assert repo_asset.display_name == "Example-Org/extorq-lab"
    assert repo_asset.parent_asset_id == "github:example-org"
    assert repo_asset.attributes["default_branch"] == "main"
    assert repo_asset.attributes["default_workflow_permissions"] == "read"
    assert repo_asset.attributes["visibility"] == "private"

    commits = events(records, "github.commit.observed")
    assert len(commits) == 1
    commit = commits[0]
    assert commit.attributes["initial_backfill"] is True
    assert commit.attributes["time_basis"] == "push_activity"
    assert commit.actor is not None and commit.actor.name == "synthetic-dev"
    workflows = events(records, "github.workflow.modified")
    assert len(workflows) == 1 and workflows[0].attributes["change_type"] == "added"
    assert workflows[0].attributes["write_all_added"] is False
    assert workflows[0].attributes["initial_backfill"] is True
    assert events(records, "github.repo.settings_changed") == []  # no diff on a baseline

    posture = scans(records, "extorq-posture-github")
    assert len(posture) == 1 and posture[0].status == ScanStatus.SUCCEEDED
    checks = {f.check_id for f in of_type(records, PostureFinding)}
    assert {
        "github.branch.unprotected",
        "github.secret_scanning.disabled",
        "github.secret_scanning.push_protection_disabled",
        "github.repo.private_fork_allowed",
        "github.repo.codeowners_missing",
        "github.actions.allowed_actions_unrestricted",
    } <= checks
    assert "github.workflow.write_all" not in checks
    assert "github.actions.default_token_write" not in checks
    assert len(scans(records, "github-security-alerts")) == 1

    items = {(i.item_type.value, i.item_key): i for i in of_type(records, InventoryItem)}
    workflow_item = items[("github_workflow", CI)]
    assert workflow_item.present and workflow_item.attributes["write_all"] is False
    assert workflow_item.attributes["permissions"] == "workflow=contents:read"
    assert items[("github_branch", "main")].attributes["default_branch"] is True
    assert harness.state.branch_heads["main"] == harness.fake.branches["main"]
    assert harness.state.inventory_workflows == [CI]


def test_unchanged_repository_is_polled_with_conditional_requests(baseline: Harness) -> None:
    before = len(baseline.fake.requests)
    report, records = baseline.poll()
    assert report.completed
    assert events(records) == [] and of_type(records, ScanRun) == []
    new_requests = baseline.fake.requests[before:]
    repo_request = next(r for r in new_requests if r.url.path.endswith("/extorq-lab"))
    assert repo_request.headers.get("if-none-match")
    assert baseline.client.not_modified_count >= 3
    # No commit listing or detail calls when the branch head did not move.
    assert not any("/commits" in r.url.path or "/compare/" in r.url.path for r in new_requests)


# ── GH-001 ──────────────────────────────────────────────────────────────────


def test_gh001_escalation_commit_and_cleanup(baseline: Harness) -> None:
    fake = baseline.fake
    sha = fake.commit(
        "ci: add PR preview job and broaden token permissions [extorq-sim gh001run01]",
        {CI: GH001},
        pusher="synthetic-operator",
    )
    pushed_at = fake.clock
    fake.add_run(
        head_sha=sha,
        head_commit={"message": "ci: ... [extorq-sim gh001run01]"},
        status="in_progress",
        conclusion=None,
    )
    report, records = baseline.poll()
    assert report.completed, report.errors

    commit = events(records, "github.commit.observed")[0]
    assert commit.github is not None and commit.github.commit_sha == sha
    assert commit.simulation is not None and commit.simulation.run_id == "gh001run01"
    assert commit.event_time == pushed_at
    assert commit.actor is not None and commit.actor.name == "synthetic-operator"
    assert commit.attributes["workflow_files_changed"] == [CI]
    assert commit.attributes["initial_backfill"] is False

    (wf,) = events(records, "github.workflow.modified")
    assert wf.event_id == event_id("github.api", ASSET, f"{sha}:{CI}")
    assert wf.github is not None
    assert (wf.github.workflow_path, wf.github.commit_sha) == (CI, sha)
    assert wf.github.repository == "Example-Org/extorq-lab"
    a = wf.attributes
    assert a["write_all_added"] is True
    assert a["permissions_before"] == "workflow=contents:read"
    assert a["permissions_after"] == "workflow=write-all"
    assert {"contents", "actions", "packages", "id-token"} <= set(a["added_write_scopes"])
    assert a["triggers_added"] == ["pull_request_target"]
    assert a["dangerous_triggers_added"] == ["pull_request_target"]
    assert a["untrusted_checkout_added"] is True
    assert a["repo_default_workflow_permissions"] == "read"
    assert "write_all_added" in a["risk_flags"]
    assert a["parent_sha"] == fake.commits[sha].parents[0]
    assert wf.simulation is not None and wf.simulation.run_id == "gh001run01"
    assert wf.raw and "+permissions: write-all" in wf.raw  # redacted unified diff

    (run,) = events(records, "github.workflow_run.observed")
    assert run.github is not None and run.github.commit_sha == sha
    assert run.simulation is not None

    # Escalation triggers an immediate posture scan.
    checks = {f.check_id for f in of_type(records, PostureFinding)}
    assert {"github.workflow.write_all", "github.workflow.privileged_untrusted_checkout"} <= checks
    item = next(i for i in of_type(records, InventoryItem) if i.item_key == CI)
    assert item.attributes["write_all"] is True
    assert item.attributes["privileged_triggers"] == ["pull_request_target"]

    cleanup = fake.commit(
        "ci: restore least-privilege CI workflow [extorq-sim gh001run01 cleanup]", {CI: LAB_CI}
    )
    _, records = baseline.poll()
    (revert,) = events(records, "github.workflow.modified")
    assert revert.github is not None and revert.github.commit_sha == cleanup
    assert revert.attributes["write_all_added"] is False
    assert revert.attributes["added_write_scopes"] == []
    assert revert.attributes["triggers_removed"] == ["pull_request_target"]
    assert revert.attributes["permissions_after"] == "workflow=contents:read"


# ── checkpoints and restart safety ─────────────────────────────────────────


def test_crash_before_commit_resumes_without_loss_and_with_same_ids(
    baseline: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(poller_mod, "COMMIT_CHUNK", 1)
    fake = baseline.fake
    shas = [fake.commit(f"change {i}", {"README.md": f"v{i}\n"}) for i in range(3)]
    # emits: repository phase, branches phase, commit 1, commit 2 (crash) ...
    baseline.fail_at_emit = baseline.emit_calls + 4
    with pytest.raises(SimulatedCrash):
        baseline.poll()
    committed = [
        e.github.commit_sha for e in events(baseline.records, "github.commit.observed") if e.github
    ]
    assert shas[0] in committed and shas[1] not in committed
    assert baseline.state.branch_heads["main"] == shas[0]

    baseline.fail_at_emit = None
    report, records = baseline.poll()
    assert report.completed
    resumed = [e.github.commit_sha for e in events(records, "github.commit.observed") if e.github]
    assert resumed == shas[1:]
    assert baseline.state.branch_heads["main"] == shas[-1]

    # A replay from an older checkpoint re-derives identical event identities.
    replay = Harness(fake)
    replay.state_json = baseline.state_json
    state = replay.state
    state.branch_heads["main"] = shas[0]
    replay.state_json = state.to_json()
    _, again = replay.poll()
    assert {e.event_id for e in events(again, "github.commit.observed")} == {
        e.event_id for e in events(records, "github.commit.observed")
    }


def test_commit_backlog_is_deferred_and_checkpointed(baseline: Harness) -> None:
    baseline.cfg = baseline.cfg.model_copy(update={"max_commits_per_poll": 2})
    fake = baseline.fake
    shas = [fake.commit(f"bulk {i}", {"README.md": f"bulk {i}\n"}) for i in range(5)]
    seen: list[str] = []
    for expected_head in (shas[1], shas[3], shas[4]):
        report, records = baseline.poll()
        seen += [
            e.github.commit_sha
            for e in events(records, "github.commit.observed")
            if e.github and e.github.commit_sha
        ]
        assert baseline.state.branch_heads["main"] == expected_head
    assert seen == shas
    assert any("deferred" in w for w in report.warnings) is False  # last poll had no backlog


def test_force_push_emits_history_gap_events(baseline: Harness) -> None:
    fake = baseline.fake
    root = fake.branches["main"]
    fake.commit("will be rewritten", {"README.md": "a\n"})
    baseline.poll()
    fake.force_reset("main", root)
    rewritten = fake.commit("rewritten history", {"README.md": "b\n"})
    report, records = baseline.poll()
    (gap,) = events(records, "extorq.collector.gap_detected")
    assert gap.attributes["gap_reason"] == "history_rewritten"
    assert gap.attributes["source_type"] == "github.api"
    assert gap.attributes["behind_by"] == 1
    assert gap.category.value == "collector"
    commit = events(records, "github.commit.observed")[0]
    assert commit.github is not None and commit.github.commit_sha == rewritten
    assert commit.attributes["history_rewritten"] is True
    assert any("history rewritten" in w for w in report.warnings)


def test_missing_checkpoint_commit_is_a_gap(baseline: Harness) -> None:
    state = baseline.state
    state.branch_heads["main"] = "f" * 40  # vanished after a force push + GC
    baseline.state_json = state.to_json()
    baseline.fake.commit("after gc", {"README.md": "c\n"})
    _, records = baseline.poll()
    (gap,) = events(records, "extorq.collector.gap_detected")
    assert gap.attributes["gap_reason"] == "checkpoint_commit_not_found"
    assert gap.attributes["checkpoint_sha"] == "f" * 40
    commits = events(records, "github.commit.observed")
    # The flag sits on the first (oldest) commit of the re-listed batch; already-seen
    # commits are re-emitted with identical event ids (collapsed downstream).
    assert commits[0].attributes["history_gap"] is True
    assert not any(c.attributes["history_gap"] for c in commits[1:])


# ── settings and protection diffs ──────────────────────────────────────────


def test_settings_change_is_reported_with_before_and_after(baseline: Harness) -> None:
    baseline.fake.workflow_permissions["default_workflow_permissions"] = "write"
    baseline.fake.allow_forking = False
    _, records = baseline.poll()
    (change,) = events(records, "github.repo.settings_changed")
    fields = change.attributes["changed_fields"]
    assert "actions.default_workflow_permissions" in fields and "allow_forking" in fields
    assert "actions.default_workflow_permissions=read" in change.attributes["previous_values"]
    assert "actions.default_workflow_permissions=write" in change.attributes["current_values"]
    checks = {f.check_id for f in of_type(records, PostureFinding)}
    assert "github.actions.default_token_write" in checks  # posture re-run on change
    asset = next(a for a in of_type(records, Asset) if a.asset_id == ASSET)
    assert asset.attributes["default_workflow_permissions"] == "write"


def test_protection_change_and_transient_errors_do_not_fabricate_changes(
    baseline: Harness,
) -> None:
    fake = baseline.fake
    fake.protected["main"] = True
    fake.protection["main"] = {
        "required_pull_request_reviews": {"required_approving_review_count": 1},
        "allow_force_pushes": {"enabled": False},
        "enforce_admins": {"enabled": True},
    }
    _, records = baseline.poll()
    (change,) = events(records, "github.branch_protection.changed")
    assert change.github is not None and change.github.ref == "refs/heads/main"
    assert "protected" in change.attributes["changed_fields"]
    assert change.attributes["protection_status"] == "present"

    # Transient 5xx on the protection and rules endpoints: no event, previous state kept.
    fake.inject(r".*/branches/main/protection", 502)
    fake.inject(r".*/rules/branches/main", 503)
    report, records = baseline.poll()
    assert events(records, "github.branch_protection.changed") == []
    assert any("branch protection main" in e for e in report.errors)
    assert baseline.state.protection["main"]["protection_status"] == "present"
    assert baseline.state.protection["main"]["required_approving_review_count"] == 1

    fake.clear_errors()
    _, records = baseline.poll()
    assert events(records, "github.branch_protection.changed") == []

    # Losing visibility (403) is a coverage gap, never a protection change.
    fake.inject(
        r".*/branches/main/protection",
        403,
        {"message": "Resource not accessible by personal access token"},
    )
    report, records = baseline.poll()
    assert events(records, "github.branch_protection.changed") == []
    assert "branch_protection:main" in report.gaps
    assert "not authorised" in report.gaps["branch_protection:main"]


def test_transient_vulnerability_alert_status_keeps_last_value(baseline: Harness) -> None:
    baseline.fake.inject(r".*/vulnerability-alerts", 500)
    report, records = baseline.poll()
    assert events(records, "github.repo.settings_changed") == []
    assert baseline.state.settings is not None
    assert baseline.state.settings["vulnerability_alerts"] is True
    assert any("vulnerability_alerts" in e for e in report.errors)


# ── security alerts and data gaps ──────────────────────────────────────────


def test_unavailable_alert_features_are_gaps_not_empty_results() -> None:
    fake = lab_repo()
    fake.inject(
        r".*/dependabot/alerts",
        403,
        {"message": "Dependabot alerts are disabled for this repository."},
    )
    fake.inject(
        r".*/code-scanning/alerts",
        403,
        {"message": "Code scanning is not enabled for this repository"},
    )
    fake.inject(r".*/secret-scanning/alerts", 404, {"message": "Not Found"})
    harness = Harness(fake)
    report, records = harness.poll()
    (scan,) = scans(records, "github-security-alerts")
    assert scan.status == ScanStatus.PARTIAL
    assert scan.findings_count is None  # never "0 alerts"
    skipped = {s.check: s.reason for s in scan.coverage.skipped}
    assert set(skipped) == {"dependabot_alerts", "code_scanning_alerts", "secret_scanning_alerts"}
    assert all("feature unavailable or not authorised" in r for r in skipped.values())
    assert {"dependabot_alerts", "code_scanning_alerts", "secret_scanning_alerts"} <= set(
        report.gaps
    )
    alert_findings = [
        f for f in of_type(records, PostureFinding) if f.scanner == "github-security-alerts"
    ]
    assert alert_findings == []


def test_alert_scan_with_partial_access_excludes_unavailable_features_from_scope() -> None:
    fake = lab_repo()
    fake.alerts["dependabot"] = [
        {
            "number": 1,
            "state": "open",
            "html_url": "https://github.com/Example-Org/extorq-lab/security/dependabot/1",
            "dependency": {
                "package": {"name": "werkzeug", "ecosystem": "pip"},
                "manifest_path": "requirements.txt",
            },
            "security_advisory": {
                "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                "cve_id": "CVE-2023-25577",
                "severity": "high",
                "summary": "synthetic advisory",
            },
            "security_vulnerability": {
                "vulnerable_version_range": "< 2.2.3",
                "first_patched_version": {"identifier": "2.2.3"},
            },
        }
    ]
    fake.inject(r".*/code-scanning/alerts", 404, {"message": "no analysis found"})
    fake.inject(r".*/secret-scanning/alerts", 404, {"message": "Not Found"})
    harness = Harness(fake)
    _, records = harness.poll()
    (scan,) = scans(records, "github-security-alerts")
    assert scan.status == ScanStatus.SUCCEEDED and scan.findings_count == 1
    assert "check:dependabot_alerts" in scan.scope.targets
    assert "check:code_scanning_alerts" not in scan.scope.targets
    (finding,) = [
        f for f in of_type(records, PostureFinding) if f.scanner == "github-security-alerts"
    ]
    assert finding.check_id == "dependabot:GHSA-xxxx-yyyy-zzzz"
    assert finding.package is not None and finding.package.fixed_version == "2.2.3"
    assert finding.cve_ids == ["CVE-2023-25577"]


def test_transient_alert_failure_makes_scan_partial() -> None:
    fake = lab_repo()
    fake.inject(r".*/dependabot/alerts", 502)
    harness = Harness(fake)
    report, records = harness.poll()
    (scan,) = scans(records, "github-security-alerts")
    assert scan.status == ScanStatus.PARTIAL
    assert "check:dependabot_alerts" in scan.scope.targets  # stays in scope: nothing resolved
    assert any("dependabot_alerts" in e for e in report.errors)


# ── workflow runs ───────────────────────────────────────────────────────────


def test_workflow_runs_are_emitted_once_per_state(baseline: Harness) -> None:
    fake = baseline.fake
    run = fake.add_run(status="in_progress", conclusion=None, head_branch="extorq-sim-runbranch1")
    _, records = baseline.poll()
    (first,) = events(records, "github.workflow_run.observed")
    assert first.github is not None
    assert (first.github.workflow_run_id, first.github.run_attempt) == (run["id"], 1)
    assert first.github.event_name == "push" and first.github.conclusion is None
    assert first.github.workflow_path == CI
    assert first.simulation is not None and first.simulation.run_id == "runbranch1"
    _, records = baseline.poll()
    assert events(records, "github.workflow_run.observed") == []
    run.update(status="completed", conclusion="failure")
    _, records = baseline.poll()
    (done,) = events(records, "github.workflow_run.observed")
    assert done.outcome.value == "failure" and done.github is not None
    assert done.github.conclusion == "failure"
    assert done.event_id != first.event_id


def test_truncated_run_listing_is_reported_as_gap() -> None:
    fake = lab_repo()
    for _ in range(12):
        fake.add_run()
    harness = Harness(fake, page_size=5, max_pages=2)
    _, records = harness.poll()
    assert len(events(records, "github.workflow_run.observed")) == 10
    (gap,) = events(records, "extorq.collector.gap_detected")
    assert gap.attributes["gap_reason"] == "workflow_runs_truncated"


# ── failures ────────────────────────────────────────────────────────────────


def test_rate_limit_stops_poll_after_committing_earlier_phases(baseline: Harness) -> None:
    fake = baseline.fake
    fake.commit("needs compare", {"README.md": "z\n"})
    fake.inject(
        r".*/compare/.*",
        403,
        {"message": "API rate limit exceeded"},
        headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "4102444800"},
    )
    head_before = baseline.state.branch_heads["main"]
    with pytest.raises(GitHubRateLimited):
        baseline.poll()
    assert baseline.state.branch_heads["main"] == head_before  # commits not checkpointed


def test_unauthorized_propagates() -> None:
    fake = lab_repo()
    fake.inject(r".*", 401, {"message": "Bad credentials"})
    with pytest.raises(GitHubUnauthorized):
        Harness(fake).poll()


def test_missing_repository_is_an_error_not_a_crash() -> None:
    fake = lab_repo()
    fake.inject(r"/repos/Example-Org/extorq-lab", 404)
    report, records = Harness(fake).poll()
    assert not report.completed and records == []
    assert any("not found or not accessible" in e for e in report.errors)


def test_empty_repository_is_handled() -> None:
    fake = FakeGitHub()  # no commits, no branches
    report, records = Harness(fake).poll()
    assert report.completed
    assert "protection" in report.gaps
    (posture,) = scans(records, "extorq-posture-github")
    skipped = {s.check for s in posture.coverage.skipped}
    assert "github.workflow.write_all" in skipped and "github.repo.codeowners_missing" in skipped


# ── inventory tombstones ────────────────────────────────────────────────────


def test_removed_workflow_gets_an_inventory_tombstone(baseline: Harness) -> None:
    baseline.fake.commit("drop CI", {CI: None})
    _, records = baseline.poll()
    (removed,) = events(records, "github.workflow.modified")
    assert removed.attributes["change_type"] == "removed"
    tombstones = [i for i in of_type(records, InventoryItem) if not i.present]
    assert [(t.item_type.value, t.item_key) for t in tombstones] == [("github_workflow", CI)]
    assert baseline.state.inventory_workflows == []


def test_rerun_attempt_of_recent_run_is_observed(baseline: Harness) -> None:
    fake = baseline.fake
    run = fake.add_run(status="completed", conclusion="failure")
    baseline.poll()
    # Re-run: same id and created_at, new attempt; a later poll still lists it.
    run.update(run_attempt=2, status="completed", conclusion="success")
    fake.clock += timedelta(hours=2)
    _, records = baseline.poll()
    (rerun,) = events(records, "github.workflow_run.observed")
    assert rerun.github is not None and rerun.github.run_attempt == 2
    assert rerun.outcome.value == "success"


def test_idle_repository_does_not_report_run_gaps(baseline: Harness) -> None:
    for _ in range(3):
        baseline.fake.clock += timedelta(hours=10)
        _, records = baseline.poll()
        assert events(records, "extorq.collector.gap_detected") == []


def test_listing_pause_longer_than_lookback_is_a_gap(baseline: Harness) -> None:
    baseline.fake.clock += timedelta(hours=30)  # collector stopped for 30 h
    _, records = baseline.poll()
    (gap,) = events(records, "extorq.collector.gap_detected")
    assert gap.attributes["gap_reason"] == "workflow_runs_outside_lookback"
    assert gap.attributes["gap_start"] < gap.attributes["gap_end"]


def test_run_listing_uses_conditional_request_within_the_same_window(baseline: Harness) -> None:
    baseline.poll()
    before = baseline.client.not_modified_count
    baseline.poll()
    runs_requests = [r for r in baseline.fake.requests if r.url.path.endswith("/actions/runs")]
    assert runs_requests[-1].headers.get("if-none-match")
    assert baseline.client.not_modified_count > before


def test_unconvertible_run_is_a_gap_not_a_poison_pill(baseline: Harness) -> None:
    bad = baseline.fake.add_run(run_attempt=-1)  # violates the contract (attempt >= 0)
    report, records = baseline.poll()
    assert report.completed
    (gap,) = events(records, "extorq.collector.gap_detected")
    assert gap.attributes["gap_reason"] == "record_build_failed"
    assert gap.attributes["record_key"] == f"{bad['id']}:-1"
    assert "-1" not in gap.attributes["gap_detail"].split("(")[1]  # only the exception type
    _, again = baseline.poll()
    assert events(again) == []  # checkpoint advanced: no retry loop


# ── fail closed: unanalysable workflows are compared lexically ─────────────


def _padded(text: str) -> str:
    """GitHub-valid YAML beyond the analyser's size budget (comment padding)."""
    return "# synthetic padding\n" * (MAX_WORKFLOW_BYTES // 20 + 16) + text


def test_oversized_escalation_is_detected_lexically(baseline: Harness) -> None:
    fake = baseline.fake
    sha = fake.commit(
        "ci: pad workflow and broaden permissions [extorq-sim gh001big01]", {CI: _padded(GH001)}
    )
    report, records = baseline.poll()
    assert report.completed, report.errors
    (wf,) = events(records, "github.workflow.modified")
    assert wf.github is not None and wf.github.commit_sha == sha
    a = wf.attributes
    assert a["analysis"] == "lexical_fallback"
    assert a["effective_permissions_unknown"] is True
    assert a["write_all_added"] is True
    assert a["dangerous_triggers_added"] == ["pull_request_target"]
    assert a["untrusted_checkout_added"] is True
    assert "analysis_lexical_fallback" in a["risk_flags"]
    assert "workflow_unparseable" in a["risk_flags"]
    assert a["parse_error_after"] == f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes"
    assert a["permissions_before"] == "workflow=contents:read"
    assert a["permissions_after"] == "unparseable;lexical=write-all"
    assert a["lexical_truncated"] is False
    assert a["workflow_sha256_after"]  # whole file read: its hash is known
    assert wf.raw is not None and wf.raw.startswith("diff omitted")
    assert wf.simulation is not None and wf.simulation.run_id == "gh001big01"
    assert "compared lexically" in (wf.message or "")
    # The content was read as a bounded prefix with the raw media type.
    content = [r for r in fake.requests if "/contents/" in r.url.path]
    assert content and all("raw" in r.headers["accept"] for r in content)

    # Posture fails closed too: the unparseable finding carries the lexical indicators.
    (finding,) = [
        f for f in of_type(records, PostureFinding) if f.check_id == "github.workflow.unparseable"
    ]
    assert finding.severity == Severity.HIGH
    assert finding.evidence is not None and "lexical scan: write-all" in finding.evidence
    assert finding.attributes["lexical_write_all"] is True
    item = next(i for i in of_type(records, InventoryItem) if i.item_key == CI)
    assert item.attributes["analysis"] == "lexical_fallback"
    assert item.attributes["lexical_write_all"] is True


def test_alias_bomb_escalation_is_detected_lexically(baseline: Harness) -> None:
    reuse = "".join(f"  R{i}: *base\n" for i in range(150))
    bomb = GH001 + "env:\n  BASE: &base synthetic\n" + reuse
    baseline.fake.commit("ci: reuse anchors", {CI: bomb})
    _, records = baseline.poll()
    (wf,) = events(records, "github.workflow.modified")
    a = wf.attributes
    assert a["analysis"] == "lexical_fallback" and "aliases" in a["parse_error_after"]
    assert a["write_all_added"] is True and a["effective_permissions_unknown"] is True
    assert wf.raw and "+permissions: write-all" in wf.raw  # small file: real diff kept


def test_workflow_beyond_lexical_bound_is_marked_truncated(baseline: Harness) -> None:
    huge = "#" * (MAX_LEXICAL_BYTES + 64) + "\npermissions: write-all\n"
    baseline.fake.commit("ci: giant workflow", {CI: huge})
    report, records = baseline.poll()
    assert report.completed
    (wf,) = events(records, "github.workflow.modified")
    a = wf.attributes
    assert a["analysis"] == "lexical_fallback" and a["lexical_truncated"] is True
    assert "lexical_scan_truncated" in a["risk_flags"]
    assert a["workflow_sha256_after"] is None  # only a prefix was read: hash unknown
    assert a["write_all_added"] is False  # never claimed without evidence


# ── per-commit isolation: one unreadable commit never blinds the repository ─


def test_permanently_unreadable_commit_is_a_gap_and_collection_continues(
    baseline: Harness,
) -> None:
    fake = baseline.fake
    bad = fake.commit("huge vendored import", {"README.md": "vendored\n"})
    escalation = fake.commit("ci: broaden token permissions", {CI: GH001})
    fake.add_run(head_sha=escalation)
    fake.inject(
        rf".*/commits/{bad}",
        422,
        {"message": "Sorry, this diff is taking too long to generate."},
    )
    report, records = baseline.poll()
    assert report.completed, report.errors
    (gap,) = events(records, "extorq.collector.gap_detected")
    a = gap.attributes
    assert a["gap_reason"] == "commit_unavailable" and a["source_type"] == "github.api"
    assert a["commit_sha"] == bad and a["http_status"] == 422 and a["transient"] is False
    assert gap.github is not None
    assert gap.github.repository == "Example-Org/extorq-lab" and gap.github.commit_sha == bad
    assert bad[:12] in (gap.message or "") and "HTTP 422" in (gap.message or "")
    assert gap.event_id == event_id("github.api", ASSET, f"gap:commit_unavailable:{bad}")
    # The rest of the repository is still collected in the same poll.
    (wf,) = events(records, "github.workflow.modified")
    assert wf.github is not None and wf.github.commit_sha == escalation
    assert wf.attributes["write_all_added"] is True
    committed = [e.github.commit_sha for e in events(records, "github.commit.observed") if e.github]
    assert committed == [escalation]
    assert events(records, "github.workflow_run.observed")
    assert scans(records, "extorq-posture-github")
    assert baseline.state.branch_heads["main"] == escalation
    assert baseline.state.commit_retries == {}
    _, again = baseline.poll()
    assert events(again) == []  # advanced past it: no retry loop, no duplicate gap


def test_transient_commit_failure_is_retried_then_given_up(baseline: Harness) -> None:
    fake = baseline.fake
    flaky = fake.commit("touch readme", {"README.md": "flaky\n"})
    later = fake.commit("ci: broaden token permissions", {CI: GH001})
    fake.inject(rf".*/commits/{flaky}", 502, {"message": "Server Error"})
    report, records = baseline.poll()
    assert report.completed
    assert events(records, "extorq.collector.gap_detected") == []
    (wf,) = events(records, "github.workflow.modified")  # later commit not blocked
    assert wf.github is not None and wf.github.commit_sha == later
    assert baseline.state.branch_heads["main"] == later
    assert baseline.state.commit_retries[flaky]["attempts"] == 1
    assert any("retried next poll" in e for e in report.errors)

    _, records = baseline.poll()  # attempt 2 of 3: still pending
    assert events(records) == []
    assert baseline.state.commit_retries[flaky]["attempts"] == 2

    _, records = baseline.poll()  # attempt 3: given up with a gap
    (gap,) = events(records, "extorq.collector.gap_detected")
    assert gap.attributes["gap_reason"] == "commit_unavailable"
    assert gap.attributes["http_status"] == 502 and gap.attributes["transient"] is True
    assert gap.attributes["attempts"] == 3
    assert baseline.state.commit_retries == {}


def test_transient_commit_failure_recovers_with_the_genuine_push_time(
    baseline: Harness,
) -> None:
    fake = baseline.fake
    flaky = fake.commit(
        "ci: broaden token permissions [extorq-sim retry0001]", {CI: GH001}, pusher="synthetic-op"
    )
    pushed_at = fake.clock
    fake.inject(rf".*/commits/{flaky}", 503, times=3)  # one request = 3 client attempts
    _, records = baseline.poll()
    assert events(records, "github.commit.observed") == []
    assert flaky in baseline.state.commit_retries

    report, records = baseline.poll()
    assert report.completed and not report.errors
    (commit,) = events(records, "github.commit.observed")
    assert commit.github is not None and commit.github.commit_sha == flaky
    assert commit.event_time == pushed_at and commit.attributes["time_basis"] == "push_activity"
    assert commit.actor is not None and commit.actor.name == "synthetic-op"
    (wf,) = events(records, "github.workflow.modified")
    assert wf.attributes["write_all_added"] is True and wf.event_time == pushed_at
    assert wf.simulation is not None and wf.simulation.run_id == "retry0001"
    assert baseline.state.commit_retries == {}
    assert events(records, "extorq.collector.gap_detected") == []


def test_commit_listing_failure_does_not_stop_other_phases(baseline: Harness) -> None:
    fake = baseline.fake
    sha = fake.commit("needs compare", {"README.md": "q\n"})
    fake.add_run(head_sha=sha)
    fake.inject(r".*/compare/.*", 500)
    fake.clock += timedelta(hours=1)  # posture and security-alert scans are due
    head_before = baseline.state.branch_heads["main"]
    report, records = baseline.poll()
    assert not report.completed  # the branch checkpoint did not advance
    assert any("commits on main not listed" in e for e in report.errors)
    assert baseline.state.branch_heads["main"] == head_before
    assert events(records, "github.workflow_run.observed")  # later phases still ran
    assert scans(records, "extorq-posture-github")
    assert scans(records, "github-security-alerts")
    fake.clear_errors()
    report, records = baseline.poll()
    assert report.completed
    assert [e.github.commit_sha for e in events(records, "github.commit.observed") if e.github] == [
        sha
    ]


def test_auth_and_rate_limit_errors_on_a_commit_still_propagate(baseline: Harness) -> None:
    fake = baseline.fake
    sha = fake.commit("x", {"README.md": "x\n"})
    fake.inject(rf".*/commits/{sha}", 401, {"message": "Bad credentials"})
    with pytest.raises(GitHubUnauthorized):
        baseline.poll()
    fake.clear_errors()
    fake.inject(
        rf".*/commits/{sha}",
        403,
        {"message": "API rate limit exceeded"},
        headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "4102444800"},
    )
    head_before = baseline.state.branch_heads["main"]
    with pytest.raises(GitHubRateLimited):
        baseline.poll()
    assert baseline.state.branch_heads["main"] == head_before  # nothing skipped
    assert baseline.state.commit_retries == {}

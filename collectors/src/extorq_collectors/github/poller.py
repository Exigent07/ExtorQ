"""Per-repository polling: GitHub REST API -> ExtorQ records + checkpoint state.

Independent of the collector SDK: records are handed to ``emit(records, state)``
together with the state that produced them, once per phase, so the SDK can commit
records and checkpoint atomically. A phase that fails transiently leaves the
checkpoint where the previous phase committed it and is retried on the next poll.

Phases (each bounded):
  1. repository metadata + Actions settings + Dependabot alert status
     -> Assets, ``github.repo.settings_changed``
  2. monitored branches: head, protection, rulesets -> ``github.branch_protection.changed``
  3. commits since the per-branch checkpoint (compare API, Link pagination) with
     changed files -> ``github.commit.observed`` and, for workflow files, before/after
     analysis -> ``github.workflow.modified``
  4. workflow runs -> ``github.workflow_run.observed``
  5. posture scan (interval or on change) -> ScanRun ``extorq-posture-github`` + findings
  6. security alerts (interval) -> ScanRun ``github-security-alerts`` + findings
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote

from extorq.contracts import GitHubInfo, Outcome, Resource, SecurityEvent
from extorq.contracts.identity import canonical_json, sha256_hex
from extorq.contracts.ingest import (
    AssetRecord,
    EventRecord,
    FindingRecord,
    IngestRecord,
    ScanRunRecord,
)
from extorq_collectors.github import alerts as alerts_mod
from extorq_collectors.github import posture as posture_mod
from extorq_collectors.github.client import (
    GitHubApiError,
    GitHubClient,
    GitHubConflict,
    GitHubForbidden,
    GitHubNotFound,
    GitHubRateLimited,
    GitHubResponseError,
    GitHubUnauthorized,
)
from extorq_collectors.github.config import GitHubCollectorConfig, RepoConfig, valid_branch_name
from extorq_collectors.github.findings import CheckOutcome, build_scan_records
from extorq_collectors.github.posture import CODEOWNERS_PATHS, Gap, RepoSnapshot
from extorq_collectors.github.records import (
    EventBuilder,
    as_dict,
    change_attributes,
    clean_redacted,
    clean_text,
    diff_snapshots,
    github_actor,
    iso,
    normalize_actions_settings,
    normalize_protection,
    normalize_repo_settings,
    now_utc,
    owner_asset,
    parse_time,
    redact,
    repo_asset,
    simulation_run_id,
)
from extorq_collectors.github.state import RepoState
from extorq_collectors.github.workflow import (
    MAX_WORKFLOW_BYTES,
    WorkflowAnalysis,
    analyse_workflow,
    compare_workflows,
    is_workflow_path,
)

EmitFn = Callable[[list[IngestRecord], RepoState], None]

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
COMMIT_CHUNK = 20
MAX_FILE_PAGES = 10
MAX_WORKFLOW_FILES = 100
MAX_RAW_DIFF_CHARS = 8000
ACTIONS_WORKFLOW_KEYS = (
    "actions.default_workflow_permissions",
    "actions.can_approve_pull_request_reviews",
)
ACTIONS_PERMISSION_KEYS = (
    "actions.enabled",
    "actions.allowed_actions",
    "actions.sha_pinning_required",
)
_RUN_FAILURE = {"failure", "timed_out", "startup_failure"}


@dataclass
class PollReport:
    """What one poll of one repository did; feeds collector health."""

    repo: str
    events: int = 0
    assets: int = 0
    findings: int = 0
    scan_runs: int = 0
    #: input/feature -> reason (permanent: unavailable or not authorised).
    gaps: dict[str, str] = field(default_factory=dict)
    #: transient or unexpected errors (sanitised).
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    newest_source_time: datetime | None = None
    completed: bool = False


@dataclass
class _Fetched:
    data: Any = None
    not_modified: bool = False
    error: GitHubApiError | None = None

    @property
    def permanent(self) -> bool:
        return isinstance(self.error, GitHubForbidden | GitHubNotFound)


@dataclass(frozen=True)
class _Push:
    pushed_at: datetime
    login: str | None
    user_id: int | None
    user_type: str | None
    activity_type: str


class RepoPoller:
    def __init__(
        self,
        *,
        client: GitHubClient,
        repo_cfg: RepoConfig,
        cfg: GitHubCollectorConfig,
        collector_id: str,
        producer_id: str,
        state: RepoState,
        emit: EmitFn,
        workflow_cache: dict[str, WorkflowAnalysis] | None = None,
        clock: Callable[[], datetime] = now_utc,
    ) -> None:
        self.client = client
        self.repo_cfg = repo_cfg
        self.repo = repo_cfg.ref
        self.api = self.repo.api_path
        self.cfg = cfg
        self.collector_id = collector_id
        self.producer_id = producer_id
        self.state = state
        self._emit = emit
        self.cache = workflow_cache if workflow_cache is not None else {}
        self.clock = clock
        self.builder = EventBuilder(collector_id, self.repo)
        self.report = PollReport(self.repo.full_name)
        self.gaps: dict[str, Gap] = {}
        self.meta: dict[str, Any] = {}
        self.settings: dict[str, Any] = {}
        self.protection: dict[str, dict[str, Any]] = {}
        self.heads: dict[str, str] = {}
        self.changed = False
        self.now = clock()

    # ── plumbing ────────────────────────────────────────────────────────────

    def emit(self, records: list[IngestRecord]) -> None:
        self._emit(records, self.state)
        for record in records:
            if isinstance(record, EventRecord):
                self.report.events += 1
                when = record.data.event_time
                if self.report.newest_source_time is None or when > self.report.newest_source_time:
                    self.report.newest_source_time = when
            elif isinstance(record, AssetRecord):
                self.report.assets += 1
            elif isinstance(record, FindingRecord):
                self.report.findings += 1
            elif isinstance(record, ScanRunRecord):
                self.report.scan_runs += 1

    def _fetch(
        self, etag_key: str | None, path: str, params: Mapping[str, str | int | bool] | None = None
    ) -> _Fetched:
        """GET with optional ETag; API errors (except auth/rate-limit) are returned, not raised."""
        etag = self.state.etags.get(etag_key) if etag_key else None
        try:
            response = self.client.get(path, params=params, etag=etag)
        except (GitHubUnauthorized, GitHubRateLimited):
            raise
        except GitHubApiError as exc:
            if etag_key:
                self.state.forget_etag(etag_key)
            return _Fetched(error=exc)
        if response.not_modified:
            return _Fetched(not_modified=True)
        if etag_key:
            self.state.remember_etag(etag_key, response.etag)
        return _Fetched(data=response.data)

    def _gap(self, name: str, error: GitHubApiError, *, reason: str | None = None) -> Gap:
        permanent = isinstance(error, GitHubForbidden | GitHubNotFound)
        text = reason or (
            f"feature unavailable or not authorised ({error.gap_reason})"
            if permanent
            else error.gap_reason
        )
        gap = Gap(clean_text(text, 400), transient=not permanent)
        self.gaps[name] = gap
        if permanent:
            self.report.gaps[name] = gap.reason
        else:
            self.report.errors.append(clean_text(f"{name}: {gap.reason}", 400))
        return gap

    def _repo_info(self) -> GitHubInfo:
        return GitHubInfo(repository=self.meta.get("full_name") or self.repo.full_name)

    # ── entry point ─────────────────────────────────────────────────────────

    def poll(self) -> PollReport:
        """Run all phases. Raises only GitHubUnauthorized / GitHubRateLimited."""
        self.now = self.clock()
        try:
            if not self._phase_repository():
                return self.report
            self._phase_branches()
            for branch, head in list(self.heads.items()):
                self._phase_commits(branch, head)
            self._phase_runs()
            self._phase_posture()
            self._phase_alerts()
            self.state.last_poll_at = iso(self.now)
            self.emit([])
            self.report.completed = True
        except (GitHubUnauthorized, GitHubRateLimited):
            raise
        except GitHubApiError as exc:
            self.report.errors.append(clean_text(str(exc), 400))
        return self.report

    # ── phase 1: repository ─────────────────────────────────────────────────

    def _phase_repository(self) -> bool:
        st = self.state
        fetched = self._fetch("repo", self.api)
        if fetched.not_modified and (st.repo_meta is None or st.settings is None):
            st.forget_etag("repo")
            fetched = self._fetch("repo", self.api)
        if fetched.error is not None:
            if isinstance(fetched.error, GitHubNotFound):
                self.report.errors.append(
                    f"repository {self.repo.full_name} not found or not accessible with this token"
                )
            else:
                self.report.errors.append(clean_text(str(fetched.error), 400))
            return False
        if fetched.not_modified and st.repo_meta is not None and st.settings is not None:
            self.meta = dict(st.repo_meta)
            base = {
                k: v
                for k, v in st.settings.items()
                if not k.startswith("actions.") and k != "vulnerability_alerts"
            }
        else:
            data = as_dict(fetched.data)
            owner = as_dict(data.get("owner"))
            perms = as_dict(data.get("permissions"))
            repo_id = data.get("id")
            self.meta = {
                "id": repo_id if isinstance(repo_id, int) else None,
                "full_name": clean_text(data.get("full_name"), 200) or self.repo.full_name,
                "owner_login": clean_text(owner.get("login"), 100) or self.repo.owner,
                "owner_type": clean_text(owner.get("type"), 40)
                if isinstance(owner.get("type"), str)
                else None,
                "admin": perms.get("admin") if isinstance(perms.get("admin"), bool) else None,
                "fork": data.get("fork") if isinstance(data.get("fork"), bool) else None,
                "html_url": clean_text(data.get("html_url"), 300)
                if isinstance(data.get("html_url"), str)
                else None,
            }
            base = normalize_repo_settings(data)
            if self.meta["full_name"].lower() != self.repo.full_name.lower():
                self.report.warnings.append(
                    f"repository is now {self.meta['full_name']} (renamed or transferred); "
                    "update the config"
                )
        repo_id = self.meta.get("id")
        if st.repo_id is not None and repo_id is not None and st.repo_id != repo_id:
            self.report.warnings.append(
                "repository id changed (deleted and recreated?): checkpoint reset"
            )
            self.state = st = RepoState()
            st.remember_etag("repo", None)
        st.repo_id = repo_id if repo_id is not None else st.repo_id
        st.repo_meta = self.meta
        if not base.get("security_and_analysis_visible"):
            self.report.gaps["security_and_analysis"] = (
                "security_and_analysis not visible to this token (requires admin access)"
            )

        settings = dict(base)
        settings.update(self._actions_settings())
        settings["vulnerability_alerts"] = self._vulnerability_alerts()
        self.settings = settings

        records: list[IngestRecord] = []
        changes = diff_snapshots(st.settings, settings)
        if changes:
            self.changed = True
            st.change_seq += 1
            fields = ", ".join(key for key, _, _ in changes)
            attributes = change_attributes(changes) | {
                "time_basis": "observed",
                "previous_observed_at": st.last_poll_at,
                "change_seq": st.change_seq,
            }
            records.append(
                EventRecord(
                    data=self.builder.build(
                        event_type="github.repo.settings_changed",
                        native_key=f"settings:{st.change_seq}:{sha256_hex(canonical_json(settings))[:16]}",
                        event_time=self.now,
                        observed_time=self.now,
                        action="settings_changed",
                        github=self._repo_info(),
                        resource=Resource(type="github_repository", name=self.meta["full_name"]),
                        message=f"Repository settings changed: {fields}",
                        attributes=attributes,
                        raw_source=canonical_json({"before": st.settings, "after": settings}),
                    )
                )
            )
        first = st.first_seen is None
        if first:
            st.first_seen = iso(self.now)
        st.settings = settings
        asset_due = parse_time(st.last_asset_at) is None or (
            self.now - (parse_time(st.last_asset_at) or self.now)
        ) >= timedelta(seconds=self.cfg.posture_interval_seconds)
        if first or changes or asset_due:
            records.extend(self._asset_records())
            st.last_asset_at = iso(self.now)
        self.emit(records)
        return True

    def _actions_settings(self) -> dict[str, Any]:
        prev = self.state.settings or {}
        result: dict[str, Any] = {}
        endpoints = (
            ("actions_workflow", f"{self.api}/actions/permissions/workflow", ACTIONS_WORKFLOW_KEYS),
            ("actions_permissions", f"{self.api}/actions/permissions", ACTIONS_PERMISSION_KEYS),
        )
        for name, path, keys in endpoints:
            fetched = self._fetch(name, path)
            if fetched.not_modified and not all(k in prev for k in keys):
                self.state.forget_etag(name)
                fetched = self._fetch(name, path)
            if fetched.error is not None:
                self._gap(name, fetched.error)
                result.update({k: None if fetched.permanent else prev.get(k) for k in keys})
            elif fetched.not_modified:
                result.update({k: prev.get(k) for k in keys})
            else:
                data = as_dict(fetched.data)
                normalized = normalize_actions_settings(
                    data if name == "actions_workflow" else None,
                    data if name == "actions_permissions" else None,
                )
                result.update({k: normalized[k] for k in keys})
        return result

    def _vulnerability_alerts(self) -> bool | None:
        fetched = self._fetch(None, f"{self.api}/vulnerability-alerts")
        if fetched.error is None:
            return True  # 204 No Content: enabled
        if isinstance(fetched.error, GitHubNotFound):
            if self.meta.get("admin") is True:
                return False  # 404 for an admin-visible repository: disabled
            self._gap(
                "vulnerability_alerts",
                fetched.error,
                reason="Dependabot alert status hidden (HTTP 404 without admin access: "
                "disabled or not authorised)",
            )
            return None
        self._gap("vulnerability_alerts", fetched.error)
        return None

    def _asset_records(self) -> list[IngestRecord]:
        first_seen = parse_time(self.state.first_seen) or self.now
        s = self.settings
        default_branch = s.get("default_branch")
        protection = self.state.protection.get(default_branch or "", {})
        attributes: dict[str, Any] = {
            "repo_id": self.meta.get("id"),
            "visibility": s.get("visibility"),
            "private": s.get("private"),
            "default_branch": default_branch,
            "archived": s.get("archived"),
            "fork": self.meta.get("fork"),
            "allow_forking": s.get("allow_forking"),
            "html_url": self.meta.get("html_url"),
            "default_workflow_permissions": s.get("actions.default_workflow_permissions"),
            "default_branch_protected": protection.get("protected"),
            "secret_scanning": s.get("secret_scanning"),
            "secret_scanning_push_protection": s.get("secret_scanning_push_protection"),
            "dependabot_alerts": s.get("vulnerability_alerts"),
            "token_has_admin": self.meta.get("admin"),
            "monitored_branches": self._monitored_branches(),
        }
        return [
            AssetRecord(
                data=owner_asset(
                    self.repo,
                    owner_login=self.meta.get("owner_login") or self.repo.owner,
                    owner_type=self.meta.get("owner_type"),
                    first_seen=first_seen,
                    last_seen=self.now,
                    observed_by=self.collector_id,
                )
            ),
            AssetRecord(
                data=repo_asset(
                    self.repo,
                    display_name=self.meta.get("full_name") or self.repo.full_name,
                    attributes=attributes,
                    first_seen=first_seen,
                    last_seen=self.now,
                    observed_by=self.collector_id,
                )
            ),
        ]

    def _monitored_branches(self) -> list[str]:
        branches: list[str] = []
        default = self.settings.get("default_branch")
        if isinstance(default, str) and valid_branch_name(default):
            branches.append(default)
        for branch in self.repo_cfg.branches:
            if branch not in branches:
                branches.append(branch)
        return branches

    # ── phase 2: branches, protection, rulesets ────────────────────────────

    def _phase_branches(self) -> None:
        st = self.state
        records: list[IngestRecord] = []
        rulesets = self._rulesets()
        default = self.settings.get("default_branch")
        for branch in self._monitored_branches():
            quoted = quote(branch, safe="/")
            key = f"branch:{branch}"
            fetched = self._fetch(key, f"{self.api}/branches/{quoted}")
            if fetched.not_modified and branch not in st.branch_info:
                st.forget_etag(key)
                fetched = self._fetch(key, f"{self.api}/branches/{quoted}")
            if fetched.error is not None:
                if branch == default:
                    reason = (
                        "default branch not found (empty repository?)"
                        if isinstance(fetched.error, GitHubNotFound)
                        else None
                    )
                    self._gap("protection", fetched.error, reason=reason)
                else:
                    self.report.errors.append(
                        clean_text(f"branch {branch}: {fetched.error.gap_reason}", 300)
                    )
                continue
            if fetched.not_modified:
                info = st.branch_info[branch]
            else:
                data = as_dict(fetched.data)
                commit = as_dict(data.get("commit"))
                sha = commit.get("sha")
                protected = data.get("protected")
                info = {
                    "sha": sha if isinstance(sha, str) and _SHA_RE.match(sha) else None,
                    "protected": protected if isinstance(protected, bool) else None,
                }
                st.branch_info[branch] = info
            if info.get("sha"):
                self.heads[branch] = info["sha"]
            snapshot = self._protection_snapshot(branch, quoted, info.get("protected"), rulesets)
            self.protection[branch] = snapshot
            changes = diff_snapshots(
                st.protection.get(branch), snapshot, ignore=frozenset({"protection_gap"})
            )
            if changes:
                self.changed = True
                st.change_seq += 1
                fields = ", ".join(k for k, _, _ in changes)
                records.append(
                    EventRecord(
                        data=self.builder.build(
                            event_type="github.branch_protection.changed",
                            native_key=f"protection:{branch}:{st.change_seq}:{sha256_hex(canonical_json(snapshot))[:16]}",
                            event_time=self.now,
                            observed_time=self.now,
                            action="branch_protection_changed",
                            github=GitHubInfo(
                                repository=self.meta.get("full_name") or self.repo.full_name,
                                ref=clean_text(f"refs/heads/{branch}", 256),
                            ),
                            resource=Resource(type="github_branch", name=clean_text(branch, 256)),
                            message=f"Branch protection/rulesets changed on "
                            f"{clean_text(branch, 100)}: {fields}",
                            attributes=change_attributes(changes)
                            | {
                                "time_basis": "observed",
                                "previous_observed_at": st.last_poll_at,
                                "change_seq": st.change_seq,
                                "protection_status": snapshot.get("protection_status"),
                            },
                            raw_source=canonical_json(
                                {"before": st.protection.get(branch), "after": snapshot}
                            ),
                            sim_run_id=simulation_run_id(branch),
                        )
                    )
                )
            st.protection[branch] = snapshot
        self.emit(records)

    def _rulesets(self) -> list[str] | None:
        fetched = self._fetch(None, f"{self.api}/rulesets", {"per_page": 100})
        if fetched.error is not None:
            self._gap("rulesets", fetched.error)
            return None
        items = fetched.data if isinstance(fetched.data, list) else []
        rendered: list[str] = []
        for item in items[:64]:
            if isinstance(item, dict):
                rendered.append(
                    clean_text(
                        "|".join(
                            str(item.get(k))
                            for k in ("name", "target", "enforcement", "source_type")
                        ),
                        300,
                    )
                )
        return rendered

    def _protection_snapshot(
        self, branch: str, quoted: str, protected: bool | None, rulesets: list[str] | None
    ) -> dict[str, Any]:
        fetched = self._fetch(None, f"{self.api}/branches/{quoted}/protection")
        protection: dict[str, Any] | None = None
        gap: str | None = None
        if fetched.error is None:
            status = "present"
            protection = as_dict(fetched.data)
        elif isinstance(fetched.error, GitHubNotFound) and protected is False:
            status = "absent"
        elif isinstance(fetched.error, GitHubNotFound):
            status = "unknown"
            gap = (
                "protection details hidden from this token "
                "(HTTP 404 while the branch reports protected)"
            )
            self.report.gaps[f"branch_protection:{branch}"] = gap
        else:
            status = "unknown"
            gap = clean_text(
                f"feature unavailable or not authorised ({fetched.error.gap_reason})", 300
            )
            if fetched.permanent:
                self.report.gaps[f"branch_protection:{branch}"] = gap
            else:
                self.report.errors.append(clean_text(f"branch protection {branch}: {gap}", 300))
        rules = self._fetch(None, f"{self.api}/rules/branches/{quoted}", {"per_page": 100})
        rule_types: list[str] | None = None
        if rules.error is None:
            items = rules.data if isinstance(rules.data, list) else []
            rule_types = [
                clean_text(i.get("type"), 64)
                for i in items
                if isinstance(i, dict) and i.get("type")
            ]
        else:
            self._gap(f"rules:{branch}", rules.error)
        return normalize_protection(
            protected=protected,
            protection=protection,
            protection_status=status,
            protection_gap=gap,
            rule_types=rule_types,
            rulesets=rulesets,
        )

    # ── phase 3: commits and workflow changes ──────────────────────────────

    def _phase_commits(self, branch: str, head: str) -> None:
        st = self.state
        last = st.branch_heads.get(branch)
        if last == head:
            return
        try:
            commits, flags = self._new_commits(branch, head, last)
        except GitHubConflict:  # "Git Repository is empty."
            return
        if not commits:
            st.branch_heads[branch] = head
            self.emit([])
            return
        to_process = commits[: self.cfg.max_commits_per_poll]
        # More commits exist than were listed (compare pagination truncated) or processed:
        # advance the checkpoint only to the last processed commit and continue next poll.
        remaining = len(commits) > len(to_process) or bool(flags.get("more_available"))
        if remaining:
            self.report.warnings.append(
                f"{branch}: {len(commits) - len(to_process)} commit(s) deferred to the next poll"
            )
        pushes = self._push_activity(branch) if self.cfg.collect_push_activity else {}
        push_for = self._assign_pushes(to_process, pushes)
        for start in range(0, len(to_process), COMMIT_CHUNK):
            chunk = to_process[start : start + COMMIT_CHUNK]
            records: list[IngestRecord] = []
            for index, summary in enumerate(chunk):
                sha = summary["sha"]
                chunk_flags = (
                    {k: v for k, v in flags.items() if k != "more_available"}
                    if (start == 0 and index == 0)
                    else {}
                )
                records.extend(self._commit_records(branch, sha, push_for.get(sha), chunk_flags))
            last_sha = chunk[-1]["sha"]
            final = start + COMMIT_CHUNK >= len(to_process)
            st.branch_heads[branch] = head if (final and not remaining) else last_sha
            self.emit(records)

    def _new_commits(
        self, branch: str, head: str, last: str | None
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Commits after the checkpoint, oldest first, plus history flags."""
        commits_path = f"{self.api}/commits"
        if last is None:
            limit = self.cfg.initial_commit_backfill
            if limit == 0:
                return [], {}
            per_page = min(self.cfg.page_size, limit)
            pages = min(self.cfg.max_pages, -(-limit // per_page))
            page = self.client.paginate(
                commits_path, params={"sha": head, "per_page": per_page}, max_pages=pages
            )
            items = [
                c for c in page.items if isinstance(c, dict) and _SHA_RE.match(str(c.get("sha")))
            ]
            return list(reversed(items[:limit])), {"initial_backfill": True}
        try:
            page = self.client.paginate(
                f"{self.api}/compare/{last}...{head}",
                params={"per_page": self.cfg.page_size},
                max_pages=self.cfg.max_pages,
                items_key="commits",
            )
        except GitHubNotFound:
            # Checkpoint commit no longer exists (force push + garbage collection).
            page = self.client.paginate(
                commits_path, params={"sha": head, "per_page": self.cfg.page_size}, max_pages=1
            )
            items = [
                c for c in page.items if isinstance(c, dict) and _SHA_RE.match(str(c.get("sha")))
            ]
            self.report.warnings.append(f"{branch}: checkpoint commit not found; history gap")
            return list(reversed(items[: self.cfg.max_commits_per_poll])), {
                "history_gap": True,
                "history_rewritten": True,
            }
        commits = [
            c for c in page.items if isinstance(c, dict) and _SHA_RE.match(str(c.get("sha")))
        ]
        meta = as_dict(page.first)
        flags: dict[str, Any] = {"more_available": page.truncated}
        if meta.get("status") in ("diverged", "behind"):
            flags["history_rewritten"] = True
            self.report.warnings.append(
                f"{branch}: history rewritten (force push); {meta.get('behind_by')} commit(s) "
                "no longer on the branch"
            )
        return commits, flags

    def _push_activity(self, branch: str) -> dict[str, _Push]:
        fetched = self._fetch(
            None,
            f"{self.api}/activity",
            {"ref": f"refs/heads/{branch}", "per_page": min(100, max(self.cfg.page_size, 30))},
        )
        if fetched.error is not None:
            self._gap("push_activity", fetched.error)
            return {}
        pushes: dict[str, _Push] = {}
        for item in fetched.data if isinstance(fetched.data, list) else []:
            if not isinstance(item, dict):
                continue
            after = item.get("after")
            when = parse_time(item.get("timestamp"))
            if not isinstance(after, str) or not _SHA_RE.match(after) or when is None:
                continue
            actor = as_dict(item.get("actor"))
            pushes.setdefault(
                after,
                _Push(
                    pushed_at=when,
                    login=actor.get("login") if isinstance(actor.get("login"), str) else None,
                    user_id=actor.get("id") if isinstance(actor.get("id"), int) else None,
                    user_type=actor.get("type") if isinstance(actor.get("type"), str) else None,
                    activity_type=clean_text(item.get("activity_type"), 40) or "push",
                ),
            )
        return pushes

    @staticmethod
    def _assign_pushes(
        commits: Sequence[Mapping[str, Any]], pushes: Mapping[str, _Push]
    ) -> dict[str, _Push]:
        """Attribute each commit (oldest first) to the first push whose ``after`` covers it."""
        assigned: dict[str, _Push] = {}
        pending: list[str] = []
        for commit in commits:
            pending.append(commit["sha"])
            push = pushes.get(commit["sha"])
            if push is not None:
                for sha in pending:
                    assigned[sha] = push
                pending = []
        return assigned

    def _commit_detail(self, sha: str) -> dict[str, Any]:
        response = self.client.get(f"{self.api}/commits/{sha}", params={"per_page": 300})
        detail = as_dict(response.data)
        files = list(detail.get("files") or [])
        next_url = response.links.get("next")
        pages = 1
        while next_url and pages < MAX_FILE_PAGES:
            page = self.client.follow(next_url, endpoint=f"{self.api}/commits/{sha}")
            data = as_dict(page.data)
            files.extend(data.get("files") or [])
            next_url = page.links.get("next")
            pages += 1
        detail["files"] = files
        detail["_files_truncated"] = bool(next_url)
        return detail

    def _commit_records(
        self, branch: str, sha: str, push: _Push | None, flags: Mapping[str, Any]
    ) -> list[IngestRecord]:
        detail = self._commit_detail(sha)
        commit = as_dict(detail.get("commit"))
        raw_message = commit.get("message")
        message_raw = raw_message if isinstance(raw_message, str) else ""
        git_author = as_dict(commit.get("author"))
        git_committer = as_dict(commit.get("committer"))
        verification = as_dict(commit.get("verification"))
        author = as_dict(detail.get("author"))
        committer = as_dict(detail.get("committer"))
        parents = [p.get("sha") for p in detail.get("parents") or [] if isinstance(p, dict)]
        parents = [p for p in parents if isinstance(p, str) and _SHA_RE.match(p)]
        files = [f for f in detail.get("files") or [] if isinstance(f, dict)]
        stats = as_dict(detail.get("stats"))

        actor_basis: str | None
        if push is not None:
            event_time, time_basis = push.pushed_at, "push_activity"
            actor = github_actor(push.login, push.user_id, push.user_type)
            actor_basis = "pusher"
        else:
            event_time, time_basis = self.now, "first_observed"
            actor = github_actor(author.get("login"), author.get("id"), author.get("type"))
            actor_basis = "commit_author_account" if actor else None
        first_line, _, _ = message_raw.partition("\n")
        summary, red1, _ = clean_redacted(first_line, 200)
        full_message, red2, truncated = clean_redacted(message_raw, 4000, single_line=False)
        sim = simulation_run_id(message_raw, branch)
        workflow_paths = sorted(
            {
                str(f.get("filename"))
                for f in files
                if is_workflow_path(str(f.get("filename")))
                or is_workflow_path(str(f.get("previous_filename")))
            }
        )
        verified = verification.get("verified")
        info = GitHubInfo(
            repository=self.meta.get("full_name") or self.repo.full_name,
            ref=clean_text(f"refs/heads/{branch}", 256),
            commit_sha=sha,
            actor_login=actor.name if actor else None,
        )
        attributes: dict[str, Any] = {
            "files_changed": len(files),
            "files_truncated": bool(detail.get("_files_truncated")),
            "workflow_files_changed": [clean_text(p, 500) for p in workflow_paths[:32]],
            "additions": stats.get("additions")
            if isinstance(stats.get("additions"), int)
            else None,
            "deletions": stats.get("deletions")
            if isinstance(stats.get("deletions"), int)
            else None,
            "parent_count": len(parents),
            "signature_verified": verified if isinstance(verified, bool) else None,
            "signature_reason": clean_text(verification.get("reason"), 64)
            if verification.get("reason")
            else None,
            "author_login": clean_text(author.get("login"), 100) if author.get("login") else None,
            "committer_login": clean_text(committer.get("login"), 100)
            if committer.get("login")
            else None,
            "git_author_name": clean_text(git_author.get("name"), 100)
            if git_author.get("name")
            else None,
            "authored_at": clean_text(git_author.get("date"), 40)
            if git_author.get("date")
            else None,
            "committed_at": clean_text(git_committer.get("date"), 40)
            if git_committer.get("date")
            else None,
            "pushed_at": iso(push.pushed_at) if push else None,
            "push_activity_type": push.activity_type if push else None,
            "actor_basis": actor_basis,
            "time_basis": time_basis,
            "force_push": True if (push and push.activity_type == "force_push") else None,
            "history_rewritten": bool(flags.get("history_rewritten")),
            "history_gap": bool(flags.get("history_gap")),
            "initial_backfill": bool(flags.get("initial_backfill")),
        }
        commit_event = self.builder.build(
            event_type="github.commit.observed",
            native_key=sha,
            event_time=event_time,
            observed_time=self.now,
            action="commit",
            actor=actor,
            resource=Resource(type="github_commit", id=sha),
            github=info,
            message=f"Commit {sha[:12]} on {clean_text(branch, 100)}: {summary}",
            attributes=attributes,
            raw=full_message or None,
            raw_source=message_raw,
            truncated=truncated,
            redactions=red1 + red2,
            sim_run_id=sim,
        )
        records: list[IngestRecord] = [EventRecord(data=commit_event)]
        parent = parents[0] if parents else None
        for change in files:
            event = self._workflow_event(
                change, sha, parent, branch, info, actor, event_time, time_basis, sim
            )
            if event is not None:
                records.append(EventRecord(data=event))
        return records

    def _workflow_content(self, path: str, ref: str) -> str | WorkflowAnalysis | None:
        """Raw workflow text at ``ref``; None when absent; an error analysis when too large."""
        try:
            return self.client.get_text(
                f"{self.api}/contents/{quote(path, safe='/')}",
                params={"ref": ref},
                max_bytes=MAX_WORKFLOW_BYTES + 1,
            )
        except GitHubNotFound:
            return None
        except GitHubResponseError as exc:
            if "exceeds" in exc.message:
                return WorkflowAnalysis(
                    path=path, ok=False, error=f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes"
                )
            raise

    def _workflow_event(
        self,
        change: Mapping[str, Any],
        sha: str,
        parent: str | None,
        branch: str,
        info: GitHubInfo,
        actor: Any,
        event_time: datetime,
        time_basis: str,
        sim: str | None,
    ) -> SecurityEvent | None:
        path = str(change.get("filename") or "")
        previous = change.get("previous_filename")
        previous = str(previous) if isinstance(previous, str) else None
        status = str(change.get("status") or "")
        new_is_wf, old_is_wf = is_workflow_path(path), bool(previous and is_workflow_path(previous))
        if status == "unchanged" or not (new_is_wf or old_is_wf):
            return None
        before_path: str | None
        after_path: str | None
        if status in ("added", "copied"):
            before_path, after_path, change_type = None, path, "added"
        elif status == "removed":
            before_path, after_path, change_type = path, None, "removed"
        elif status == "renamed":
            before_path = previous if old_is_wf else None
            after_path = path if new_is_wf else None
            change_type = (
                "renamed"
                if (before_path and after_path)
                else ("added" if after_path else "removed")
            )
        else:  # modified / changed
            before_path, after_path, change_type = path, path, "modified"
        if parent is None:
            before_path = None
            if change_type in ("modified", "renamed"):
                change_type = "added"

        def load(p: str | None, ref: str | None) -> tuple[WorkflowAnalysis | None, str | None]:
            if p is None or ref is None:
                return None, None
            content = self._workflow_content(p, ref)
            if content is None:
                return None, None
            if isinstance(content, WorkflowAnalysis):
                return content, None
            return analyse_workflow(p, content), content

        before, before_text = load(before_path, parent)
        after, after_text = load(after_path, sha)
        repo_default = self.settings.get("actions.default_workflow_permissions")
        delta = compare_workflows(
            after_path or before_path or path,
            before,
            after,
            repo_default=repo_default if repo_default in ("read", "write") else None,
            change_type=change_type,  # type: ignore[arg-type]
            previous_path=before_path if change_type == "renamed" else None,
        )
        diff = "\n".join(
            difflib.unified_diff(
                (before_text or "").splitlines(),
                (after_text or "").splitlines(),
                fromfile=f"a/{before_path or '/dev/null'}",
                tofile=f"b/{after_path or '/dev/null'}",
                lineterm="",
                n=2,
            )
        )
        redacted_diff, redactions = redact(diff)
        raw = clean_text(redacted_diff, MAX_RAW_DIFF_CHARS, single_line=False)
        attributes = delta.to_attributes() | {
            "time_basis": time_basis,
            "parent_sha": parent,
            "workflow_sha256_after": sha256_hex(after_text) if after_text is not None else None,
            "workflow_sha256_before": sha256_hex(before_text) if before_text is not None else None,
        }
        name = (after.name if after and after.name else None) or (
            before.name if before and before.name else None
        )
        if delta.escalation:
            self.changed = True
        return self.builder.build(
            event_type="github.workflow.modified",
            native_key=f"{sha}:{delta.path}",
            event_time=event_time,
            observed_time=self.now,
            action="workflow_modified",
            actor=actor,
            resource=Resource(
                type="github_workflow",
                name=clean_text(delta.path.rsplit("/", 1)[-1], 256),
                path=clean_text(delta.path, 2048),
            ),
            github=info.model_copy(
                update={"workflow_path": clean_text(delta.path, 256), "workflow_name": name}
            ),
            message=delta.summary(),
            attributes=attributes,
            raw=raw or None,
            raw_source=after_text if after_text is not None else (before_text or ""),
            truncated=len(redacted_diff) > MAX_RAW_DIFF_CHARS,
            redactions=redactions,
            sim_run_id=sim,
        )

    # ── phase 4: workflow runs ──────────────────────────────────────────────

    def _phase_runs(self) -> None:
        st = self.state
        floor = self.now - timedelta(hours=self.cfg.runs_lookback_hours)
        cursor_time = parse_time(st.runs_cursor) or floor
        cursor_time = max(cursor_time, floor).replace(second=0, microsecond=0)
        cursor = iso(cursor_time).replace(".000Z", "Z")
        key = f"runs:{cursor}"
        etag = st.etags.get(key)
        try:
            page = self.client.paginate(
                f"{self.api}/actions/runs",
                params={
                    "per_page": self.cfg.page_size,
                    "created": f">={cursor}",
                    "exclude_pull_requests": True,
                },
                etag=etag,
                max_pages=self.cfg.max_pages,
                items_key="workflow_runs",
            )
        except (GitHubUnauthorized, GitHubRateLimited):
            raise
        except GitHubApiError as exc:
            st.forget_etag(key)
            self._gap("workflow_runs", exc)
            return
        if page.not_modified:
            return
        for old in [k for k in st.etags if k.startswith("runs:") and k != key]:
            st.forget_etag(old)
        st.remember_etag(key, page.etag)
        if page.truncated:
            self.report.warnings.append(
                "workflow runs listing truncated by max_pages; older runs in window skipped"
            )
        records: list[IngestRecord] = []
        open_created: list[str] = []
        newest_created: str | None = None
        for run in page.items:
            if not isinstance(run, dict) or not isinstance(run.get("id"), int):
                continue
            created = run.get("created_at") if isinstance(run.get("created_at"), str) else ""
            status = clean_text(run.get("status"), 32) or "unknown"
            conclusion = clean_text(run.get("conclusion"), 32) if run.get("conclusion") else None
            raw_attempt = run.get("run_attempt")
            attempt = raw_attempt if isinstance(raw_attempt, int) else 1
            if status != "completed" and created:
                open_created.append(created)
            if created and (newest_created is None or created > newest_created):
                newest_created = created
            seen_value = f"{attempt}:{status}:{conclusion}|{created}"
            if st.runs_seen.get(str(run["id"])) == seen_value:
                continue
            records.append(EventRecord(data=self._run_event(run, status, conclusion, attempt)))
            st.runs_seen[str(run["id"])] = seen_value
        if open_created:
            new_cursor = min(open_created)
        elif newest_created:
            new_cursor = newest_created
        else:
            new_cursor = iso(cursor_time)
        st.runs_cursor = new_cursor
        st.prune_runs(iso(floor))
        self.emit(records)

    def _run_event(
        self, run: Mapping[str, Any], status: str, conclusion: str | None, attempt: int
    ) -> SecurityEvent:
        run_id = int(run["id"])
        created = parse_time(run.get("created_at"))
        started = parse_time(run.get("run_started_at"))
        updated = parse_time(run.get("updated_at"))
        if status == "completed":
            event_time = updated or started or created or self.now
        elif status == "in_progress":
            event_time = started or updated or created or self.now
        else:
            event_time = created or updated or self.now
        triggering = as_dict(run.get("triggering_actor"))
        actor_data = as_dict(run.get("actor"))
        source = triggering or actor_data
        actor = github_actor(source.get("login"), source.get("id"), source.get("type"))
        head_sha = (
            run.get("head_sha")
            if isinstance(run.get("head_sha"), str) and _SHA_RE.match(run["head_sha"])
            else None
        )
        head_branch = (
            clean_text(run.get("head_branch"), 200)
            if isinstance(run.get("head_branch"), str)
            else None
        )
        raw_path = run.get("path") if isinstance(run.get("path"), str) else None
        path = clean_text(raw_path.split("@", 1)[0], 256) if raw_path else None
        name = clean_text(run.get("name"), 200) if isinstance(run.get("name"), str) else None
        event_name = clean_text(run.get("event"), 64) if isinstance(run.get("event"), str) else None
        head_commit = as_dict(run.get("head_commit"))
        head_repo = as_dict(run.get("head_repository"))
        head_repo_name = (
            clean_text(head_repo.get("full_name"), 200) if head_repo.get("full_name") else None
        )
        title, redactions, _ = clean_redacted(run.get("display_title"), 200)
        if conclusion == "success":
            outcome = Outcome.SUCCESS
        elif conclusion in _RUN_FAILURE:
            outcome = Outcome.FAILURE
        else:
            outcome = Outcome.UNKNOWN
        sim = simulation_run_id(
            head_commit.get("message"), run.get("head_branch"), run.get("display_title")
        )
        run_number = run.get("run_number") if isinstance(run.get("run_number"), int) else None
        return self.builder.build(
            event_type="github.workflow_run.observed",
            native_key=f"{run_id}:{attempt}:{status}",
            event_time=event_time,
            observed_time=self.now,
            action=f"workflow_run_{status}",
            outcome=outcome,
            actor=actor,
            resource=Resource(type="github_workflow_run", id=str(run_id), name=name, path=path),
            github=GitHubInfo(
                repository=self.meta.get("full_name") or self.repo.full_name,
                ref=clean_text(f"refs/heads/{head_branch}", 256) if head_branch else None,
                commit_sha=head_sha,
                workflow_path=path,
                workflow_name=name,
                workflow_run_id=run_id,
                run_attempt=attempt,
                event_name=event_name,
                actor_login=actor.name if actor else None,
                conclusion=conclusion,
            ),
            message=f"Workflow run {name or path or run_id} #{run_number} ({event_name}) {status}"
            + (f"/{conclusion}" if conclusion else ""),
            attributes={
                "status": status,
                "run_number": run_number,
                "workflow_id": run.get("workflow_id")
                if isinstance(run.get("workflow_id"), int)
                else None,
                "head_branch": head_branch,
                "head_repository": head_repo_name,
                "from_fork": (head_repo_name.lower() != (self.meta.get("full_name") or "").lower())
                if head_repo_name
                else None,
                "display_title": title or None,
                "created_at": iso(created) if created else None,
                "run_started_at": iso(started) if started else None,
                "updated_at": iso(updated) if updated else None,
                "triggering_actor": clean_text(triggering.get("login"), 100)
                if triggering.get("login")
                else None,
                "actor": clean_text(actor_data.get("login"), 100)
                if actor_data.get("login")
                else None,
                "html_url": clean_text(run.get("html_url"), 300)
                if isinstance(run.get("html_url"), str)
                else None,
            },
            raw_source=canonical_json(
                {
                    k: run.get(k)
                    for k in ("id", "run_attempt", "status", "conclusion", "head_sha", "updated_at")
                }
            ),
            redactions=redactions,
            sim_run_id=sim,
        )

    # ── phase 5: posture ────────────────────────────────────────────────────

    def _budget_ok(self, phase: str) -> bool:
        remaining = self.client.rate_limit.remaining
        if remaining is not None and remaining < self.cfg.rate_limit_reserve:
            self.report.warnings.append(
                f"{phase} skipped: rate limit remaining {remaining} below reserve"
            )
            return False
        return True

    def _due(self, last: str | None, interval: int) -> bool:
        previous = parse_time(last)
        return previous is None or (self.now - previous) >= timedelta(seconds=interval)

    def _phase_posture(self) -> None:
        st = self.state
        if not (self.changed or self._due(st.last_posture_at, self.cfg.posture_interval_seconds)):
            return
        if not self._budget_ok("posture scan"):
            return
        started = self.clock()
        default = self.settings.get("default_branch")
        head = self.heads.get(default) if isinstance(default, str) else None
        snapshot = RepoSnapshot(
            repo=self.repo,
            default_branch=default if isinstance(default, str) else "",
            head_sha=head,
            settings=dict(self.settings),
            protection=self.protection.get(default) if isinstance(default, str) else None,
            vulnerability_alerts=self.settings.get("vulnerability_alerts"),
            gaps=dict(self.gaps),
        )
        if head is None:
            reason = Gap("default branch head unknown (empty repository or branch not readable)")
            snapshot.gaps.setdefault("tree", reason)
            snapshot.gaps.setdefault("workflows", reason)
        else:
            self._inspect_tree(snapshot, head)
        outcomes = posture_mod.evaluate_posture(snapshot)
        finished = self.clock()
        scan = build_scan_records(
            scanner=posture_mod.SCANNER,
            scanner_version=posture_mod.SCANNER_VERSION,
            asset_id=self.repo.asset_id,
            repo_target=f"github:{self.repo.full_name.lower()}",
            description=posture_mod.SCOPE_DESCRIPTION,
            producer_id=self.producer_id,
            started_at=started,
            finished_at=finished,
            outcomes=outcomes,
            attributes={
                "default_branch": snapshot.default_branch or None,
                "head_sha": head,
                "workflows_analyzed": len(snapshot.workflows or []),
                "trigger": "change" if self.changed else "interval",
            },
        )
        st.last_posture_at = iso(self.now)
        self.emit(
            [ScanRunRecord(data=scan.scan_run), *(FindingRecord(data=f) for f in scan.findings)]
        )

    def _inspect_tree(self, snapshot: RepoSnapshot, head: str) -> None:
        fetched = self._fetch(None, f"{self.api}/git/trees/{head}", {"recursive": 1})
        if fetched.error is not None:
            gap = self._gap("tree", fetched.error)
            snapshot.gaps["tree"] = gap
            snapshot.gaps["workflows"] = gap
            return
        data = as_dict(fetched.data)
        entries = [
            e for e in data.get("tree") or [] if isinstance(e, dict) and e.get("type") == "blob"
        ]
        paths = {str(e.get("path")): e for e in entries}
        if data.get("truncated"):
            self.report.warnings.append(
                "repository tree truncated; CODEOWNERS/workflow inventory may be incomplete"
            )
        snapshot.codeowners_known = not data.get("truncated") or any(
            p in paths for p in CODEOWNERS_PATHS
        )
        snapshot.codeowners_path = next((p for p in CODEOWNERS_PATHS if p in paths), None)
        workflows: list[WorkflowAnalysis] = []
        for path, entry in sorted(paths.items()):
            if not is_workflow_path(path):
                continue
            if len(workflows) >= MAX_WORKFLOW_FILES:
                self.report.warnings.append(
                    f"more than {MAX_WORKFLOW_FILES} workflow files; rest not analysed"
                )
                break
            blob = entry.get("sha")
            size = entry.get("size")
            if not isinstance(blob, str) or not _SHA_RE.match(blob):
                continue
            cached = self.cache.get(blob)
            if cached is not None and cached.path == path:
                workflows.append(cached)
                continue
            if isinstance(size, int) and size > MAX_WORKFLOW_BYTES:
                analysis = WorkflowAnalysis(
                    path=path, ok=False, error=f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes"
                )
            else:
                try:
                    text = self.client.get_text(
                        f"{self.api}/git/blobs/{blob}", max_bytes=MAX_WORKFLOW_BYTES + 1
                    )
                except (GitHubUnauthorized, GitHubRateLimited):
                    raise
                except GitHubApiError as exc:
                    gap = self._gap("workflows", exc)
                    snapshot.gaps["workflows"] = gap
                    return
                analysis = analyse_workflow(path, text)
            if len(self.cache) > 512:
                self.cache.clear()
            self.cache[blob] = analysis
            workflows.append(analysis)
        snapshot.workflows = workflows

    # ── phase 6: security alerts ────────────────────────────────────────────

    def _phase_alerts(self) -> None:
        st = self.state
        if not self.cfg.collect_security_alerts:
            return
        if not self._due(st.last_alerts_at, self.cfg.security_alerts_interval_seconds):
            return
        if not self._budget_ok("security alerts scan"):
            return
        started = self.clock()
        outcomes: list[CheckOutcome] = []
        for feature, (suffix, extra) in alerts_mod.FEATURES.items():
            builder = alerts_mod.BUILDERS[feature]
            try:
                page = self.client.paginate(
                    f"{self.api}{suffix}",
                    params={**extra, "per_page": 100},
                    max_pages=self.cfg.max_pages,
                )
            except (GitHubUnauthorized, GitHubRateLimited):
                raise
            except GitHubApiError as exc:
                gap = self._gap(feature, exc)
                outcomes.append(CheckOutcome.skip(feature, gap.reason, transient=gap.transient))
                continue
            if page.truncated:
                outcomes.append(
                    CheckOutcome.skip(
                        feature,
                        "more open alerts than max_pages allows; listing incomplete",
                        transient=True,
                    )
                )
                continue
            drafts = [
                d for d in (builder(a) for a in page.items if isinstance(a, dict)) if d is not None
            ]
            outcomes.append(CheckOutcome.ok(feature, drafts))
        finished = self.clock()
        scan = build_scan_records(
            scanner=alerts_mod.SCANNER,
            scanner_version=alerts_mod.SCANNER_VERSION,
            asset_id=self.repo.asset_id,
            repo_target=f"github:{self.repo.full_name.lower()}",
            description=alerts_mod.SCOPE_DESCRIPTION,
            producer_id=self.producer_id,
            started_at=started,
            finished_at=finished,
            outcomes=outcomes,
        )
        st.last_alerts_at = iso(self.now)
        self.emit(
            [ScanRunRecord(data=scan.scan_run), *(FindingRecord(data=f) for f in scan.findings)]
        )

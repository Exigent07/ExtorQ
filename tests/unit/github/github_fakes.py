"""SYNTHETIC GitHub REST API fake for C1 unit tests (served through ``httpx.MockTransport``).

Everything here is synthetic test data: the owner ``example-org``, logins ``synthetic-*``,
commit SHAs derived from a counter, timestamps in 2026. Nothing is real GitHub telemetry.

The fake models just enough of the REST API used by the collector: repository metadata,
Actions settings, branches, protection, rulesets, commits (list, compare, detail with
files), contents and blobs at a ref, the activity feed, workflow runs, trees and the three
security-alert listings. It implements ETag / ``If-None-Match`` (304), ``Link``
pagination with ``page``/``per_page``, rate-limit headers and per-path error injection,
and it records every request so tests can assert on headers and conditional requests.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import httpx

API = "https://api.github.com"
T0 = datetime(2026, 11, 20, 9, 0, tzinfo=UTC)


def iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def git_blob_sha(text: str) -> str:
    data = text.encode("utf-8")
    return hashlib.sha1(b"blob %d\x00" % len(data) + data, usedforsecurity=False).hexdigest()


@dataclass
class FakeCommit:
    sha: str
    message: str
    parents: list[str]
    tree: dict[str, str]
    author_login: str | None
    date: datetime


@dataclass
class Injected:
    status: int
    body: Any = None
    headers: dict[str, str] = field(default_factory=dict)
    #: How many times to serve the error (None = forever).
    times: int | None = None


class FakeGitHub:
    """A single synthetic repository behind a fake GitHub REST API."""

    def __init__(
        self, owner: str = "Example-Org", name: str = "extorq-lab", *, sha_salt: str = ""
    ) -> None:
        #: Distinguishes the synthetic commit SHAs of separate scenarios (fixtures).
        self.sha_salt = sha_salt
        self.owner = owner
        self.name = name
        self.full_name = f"{owner}/{name}"
        self.repo_id = 4242
        self.private = True
        self.allow_forking = True
        self.admin = True
        self.security_and_analysis: dict[str, Any] | None = {
            "secret_scanning": {"status": "disabled"},
            "secret_scanning_push_protection": {"status": "disabled"},
            "dependabot_security_updates": {"status": "disabled"},
        }
        self.default_branch = "main"
        self.workflow_permissions: dict[str, Any] = {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        }
        self.actions_permissions: dict[str, Any] = {
            "enabled": True,
            "allowed_actions": "all",
            "sha_pinning_required": False,
        }
        self.vulnerability_alerts_enabled = True
        self.commits: dict[str, FakeCommit] = {}
        self.branches: dict[str, str] = {}
        self.protected: dict[str, bool] = {}
        self.protection: dict[str, dict[str, Any]] = {}
        self.branch_rules: dict[str, list[dict[str, Any]]] = {}
        self.rulesets: list[dict[str, Any]] = []
        self.activity: list[dict[str, Any]] = []
        self.runs: list[dict[str, Any]] = []
        self.alerts: dict[str, list[dict[str, Any]]] = {
            "dependabot": [],
            "code-scanning": [],
            "secret-scanning": [],
        }
        self.errors: list[tuple[re.Pattern[str], Injected]] = []
        self.requests: list[httpx.Request] = []
        self.rate_remaining = 4999
        self._counter = 0
        self.clock = T0

    # ── building the synthetic repository ──────────────────────────────────

    def _next_sha(self) -> str:
        self._counter += 1
        return hashlib.sha1(
            f"synthetic-commit-{self.sha_salt}{self._counter}".encode(), usedforsecurity=False
        ).hexdigest()

    def commit(
        self,
        message: str,
        changes: dict[str, str | None],
        *,
        branch: str = "main",
        author: str | None = "synthetic-dev",
        pushed: bool = True,
        pusher: str = "synthetic-dev",
        when: datetime | None = None,
    ) -> str:
        """Create a commit on ``branch`` applying ``changes`` (None deletes a path)."""
        parent = self.branches.get(branch)
        tree = dict(self.commits[parent].tree) if parent else {}
        for path, content in changes.items():
            if content is None:
                tree.pop(path, None)
            else:
                tree[path] = content
        self.clock = when or (self.clock + timedelta(minutes=5))
        sha = self._next_sha()
        self.commits[sha] = FakeCommit(
            sha=sha,
            message=message,
            parents=[parent] if parent else [],
            tree=tree,
            author_login=author,
            date=self.clock,
        )
        self.branches[branch] = sha
        if pushed:
            self.activity.insert(
                0,
                {
                    "id": len(self.activity) + 1,
                    "before": parent or "0" * 40,
                    "after": sha,
                    "ref": f"refs/heads/{branch}",
                    "timestamp": iso(self.clock),
                    "activity_type": "push",
                    "actor": {"login": pusher, "id": 1001, "type": "User"},
                },
            )
        return sha

    def force_reset(self, branch: str, sha: str) -> None:
        """Point ``branch`` at an older commit (history rewrite)."""
        self.branches[branch] = sha

    def add_run(self, **fields: Any) -> dict[str, Any]:
        run_id = 9000 + len(self.runs)
        run = {
            "id": run_id,
            "name": "CI",
            "path": ".github/workflows/ci.yml",
            "run_attempt": 1,
            "run_number": len(self.runs) + 1,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": self.branches.get("main"),
            "created_at": iso(self.clock),
            "run_started_at": iso(self.clock),
            "updated_at": iso(self.clock + timedelta(minutes=2)),
            "display_title": "synthetic run",
            "actor": {"login": "synthetic-dev", "id": 1001, "type": "User"},
            "triggering_actor": {"login": "synthetic-dev", "id": 1001, "type": "User"},
            "head_commit": {"message": "synthetic"},
            "head_repository": {"full_name": self.full_name},
            "workflow_id": 77,
            "html_url": f"https://github.com/{self.full_name}/actions/runs/{run_id}",
        }
        run.update(fields)
        self.runs.insert(0, run)
        return run

    def inject(
        self,
        pattern: str,
        status: int,
        body: Any = None,
        *,
        times: int | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Serve ``status`` for request paths matching ``pattern`` (regex, full match)."""
        self.errors.append(
            (re.compile(pattern), Injected(status, body, dict(headers or {}), times))
        )

    def clear_errors(self) -> None:
        self.errors.clear()

    # ── transport ───────────────────────────────────────────────────────────

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def paths(self) -> list[str]:
        return [request.url.path for request in self.requests]

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = unquote(request.url.path)
        for index, (pattern, injected) in enumerate(list(self.errors)):
            if pattern.fullmatch(path):
                if injected.times is not None:
                    injected.times -= 1
                    if injected.times <= 0:
                        self.errors.pop(index)
                body = injected.body if injected.body is not None else {"message": "injected"}
                return httpx.Response(
                    injected.status,
                    json=body,
                    headers={**self._rate_headers(), **injected.headers},
                )
        query = {k: v[-1] for k, v in parse_qs(request.url.query.decode()).items()}
        raw = "raw" in request.headers.get("accept", "")
        result = self._route(path, query, raw)
        if isinstance(result, httpx.Response):
            return result
        status, payload, headers = result
        return self._respond(request, status, payload, headers, raw=raw)

    def _rate_headers(self) -> dict[str, str]:
        self.rate_remaining = max(0, self.rate_remaining - 1)
        return {
            "x-ratelimit-limit": "5000",
            "x-ratelimit-remaining": str(self.rate_remaining),
            "x-ratelimit-reset": str(int(T0.timestamp()) + 3600),
            "x-ratelimit-used": str(5000 - self.rate_remaining),
            "x-ratelimit-resource": "core",
        }

    def _respond(
        self,
        request: httpx.Request,
        status: int,
        payload: Any,
        headers: dict[str, str],
        *,
        raw: bool,
    ) -> httpx.Response:
        if status == 204:
            return httpx.Response(204, headers=self._rate_headers())
        body = (
            payload.encode("utf-8")
            if raw and isinstance(payload, str)
            else json.dumps(payload, sort_keys=True).encode("utf-8")
        )
        etag = 'W/"' + hashlib.sha256(body).hexdigest()[:20] + '"'
        if status == 200 and request.headers.get("if-none-match") == etag:
            # Authenticated 304s are free on GitHub: do not consume rate limit.
            return httpx.Response(304, headers={"etag": etag})
        all_headers = {**self._rate_headers(), **headers}
        if status == 200:
            all_headers["etag"] = etag
        all_headers["content-type"] = (
            "text/plain; charset=utf-8" if raw else "application/json; charset=utf-8"
        )
        return httpx.Response(status, content=body, headers=all_headers)

    def _paginate(
        self, path: str, query: dict[str, str], items: list[Any], wrap: Callable[[list[Any]], Any]
    ) -> tuple[int, Any, dict[str, str]]:
        per_page = max(1, min(100, int(query.get("per_page", "30"))))
        page = max(1, int(query.get("page", "1")))
        start = (page - 1) * per_page
        chunk = items[start : start + per_page]
        headers: dict[str, str] = {}
        if start + per_page < len(items):
            next_query = dict(query)
            next_query["page"] = str(page + 1)
            last_query = dict(query)
            last_query["page"] = str(-(-len(items) // per_page))
            headers["link"] = (
                f'<{API}{path}?{urlencode(next_query)}>; rel="next", '
                f'<{API}{path}?{urlencode(last_query)}>; rel="last"'
            )
        return 200, wrap(chunk), headers

    def _route(
        self, path: str, query: dict[str, str], raw: bool
    ) -> tuple[int, Any, dict[str, str]] | httpx.Response:
        base = f"/repos/{self.owner}/{self.name}"
        if not path.lower().startswith(base.lower()):
            return 404, {"message": "Not Found"}, {}
        rest = path[len(base) :]
        not_found = (404, {"message": "Not Found"}, {})
        if rest == "":
            return 200, self.repo_json(), {}
        if rest == "/actions/permissions/workflow":
            return 200, self.workflow_permissions, {}
        if rest == "/actions/permissions":
            return 200, self.actions_permissions, {}
        if rest == "/vulnerability-alerts":
            return (204, None, {}) if self.vulnerability_alerts_enabled else not_found
        if rest == "/rulesets":
            return 200, self.rulesets, {}
        match = re.fullmatch(r"/branches/(.+)/protection", rest)
        if match:
            branch = match.group(1)
            if branch in self.protection:
                return 200, self.protection[branch], {}
            return 404, {"message": "Branch not protected"}, {}
        match = re.fullmatch(r"/rules/branches/(.+)", rest)
        if match:
            return 200, self.branch_rules.get(match.group(1), []), {}
        match = re.fullmatch(r"/branches/(.+)", rest)
        if match:
            branch = match.group(1)
            if branch not in self.branches:
                return 404, {"message": "Branch not found"}, {}
            return (
                200,
                {
                    "name": branch,
                    "commit": {"sha": self.branches[branch]},
                    "protected": self.protected.get(branch, False),
                },
                {},
            )
        if rest == "/commits":
            head = query.get("sha", self.branches.get(self.default_branch))
            if head not in self.commits:
                return 409, {"message": "Git Repository is empty."}, {}
            history = self._history(head)  # newest first
            return self._paginate(
                path, query, [self._commit_summary(c) for c in history], lambda chunk: chunk
            )
        match = re.fullmatch(r"/compare/([0-9a-f]{40})\.\.\.([0-9a-f]{40})", rest)
        if match:
            base_sha, head_sha = match.groups()
            if base_sha not in self.commits or head_sha not in self.commits:
                return not_found
            head_hist = [c.sha for c in self._history(head_sha)]
            base_hist = [c.sha for c in self._history(base_sha)]
            merge_base = next((s for s in head_hist if s in base_hist), None)
            ahead = head_hist[: head_hist.index(merge_base)] if merge_base else head_hist
            behind = base_hist[: base_hist.index(merge_base)] if merge_base else base_hist
            if not ahead and not behind:
                status = "identical"
            elif not behind:
                status = "ahead"
            elif not ahead:
                status = "behind"
            else:
                status = "diverged"
            commits = [self._commit_summary(self.commits[s]) for s in reversed(ahead)]
            meta = {
                "status": status,
                "ahead_by": len(ahead),
                "behind_by": len(behind),
                "total_commits": len(ahead),
            }
            return self._paginate(path, query, commits, lambda chunk: {**meta, "commits": chunk})
        match = re.fullmatch(r"/commits/([0-9a-f]{40})", rest)
        if match:
            commit = self.commits.get(match.group(1))
            if commit is None:
                return 422, {"message": "No commit found for SHA"}, {}
            return 200, self._commit_detail(commit), {}
        match = re.fullmatch(r"/contents/(.+)", rest)
        if match:
            commit = self.commits.get(query.get("ref", ""))
            content = commit.tree.get(match.group(1)) if commit else None
            if content is None:
                return not_found
            return 200, content, {}
        if rest == "/activity":
            ref = query.get("ref")
            items = [a for a in self.activity if ref is None or a["ref"] == ref]
            return self._paginate(path, query, items, lambda chunk: chunk)
        if rest == "/actions/runs":
            created = query.get("created", "")
            floor = created[2:] if created.startswith(">=") else ""
            items = [r for r in self.runs if r["created_at"] >= floor]
            return self._paginate(
                path,
                query,
                items,
                lambda chunk: {"total_count": len(items), "workflow_runs": chunk},
            )
        match = re.fullmatch(r"/git/trees/([0-9a-f]{40})", rest)
        if match:
            commit = self.commits.get(match.group(1))
            if commit is None:
                return not_found
            tree = [
                {
                    "path": p,
                    "type": "blob",
                    "mode": "100644",
                    "sha": git_blob_sha(c),
                    "size": len(c.encode()),
                }
                for p, c in sorted(commit.tree.items())
            ]
            return 200, {"sha": commit.sha, "tree": tree, "truncated": False}, {}
        match = re.fullmatch(r"/git/blobs/([0-9a-f]{40})", rest)
        if match:
            for commit in self.commits.values():
                for content in commit.tree.values():
                    if git_blob_sha(content) == match.group(1):
                        return 200, content, {}
            return not_found
        match = re.fullmatch(r"/(dependabot|code-scanning|secret-scanning)/alerts", rest)
        if match:
            items = [a for a in self.alerts[match.group(1)] if a.get("state", "open") == "open"]
            return self._paginate(path, query, items, lambda chunk: chunk)
        return not_found

    # ── JSON shapes ─────────────────────────────────────────────────────────

    def repo_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.repo_id,
            "full_name": self.full_name,
            "name": self.name,
            "owner": {"login": self.owner, "type": "User"},
            "private": self.private,
            "visibility": "private" if self.private else "public",
            "default_branch": self.default_branch,
            "archived": False,
            "disabled": False,
            "fork": False,
            "allow_forking": self.allow_forking,
            "web_commit_signoff_required": False,
            "html_url": f"https://github.com/{self.full_name}",
            "permissions": {"admin": self.admin, "push": True, "pull": True},
        }
        if self.security_and_analysis is not None:
            data["security_and_analysis"] = self.security_and_analysis
        return data

    def _history(self, head: str) -> list[FakeCommit]:
        out: list[FakeCommit] = []
        sha: str | None = head
        while sha:
            commit = self.commits[sha]
            out.append(commit)
            sha = commit.parents[0] if commit.parents else None
        return out

    def _commit_summary(self, commit: FakeCommit) -> dict[str, Any]:
        return {"sha": commit.sha, "commit": {"message": commit.message}}

    def _commit_detail(self, commit: FakeCommit) -> dict[str, Any]:
        parent_tree = self.commits[commit.parents[0]].tree if commit.parents else {}
        files: list[dict[str, Any]] = []
        for path in sorted(set(parent_tree) | set(commit.tree)):
            before, after = parent_tree.get(path), commit.tree.get(path)
            if before == after:
                continue
            status = "added" if before is None else ("removed" if after is None else "modified")
            files.append({"filename": path, "status": status, "additions": 1, "deletions": 0})
        author = (
            {"login": commit.author_login, "id": 1001, "type": "User"}
            if commit.author_login
            else None
        )
        return {
            "sha": commit.sha,
            "commit": {
                "message": commit.message,
                "author": {"name": "Synthetic Dev", "date": iso(commit.date)},
                "committer": {"name": "Synthetic Dev", "date": iso(commit.date)},
                "verification": {"verified": False, "reason": "unsigned"},
            },
            "author": author,
            "committer": author,
            "parents": [{"sha": p} for p in commit.parents],
            "files": files,
            "stats": {"additions": len(files), "deletions": 0, "total": len(files)},
        }


def request_query(request: httpx.Request) -> dict[str, str]:
    return {k: v[-1] for k, v in parse_qs(urlsplit(str(request.url)).query).items()}

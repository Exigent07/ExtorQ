"""GitHub Actions workflow analyser (pure: no network, no file or process access).

Used by the GitHub collector (per-commit before/after deltas and repository posture)
and by the offline GH-001 dry run (``python -m extorq_collectors.github.analyze``).

Workflow YAML is attacker-controlled: anyone able to push, or to get a pull request
merged, authors it. Parsing is therefore defensive:

* a ``yaml.SafeLoader`` subclass (no arbitrary object construction);
* YAML 1.2 boolean rules, as GitHub uses, so the key ``on`` stays the string ``"on"``
  (PyYAML's YAML 1.1 rules would turn it into the boolean ``True``). A mapping that
  was loaded elsewhere with a ``True`` key is still handled;
* duplicate mapping keys are rejected (GitHub rejects such workflows; accepting
  them with PyYAML's last-key-wins rule would be a parser differential);
* input size, alias count and node count are bounded, and the document is never
  walked recursively, so alias expansion cannot blow up memory or CPU.

Permission model (docs.github.com, "Controlling permissions for GITHUB_TOKEN"):
a job's token permissions come from ``jobs.<id>.permissions`` if present, otherwise
from the workflow-level ``permissions``, otherwise from the repository/organisation
default (``GET /repos/{o}/{r}/actions/permissions/workflow``: ``read`` = restricted,
``write`` = permissive). A job-level block replaces the workflow-level block entirely.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

import yaml

ANALYZER_VERSION = "1.0.0"

MAX_WORKFLOW_BYTES = 512 * 1024
MAX_YAML_ALIASES = 100
MAX_YAML_NODES = 50_000
MAX_JOBS = 256
MAX_STEPS_PER_JOB = 512
MAX_SCRIPT_CHARS = 64 * 1024
MAX_EVIDENCE_ITEMS = 32
MAX_EVIDENCE_CHARS = 200

WORKFLOW_PATH_RE = re.compile(r"^\.github/workflows/[^/\x00-\x1f]{1,200}\.ya?ml$")

Level = Literal["none", "read", "write"]
RepoDefault = Literal["read", "write"]

_LEVEL_RANK: dict[str, int] = {"none": 0, "read": 1, "write": 2}

#: GITHUB_TOKEN scopes that accept ``write``.
WRITE_CAPABLE_SCOPES: frozenset[str] = frozenset(
    {
        "actions",
        "attestations",
        "checks",
        "contents",
        "deployments",
        "discussions",
        "id-token",
        "issues",
        "packages",
        "pages",
        "pull-requests",
        "repository-projects",
        "security-events",
        "statuses",
    }
)
#: Scopes that only accept ``read`` / ``none``.
READ_ONLY_SCOPES: frozenset[str] = frozenset({"models"})
KNOWN_SCOPES: frozenset[str] = WRITE_CAPABLE_SCOPES | READ_ONLY_SCOPES

#: Write-relevant subset of the repository default token permissions. ``metadata: read``
#: is always granted and not configurable, so it is omitted.
PERMISSIVE_DEFAULT: dict[str, str] = {
    scope: "write" for scope in sorted(WRITE_CAPABLE_SCOPES - {"id-token"})
}
RESTRICTED_DEFAULT: dict[str, str] = {"contents": "read", "packages": "read"}

#: Triggers whose runs execute in the context of the base repository with access to
#: secrets and a potentially write-capable token while processing input from people
#: who may not have write access (pull request authors, commenters, other workflows).
PRIVILEGED_TRIGGERS: frozenset[str] = frozenset(
    {"pull_request_target", "workflow_run", "issue_comment"}
)

#: Owners whose actions are maintained by GitHub itself.
GITHUB_OWNED_ACTION_OWNERS: frozenset[str] = frozenset({"actions", "github"})

_SCOPE_KEY_RE = re.compile(r"^[a-z][a-z-]{1,40}$")
_TRIGGER_RE = re.compile(r"^[a-z_]{1,64}$")
_JOB_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,99}$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_REMOTE_USES_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9._-]{1,100})"
    r"(?P<path>/[^@\s]{1,300})?@(?P<ref>[^@\s]{1,255})$"
)
_DOCKER_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
#: Bounded expression length keeps matching linear on hostile input (no `}}` terminator).
_EXPR_RE = re.compile(r"\$\{\{(.{0,512}?)\}\}", re.DOTALL)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")

#: Expression contexts an external party can control (GitHub Security Lab list of
#: untrusted input). Interpolating them into ``run`` scripts allows script injection.
UNTRUSTED_CONTEXT_RE = re.compile(
    r"\bgithub\s*\.\s*(?:"
    r"head_ref"
    r"|event\s*\.\s*(?:"
    r"issue\s*\.\s*(?:title|body)"
    r"|pull_request\s*\.\s*(?:title|body|head\s*\.\s*(?:ref|label|repo\s*\.\s*default_branch))"
    r"|comment\s*\.\s*body"
    r"|review\s*\.\s*body"
    r"|review_comment\s*\.\s*body"
    r"|pages\s*(?:\.\s*[\w*]+|\[[^\]]*\])\s*\.\s*page_name"
    r"|commits\s*(?:\.\s*[\w*]+|\[[^\]]*\])\s*\.\s*(?:message|author\s*\.\s*(?:email|name))"
    r"|head_commit\s*\.\s*(?:message|author\s*\.\s*(?:email|name))"
    r"|workflow_run\s*\.\s*(?:head_branch|head_commit\s*\.\s*(?:message|author\s*\.\s*(?:email|name)))"
    r"|discussion\s*\.\s*(?:title|body)"
    r"))\b"
)
_ANY_EVENT_CONTEXT_RE = re.compile(r"\bgithub\s*\.\s*event\s*\.")

#: References to code controlled by a pull request author or by another workflow run.
_UNTRUSTED_REF_RE = re.compile(
    r"github\s*\.\s*event\s*\.\s*pull_request\s*\.\s*head\s*\.\s*(?:sha|ref)"
    r"|github\s*\.\s*event\s*\.\s*pull_request\s*\.\s*merge_commit_sha"
    r"|github\s*\.\s*head_ref"
    r"|github\s*\.\s*event\s*\.\s*workflow_run\s*\.\s*head_(?:sha|branch)"
    r"|github\s*\.\s*event\s*\.\s*workflow_run\s*\.\s*head_commit\s*\.\s*id"
    r"|refs/pull/"
    r"|\bpull/\$\{\{"
)
_UNTRUSTED_REPO_RE = re.compile(
    r"github\s*\.\s*event\s*\.\s*pull_request\s*\.\s*head\s*\.\s*repo\s*\.\s*full_name"
    r"|github\s*\.\s*event\s*\.\s*workflow_run\s*\.\s*head_repository\s*\.\s*full_name"
)
_RUN_CHECKOUT_RE = re.compile(r"\bgh\s+pr\s+checkout\b")
_RUN_GIT_FETCH_RE = re.compile(r"\bgit\s+(?:fetch|checkout|switch|pull|reset)\b")


class WorkflowParseError(ValueError):
    """Workflow text is not a valid, bounded GitHub Actions workflow document."""


# ── YAML loading ────────────────────────────────────────────────────────────────


class _WorkflowLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 booleans, duplicate-key rejection and size budgets."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._alias_count = 0
        self._node_count = 0

    def compose_node(self, parent: yaml.Node | None, index: Any) -> yaml.Node | None:
        if self.check_event(yaml.AliasEvent):
            self._alias_count += 1
            if self._alias_count > MAX_YAML_ALIASES:
                raise WorkflowParseError(f"more than {MAX_YAML_ALIASES} YAML aliases")
        else:
            self._node_count += 1
            if self._node_count > MAX_YAML_NODES:
                raise WorkflowParseError(f"more than {MAX_YAML_NODES} YAML nodes")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _value in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            if isinstance(key_node, yaml.ScalarNode):
                key = str(key_node.value)
                if key in seen:
                    line = key_node.start_mark.line + 1
                    raise WorkflowParseError(
                        f"duplicate mapping key {_clip(key, 40)!r} (line {line})"
                    )
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


# Remove YAML 1.1 booleans (yes/no/on/off) and re-add YAML 1.2 ones (true/false only).
_WorkflowLoader.yaml_implicit_resolvers = {
    first: [(tag, regexp) for tag, regexp in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


def load_workflow_yaml(text: str) -> dict[str, Any]:
    """Parse workflow text into a mapping, or raise :class:`WorkflowParseError`."""
    if len(text.encode("utf-8", errors="replace")) > MAX_WORKFLOW_BYTES:
        raise WorkflowParseError(f"workflow exceeds {MAX_WORKFLOW_BYTES} bytes")
    loader = _WorkflowLoader(text)
    try:
        document = loader.get_single_data()
    except WorkflowParseError:
        raise
    except yaml.YAMLError as exc:
        raise WorkflowParseError(f"invalid YAML: {_clip(_one_line(str(exc)), 300)}") from exc
    except RecursionError as exc:
        raise WorkflowParseError("YAML nesting too deep") from exc
    finally:
        loader.dispose()
    if not isinstance(document, dict):
        raise WorkflowParseError("workflow document is not a mapping")
    return document


# ── Model ───────────────────────────────────────────────────────────────────────

PermissionKind = Literal["unset", "read-all", "write-all", "none", "map", "invalid"]


@dataclass(frozen=True)
class PermissionSpec:
    """A declared ``permissions`` value (workflow- or job-level)."""

    kind: PermissionKind
    scopes: tuple[tuple[str, str], ...] = ()
    invalid_reason: str | None = None

    def render(self) -> str:
        if self.kind == "map":
            return ",".join(f"{scope}:{level}" for scope, level in self.scopes)
        if self.kind == "none":
            return "{}"
        return self.kind

    def resolve(self) -> dict[str, str] | None:
        """Scope -> level for an explicit spec; ``None`` for unset/invalid specs."""
        if self.kind == "write-all":
            return {scope: "write" for scope in WRITE_CAPABLE_SCOPES} | {"models": "read"}
        if self.kind == "read-all":
            return {scope: "read" for scope in KNOWN_SCOPES - {"id-token"}}
        if self.kind == "none":
            return {}
        if self.kind == "map":
            return {scope: level for scope, level in self.scopes if level != "none"}
        return None


UNSET = PermissionSpec("unset")


@dataclass(frozen=True)
class ActionRef:
    """A ``uses:`` reference (step action or reusable workflow)."""

    raw: str
    kind: Literal["local", "docker", "remote", "invalid"]
    owner: str | None = None
    repo: str | None = None
    ref: str | None = None
    pinned: bool = False

    @property
    def github_owned(self) -> bool:
        return self.kind == "remote" and (self.owner or "").lower() in GITHUB_OWNED_ACTION_OWNERS

    @property
    def third_party(self) -> bool:
        return self.kind == "docker" or (self.kind == "remote" and not self.github_owned)


@dataclass(frozen=True)
class JobAnalysis:
    job_id: str
    permissions: PermissionSpec
    uses: ActionRef | None = None
    secrets_inherit: bool = False
    actions: tuple[ActionRef, ...] = ()
    untrusted_checkout: tuple[str, ...] = ()
    script_injection: tuple[str, ...] = ()
    event_expressions_in_run: tuple[str, ...] = ()


@dataclass(frozen=True)
class WorkflowAnalysis:
    path: str
    ok: bool
    error: str | None = None
    name: str | None = None
    triggers: tuple[str, ...] = ()
    invalid_triggers: bool = False
    permissions: PermissionSpec = UNSET
    jobs: tuple[JobAnalysis, ...] = ()

    @property
    def has_write_all(self) -> bool:
        return self.permissions.kind == "write-all" or any(
            job.permissions.kind == "write-all" for job in self.jobs
        )

    @property
    def relies_on_default(self) -> bool:
        """True when at least one job gets its token permissions from the repo default."""
        if self.permissions.kind != "unset":
            return False
        if not self.jobs:
            return True
        return any(job.permissions.kind == "unset" for job in self.jobs)

    @property
    def privileged_triggers(self) -> tuple[str, ...]:
        return tuple(t for t in self.triggers if t in PRIVILEGED_TRIGGERS)

    @property
    def unpinned_third_party_actions(self) -> tuple[str, ...]:
        return _unique(ref.raw for ref in self._all_refs() if ref.third_party and not ref.pinned)

    @property
    def unpinned_github_owned_actions(self) -> tuple[str, ...]:
        return _unique(ref.raw for ref in self._all_refs() if ref.github_owned and not ref.pinned)

    @property
    def invalid_uses(self) -> tuple[str, ...]:
        return _unique(ref.raw for ref in self._all_refs() if ref.kind == "invalid")

    @property
    def secrets_inherit_jobs(self) -> tuple[str, ...]:
        return tuple(job.job_id for job in self.jobs if job.secrets_inherit)

    @property
    def untrusted_checkouts(self) -> tuple[str, ...]:
        return _unique(item for job in self.jobs for item in job.untrusted_checkout)

    @property
    def script_injections(self) -> tuple[str, ...]:
        return _unique(item for job in self.jobs for item in job.script_injection)

    @property
    def event_expressions_in_run(self) -> tuple[str, ...]:
        return _unique(item for job in self.jobs for item in job.event_expressions_in_run)

    @property
    def privileged_untrusted_checkout(self) -> bool:
        return bool(self.privileged_triggers) and bool(self.untrusted_checkouts)

    def _all_refs(self) -> Iterable[ActionRef]:
        for job in self.jobs:
            if job.uses is not None:
                yield job.uses
            yield from job.actions

    def effective_permissions(self, repo_default: RepoDefault | None) -> EffectivePermissions:
        """Token permissions per job, combining job, workflow and repository defaults."""
        default_map: dict[str, str] | None
        if repo_default == "write":
            default_map = dict(PERMISSIVE_DEFAULT)
        elif repo_default == "read":
            default_map = dict(RESTRICTED_DEFAULT)
        else:
            default_map = None

        def resolve(spec: PermissionSpec) -> dict[str, str] | None:
            if spec.kind == "unset":
                return default_map
            return spec.resolve()

        by_job: dict[str, dict[str, str] | None] = {}
        if not self.jobs:
            by_job["<workflow>"] = resolve(self.permissions)
        for job in self.jobs:
            spec = job.permissions if job.permissions.kind != "unset" else self.permissions
            by_job[job.job_id] = resolve(spec)
        union: dict[str, str] = {}
        unknown = False
        for resolved in by_job.values():
            if resolved is None:
                unknown = True
                continue
            for scope, level in resolved.items():
                if _LEVEL_RANK.get(level, 0) > _LEVEL_RANK.get(union.get(scope, "none"), 0):
                    union[scope] = level
        return EffectivePermissions(by_job=by_job, union=union, unknown=unknown)


@dataclass(frozen=True)
class EffectivePermissions:
    by_job: dict[str, dict[str, str] | None]
    union: dict[str, str]
    #: True when at least one job's permissions could not be determined (unset
    #: permissions and unknown repository default, or an invalid declaration).
    unknown: bool

    @property
    def write_scopes(self) -> tuple[str, ...]:
        return tuple(sorted(scope for scope, level in self.union.items() if level == "write"))


# ── Parsing helpers ─────────────────────────────────────────────────────────────


def _one_line(text: str) -> str:
    return " ".join(_CONTROL_RE.sub(" ", text).split())


def _clip(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    text = _one_line(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _unique(items: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for item in items:
        if item not in seen:
            seen[item] = None
    return tuple(seen)


def _safe_job_id(raw: object, index: int) -> str:
    text = str(raw)
    return text if _JOB_ID_RE.match(text) else f"job[{index}]"


def parse_permissions(value: object, *, present: bool) -> PermissionSpec:
    """Normalise a ``permissions`` value; ``present`` is False when the key is absent."""
    if not present:
        return UNSET
    if isinstance(value, str):
        text = value.strip()
        if text in ("read-all", "write-all"):
            return PermissionSpec(text)  # type: ignore[arg-type]
        return PermissionSpec(
            "invalid", invalid_reason=f"unsupported shorthand {_clip(text, 40)!r}"
        )
    if isinstance(value, Mapping):
        if not value:
            return PermissionSpec("none")
        scopes: dict[str, str] = {}
        for raw_scope, raw_level in value.items():
            scope = str(raw_scope).strip()
            level = str(raw_level).strip() if isinstance(raw_level, str) else None
            if not _SCOPE_KEY_RE.match(scope):
                return PermissionSpec(
                    "invalid", invalid_reason=f"invalid scope {_clip(scope, 40)!r}"
                )
            if level not in _LEVEL_RANK:
                return PermissionSpec(
                    "invalid",
                    invalid_reason=f"invalid level for {scope}: {_clip(str(raw_level), 20)!r}",
                )
            scopes[scope] = level
        return PermissionSpec("map", scopes=tuple(sorted(scopes.items())))
    return PermissionSpec("invalid", invalid_reason=f"unsupported type {type(value).__name__}")


def parse_triggers(value: object) -> tuple[tuple[str, ...], bool]:
    """Return (sorted trigger names, invalid_flag) from an ``on`` value."""
    names: list[object]
    if isinstance(value, str):
        names = [value]
    elif isinstance(value, list):
        names = list(value)
    elif isinstance(value, Mapping):
        names = list(value.keys())
    else:
        return (), True
    triggers: set[str] = set()
    invalid = False
    for name in names[:128]:
        text = str(name).strip() if isinstance(name, str) else ""
        if _TRIGGER_RE.match(text):
            triggers.add(text)
        else:
            invalid = True
    return tuple(sorted(triggers)), invalid


def parse_uses(value: object) -> ActionRef:
    """Classify a ``uses:`` value; pinning means a full 40-hex commit SHA (or image digest)."""
    if not isinstance(value, str) or not value.strip():
        return ActionRef(raw=_clip(str(value), 120), kind="invalid")
    raw = value.strip()
    shown = _clip(raw, 200)
    if len(raw) > 512:
        return ActionRef(raw=shown, kind="invalid")
    if raw.startswith("./"):
        return ActionRef(raw=shown, kind="local", pinned=True)
    if raw.startswith("docker://"):
        return ActionRef(raw=shown, kind="docker", pinned=bool(_DOCKER_DIGEST_RE.search(raw)))
    match = _REMOTE_USES_RE.match(raw)
    if match is None or "${{" in raw:
        return ActionRef(raw=shown, kind="invalid")
    ref = match.group("ref")
    return ActionRef(
        raw=shown,
        kind="remote",
        owner=match.group("owner"),
        repo=match.group("repo"),
        ref=ref,
        pinned=bool(_SHA40_RE.match(ref)),
    )


def _expressions(script: str) -> list[str]:
    return [_clip(m.group(1).strip(), 120) for m in _EXPR_RE.finditer(script[:MAX_SCRIPT_CHARS])]


def _analyse_job(job_id: str, job: Mapping[str, Any]) -> JobAnalysis:
    permissions = parse_permissions(job.get("permissions"), present="permissions" in job)
    uses = parse_uses(job["uses"]) if "uses" in job else None
    secrets_inherit = isinstance(job.get("secrets"), str) and job["secrets"].strip() == "inherit"
    actions: list[ActionRef] = []
    untrusted: list[str] = []
    injections: list[str] = []
    event_exprs: list[str] = []
    steps = job.get("steps")
    if isinstance(steps, list):
        for index, step in enumerate(steps[:MAX_STEPS_PER_JOB]):
            if not isinstance(step, Mapping):
                continue
            label = f"{job_id}.steps[{index}]"
            ref = parse_uses(step["uses"]) if "uses" in step else None
            if ref is not None:
                actions.append(ref)
            with_block = step.get("with")
            inputs: Mapping[str, Any] = with_block if isinstance(with_block, Mapping) else {}
            if (
                ref is not None
                and ref.kind == "remote"
                and (ref.owner or "").lower() == "actions"
                and ((ref.repo or "").lower() == "checkout")
            ):
                checkout_ref = inputs.get("ref")
                checkout_repo = inputs.get("repository")
                if isinstance(checkout_ref, str) and _UNTRUSTED_REF_RE.search(checkout_ref):
                    untrusted.append(_clip(f"{label}: actions/checkout ref={checkout_ref}"))
                elif isinstance(checkout_repo, str) and _UNTRUSTED_REPO_RE.search(checkout_repo):
                    untrusted.append(_clip(f"{label}: actions/checkout repository={checkout_repo}"))
                # actions/checkout >= v7 refuses fork PR code in pull_request_target /
                # workflow_run unless this explicit opt-in is set (or set by an expression).
                unsafe_opt_in = inputs.get("allow-unsafe-pr-checkout")
                if unsafe_opt_in is True or (
                    isinstance(unsafe_opt_in, str)
                    and (unsafe_opt_in.strip().lower() == "true" or "${{" in unsafe_opt_in)
                ):
                    untrusted.append(_clip(f"{label}: actions/checkout allow-unsafe-pr-checkout=true"))
            scripts: list[str] = []
            run = step.get("run")
            if isinstance(run, str):
                scripts.append(run[:MAX_SCRIPT_CHARS])
                if _RUN_CHECKOUT_RE.search(run) or (
                    _RUN_GIT_FETCH_RE.search(run) and _UNTRUSTED_REF_RE.search(run)
                ):
                    untrusted.append(_clip(f"{label}: run checks out pull request code"))
            if (
                ref is not None
                and ref.kind == "remote"
                and (ref.owner or "").lower() == "actions"
                and ((ref.repo or "").lower() == "github-script")
            ):
                script = inputs.get("script")
                if isinstance(script, str):
                    scripts.append(script[:MAX_SCRIPT_CHARS])
            for script in scripts:
                for expression in _expressions(script):
                    if UNTRUSTED_CONTEXT_RE.search(expression):
                        injections.append(_clip(f"{label}: ${{{{ {expression} }}}}"))
                    elif _ANY_EVENT_CONTEXT_RE.search(expression):
                        event_exprs.append(_clip(f"{label}: ${{{{ {expression} }}}}"))
    return JobAnalysis(
        job_id=job_id,
        permissions=permissions,
        uses=uses,
        secrets_inherit=secrets_inherit,
        actions=tuple(actions),
        untrusted_checkout=tuple(untrusted[:MAX_EVIDENCE_ITEMS]),
        script_injection=tuple(injections[:MAX_EVIDENCE_ITEMS]),
        event_expressions_in_run=tuple(event_exprs[:MAX_EVIDENCE_ITEMS]),
    )


def analyse_workflow_document(path: str, document: Mapping[Any, Any]) -> WorkflowAnalysis:
    """Analyse an already-parsed workflow mapping."""
    if "on" in document:
        on_value: object = document["on"]
    elif True in document:  # loaded elsewhere with YAML 1.1 rules: `on` became True
        on_value = document[True]
    else:
        on_value = None
    triggers, invalid_triggers = parse_triggers(on_value) if on_value is not None else ((), True)
    name = document.get("name")
    jobs_value = document.get("jobs")
    jobs: list[JobAnalysis] = []
    if isinstance(jobs_value, Mapping):
        for index, (raw_id, job) in enumerate(list(jobs_value.items())[:MAX_JOBS]):
            if isinstance(job, Mapping):
                jobs.append(_analyse_job(_safe_job_id(raw_id, index), job))
    return WorkflowAnalysis(
        path=path,
        ok=True,
        name=_clip(name, 120) if isinstance(name, str) else None,
        triggers=triggers,
        invalid_triggers=invalid_triggers,
        permissions=parse_permissions(
            document.get("permissions"), present="permissions" in document
        ),
        jobs=tuple(jobs),
    )


def analyse_workflow(path: str, text: str) -> WorkflowAnalysis:
    """Parse and analyse workflow text; parse failures yield ``ok=False`` (never raise)."""
    try:
        document = load_workflow_yaml(text)
    except WorkflowParseError as exc:
        return WorkflowAnalysis(path=path, ok=False, error=_clip(str(exc), 300))
    return analyse_workflow_document(path, document)


# ── Before/after comparison ─────────────────────────────────────────────────────

ChangeType = Literal["added", "modified", "removed", "renamed"]


def render_permissions(analysis: WorkflowAnalysis | None, repo_default: RepoDefault | None) -> str:
    """Compact, bounded description of the declared permissions of a workflow version."""
    if analysis is None:
        return "absent"
    if not analysis.ok:
        return "unparseable"
    parts = [f"workflow={analysis.permissions.render()}"]
    for job in analysis.jobs:
        if job.permissions.kind != "unset":
            parts.append(f"job:{job.job_id}={job.permissions.render()}")
    if analysis.relies_on_default:
        parts.append(f"repo_default={repo_default or 'unknown'}")
    rendered = ";".join(parts)
    return rendered if len(rendered) <= 1024 else rendered[:1021] + "..."


@dataclass(frozen=True)
class WorkflowDelta:
    """Security-relevant difference between two versions of one workflow file."""

    path: str
    change_type: ChangeType
    previous_path: str | None
    repo_default: RepoDefault | None
    before: WorkflowAnalysis | None
    after: WorkflowAnalysis | None
    permissions_before: str
    permissions_after: str
    write_scopes_before: tuple[str, ...]
    write_scopes_after: tuple[str, ...]
    write_all_added: bool
    added_write_scopes: tuple[str, ...]
    triggers_before: tuple[str, ...]
    triggers_after: tuple[str, ...]
    triggers_added: tuple[str, ...]
    triggers_removed: tuple[str, ...]
    dangerous_triggers_added: tuple[str, ...]
    unpinned_actions_added: tuple[str, ...]
    unpinned_actions_after: tuple[str, ...]
    secrets_inherit_added: bool
    script_injection_added: tuple[str, ...]
    untrusted_checkout_added: bool
    effective_permissions_unknown: bool
    risk_flags: tuple[str, ...] = field(default_factory=tuple)

    @property
    def escalation(self) -> bool:
        """True when the change adds privilege or a dangerous pattern (GH-001 inputs)."""
        return bool(
            self.write_all_added
            or self.added_write_scopes
            or self.dangerous_triggers_added
            or self.untrusted_checkout_added
            or self.script_injection_added
            or self.secrets_inherit_added
        )

    def summary(self) -> str:
        bits: list[str] = []
        if self.write_all_added:
            bits.append(f"permissions: write-all added ({len(self.added_write_scopes)} write scopes)")
        elif self.added_write_scopes:
            shown = ", ".join(self.added_write_scopes[:6])
            more = len(self.added_write_scopes) - 6
            bits.append("write scopes added: " + shown + (f" (+{more} more)" if more > 0 else ""))
        if self.dangerous_triggers_added:
            bits.append("dangerous triggers added: " + ", ".join(self.dangerous_triggers_added))
        if self.untrusted_checkout_added:
            bits.append("privileged trigger checks out untrusted code")
        if self.unpinned_actions_added:
            bits.append(f"{len(self.unpinned_actions_added)} unpinned third-party action(s) added")
        if self.script_injection_added:
            bits.append("script injection pattern added")
        if self.secrets_inherit_added:
            bits.append("secrets: inherit added")
        if not bits:
            bits.append("no privilege increase detected")
        return f"Workflow {self.path} {self.change_type}: " + "; ".join(bits)

    def to_attributes(self) -> dict[str, Any]:
        """Event attributes (bounded scalars and scalar lists, see contracts.common)."""

        def lst(items: Iterable[str]) -> list[str]:
            return [_clip(item, 500) for item in list(items)[:MAX_EVIDENCE_ITEMS]]

        return {
            "change_type": self.change_type,
            "previous_path": self.previous_path,
            "analyzer_version": ANALYZER_VERSION,
            "repo_default_workflow_permissions": self.repo_default or "unknown",
            "permissions_before": self.permissions_before,
            "permissions_after": self.permissions_after,
            "write_scopes_before": lst(self.write_scopes_before),
            "write_scopes_after": lst(self.write_scopes_after),
            "write_all_added": self.write_all_added,
            "added_write_scopes": lst(self.added_write_scopes),
            "effective_permissions_unknown": self.effective_permissions_unknown,
            "triggers_before": lst(self.triggers_before),
            "triggers_after": lst(self.triggers_after),
            "triggers_added": lst(self.triggers_added),
            "triggers_removed": lst(self.triggers_removed),
            "dangerous_triggers_added": lst(self.dangerous_triggers_added),
            "unpinned_actions_added": lst(self.unpinned_actions_added),
            "unpinned_actions_after": lst(self.unpinned_actions_after),
            "secrets_inherit_added": self.secrets_inherit_added,
            "script_injection_added": lst(self.script_injection_added),
            "untrusted_checkout_added": self.untrusted_checkout_added,
            "parse_error_before": self.before.error if self.before is not None else None,
            "parse_error_after": self.after.error if self.after is not None else None,
            "risk_flags": lst(self.risk_flags),
        }


def compare_workflows(
    path: str,
    before: WorkflowAnalysis | None,
    after: WorkflowAnalysis | None,
    *,
    repo_default: RepoDefault | None,
    change_type: ChangeType,
    previous_path: str | None = None,
) -> WorkflowDelta:
    """Compare two versions of a workflow (``None`` = file absent at that version)."""
    before_ok = before if before is not None and before.ok else None
    after_ok = after if after is not None and after.ok else None
    eff_before = before_ok.effective_permissions(repo_default) if before_ok else None
    eff_after = after_ok.effective_permissions(repo_default) if after_ok else None
    write_before = eff_before.write_scopes if eff_before else ()
    write_after = eff_after.write_scopes if eff_after else ()
    triggers_before = before_ok.triggers if before_ok else ()
    triggers_after = after_ok.triggers if after_ok else ()
    added_triggers = tuple(t for t in triggers_after if t not in triggers_before)
    removed_triggers = tuple(t for t in triggers_before if t not in triggers_after)
    dangerous_added = tuple(t for t in added_triggers if t in PRIVILEGED_TRIGGERS)
    unpinned_before = set(before_ok.unpinned_third_party_actions) if before_ok else set()
    unpinned_after = after_ok.unpinned_third_party_actions if after_ok else ()
    unpinned_added = tuple(a for a in unpinned_after if a not in unpinned_before)
    write_all_added = bool(after_ok and after_ok.has_write_all) and not bool(
        before_ok and before_ok.has_write_all
    )
    added_scopes = tuple(s for s in write_after if s not in write_before)
    inherit_added = bool(after_ok and after_ok.secrets_inherit_jobs) and not bool(
        before_ok and before_ok.secrets_inherit_jobs
    )
    injections_before = set(before_ok.script_injections) if before_ok else set()
    injections_added = tuple(
        i for i in (after_ok.script_injections if after_ok else ()) if i not in injections_before
    )
    untrusted_added = bool(after_ok and after_ok.privileged_untrusted_checkout) and not bool(
        before_ok and before_ok.privileged_untrusted_checkout
    )
    unknown = bool(
        (eff_before is not None and eff_before.unknown)
        or (eff_after is not None and eff_after.unknown)
    )

    flags: list[str] = []
    if change_type == "added":
        flags.append("workflow_added")
    elif change_type == "removed":
        flags.append("workflow_removed")
    if write_all_added:
        flags.append("write_all_added")
    flags.extend(f"scope_escalation:{scope}" for scope in added_scopes)
    flags.extend(f"dangerous_trigger_added:{trigger}" for trigger in dangerous_added)
    if untrusted_added:
        flags.append("privileged_trigger_untrusted_checkout")
    if unpinned_added:
        flags.append("unpinned_third_party_action_added")
    if inherit_added:
        flags.append("secrets_inherit_added")
    if injections_added:
        flags.append("script_injection_added")
    if after_ok is not None:
        before_events = set(before_ok.event_expressions_in_run) if before_ok else set()
        if any(e not in before_events for e in after_ok.event_expressions_in_run):
            flags.append("github_event_expression_in_run_added")
        if after_ok.invalid_uses:
            flags.append("invalid_uses_reference")
        if after_ok.invalid_triggers:
            flags.append("invalid_triggers")
        if any(job.permissions.kind == "invalid" for job in after_ok.jobs) or (
            after_ok.permissions.kind == "invalid"
        ):
            flags.append("invalid_permissions")
        if after_ok.relies_on_default and repo_default == "write":
            flags.append("relies_on_repo_default_write")
    if (
        before_ok is not None
        and after_ok is not None
        and before_ok.permissions.kind != "unset"
        and after_ok.permissions.kind == "unset"
    ):
        flags.append("permissions_block_removed")
    if unknown:
        flags.append("effective_permissions_unknown")
    if after is not None and not after.ok:
        flags.append("workflow_unparseable")
    if before is not None and not before.ok:
        flags.append("baseline_unparseable")

    return WorkflowDelta(
        path=path,
        change_type=change_type,
        previous_path=previous_path,
        repo_default=repo_default,
        before=before,
        after=after,
        permissions_before=render_permissions(before, repo_default),
        permissions_after=render_permissions(after, repo_default),
        write_scopes_before=write_before,
        write_scopes_after=write_after,
        write_all_added=write_all_added,
        added_write_scopes=added_scopes,
        triggers_before=triggers_before,
        triggers_after=triggers_after,
        triggers_added=added_triggers,
        triggers_removed=removed_triggers,
        dangerous_triggers_added=dangerous_added,
        unpinned_actions_added=unpinned_added,
        unpinned_actions_after=unpinned_after,
        secrets_inherit_added=inherit_added,
        script_injection_added=injections_added,
        untrusted_checkout_added=untrusted_added,
        effective_permissions_unknown=unknown,
        risk_flags=tuple(flags),
    )


def is_workflow_path(path: str) -> bool:
    return bool(WORKFLOW_PATH_RE.match(path)) and ".." not in path.split("/")

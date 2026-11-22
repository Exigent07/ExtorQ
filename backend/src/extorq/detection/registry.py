"""Rule registry: load, validate and describe detection rules.

A rule is a YAML document ``rules/<domain>/<RULE-ID>.yaml`` plus the SQL file it
names. The YAML maps 1:1 onto :class:`extorq.contracts.alert.RuleMetadata`
(``query_sha256`` is computed by the loader, never written by hand) plus four
loader keys:

``query``            SQL file name, relative to the YAML file (must stay inside the rules root)
``summary_template`` deterministic alert summary, ``{placeholder}`` syntax (see templates.py)
``tests``            fixture-driven test cases used by ``extorq rules test``
``enabled``          optional, default ``true``; disabled rules are registered but never run

Validation (all problems are collected, not just the first): YAML shape, the
RuleMetadata contract, catalog membership of every required event type for its
source type, dedup/schedule coherence, SQL safety (sqlguard), declared params vs
SQL placeholders, test fixture paths, and unique rule ids.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import ValidationError

from extorq.contracts.alert import DedupStrategy, RuleMetadata
from extorq.contracts.catalog import EVENT_CATALOG
from extorq.detection.clients import ch_datetime
from extorq.detection.sqlguard import SqlCheck, check_rule_sql
from extorq.detection.templates import TemplateError, validate_template

MAX_RULE_FILE_BYTES = 64 * 1024
LOADER_KEYS = frozenset({"query", "summary_template", "tests", "enabled"})
METADATA_KEYS = frozenset(RuleMetadata.model_fields) - {"query_sha256"}
DEFAULT_SUMMARY_TEMPLATE = (
    "{rule_title} on {asset_id}: {event_count} matching events ({confidence} confidence)"
)
_REPO_RULES_DIR = Path(__file__).resolve().parents[4] / "rules"


@dataclass(frozen=True)
class RuleTestCase:
    """One fixture-driven test case declared under ``tests:`` in a rule YAML."""

    name: str
    fixture: Path
    expect: Literal["alert", "no_alert"]
    alerts: int | None = None
    confidence: str | None = None
    entities: dict[str, str] = field(default_factory=dict)
    now: datetime | None = None
    description: str = ""
    #: Expected alert feature values (exact JSON equality per key; lists in rule order).
    features: dict[str, Any] = field(default_factory=dict)
    #: Substrings every alert summary of the case must contain.
    summary_contains: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoadedRule:
    """A validated rule ready for evaluation."""

    metadata: RuleMetadata
    query_text: str
    yaml_path: Path
    query_path: Path
    summary_template: str
    enabled: bool
    tests: tuple[RuleTestCase, ...]
    #: SQL placeholder name -> normalised ClickHouse type (window params included).
    placeholders: dict[str, str]
    warnings: tuple[str, ...] = ()

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def version(self) -> str:
        return self.metadata.version

    @property
    def required_source_types(self) -> list[str]:
        return sorted({req.source_type.value for req in self.metadata.requires})

    def query_parameters(self, window_start: datetime, window_end: datetime) -> dict[str, Any]:
        """Server-side parameters for one evaluation (window bounds + declared params)."""
        params: dict[str, Any] = {
            "window_start": ch_datetime(window_start),
            "window_end": ch_datetime(window_end),
        }
        for name in self.placeholders:
            if name in params:
                continue
            if name == "bucket_seconds":
                params[name] = self.metadata.dedup.bucket_seconds
                continue
            params[name] = self.metadata.params[name]
        return params


@dataclass(frozen=True)
class RuleProblem:
    path: str
    rule_id: str | None
    message: str

    def __str__(self) -> str:
        prefix = f"{self.rule_id}: " if self.rule_id else ""
        return f"{self.path}: {prefix}{self.message}"


class RuleLoadError(Exception):
    def __init__(self, problems: list[RuleProblem]):
        self.problems = problems
        super().__init__("; ".join(str(p) for p in problems[:10]))


def resolve_rules_root(root: str | os.PathLike[str] | None = None) -> Path:
    """Find the rules directory: explicit path, ``EXTORQ_RULES_DIR``, CWD, or the repo copy."""
    candidates: list[Path] = []
    if root is not None:
        candidates.append(Path(root))
    env = os.environ.get("EXTORQ_RULES_DIR")
    if env:
        candidates.append(Path(env))
    candidates.extend([Path("rules"), _REPO_RULES_DIR])
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    raise FileNotFoundError(
        f"rules directory not found (tried: {', '.join(str(c) for c in candidates)})"
    )


def _discover(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*.yaml")):
        rel_parts = path.relative_to(root).parts
        if any(part.startswith(".") or part in {"tests", "fixtures"} for part in rel_parts[:-1]):
            continue
        found.append(path)
    return found


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _parse_tests(raw: Any, yaml_path: Path, root: Path, problems: list[str]) -> list[RuleTestCase]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        problems.append("tests must be a list")
        return []
    cases: list[RuleTestCase] = []
    names: set[str] = set()
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            problems.append(f"tests[{i}] must be a mapping")
            continue
        unknown = set(item) - {
            "name",
            "fixture",
            "expect",
            "alerts",
            "confidence",
            "entities",
            "now",
            "description",
            "features",
            "summary_contains",
        }
        if unknown:
            problems.append(f"tests[{i}] has unknown keys: {sorted(unknown)}")
        name = item.get("name")
        fixture = item.get("fixture")
        expect = item.get("expect")
        if not isinstance(name, str) or not name:
            problems.append(f"tests[{i}].name is required")
            continue
        if name in names:
            problems.append(f"duplicate test name {name}")
        names.add(name)
        if expect not in {"alert", "no_alert"}:
            problems.append(f"tests[{i}].expect must be 'alert' or 'no_alert'")
            continue
        if not isinstance(fixture, str) or not fixture:
            problems.append(f"tests[{i}].fixture is required")
            continue
        fixture_path = (yaml_path.parent / fixture).resolve()
        if not _inside(root, fixture_path):
            problems.append(f"tests[{i}].fixture escapes the rules root")
            continue
        if not fixture_path.is_file():
            problems.append(f"tests[{i}].fixture not found: {fixture}")
            continue
        alerts = item.get("alerts")
        if alerts is not None and (
            not isinstance(alerts, int) or isinstance(alerts, bool) or alerts < 0
        ):
            problems.append(f"tests[{i}].alerts must be a non-negative integer")
            continue
        if expect == "no_alert" and alerts not in (None, 0):
            problems.append(f"tests[{i}]: expect no_alert contradicts alerts={alerts}")
        confidence = item.get("confidence")
        if confidence is not None and confidence not in {"high", "medium", "low"}:
            problems.append(f"tests[{i}].confidence must be high|medium|low")
            continue
        entities = item.get("entities") or {}
        if not isinstance(entities, dict) or not all(isinstance(v, str) for v in entities.values()):
            problems.append(f"tests[{i}].entities must map strings to strings")
            continue
        features = item.get("features") or {}
        if not isinstance(features, dict) or not all(
            isinstance(k, str) and _is_feature_value(v) for k, v in features.items()
        ):
            problems.append(f"tests[{i}].features must map names to scalars or scalar lists")
            continue
        summary_raw = item.get("summary_contains") or []
        if isinstance(summary_raw, str):
            summary_raw = [summary_raw]
        if not isinstance(summary_raw, list) or not all(
            isinstance(x, str) and x for x in summary_raw
        ):
            problems.append(f"tests[{i}].summary_contains must be a string or list of strings")
            continue
        now_raw = item.get("now")
        now: datetime | None = None
        if now_raw is not None:
            try:
                now = (
                    now_raw
                    if isinstance(now_raw, datetime)
                    else datetime.fromisoformat(str(now_raw))
                )
            except ValueError:
                problems.append(f"tests[{i}].now is not an ISO-8601 timestamp")
                continue
            if now.tzinfo is None:
                problems.append(f"tests[{i}].now must be timezone-aware")
                continue
            now = now.astimezone(UTC)
        cases.append(
            RuleTestCase(
                name=name,
                fixture=fixture_path,
                expect=expect,
                alerts=alerts,
                confidence=confidence,
                entities={str(k): str(v) for k, v in entities.items()},
                now=now,
                description=str(item.get("description") or ""),
                features=dict(features),
                summary_contains=tuple(summary_raw),
            )
        )
    return cases


def _is_feature_value(value: Any) -> bool:
    scalar = (str, int, float, bool)
    if value is None or isinstance(value, scalar):
        return True
    return isinstance(value, list) and all(isinstance(v, scalar) for v in value)


def load_rule_file(yaml_path: Path, root: Path) -> tuple[LoadedRule | None, list[RuleProblem]]:
    """Load and validate one rule file. Returns ``(rule or None, problems)``."""
    problems: list[str] = []
    rel = str(yaml_path.relative_to(root)) if _inside(root, yaml_path) else str(yaml_path)
    rule_id: str | None = None

    def done() -> tuple[None, list[RuleProblem]]:
        return None, [RuleProblem(rel, rule_id, msg) for msg in problems]

    try:
        if yaml_path.stat().st_size > MAX_RULE_FILE_BYTES:
            problems.append(f"file exceeds {MAX_RULE_FILE_BYTES} bytes")
            return done()
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        problems.append(f"cannot read YAML: {type(exc).__name__}: {str(exc).splitlines()[0][:200]}")
        return done()
    if not isinstance(doc, dict):
        problems.append("rule YAML must be a mapping")
        return done()
    rule_id = doc.get("rule_id") if isinstance(doc.get("rule_id"), str) else None

    unknown = set(doc) - METADATA_KEYS - LOADER_KEYS
    if unknown:
        problems.append(f"unknown keys: {sorted(unknown)}")
    if "query_sha256" in doc:
        problems.append("query_sha256 is computed by the loader and must not be set")
    if rule_id and yaml_path.stem != rule_id:
        problems.append(f"file name {yaml_path.name} does not match rule_id {rule_id}")

    query_name = doc.get("query")
    query_path = Path()
    query_text = ""
    if not isinstance(query_name, str) or not query_name.endswith(".sql"):
        problems.append("query must name a .sql file next to the YAML")
    else:
        query_path = (yaml_path.parent / query_name).resolve()
        if not _inside(root, query_path):
            problems.append("query path escapes the rules root")
        elif not query_path.is_file():
            problems.append(f"query file not found: {query_name}")
        else:
            try:
                query_text = query_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                problems.append(f"cannot read query: {type(exc).__name__}")

    metadata_input = {k: v for k, v in doc.items() if k in METADATA_KEYS}
    metadata_input["query_sha256"] = hashlib.sha256(query_text.encode("utf-8")).hexdigest()
    metadata: RuleMetadata | None = None
    try:
        metadata = RuleMetadata.model_validate(metadata_input)
    except ValidationError as exc:
        for err in exc.errors()[:20]:
            loc = ".".join(str(x) for x in err.get("loc", ()))
            problems.append(f"metadata {loc}: {err.get('msg')}")

    sql_check = SqlCheck()
    if metadata is not None:
        for req in metadata.requires:
            for event_type in req.event_types:
                spec = EVENT_CATALOG.get(event_type)
                if spec is None:
                    problems.append(f"requires: unknown event type {event_type}")
                elif req.source_type not in spec.sources:
                    source = req.source_type.value
                    problems.append(f"requires: catalog says {source} does not emit {event_type}")
        if all(req.optional for req in metadata.requires):
            problems.append("requires: at least one telemetry requirement must be non-optional")
        if (
            metadata.dedup.strategy is DedupStrategy.WINDOW_BUCKET
            and metadata.dedup.bucket_seconds is None
        ):
            problems.append("dedup: window_bucket requires bucket_seconds")
        if (
            metadata.dedup.strategy is DedupStrategy.EVENT
            and metadata.dedup.bucket_seconds is not None
        ):
            problems.append("dedup: event strategy must not set bucket_seconds")
        schedule = metadata.schedule
        window = metadata.params.get("window_seconds")
        min_lookback = schedule.interval_seconds + (window if isinstance(window, int) else 0)
        if schedule.lookback_seconds < min_lookback:
            problems.append(
                f"schedule: lookback_seconds ({schedule.lookback_seconds}) must cover interval + "
                f"params.window_seconds ({min_lookback}) or evaluations leave gaps"
            )
        if query_text:
            reserved = {}
            if metadata.dedup.strategy is DedupStrategy.WINDOW_BUCKET:
                reserved = {"bucket_seconds": "UInt32"}
            sql_check = check_rule_sql(query_text, metadata.params, reserved=reserved)
            problems.extend(f"sql: {err}" for err in sql_check.errors)
            expected_column = (
                "bucket_start"
                if metadata.dedup.strategy is DedupStrategy.WINDOW_BUCKET
                else "signature"
            )
            if expected_column not in query_text:
                strategy = metadata.dedup.strategy.value
                problems.append(f"sql: {strategy} rules must return a {expected_column} column")

    template = doc.get("summary_template", DEFAULT_SUMMARY_TEMPLATE)
    if not isinstance(template, str):
        problems.append("summary_template must be a string")
        template = DEFAULT_SUMMARY_TEMPLATE
    else:
        try:
            validate_template(template)
        except TemplateError as exc:
            problems.append(f"summary_template: {exc}")

    enabled = doc.get("enabled", True)
    if not isinstance(enabled, bool):
        problems.append("enabled must be a boolean")
        enabled = True

    tests = _parse_tests(doc.get("tests"), yaml_path, root, problems)

    if problems or metadata is None:
        return done()
    return (
        LoadedRule(
            metadata=metadata,
            query_text=query_text,
            yaml_path=yaml_path.resolve(),
            query_path=query_path,
            summary_template=template,
            enabled=enabled,
            tests=tuple(tests),
            placeholders=dict(sql_check.placeholders),
            warnings=tuple(sql_check.warnings),
        ),
        [],
    )


def load_rules_report(
    root: str | os.PathLike[str] | None = "rules",
) -> tuple[list[LoadedRule], list[RuleProblem]]:
    """Load every rule under ``root``; return valid rules and all problems found."""
    root_path = resolve_rules_root(root)
    rules: list[LoadedRule] = []
    problems: list[RuleProblem] = []
    seen: dict[str, Path] = {}
    for path in _discover(root_path):
        rule, rule_problems = load_rule_file(path, root_path)
        problems.extend(rule_problems)
        if rule is None:
            continue
        if rule.rule_id in seen:
            problems.append(
                RuleProblem(
                    str(path.relative_to(root_path)),
                    rule.rule_id,
                    f"duplicate rule_id (also in {seen[rule.rule_id].name})",
                )
            )
            continue
        seen[rule.rule_id] = path
        rules.append(rule)
    if not rules and not problems:
        problems.append(RuleProblem(str(root_path), None, "no rules found"))
    return rules, problems


def load_rules(
    root: str | os.PathLike[str] | None = "rules", *, strict: bool = True
) -> list[LoadedRule]:
    """Load all rules. ``strict`` raises :class:`RuleLoadError` if any rule is invalid."""
    rules, problems = load_rules_report(root)
    if problems and strict:
        raise RuleLoadError(problems)
    return rules

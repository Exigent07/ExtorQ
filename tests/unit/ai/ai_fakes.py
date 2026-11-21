"""Shared fakes and builders for AI tests. No network: both SDKs are replaced by fakes.

Every context used here is SYNTHETIC (``extorq.ai.synthetic`` / ``eval/jev/dataset.jsonl``).
Fake credentials are obviously fake strings; secret-shaped test values are assembled at
runtime so secret scanners never see a contiguous token in the source.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from extorq.ai import settings as ai_settings
from extorq.ai._compat import reset_optional_cache
from extorq.ai.settings import AISettings, KeyState, ProviderKey
from extorq.ai.synthetic import VM_ASSET, CaseSpec, Ev, cov, make_context
from extorq.contracts.alert import EvidenceConfidence
from extorq.contracts.catalog import SourceType
from extorq.contracts.common import Outcome
from extorq.contracts.context import InvestigationContext, RelationshipBasis, RelationshipType

REPO_ROOT = Path(__file__).resolve().parents[3]
DATASET = REPO_ROOT / "eval" / "jev" / "dataset.jsonl"
FAKE_JEV_KEY = "jev-test-key-0000000000000000"  # synthetic test credential
FAKE_GEMINI_KEY = "gemini-test-key-111111111111"  # synthetic test credential

_AI_ENV = [
    "EXTORQ_JEV_ENABLED",
    "EXTORQ_GEMINI_ENABLED",
    "EXTORQ_JEV_MODEL",
    "EXTORQ_GEMINI_MODEL",
    "JEV_API_KEY",
    "JEV_API_KEY_FILE",
    "GEMINI_API_KEY",
    "GEMINI_API_KEY_FILE",
    "EXTORQ_JEV_API_KEY",
    "EXTORQ_GEMINI_API_KEY",
    "TYPESAFE_API_KEY",
    "GOOGLE_API_KEY",
]


def isolate_ai_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Never read the developer's .env or real keys in tests."""
    for name in _AI_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EXTORQ_AI_DOTENV", str(tmp_path / "no-such.env"))
    monkeypatch.setattr(ai_settings, "_platform_key", lambda name: None)
    ai_settings.get_ai_settings.cache_clear()
    ai_settings.get_provider_key.cache_clear()
    reset_optional_cache()
    yield
    ai_settings.get_ai_settings.cache_clear()
    ai_settings.get_provider_key.cache_clear()
    reset_optional_cache()


def enabled_settings(**overrides: Any) -> AISettings:
    base: dict[str, Any] = {"jev_enabled": True, "gemini_enabled": True}
    base.update(overrides)
    return AISettings(**base)


def jev_key() -> ProviderKey:
    return ProviderKey("JEV_API_KEY", KeyState.CONFIGURED, SecretStr(FAKE_JEV_KEY), "env")


def gemini_key() -> ProviderKey:
    return ProviderKey("GEMINI_API_KEY", KeyState.CONFIGURED, SecretStr(FAKE_GEMINI_KEY), "env")


def load_dataset_records() -> list[dict[str, Any]]:
    lines = DATASET.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


# ── custom synthetic contexts ─────────────────────────────────────────


def ssh_context(
    *,
    actor: str = "deploy",
    summary_text: str | None = None,
    extra_fields: dict[str, Any] | None = None,
    alert_summary: str = "6 failed SSH authentication connections from 203.0.113.9",
    entities: dict[str, str] | None = None,
    alert_features: dict[str, Any] | None = None,
    context_features: dict[str, Any] | None = None,
    related_summary: str = "GET /login -> 401 (curl/8.5)",
    related_fields: dict[str, Any] | None = None,
    explanation: str = "same source IP on the same host within the window",
    evidence_count: int = 6,
    case_id: str = "TEST-SSH",
) -> InvestigationContext:
    """A small SYNTHETIC VM-001 context whose free-text fields can be replaced (injection tests)."""
    ip = "203.0.113.9"
    events = [
        Ev(
            f"f{i}",
            i * 10,
            "auth.ssh.login_failed",
            SourceType.LINUX_JOURNALD,
            Outcome.FAILURE,
            summary_text or f"sshd: Failed password for {actor} from {ip} port {40000 + i} ssh2",
            actor=actor,
            src_ip=ip,
            evidence=True,
            fields={"auth_method": "password", "src_port": 40000 + i, **(extra_fields or {})},
        )
        for i in range(evidence_count)
    ]
    events.append(
        Ev(
            "h1",
            -60,
            "http.request",
            SourceType.LINUX_NGINX,
            Outcome.FAILURE,
            related_summary,
            src_ip=ip,
            fields={"http_method": "GET", "http_route": "/login", **(related_fields or {})},
            rel=RelationshipType.CANDIDATE,
            bases=(RelationshipBasis.SHARED_SOURCE_IP, RelationshipBasis.SAME_ASSET_TIME_WINDOW),
            explanation=explanation,
        )
    )
    spec = CaseSpec(
        case_id,
        "ssh_http",
        "priority_investigation",
        "SYNTHETIC unit-test case",
        "VM-001",
        VM_ASSET,
        EvidenceConfidence.HIGH,
        f"linux:lab-vm-01|{ip}",
        entities if entities is not None else {"src_ip": ip},
        alert_summary,
        events,
        alert_features=alert_features or {"failed_attempts": evidence_count},
        context_features=context_features or {"success_after_failures": False},
        coverage=[cov(SourceType.LINUX_JOURNALD), cov(SourceType.LINUX_NGINX)],
    )
    return make_context(spec)


# ── Jev fakes ─────────────────────────────────────────────────────────


@dataclass
class FakeNoul:
    noul: float
    type: str = "noul"


@dataclass
class FakeChoice:
    choice: str
    confidence: float
    probabilities: dict[str, float]
    type: str = "choice"


@dataclass
class FakeUsage:
    input_tokens: int | None = 1234
    output_tokens: int | None = 12


@dataclass
class FakeJevResponse:
    answers: dict[str, Any]
    model: str = "jev-1.14.0"
    usage: FakeUsage = field(default_factory=FakeUsage)
    request_id: str = "req_test_123"


PRIORITY_LABELS = ["priority_investigation", "routine_review", "likely_benign_maintenance"]


def choice(label: str, conf: float = 0.8) -> FakeChoice:
    rest = (1.0 - conf) / 2
    return FakeChoice(
        label, conf, {lbl: (conf if lbl == label else rest) for lbl in PRIORITY_LABELS}
    )


def jev_answers(
    *,
    sc: float = 0.9,
    pa: str | FakeChoice = "priority_investigation",
    pb: str | FakeChoice = "priority_investigation",
    mc: float = 0.1,
    ji: float = 0.8,
    domain: dict[str, float] | None = None,
) -> dict[str, Any]:
    answers: dict[str, Any] = {
        "sufficient_context": FakeNoul(sc),
        "priority_a": choice(pa) if isinstance(pa, str) else pa,
        "priority_b": choice(pb) if isinstance(pb, str) else pb,
        "maintenance_consistent": FakeNoul(mc),
        "joint_investigation": FakeNoul(ji),
    }
    for name, value in (domain or {}).items():
        answers[name] = FakeNoul(value)
    return answers


class FakeJevClient:
    def __init__(self, respond: Callable[[Any, dict[str, Any]], Any]) -> None:
        self.respond = respond
        self.calls: list[dict[str, Any]] = []

    def system_one(self, state: Any, questions: Any, **kwargs: Any) -> Any:
        self.calls.append({"state": state, "questions": dict(questions), "kwargs": kwargs})
        return self.respond(state, dict(questions))


COMMON_QUESTIONS = {
    "sufficient_context",
    "priority_a",
    "priority_b",
    "maintenance_consistent",
    "joint_investigation",
}


def domain_answers_for(questions: dict[str, Any], value: float = 0.5) -> dict[str, float]:
    return {name: value for name in questions if name not in COMMON_QUESTIONS}


def answering_client(**answer_kwargs: Any) -> FakeJevClient:
    """Fake Jev client answering every question set (domain Nouls get ``domain_value``)."""
    domain_value = answer_kwargs.pop("domain_value", 0.5)

    def respond(state: Any, questions: dict[str, Any]) -> FakeJevResponse:
        answers = jev_answers(domain=domain_answers_for(questions, domain_value), **answer_kwargs)
        return FakeJevResponse(answers)

    return FakeJevClient(respond)


# ── Gemini fakes ──────────────────────────────────────────────────────


@dataclass
class FakeUsageMeta:
    prompt_token_count: int | None = 2000
    candidates_token_count: int | None = 500
    thoughts_token_count: int | None = 100


@dataclass
class FakeFinish:
    value: str


@dataclass
class FakeCandidate:
    finish_reason: Any = field(default_factory=lambda: FakeFinish("STOP"))


@dataclass
class FakeGeminiResponse:
    text: str | None
    usage_metadata: FakeUsageMeta = field(default_factory=FakeUsageMeta)
    model_version: str | None = "gemini-3.6-flash"
    response_id: str | None = "resp_test_456"
    candidates: list[FakeCandidate] = field(default_factory=lambda: [FakeCandidate()])
    prompt_feedback: Any = None


class _FakeModels:
    def __init__(self, owner: FakeGeminiClient) -> None:
        self.owner = owner

    def generate_content(self, *, model: str, contents: Any, config: Any) -> Any:
        self.owner.calls.append({"model": model, "contents": contents, "config": config})
        return self.owner.respond(contents, config)


class FakeGeminiClient:
    def __init__(self, respond: Callable[[Any, Any], Any]) -> None:
        self.respond = respond
        self.calls: list[dict[str, Any]] = []
        self.models = _FakeModels(self)


def summary_json(
    evidence_ids: list[str],
    *,
    extra_ids: list[str] | None = None,
    steps: list[str] | None = None,
    text: str = "Six failed SSH logins came from 203.0.113.9.",
) -> str:
    """A schema-valid model reply citing ``evidence_ids`` (+ ``extra_ids``)."""
    cited = evidence_ids[:2] + (extra_ids or [])
    return json.dumps(
        {
            "what_happened": [{"text": text, "evidence_ids": cited}],
            "timeline": [
                {
                    "time": "2026-11-20T10:00:00.000Z",
                    "description": "First failure.",
                    "evidence_ids": evidence_ids[:1],
                }
            ],
            "why_rule_fired": {
                "text": "Five or more failed connections from one source.",
                "evidence_ids": evidence_ids[:1],
            },
            "related_activity": [{"text": "No related activity was cited.", "evidence_ids": []}],
            "benign_explanations": ["A misconfigured client could cause this."],
            "missing_information": ["Whether the source address is known."],
            "limitations": ["Only journald data was available."],
            "recommended_next_steps": steps
            if steps is not None
            else ["Review other logins from 203.0.113.9."],
            "overall_confidence": "medium",
        }
    )


# ── ClickHouse fake ───────────────────────────────────────────────────


@dataclass
class FakeResult:
    result_rows: list[tuple[Any, ...]]


class FakeClickHouse:
    """Records inserts; answers queries through ``handler(sql, parameters) -> rows``."""

    def __init__(
        self, handler: Callable[[str, dict[str, Any]], list[tuple[Any, ...]]] | None = None
    ) -> None:
        self.handler = handler or (lambda sql, params: [])
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.inserts: list[dict[str, Any]] = []
        self.fail_inserts = False
        self.fail_queries = False

    def query(
        self, sql: str, parameters: dict[str, Any] | None = None, **kwargs: Any
    ) -> FakeResult:
        params = dict(parameters or {})
        self.queries.append((sql, params))
        if self.fail_queries:
            raise ConnectionError("synthetic query failure")
        return FakeResult(self.handler(sql, params))

    def insert(
        self,
        table: str,
        data: list[list[Any]],
        column_names: list[str],
        database: str = "",
        **kw: Any,
    ) -> None:
        if self.fail_inserts:
            raise ConnectionError("synthetic insert failure")
        self.inserts.append(
            {"table": table, "database": database, "columns": list(column_names), "rows": data}
        )

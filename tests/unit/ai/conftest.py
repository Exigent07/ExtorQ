"""Shared fixtures for AI unit tests. No network: both SDKs are replaced by fakes."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from extorq.ai import settings as ai_settings
from extorq.ai.settings import AISettings, KeyState, ProviderKey
from extorq.contracts.context import InvestigationContext
from pydantic import SecretStr

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


@pytest.fixture(autouse=True)
def _isolate_ai_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Never read the developer's .env or real keys in unit tests."""
    for name in _AI_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("EXTORQ_AI_DOTENV", str(tmp_path / "no-such.env"))
    monkeypatch.setattr(ai_settings, "_platform_key", lambda name: None)
    ai_settings.get_ai_settings.cache_clear()
    ai_settings.get_provider_key.cache_clear()
    yield
    ai_settings.get_ai_settings.cache_clear()
    ai_settings.get_provider_key.cache_clear()


def enabled_settings(**overrides: Any) -> AISettings:
    base: dict[str, Any] = {"jev_enabled": True, "gemini_enabled": True}
    base.update(overrides)
    return AISettings(**base)


def jev_key() -> ProviderKey:
    return ProviderKey("JEV_API_KEY", KeyState.CONFIGURED, SecretStr(FAKE_JEV_KEY), "env")


def gemini_key() -> ProviderKey:
    return ProviderKey("GEMINI_API_KEY", KeyState.CONFIGURED, SecretStr(FAKE_GEMINI_KEY), "env")


@pytest.fixture(scope="session")
def dataset_records() -> list[dict[str, Any]]:
    return [json.loads(line) for line in DATASET.read_text(encoding="utf-8").splitlines() if line]


@pytest.fixture(scope="session")
def contexts(dataset_records: list[dict[str, Any]]) -> dict[str, InvestigationContext]:
    return {r["case_id"]: InvestigationContext.model_validate(r["context"]) for r in dataset_records}


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


def choice(label: str, conf: float = 0.8) -> FakeChoice:
    labels = ["priority_investigation", "routine_review", "likely_benign_maintenance"]
    rest = (1.0 - conf) / 2
    return FakeChoice(label, conf, {lbl: (conf if lbl == label else rest) for lbl in labels})


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


def domain_answers_for(questions: dict[str, Any], value: float = 0.5) -> dict[str, float]:
    common = {"sufficient_context", "priority_a", "priority_b", "maintenance_consistent", "joint_investigation"}
    return {name: value for name in questions if name not in common}


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


# ── ClickHouse fake ───────────────────────────────────────────────────


@dataclass
class FakeResult:
    result_rows: list[tuple[Any, ...]]


class FakeClickHouse:
    """Records inserts; answers queries through ``handler(sql, parameters) -> rows``."""

    def __init__(self, handler: Callable[[str, dict[str, Any]], list[tuple[Any, ...]]] | None = None) -> None:
        self.handler = handler or (lambda sql, params: [])
        self.queries: list[tuple[str, dict[str, Any]]] = []
        self.inserts: list[dict[str, Any]] = []
        self.fail_inserts = False

    def query(self, sql: str, parameters: dict[str, Any] | None = None, **kwargs: Any) -> FakeResult:
        params = dict(parameters or {})
        self.queries.append((sql, params))
        return FakeResult(self.handler(sql, params))

    def insert(self, table: str, data: list[list[Any]], column_names: list[str], database: str = "", **kw: Any) -> None:
        if self.fail_inserts:
            raise ConnectionError("synthetic insert failure")
        self.inserts.append({"table": table, "database": database, "columns": list(column_names), "rows": data})

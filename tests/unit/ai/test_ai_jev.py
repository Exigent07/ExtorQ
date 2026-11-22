"""Jev triage provider: question sets, deterministic post-processing, failure mapping.

Unit tests only: the TypeSafe SDK client is replaced by a fake; SDK exception classes
are the real ones (constructed locally, no network).
"""

from __future__ import annotations

from typing import Any

import httpx2
import pytest
from ai_fakes import (
    FAKE_JEV_KEY,
    FakeChoice,
    FakeJevClient,
    FakeJevResponse,
    FakeNoul,
    FakeUsage,
    answering_client,
    choice,
    enabled_settings,
    jev_answers,
    jev_key,
    ssh_context,
)
from typesafe_sdk import (
    TypeSafeAPIConnectionError,
    TypeSafeAPIError,
    TypeSafeAPIResponseValidationError,
    TypeSafeAPITimeoutError,
    TypeSafeAuthenticationError,
    TypeSafeError,
    TypeSafeRateLimitError,
)

from extorq.ai.jev import (
    CONFIDENT_ABOVE,
    INSUFFICIENT_BELOW,
    JEV_BASE_URL,
    ORDER_A,
    ORDER_B,
    TRIAGE_PROMPT_VERSION,
    InvalidJevOutput,
    JevTriageProvider,
    classify_jev_error,
    decide,
    parse_answers,
    question_set,
)
from extorq.ai.projection import Domain
from extorq.ai.settings import AISettings, KeyState, ProviderKey
from extorq.contracts.ai import AIProvider, AIStatus, AITask, JevAnswer, TriageRecommendation
from extorq.contracts.context import InvestigationContext

R = TriageRecommendation


# ── question sets ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("domain", "extra"),
    [
        (Domain.GITHUB, "change_appears_reviewed"),
        (Domain.SSH_HTTP, "coordinated_activity"),
        (Domain.K8S, "privilege_escalation_attempt"),
        (Domain.GENERIC, None),
    ],
)
def test_question_set_variants(domain: Domain, extra: str | None) -> None:
    qs = question_set(domain)
    names = [q.name for q in qs.questions]
    assert names[:5] == [
        "sufficient_context",
        "priority_a",
        "priority_b",
        "maintenance_consistent",
        "joint_investigation",
    ]
    assert names[5:] == ([extra] if extra else [])
    assert qs.version.startswith(f"{TRIAGE_PROMPT_VERSION}:{domain.value}:")
    assert qs.version == question_set(domain).version  # deterministic fingerprint


def test_priority_asked_twice_with_reversed_option_order() -> None:
    qs = question_set(Domain.SSH_HTTP).by_name()
    assert qs["priority_a"].labels == ORDER_A
    assert qs["priority_b"].labels == ORDER_B
    assert tuple(reversed(ORDER_A)) == ORDER_B
    assert qs["priority_a"].instructions == qs["priority_b"].instructions


def test_questions_are_narrow_and_never_ask_for_arithmetic_or_text() -> None:
    forbidden = ("how many", "count", "calculate", "explain", "describe", "summari", "write")
    for domain in Domain:
        for q in question_set(domain).questions:
            text = q.instructions.lower()
            assert not any(word in text for word in forbidden), (q.name, text)
            assert q.kind in ("noul", "choice")


def test_questions_build_real_sdk_objects() -> None:
    from typesafe_sdk import Choice, Noul

    for q in question_set(Domain.K8S).questions:
        sdk = q.to_sdk()
        assert isinstance(sdk, Noul if q.kind == "noul" else Choice)
        wire = sdk.model_dump()
        assert wire["type"] == q.kind
        assert wire["instructions"] == q.instructions


# ── deterministic post-processing ─────────────────────────────────────


def _answers(**kwargs: Any) -> dict[str, JevAnswer]:
    qs = question_set(Domain.SSH_HTTP)
    domain = {"coordinated_activity": kwargs.pop("coordinated", 0.5)}
    return parse_answers(FakeJevResponse(jev_answers(domain=domain, **kwargs)), qs)


def _decide(**kwargs: Any) -> Any:
    has_related = kwargs.pop("has_related", True)
    return decide(_answers(**kwargs), question_set(Domain.SSH_HTTP), has_related=has_related)


def test_insufficient_context_below_threshold() -> None:
    result = _decide(sc=INSUFFICIENT_BELOW - 0.01)
    assert result.recommendation is R.INSUFFICIENT_CONTEXT
    assert "context_insufficient" in result.rationale_codes


def test_borderline_context_is_uncertain() -> None:
    result = _decide(sc=0.5, pa="priority_investigation", pb="priority_investigation")
    assert result.recommendation is R.PRIORITY_INVESTIGATION
    assert result.uncertain is True
    assert "context_borderline" in result.rationale_codes


def test_confident_consistent_answer() -> None:
    result = _decide(sc=0.95, mc=0.05, ji=0.9, coordinated=0.85)
    assert result.recommendation is R.PRIORITY_INVESTIGATION
    assert result.uncertain is False
    assert result.order_consistent is True
    assert result.question_set_version == question_set(Domain.SSH_HTTP).version
    for code in (
        "context_sufficient",
        "priority_order_consistent",
        "priority_priority_investigation",
        "maintenance_inconsistent",
        "joint_investigation_warranted",
        "coordinated_activity",
    ):
        assert code in result.rationale_codes
    assert len(result.answers) == 6


def test_order_sensitivity_marks_uncertain_and_resolves_cautiously() -> None:
    tie_a = FakeChoice(
        "priority_investigation",
        0.5,
        {"priority_investigation": 0.5, "routine_review": 0.0, "likely_benign_maintenance": 0.5},
    )
    tie_b = FakeChoice(
        "likely_benign_maintenance",
        0.5,
        {"priority_investigation": 0.5, "routine_review": 0.0, "likely_benign_maintenance": 0.5},
    )
    result = _decide(sc=0.9, pa=tie_a, pb=tie_b)
    assert result.order_consistent is False
    assert result.uncertain is True
    assert "priority_order_sensitive" in result.rationale_codes
    # Averaged tie resolves to the more cautious option.
    assert result.recommendation is R.PRIORITY_INVESTIGATION


def test_benign_requires_sufficient_context_and_maintenance_consistency() -> None:
    borderline = _decide(
        sc=0.6, mc=0.9, pa="likely_benign_maintenance", pb="likely_benign_maintenance"
    )
    assert borderline.recommendation is R.ROUTINE_REVIEW
    assert "benign_requires_sufficient_context" in borderline.rationale_codes
    conflict = _decide(
        sc=0.9, mc=0.2, pa="likely_benign_maintenance", pb="likely_benign_maintenance"
    )
    assert conflict.recommendation is R.ROUTINE_REVIEW
    assert conflict.uncertain is True
    assert "benign_conflicts_maintenance" in conflict.rationale_codes
    clean = _decide(sc=0.9, mc=0.9, pa="likely_benign_maintenance", pb="likely_benign_maintenance")
    assert clean.recommendation is R.LIKELY_BENIGN_MAINTENANCE
    assert clean.uncertain is False


def test_k8s_benign_conflicting_with_escalation_is_not_benign() -> None:
    qs = question_set(Domain.K8S)
    response = FakeJevResponse(
        jev_answers(
            sc=0.9,
            mc=0.9,
            pa="likely_benign_maintenance",
            pb="likely_benign_maintenance",
            domain={"privilege_escalation_attempt": CONFIDENT_ABOVE + 0.1},
        )
    )
    result = decide(parse_answers(response, qs), qs, has_related=False)
    assert result.recommendation is R.ROUTINE_REVIEW
    assert "benign_conflicts_privilege_escalation" in result.rationale_codes
    assert "privilege_escalation_likely" in result.rationale_codes


def test_priority_conflicting_with_maintenance_is_flagged() -> None:
    result = _decide(sc=0.9, mc=0.9)
    assert result.recommendation is R.PRIORITY_INVESTIGATION
    assert result.uncertain is True
    assert "priority_conflicts_maintenance" in result.rationale_codes


def test_joint_investigation_code_requires_related_observations() -> None:
    assert (
        "joint_investigation_warranted" not in _decide(ji=0.95, has_related=False).rationale_codes
    )


# ── output validation ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda a: a.pop("joint_investigation"), "missing_answer:joint_investigation"),
        (lambda a: a.__setitem__("sufficient_context", choice("routine_review")), "wrong_type"),
        (lambda a: a.__setitem__("sufficient_context", FakeNoul(1.5)), "out_of_range"),
        (lambda a: a.__setitem__("sufficient_context", FakeNoul(float("nan"))), "out_of_range"),
        (lambda a: a.__setitem__("maintenance_consistent", FakeNoul(True)), "non_numeric"),  # type: ignore[arg-type]
        (
            lambda a: a.__setitem__(
                "priority_a", FakeChoice("delete_everything", 0.9, {"delete_everything": 0.9})
            ),
            "unknown_choice",
        ),
        (
            lambda a: a.__setitem__(
                "priority_b", FakeChoice("routine_review", 0.9, {"routine_review": 7.0})
            ),
            "out_of_range",
        ),
    ],
)
def test_invalid_answers_are_rejected(mutate: Any, reason: str) -> None:
    answers = jev_answers(domain={"coordinated_activity": 0.5})
    mutate(answers)
    with pytest.raises(InvalidJevOutput, match=reason.split(":")[0]):
        parse_answers(FakeJevResponse(answers), question_set(Domain.SSH_HTTP))


# ── provider behaviour ────────────────────────────────────────────────


def _provider(client: Any, settings: AISettings | None = None) -> JevTriageProvider:
    return JevTriageProvider(
        settings or enabled_settings(), key=jev_key(), client_factory=lambda key, s: client
    )


def test_disabled_provider_makes_no_call() -> None:
    client = answering_client()
    provider = JevTriageProvider(AISettings(), key=jev_key(), client_factory=lambda key, s: client)
    assessment = provider.assess(ssh_context())
    assert assessment.status is AIStatus.DISABLED
    assert assessment.error == "EXTORQ_JEV_ENABLED is false"
    assert client.calls == []


def test_missing_key_is_reported_by_name_only() -> None:
    client = answering_client()
    provider = JevTriageProvider(
        enabled_settings(),
        key=ProviderKey("JEV_API_KEY", KeyState.MISSING),
        client_factory=lambda key, s: client,
    )
    assessment = provider.assess(ssh_context())
    assert assessment.status is AIStatus.DISABLED
    assert assessment.error == "JEV_API_KEY not configured"
    assert client.calls == []


def test_successful_assessment_records_provenance() -> None:
    ctx = ssh_context()
    client = answering_client(sc=0.95, mc=0.05, domain_value=0.8)
    assessment = _provider(client).assess(ctx, "system:ai-worker")
    assert assessment.status is AIStatus.OK
    assert assessment.provider is AIProvider.JEV
    assert assessment.task is AITask.TRIAGE
    assert assessment.prompt_version == TRIAGE_PROMPT_VERSION
    assert assessment.alert_id == ctx.alert_id
    assert assessment.context_id == ctx.context_id
    assert assessment.context_input_hash == ctx.input_hash
    assert assessment.model == "jev-1.14.0"
    assert assessment.input_tokens == 1234 and assessment.output_tokens == 12
    assert assessment.provider_request_id == "req_test_123"
    assert assessment.latency_ms is not None and assessment.latency_ms >= 0
    assert assessment.requested_by == "system:ai-worker"
    assert assessment.triage is not None
    assert assessment.triage.recommendation is R.PRIORITY_INVESTIGATION
    # One request with every question of the domain set; model pinned per call.
    (call,) = client.calls
    assert set(call["questions"]) == {q.name for q in question_set(Domain.SSH_HTTP).questions}
    assert call["kwargs"] == {"model": "jev-1.14.0"}
    assert isinstance(call["state"], dict)


def test_insufficient_context_status() -> None:
    assessment = _provider(answering_client(sc=0.1)).assess(ssh_context())
    assert assessment.status is AIStatus.INSUFFICIENT_CONTEXT
    assert assessment.triage is not None
    assert assessment.triage.recommendation is R.INSUFFICIENT_CONTEXT


def test_state_contains_no_configured_secret() -> None:
    ctx = ssh_context(
        summary_text=f"leaked {FAKE_JEV_KEY} in a log line",
        extra_fields={"message": f"upstream rejected {FAKE_JEV_KEY}"},
    )
    client = answering_client()
    _provider(client).assess(ctx)
    state_text = repr(client.calls[0]["state"])
    assert FAKE_JEV_KEY not in state_text
    assert "[REDACTED:configured_secret]" in state_text


def test_oversized_state_is_shrunk_to_configured_cap() -> None:
    ctx = ssh_context(evidence_count=60, summary_text="sshd " + "x" * 1500)
    client = answering_client()
    assessment = _provider(client, enabled_settings(jev_max_state_chars=6_000)).assess(ctx)
    assert assessment.status is AIStatus.OK
    import json

    assert len(json.dumps(client.calls[0]["state"], ensure_ascii=False)) <= 6_000


def test_invalid_output_keeps_usage_and_never_raises() -> None:
    def respond(state: Any, questions: dict[str, Any]) -> FakeJevResponse:
        return FakeJevResponse({"sufficient_context": FakeNoul(0.9)}, usage=FakeUsage(50, 3))

    assessment = _provider(FakeJevClient(respond)).assess(ssh_context())
    assert assessment.status is AIStatus.INVALID_OUTPUT
    assert assessment.triage is None
    assert assessment.input_tokens == 50
    assert assessment.error is not None and assessment.error.startswith("invalid_output")


def _headers(**values: str) -> httpx2.Headers:
    return httpx2.Headers(values)


@pytest.mark.parametrize(
    ("exc", "status", "error"),
    [
        (TypeSafeAPITimeoutError(10.0), AIStatus.TIMEOUT, "timeout"),
        (TypeSafeRateLimitError(429, {}, _headers()), AIStatus.RATE_LIMITED, "rate_limited (429)"),
        (
            TypeSafeAPIError(529, {}, _headers()),
            AIStatus.RATE_LIMITED,
            "provider_overloaded (529)",
        ),
        (
            TypeSafeAuthenticationError(401, {}, _headers()),
            AIStatus.ERROR,
            "authentication_failed (401)",
        ),
        (TypeSafeAPIError(413, {}, _headers()), AIStatus.ERROR, "request_too_large (413)"),
        (TypeSafeAPIError(422, {}, _headers()), AIStatus.ERROR, "request_rejected (422)"),
        (TypeSafeAPIError(500, {}, _headers()), AIStatus.ERROR, "api_error (500)"),
        (TypeSafeAPIConnectionError("boom"), AIStatus.ERROR, "connection_error"),
        (
            TypeSafeAPIResponseValidationError(200, {}, _headers(), "answers.x"),
            AIStatus.INVALID_OUTPUT,
            "response_schema_mismatch",
        ),
        (TypeSafeError("bad"), AIStatus.ERROR, "sdk_error (TypeSafeError)"),
        (RuntimeError("x"), AIStatus.ERROR, "unexpected_error (RuntimeError)"),
    ],
)
def test_sdk_errors_map_to_fixed_statuses(exc: BaseException, status: AIStatus, error: str) -> None:
    failure = classify_jev_error(exc)
    assert failure.status is status
    assert failure.error.startswith(error)


def test_request_id_taken_from_api_errors() -> None:
    exc = TypeSafeRateLimitError(429, {}, _headers(**{"x-typesafe-request-id": "req_abc<1>"}))
    assert classify_jev_error(exc).request_id == "req_abc1"


def test_provider_failures_never_raise_and_scrub_secrets() -> None:
    def respond(state: Any, questions: dict[str, Any]) -> Any:
        raise TypeSafeAPIError(500, {"detail": FAKE_JEV_KEY}, _headers())

    assessment = _provider(FakeJevClient(respond)).assess(ssh_context())
    assert assessment.status is AIStatus.ERROR
    assert FAKE_JEV_KEY not in assessment.model_dump_json()


def test_client_construction_failure_is_an_error_not_an_exception() -> None:
    def factory(key: str, settings: AISettings) -> Any:
        raise TypeSafeError("API key must contain only printable ASCII characters")

    provider = JevTriageProvider(enabled_settings(), key=jev_key(), client_factory=factory)
    assessment = provider.assess(ssh_context())
    assert assessment.status is AIStatus.ERROR
    assert assessment.error == "sdk_error (TypeSafeError)"


def test_input_preparation_failure_is_reported(contexts: dict[str, InvestigationContext]) -> None:
    client = answering_client()
    provider = _provider(client, enabled_settings(jev_max_state_chars=2_000))
    assessment = provider.assess(contexts["SSH-S1"])
    assert assessment.status is AIStatus.ERROR
    assert assessment.error == "input_preparation_failed (ValueError)"
    assert client.calls == []


def test_default_client_is_pinned_to_the_official_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from extorq.ai.jev import _default_client_factory

    monkeypatch.setenv("TYPESAFE_BASE_URL", "https://attacker.invalid")
    monkeypatch.setenv("TYPESAFE_DEFAULT_MODEL", "jev-latest")
    client = _default_client_factory(FAKE_JEV_KEY, enabled_settings())
    config = client._config  # type: ignore[attr-defined]
    assert config.base_url == JEV_BASE_URL
    assert config.default_model == "jev-1.14.0"
    assert FAKE_JEV_KEY not in repr(config)


def test_dataset_contexts_all_produce_valid_assessments(
    contexts: dict[str, InvestigationContext],
) -> None:
    client = answering_client(sc=0.8, mc=0.4, domain_value=0.6)
    provider = _provider(client)
    for ctx in contexts.values():
        assessment = provider.assess(ctx)
        assert assessment.status is AIStatus.OK
        assert AIAssessmentRoundTrip.ok(assessment)


class AIAssessmentRoundTrip:
    @staticmethod
    def ok(assessment: Any) -> bool:
        from extorq.contracts.ai import AIAssessment

        return AIAssessment.model_validate_json(assessment.model_dump_json()) == assessment

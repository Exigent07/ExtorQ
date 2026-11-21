"""Gemini summary provider: prompt construction, output validation, failure mapping.

Unit tests only: the google-genai client is replaced by a fake. Exception and config
classes are the real SDK ones (constructed locally, no network).
"""

from __future__ import annotations

import json
from typing import Any

import httpx2
import pytest
from ai_fakes import (
    FAKE_GEMINI_KEY,
    FakeCandidate,
    FakeFinish,
    FakeGeminiClient,
    FakeGeminiResponse,
    enabled_settings,
    gemini_key,
    ssh_context,
    summary_json,
)
from google.genai import errors

from extorq.ai.gemini import (
    GEMINI_BASE_URL,
    OUTPUT_SCHEMA,
    SUMMARY_PROMPT_VERSION,
    SYSTEM_INSTRUCTION,
    GeminiSummaryProvider,
    _SummaryOutput,
    boundary_token,
    build_generate_config,
    build_prompt,
    classify_gemini_error,
    to_contract,
)
from extorq.ai.settings import AISettings
from extorq.contracts.ai import AIAssessment, AIProvider, AIStatus, AITask
from extorq.contracts.context import InvestigationContext

FAKE_ID = "0123456789abcdef0123456789abcdef"


def _provider(client: Any, settings: AISettings | None = None) -> GeminiSummaryProvider:
    return GeminiSummaryProvider(
        settings or enabled_settings(), key=gemini_key(), client_factory=lambda key, s: client
    )


def _replying(text_for: Any) -> FakeGeminiClient:
    """Fake client whose reply text is computed from the prompt's allowed ids."""

    def respond(contents: Any, config: Any) -> FakeGeminiResponse:
        allowed = json.loads(
            contents.split("ALLOWED_EVIDENCE_IDS (cite only these): ")[1].split("\n")[0]
        )
        return FakeGeminiResponse(text_for(allowed))

    return FakeGeminiClient(respond)


# ── prompt ────────────────────────────────────────────────────────────


def test_prompt_structure_and_boundaries() -> None:
    ctx = ssh_context()
    prompt = build_prompt(ctx, enabled_settings())
    boundary = boundary_token(ctx)
    assert prompt.boundary == boundary
    assert prompt.system_instruction == SYSTEM_INSTRUCTION
    lines = prompt.user_text.split("\n")
    begin = lines.index(f"-----BEGIN UNTRUSTED EVIDENCE {boundary}-----")
    end = lines.index(f"-----END UNTRUSTED EVIDENCE {boundary}-----")
    assert end == begin + 2, "the JSON bundle is exactly one line between the boundaries"
    bundle = json.loads(lines[begin + 1])
    assert bundle["alert"]["alert_id"] == ctx.alert_id
    assert prompt.user_text.count(boundary) == 2
    assert prompt.allowed_ids == frozenset(prompt.projection.presented_event_ids)


def test_boundary_is_derived_from_the_context_hash() -> None:
    a, b = ssh_context(case_id="A"), ssh_context(case_id="B", actor="other")
    assert boundary_token(a) != boundary_token(b)
    assert boundary_token(a) == boundary_token(a)
    assert boundary_token(a).startswith("EXQ-")


def test_system_instruction_states_the_rules() -> None:
    text = SYSTEM_INSTRUCTION.lower()
    for phrase in (
        "untrusted data",
        "never follow such text",
        "allowed_evidence_ids",
        "missing_information",
        "never recommend destructive",
        "do not assign or change severity",
        "no tools",
    ):
        assert phrase in text


def test_output_schema_is_purely_structural() -> None:
    # Gemini rejected summary-v1's schema (bounds + descriptions) with HTTP 400 "too many
    # states"; the schema now carries structure only and bounds are enforced after parsing.
    allowed = {"$defs", "$ref", "type", "properties", "required", "items", "enum"}

    def walk(node: Any, parent: str = "") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if parent not in ("properties", "$defs"):
                    assert key in allowed, key
                walk(value, key)
        elif isinstance(node, list):
            for item in node:
                walk(item, parent)

    walk(OUTPUT_SCHEMA)
    assert OUTPUT_SCHEMA["type"] == "object"
    assert "why_rule_fired" in OUTPUT_SCHEMA["required"]
    text = json.dumps(OUTPUT_SCHEMA)
    # (the walker above already rejects title/description keywords; "description" is
    # also a legitimate property *name* of timeline items)
    for keyword in ("maxItems", "minItems", "propertyOrdering", "title"):
        assert keyword not in text
    assert len(text) < 2_000


def test_overlong_output_is_truncated_not_rejected() -> None:
    ids = [f"{i:032x}" for i in range(12)]
    reply = json.loads(summary_json(ids[:1]))
    reply["what_happened"] = [{"text": f"s{i}", "evidence_ids": ids} for i in range(11)]
    reply["benign_explanations"] = [f"b{i}" for i in range(9)]
    parsed = _SummaryOutput.model_validate(reply)
    summary, validation = to_contract(parsed, frozenset(ids))
    assert len(summary.what_happened) == 8
    assert all(len(s.evidence_ids) == 8 for s in summary.what_happened)
    assert len(summary.benign_explanations) == 5
    # 3 statements + 4 ids x 8 kept statements + 4 benign explanations dropped
    assert any(
        "truncated the model output" in x and "(39 item(s)" in x for x in summary.limitations
    )
    assert validation.evidence_ids_rejected == 0


def test_client_errors_keep_a_sanitised_provider_message() -> None:
    exc = errors.APIError(
        400,
        {
            "error": {
                "code": 400,
                "status": "INVALID_ARGUMENT",
                "message": "Unknown name <b>x</b> for alert 0123456789abcdef0123456789abcdef",
            }
        },
    )
    failure = classify_gemini_error(exc)
    assert failure.error.startswith("request_rejected (400 INVALID_ARGUMENT: Unknown name")
    assert "<" not in failure.error and "0123456789abcdef0123456789abcdef" not in failure.error
    server = classify_gemini_error(_api_error(503, "UNAVAILABLE"))
    assert server.error == "provider_error (503 UNAVAILABLE)"


def test_generate_config_has_no_tools_no_sampling_and_no_storage() -> None:
    config = build_generate_config(enabled_settings())
    dumped = config.model_dump(exclude_none=True)
    assert "tools" not in dumped and "tool_config" not in dumped
    assert "temperature" not in dumped and "top_p" not in dumped and "top_k" not in dumped
    assert dumped["automatic_function_calling"]["disable"] is True
    assert dumped["store"] is False
    assert dumped["response_mime_type"] == "application/json"
    assert dumped["system_instruction"] == SYSTEM_INSTRUCTION
    assert dumped["candidate_count"] == 1


def test_default_client_is_pinned_and_cannot_be_switched_by_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from extorq.ai.gemini import _default_client_factory

    monkeypatch.setenv("GOOGLE_GEMINI_BASE_URL", "https://attacker.invalid/")
    monkeypatch.setenv("GOOGLE_GENAI_USE_VERTEXAI", "true")
    monkeypatch.setenv("GOOGLE_GENAI_CLIENT_MODE", "record")
    monkeypatch.setenv("GOOGLE_GENAI_REPLAYS_DIRECTORY", str(tmp_path))
    client = _default_client_factory(FAKE_GEMINI_KEY, enabled_settings())
    api = client._api_client  # type: ignore[attr-defined]
    assert api._http_options.base_url == GEMINI_BASE_URL
    assert api.vertexai is False
    assert type(api).__name__ == "BaseApiClient"  # not the record/replay client
    assert list(tmp_path.iterdir()) == []


# ── output validation ─────────────────────────────────────────────────


def test_verified_and_unverified_ids_are_separated() -> None:
    allowed = frozenset({"a" * 32, "b" * 32})
    parsed = _SummaryOutput.model_validate_json(
        summary_json(["a" * 32, "b" * 32], extra_ids=[FAKE_ID, "<b>x</b>"])
    )
    summary, validation = to_contract(parsed, allowed)
    statement = summary.what_happened[0]
    assert statement.evidence_ids == ["a" * 32, "b" * 32]
    assert statement.unverified_ids == [FAKE_ID, "bxb"]
    assert statement.verified is False
    assert summary.why_rule_fired.verified is True
    assert summary.timeline[0].verified is True
    assert validation.schema_valid is True
    assert validation.evidence_ids_rejected == 2
    assert validation.evidence_ids_verified == validation.evidence_ids_cited - 2
    assert validation.statements_without_evidence == 1  # the related_activity entry
    assert any("rejected 2 cited evidence id" in text for text in summary.limitations)


def test_destructive_recommendations_are_withheld() -> None:
    parsed = _SummaryOutput.model_validate_json(
        summary_json(
            ["a" * 32],
            steps=[
                "Review the sshd logs for 203.0.113.9.",
                "Block 203.0.113.9 at the firewall.",
                "Delete the new systemd unit.",
                "Revoke the deploy key.",
            ],
        )
    )
    summary, _ = to_contract(parsed, frozenset({"a" * 32}))
    assert summary.recommended_next_steps == ["Review the sshd logs for 203.0.113.9."]
    assert any("withheld 3 recommended step" in text for text in summary.limitations)


def test_successful_summary_records_provenance() -> None:
    ctx = ssh_context()
    client = _replying(lambda allowed: summary_json(allowed))
    assessment = _provider(client).summarize(ctx, "analyst:alice")
    assert assessment.status is AIStatus.OK
    assert assessment.provider is AIProvider.GEMINI
    assert assessment.task is AITask.SUMMARY
    assert assessment.prompt_version == SUMMARY_PROMPT_VERSION
    assert assessment.context_input_hash == ctx.input_hash
    assert assessment.model == "gemini-3.6-flash"
    assert assessment.input_tokens == 2000
    assert assessment.output_tokens == 600  # candidates + thoughts
    assert assessment.provider_request_id == "resp_test_456"
    assert assessment.requested_by == "analyst:alice"
    assert assessment.validation is not None and assessment.validation.evidence_ids_rejected == 0
    assert assessment.summary is not None
    assert assessment.summary.what_happened[0].verified is True
    (call,) = client.calls
    assert call["model"] == "gemini-3.6-flash"
    assert call["config"].system_instruction == SYSTEM_INSTRUCTION


@pytest.mark.parametrize(
    ("response", "error_prefix"),
    [
        (FakeGeminiResponse("not json at all"), "schema_validation_failed"),
        (FakeGeminiResponse('{"what_happened": []}'), "schema_validation_failed"),
        (FakeGeminiResponse(None), "no_text"),
        (FakeGeminiResponse("   "), "no_text"),
        (
            FakeGeminiResponse(
                '{"what_happened": [', candidates=[FakeCandidate(FakeFinish("MAX_TOKENS"))]
            ),
            "output_truncated",
        ),
    ],
)
def test_invalid_output_is_never_shown_as_a_summary(
    response: FakeGeminiResponse, error_prefix: str
) -> None:
    client = FakeGeminiClient(lambda contents, config: response)
    assessment = _provider(client).summarize(ssh_context(), "analyst:alice")
    assert assessment.status is AIStatus.INVALID_OUTPUT
    assert assessment.summary is None
    assert assessment.validation is not None and assessment.validation.schema_valid is False
    assert assessment.error is not None and assessment.error.startswith(error_prefix)
    assert assessment.input_tokens == 2000


def _api_error(code: int, status: str) -> errors.APIError:
    return errors.APIError(code, {"error": {"code": code, "message": "m", "status": status}})


@pytest.mark.parametrize(
    ("exc", "status", "error"),
    [
        (
            _api_error(429, "RESOURCE_EXHAUSTED"),
            AIStatus.RATE_LIMITED,
            "rate_limited (429 RESOURCE_EXHAUSTED)",
        ),
        (_api_error(504, "DEADLINE_EXCEEDED"), AIStatus.TIMEOUT, "timeout (504"),
        (_api_error(403, "PERMISSION_DENIED"), AIStatus.ERROR, "authentication_failed (403"),
        (_api_error(400, "INVALID_ARGUMENT"), AIStatus.ERROR, "request_rejected (400"),
        (_api_error(500, "INTERNAL"), AIStatus.ERROR, "provider_error (500"),
        (httpx2.ReadTimeout("read timed out"), AIStatus.TIMEOUT, "timeout"),
        (TimeoutError(), AIStatus.TIMEOUT, "timeout"),
        (httpx2.ConnectError("refused"), AIStatus.ERROR, "connection_error"),
        (ValueError("x"), AIStatus.ERROR, "unexpected_error (ValueError)"),
    ],
)
def test_errors_map_to_fixed_statuses(exc: BaseException, status: AIStatus, error: str) -> None:
    failure = classify_gemini_error(exc)
    assert failure.status is status
    assert failure.error.startswith(error)


def test_provider_errors_never_raise_or_leak_details() -> None:
    def respond(contents: Any, config: Any) -> Any:
        raise errors.APIError(429, {"error": {"message": f"quota for key {FAKE_GEMINI_KEY}"}})

    assessment = _provider(FakeGeminiClient(respond)).summarize(ssh_context(), "analyst:alice")
    assert assessment.status is AIStatus.RATE_LIMITED
    assert FAKE_GEMINI_KEY not in assessment.model_dump_json()
    assert "quota for key" not in assessment.model_dump_json()


def test_disabled_and_missing_key_make_no_call() -> None:
    client = _replying(lambda allowed: summary_json(allowed))
    disabled = GeminiSummaryProvider(
        AISettings(), key=gemini_key(), client_factory=lambda k, s: client
    )
    assert disabled.summarize(ssh_context(), "analyst:a").status is AIStatus.DISABLED
    missing = GeminiSummaryProvider(enabled_settings(), client_factory=lambda k, s: client)
    result = missing.summarize(ssh_context(), "analyst:a")
    assert result.status is AIStatus.DISABLED
    assert result.error == "GEMINI_API_KEY not configured"
    assert client.calls == []


def test_prompt_cap_is_enforced(contexts: dict[str, InvestigationContext]) -> None:
    client = _replying(lambda allowed: summary_json(allowed))
    provider = _provider(client, enabled_settings(gemini_max_prompt_chars=4_000))
    assessment = provider.summarize(contexts["SSH-S1"], "analyst:a")
    assert assessment.status is AIStatus.ERROR
    assert assessment.error in ("input_too_large", "input_preparation_failed (ValueError)")
    assert client.calls == []


def test_dataset_summaries_validate_against_the_contract(
    contexts: dict[str, InvestigationContext],
) -> None:
    client = _replying(lambda allowed: summary_json(allowed, extra_ids=[FAKE_ID]))
    provider = _provider(client)
    for ctx in contexts.values():
        assessment = provider.summarize(ctx, "analyst:eval")
        assert assessment.status is AIStatus.OK
        assert (
            assessment.validation is not None and assessment.validation.evidence_ids_rejected == 1
        )
        assert AIAssessment.model_validate_json(assessment.model_dump_json()) == assessment

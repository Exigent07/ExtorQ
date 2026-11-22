"""TypeSafe Jev ("System One") triage provider: typed, bounded questions.

Jev answers narrow, atomic questions about a JSON state. It returns
probabilities (Noul) and option distributions (Choice); it never produces free
text. ExtorQ asks question set ``triage-v2`` (one variant per domain) and turns
the answers into a recommendation with a fixed, deterministic procedure:

* ``sufficient_context < 0.3``  -> ``insufficient_context`` (status
  ``insufficient_context``);
* ``0.3 <= sufficient_context <= 0.7`` -> ``uncertain`` (a human decides);
* ``priority`` is asked twice with opposite option orders (Choice answers lean
  towards the first option); disagreement -> ``order_consistent=False``,
  ``uncertain=True`` and the averaged distribution decides, ties resolving to
  the more cautious option;
* conflicts between answers never make the outcome *less* cautious: a benign
  recommendation requires clearly sufficient context and a consistent
  ``maintenance_consistent`` answer (and, for Kubernetes, no likely privilege
  escalation), otherwise it becomes ``routine_review``.

Jev is advisory only: it never changes severity, never suppresses and never
writes alerts. Counting, time arithmetic and rule logic stay deterministic: the
correlation features already computed by ExtorQ are part of the state instead.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Literal, Protocol, cast

from extorq.ai import transport
from extorq.ai._compat import get_logger
from extorq.ai.projection import JEV_LIMITS, Domain, Projection, project_context
from extorq.ai.sanitize import clean_token, redact_secrets
from extorq.ai.settings import AISettings, ProviderKey, get_ai_settings, get_provider_key
from extorq.contracts.ai import (
    AIAssessment,
    AIProvider,
    AIStatus,
    AITask,
    JevAnswer,
    JevTriageResult,
    TriageRecommendation,
)
from extorq.contracts.common import utc_now
from extorq.contracts.context import InvestigationContext
from extorq.contracts.identity import assessment_id

#: Identifies what the provider saw: the question set AND the projection format.
#: v2 (2026-11-22): evidence key fields reach Jev under canonical names and the evidence
#: sample covers every event type. On real contexts the v1 projection carried no evidence
#: key fields, so v1 assessments are never reused for a v2 request.
TRIAGE_PROMPT_VERSION = "triage-v2"
INSUFFICIENT_BELOW = 0.3
CONFIDENT_ABOVE = 0.7
#: HTTP statuses retried by the SDK (bounded by retries and the total retry budget).
RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504, 529})
#: Pinned API root. Passed explicitly so the SDK's ``TYPESAFE_BASE_URL`` environment
#: variable can never redirect requests (and the API key) to another host.
JEV_BASE_URL = "https://api.typesafe.ai"

_log = get_logger("extorq.ai.jev")

R = TriageRecommendation
PRIORITY_OPTIONS: dict[str, str] = {
    R.PRIORITY_INVESTIGATION.value: (
        "Plausibly malicious activity or a serious policy violation; investigate promptly."
    ),
    R.ROUTINE_REVIEW.value: (
        "Unusual or policy-relevant but not clearly malicious; review in the normal queue."
    ),
    R.LIKELY_BENIGN_MAINTENANCE.value: (
        "Consistent with expected maintenance, routine automation, or authorised administration."
    ),
}
ORDER_A: tuple[str, ...] = (
    R.PRIORITY_INVESTIGATION.value,
    R.ROUTINE_REVIEW.value,
    R.LIKELY_BENIGN_MAINTENANCE.value,
)
ORDER_B: tuple[str, ...] = tuple(reversed(ORDER_A))
#: Tie-break order: more cautious first.
_CAUTION = {name: rank for rank, name in enumerate(ORDER_A)}

_DOMAIN_CONTEXT: dict[Domain, str] = {
    Domain.GITHUB: (
        "The alert concerns a change to a GitHub Actions workflow in a monitored repository."
    ),
    Domain.SSH_HTTP: (
        "The alert concerns SSH authentication activity on a Linux host, possibly with related "
        "HTTP requests to services on the same host."
    ),
    Domain.K8S: (
        "The alert concerns Kubernetes API activity related to privileges: pods requesting "
        "privileged or host access, or RBAC roles and bindings."
    ),
    Domain.GENERIC: "The alert concerns security-relevant activity on a monitored asset.",
}


@dataclass(frozen=True)
class QuestionSpec:
    name: str
    kind: Literal["noul", "choice"]
    instructions: str
    #: Ordered (label, description). Noul labels are "true"/"false".
    criteria: tuple[tuple[str, str], ...]

    @property
    def labels(self) -> tuple[str, ...]:
        return tuple(label for label, _ in self.criteria)

    def as_wire(self) -> dict[str, Any]:
        """The exact JSON form sent to the API (also used for the fingerprint)."""
        return {
            "type": self.kind,
            "instructions": self.instructions,
            "criteria": dict(self.criteria),
        }

    def to_sdk(self) -> Any:
        from typesafe_sdk import Choice, Noul

        criteria = dict(self.criteria)
        if self.kind == "noul":
            return Noul(
                instructions=self.instructions,
                criteria={"true": criteria["true"], "false": criteria["false"]},
            )
        return Choice(instructions=self.instructions, criteria=criteria)


@dataclass(frozen=True)
class QuestionSet:
    domain: Domain
    questions: tuple[QuestionSpec, ...]

    @property
    def fingerprint(self) -> str:
        wire = [[q.name, q.as_wire()] for q in self.questions]
        material = json.dumps(wire, sort_keys=False, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]

    @property
    def version(self) -> str:
        return f"{TRIAGE_PROMPT_VERSION}:{self.domain.value}:{self.fingerprint}"

    def by_name(self) -> dict[str, QuestionSpec]:
        return {q.name: q for q in self.questions}


def _noul(name: str, instructions: str, true: str, false: str) -> QuestionSpec:
    return QuestionSpec(name, "noul", instructions, (("true", true), ("false", false)))


def _priority(name: str, domain: Domain, order: tuple[str, ...]) -> QuestionSpec:
    return QuestionSpec(
        name,
        "choice",
        f"{_DOMAIN_CONTEXT[domain]} Based on the deterministic detection and its surrounding "
        "context, how should a security analyst prioritise this alert?",
        tuple((label, PRIORITY_OPTIONS[label]) for label in order),
    )


def question_set(domain: Domain) -> QuestionSet:
    """Question set ``triage-v2`` for ``domain`` (common questions + domain Noul)."""
    lead = _DOMAIN_CONTEXT[domain]
    questions: list[QuestionSpec] = [
        _noul(
            "sufficient_context",
            f"{lead} Does the state contain enough information to make a contextual triage "
            "judgment about this alert?",
            "The state shows what happened, who or what performed it, on which asset, and enough "
            "surrounding activity or context to judge whether it is expected.",
            "Important information is missing or unreliable (for example telemetry gaps, stale "
            "sources, unmonitored services involved in the activity, an unknown actor, or no "
            "surrounding context), so a judgment would be guesswork.",
        ),
        _priority("priority_a", domain, ORDER_A),
        _priority("priority_b", domain, ORDER_B),
        _noul(
            "maintenance_consistent",
            f"{lead} Is the activity consistent with planned maintenance, routine automation, or "
            "authorised administration?",
            "The actors, timing and changes match routine maintenance, known automation, or "
            "authorised administrative work.",
            "The activity does not match routine maintenance or authorised administration, or it "
            "shows signs of misuse.",
        ),
        _noul(
            "joint_investigation",
            "Do the related observations in the state (beyond the triggering evidence) warrant "
            "investigating them together with this alert?",
            "The related observations plausibly belong to the same activity and would inform the "
            "investigation.",
            "There are no related observations, or they look unrelated or merely coincidental.",
        ),
    ]
    if domain is Domain.GITHUB:
        questions.append(
            _noul(
                "change_appears_reviewed",
                "Does the workflow change appear to have been reviewed before it landed?",
                "The state shows signs of review, such as a merged pull request with an approving "
                "review.",
                "The state shows no sign of review, such as a direct push to the default "
                "branch, or review information is absent.",
            )
        )
    elif domain is Domain.SSH_HTTP:
        questions.append(
            _noul(
                "coordinated_activity",
                "Do the SSH authentication activity and the HTTP activity in the state look like "
                "one coordinated sequence from the same source?",
                "The same source appears to probe or attack several services as part of one "
                "sequence.",
                "The SSH and HTTP activity look independent, or one of them is absent.",
            )
        )
    elif domain is Domain.K8S:
        questions.append(
            _noul(
                "privilege_escalation_attempt",
                "Does the Kubernetes activity represent an attempt to obtain elevated privileges?",
                "The activity seeks elevated access, such as privileged or host-access pods, "
                "binding powerful roles like cluster-admin, or wildcard permissions.",
                "The activity does not seek elevated access, or it is a narrowly scoped, expected "
                "permission change.",
            )
        )
    return QuestionSet(domain, tuple(questions))


# ── deterministic post-processing ─────────────────────────────────────


def _combine(a: JevAnswer, b: JevAnswer) -> str:
    labels = ORDER_A
    scores = {
        label: (a.probabilities.get(label, 0.0) + b.probabilities.get(label, 0.0)) / 2
        for label in labels
    }
    return min(labels, key=lambda label: (-scores[label], _CAUTION[label]))


def decide(
    answers: Mapping[str, JevAnswer], qs: QuestionSet, *, has_related: bool
) -> JevTriageResult:
    """Deterministic mapping from validated Jev answers to a triage result."""
    sc = float(answers["sufficient_context"].value)
    pa, pb = answers["priority_a"], answers["priority_b"]
    mc = float(answers["maintenance_consistent"].value)
    ji = float(answers["joint_investigation"].value)
    codes: list[str] = []
    order_consistent = pa.value == pb.value
    uncertain = not order_consistent

    if sc < INSUFFICIENT_BELOW:
        recommendation = R.INSUFFICIENT_CONTEXT
        codes.append("context_insufficient")
    else:
        if sc <= CONFIDENT_ABOVE:
            uncertain = True
            codes.append("context_borderline")
        else:
            codes.append("context_sufficient")
        if order_consistent:
            chosen = str(pa.value)
            codes.append("priority_order_consistent")
        else:
            chosen = _combine(pa, pb)
            codes.append("priority_order_sensitive")
        recommendation = R(chosen)
        codes.append(f"priority_{chosen}")

        escalation = answers.get("privilege_escalation_attempt")
        if recommendation is R.LIKELY_BENIGN_MAINTENANCE:
            if sc <= CONFIDENT_ABOVE:
                recommendation = R.ROUTINE_REVIEW
                uncertain = True
                codes.append("benign_requires_sufficient_context")
            if mc < 0.5:
                recommendation = R.ROUTINE_REVIEW
                uncertain = True
                codes.append("benign_conflicts_maintenance")
            if escalation is not None and float(escalation.value) >= CONFIDENT_ABOVE:
                recommendation = R.ROUTINE_REVIEW
                uncertain = True
                codes.append("benign_conflicts_privilege_escalation")
        elif recommendation is R.PRIORITY_INVESTIGATION and mc > CONFIDENT_ABOVE:
            uncertain = True
            codes.append("priority_conflicts_maintenance")

    if mc >= CONFIDENT_ABOVE:
        codes.append("maintenance_consistent")
    elif mc <= INSUFFICIENT_BELOW:
        codes.append("maintenance_inconsistent")
    if has_related and ji >= CONFIDENT_ABOVE:
        codes.append("joint_investigation_warranted")
    for name, high, low in (
        ("change_appears_reviewed", "change_reviewed", "change_not_reviewed"),
        ("coordinated_activity", "coordinated_activity", None),
        ("privilege_escalation_attempt", "privilege_escalation_likely", None),
    ):
        answer = answers.get(name)
        if answer is None:
            continue
        p = float(answer.value)
        if p >= CONFIDENT_ABOVE:
            codes.append(high)
        elif low is not None and p <= INSUFFICIENT_BELOW:
            codes.append(low)

    ordered = [answers[q.name] for q in qs.questions if q.name in answers]
    unique_codes = list(dict.fromkeys(codes))[:16]
    return JevTriageResult(
        recommendation=recommendation,
        uncertain=uncertain,
        order_consistent=order_consistent,
        sufficient_context_probability=sc,
        answers=ordered,
        rationale_codes=unique_codes,
        question_set_version=qs.version,
    )


class InvalidJevOutput(ValueError):
    """The provider response does not match the question set."""


def _probability(value: object, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise InvalidJevOutput(f"non_numeric:{what}")
    p = float(value)
    if not math.isfinite(p) or p < 0.0 or p > 1.0:
        raise InvalidJevOutput(f"out_of_range:{what}")
    return p


def parse_answers(response: Any, qs: QuestionSet) -> dict[str, JevAnswer]:
    """Validate a System One response against ``qs`` (duck-typed; SDK objects or fakes)."""
    raw = getattr(response, "answers", None)
    if not isinstance(raw, Mapping):
        raise InvalidJevOutput("answers_missing")
    parsed: dict[str, JevAnswer] = {}
    for spec in qs.questions:
        answer = raw.get(spec.name)
        if answer is None:
            raise InvalidJevOutput(f"missing_answer:{spec.name}")
        kind = getattr(answer, "type", None)
        if spec.kind == "noul":
            if kind != "noul":
                raise InvalidJevOutput(f"wrong_type:{spec.name}")
            parsed[spec.name] = JevAnswer(
                question_id=spec.name,
                type="noul",
                value=_probability(getattr(answer, "noul", None), spec.name),
            )
            continue
        if kind != "choice":
            raise InvalidJevOutput(f"wrong_type:{spec.name}")
        choice = getattr(answer, "choice", None)
        if not isinstance(choice, str) or choice not in spec.labels:
            raise InvalidJevOutput(f"unknown_choice:{spec.name}")
        raw_probs = getattr(answer, "probabilities", None)
        if not isinstance(raw_probs, Mapping):
            raise InvalidJevOutput(f"probabilities_missing:{spec.name}")
        probabilities = {
            label: _probability(raw_probs[label], f"{spec.name}.{label}")
            for label in spec.labels
            if label in raw_probs
        }
        if choice not in probabilities:
            raise InvalidJevOutput(f"probabilities_incomplete:{spec.name}")
        parsed[spec.name] = JevAnswer(
            question_id=spec.name,
            type="choice",
            value=choice,
            confidence=_probability(getattr(answer, "confidence", None), f"{spec.name}.confidence"),
            probabilities=probabilities,
        )
    return parsed


# ── provider ──────────────────────────────────────────────────────────


class JevClient(Protocol):
    def system_one(self, state: Any, questions: Mapping[str, Any], **kwargs: Any) -> Any: ...


ClientFactory = Callable[[str, AISettings], JevClient]


def _default_client_factory(api_key: str, settings: AISettings) -> JevClient:
    """TypeSafe client pinned to the official endpoint with an environment-independent HTTP client.

    ``base_url`` is explicit (``TYPESAFE_BASE_URL`` cannot redirect), the key is explicit
    (``TYPESAFE_API_KEY`` is never consulted) and ``http_client`` ignores proxy / CA / key-log
    environment variables and never follows redirects (:mod:`extorq.ai.transport`).
    """
    from typesafe_sdk import RetryPolicy, TypeSafeClient

    # The SDK logs request/response bodies at DEBUG; prompt state must never be logged.
    logging.getLogger("typesafe_sdk").setLevel(logging.WARNING)
    retry = RetryPolicy(
        max_retries=settings.jev_max_retries,
        timeout=settings.jev_retry_budget_seconds,
        http_statuses=set(RETRY_STATUSES),
    )
    client = TypeSafeClient(
        api_key=api_key,
        model=settings.jev_model,
        retry=retry,
        timeout=settings.jev_timeout_seconds,
        base_url=JEV_BASE_URL,
        http_client=transport.sync_client(settings.jev_timeout_seconds),
    )
    return cast(JevClient, client)


@dataclass(frozen=True)
class _Failure:
    status: AIStatus
    error: str
    request_id: str | None = None


def classify_jev_error(exc: BaseException) -> _Failure:
    """Map SDK exceptions to an AIStatus with a fixed, secret-free message."""
    try:
        from typesafe_sdk import (
            TypeSafeAPIConnectionError,
            TypeSafeAPIError,
            TypeSafeAPIResponseValidationError,
            TypeSafeAPITimeoutError,
            TypeSafeAuthenticationError,
            TypeSafeError,
            TypeSafeRateLimitError,
        )
    except ImportError:  # pragma: no cover - SDK is a declared dependency
        return _Failure(AIStatus.ERROR, f"unexpected_error ({type(exc).__name__})")

    request_id: str | None = None
    if isinstance(exc, TypeSafeAPIError):
        try:
            rid = exc.request_id
        except Exception:  # noqa: BLE001 - metadata only
            rid = None
        request_id = clean_token(rid) if rid else None
    if isinstance(exc, TypeSafeAPITimeoutError):
        return _Failure(AIStatus.TIMEOUT, "timeout (per-attempt timeout or retry budget exhausted)")
    if isinstance(exc, TypeSafeAPIResponseValidationError):
        return _Failure(AIStatus.INVALID_OUTPUT, "response_schema_mismatch", request_id)
    if isinstance(exc, TypeSafeRateLimitError):
        return _Failure(AIStatus.RATE_LIMITED, "rate_limited (429)", request_id)
    if isinstance(exc, TypeSafeAuthenticationError):
        return _Failure(AIStatus.ERROR, "authentication_failed (401)", request_id)
    if isinstance(exc, TypeSafeAPIError):
        status = int(exc.status)
        if status == 529:
            return _Failure(AIStatus.RATE_LIMITED, "provider_overloaded (529)", request_id)
        if status == 413:
            return _Failure(AIStatus.ERROR, "request_too_large (413)", request_id)
        if status in (400, 422):
            return _Failure(AIStatus.ERROR, f"request_rejected ({status})", request_id)
        return _Failure(AIStatus.ERROR, f"api_error ({status})", request_id)
    if isinstance(exc, TypeSafeAPIConnectionError):
        return _Failure(AIStatus.ERROR, "connection_error")
    if isinstance(exc, TypeSafeError):
        return _Failure(AIStatus.ERROR, f"sdk_error ({type(exc).__name__})")
    return _Failure(AIStatus.ERROR, f"unexpected_error ({type(exc).__name__})")


class JevTriageProvider:
    """``assess(ctx)`` -> AIAssessment. Never raises for provider or input problems."""

    def __init__(
        self,
        settings: AISettings | None = None,
        *,
        key: ProviderKey | None = None,
        client_factory: ClientFactory | None = None,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings or get_ai_settings()
        self._key = key
        self._factory = client_factory or _default_client_factory
        self._client: JevClient | None = None
        self._clock = clock
        self._monotonic = monotonic

    @property
    def settings(self) -> AISettings:
        return self._settings

    def _provider_key(self) -> ProviderKey:
        if self._key is None:
            self._key = get_provider_key("JEV_API_KEY")
        return self._key

    def _secrets(self) -> tuple[str, ...]:
        """Values scrubbed verbatim from the state and from errors (the Jev key)."""
        key = self._provider_key()
        return (key.value.get_secret_value(),) if key.value is not None else ()

    def availability(self) -> tuple[bool, str]:
        """(usable, reason) without contacting the provider."""
        if not self._settings.jev_enabled:
            return False, "EXTORQ_JEV_ENABLED is false"
        key = self._provider_key()
        if not key.usable:
            return False, key.describe()
        return True, "enabled"

    def build_state(self, ctx: InvestigationContext) -> tuple[Projection, QuestionSet]:
        """Jev's state for ``ctx`` and the question set of its domain (no network)."""
        # The projection shrinks itself to the configured state cap (never above JEV_LIMITS).
        limits = replace(
            JEV_LIMITS, max_chars=min(JEV_LIMITS.max_chars, self._settings.jev_max_state_chars)
        )
        projection = project_context(
            ctx,
            limits,
            known_secrets=self._secrets(),
            include_excerpts=self._settings.ai_include_excerpts,
        )
        return projection, question_set(projection.domain)

    def _assessment(
        self,
        ctx: InvestigationContext,
        requested_by: str,
        status: AIStatus,
        *,
        model: str | None = None,
        triage: JevTriageResult | None = None,
        error: str | None = None,
        latency_ms: int | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        request_id: str | None = None,
    ) -> AIAssessment:
        model_id = clean_token(model or self._settings.jev_model) or self._settings.jev_model
        if error is not None:
            error, _ = redact_secrets(error, self._secrets())
        return AIAssessment(
            assessment_id=assessment_id(
                AIProvider.JEV.value,
                model_id,
                AITask.TRIAGE.value,
                TRIAGE_PROMPT_VERSION,
                ctx.input_hash,
                uuid.uuid4().hex,
            ),
            alert_id=ctx.alert_id,
            context_id=ctx.context_id,
            context_input_hash=ctx.input_hash,
            provider=AIProvider.JEV,
            model=model_id,
            task=AITask.TRIAGE,
            prompt_version=TRIAGE_PROMPT_VERSION,
            status=status,
            triage=triage,
            latency_ms=latency_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            provider_request_id=request_id,
            error=error,
            created_at=self._clock(),
            requested_by=clean_token(requested_by) or "unknown",
        )

    def assess(
        self, ctx: InvestigationContext, requested_by: str = "system:ai-worker"
    ) -> AIAssessment:
        usable, reason = self.availability()
        if not usable:
            return self._assessment(ctx, requested_by, AIStatus.DISABLED, error=reason)
        try:
            projection, qs = self.build_state(ctx)
            state = projection.payload
            if len(projection.serialised()) > self._settings.jev_max_state_chars:
                return self._assessment(ctx, requested_by, AIStatus.ERROR, error="input_too_large")
            questions = {q.name: q.to_sdk() for q in qs.questions}
        except Exception as exc:  # noqa: BLE001 - never raise into alert-serving callers
            _log.warning(
                "jev_input_preparation_failed",
                alert_id=ctx.alert_id,
                error_class=type(exc).__name__,
            )
            return self._assessment(
                ctx,
                requested_by,
                AIStatus.ERROR,
                error=f"input_preparation_failed ({type(exc).__name__})",
            )

        key = self._provider_key()
        started = self._monotonic()
        try:
            if self._client is None:
                if key.value is None:  # availability() already checked; defensive
                    return self._assessment(
                        ctx, requested_by, AIStatus.DISABLED, error=key.describe()
                    )
                self._client = self._factory(key.value.get_secret_value(), self._settings)
            response = self._client.system_one(state, questions, model=self._settings.jev_model)
        except Exception as exc:  # noqa: BLE001 - mapped to a status; never re-raised
            latency = int((self._monotonic() - started) * 1000)
            failure = classify_jev_error(exc)
            _log.warning(
                "jev_call_failed",
                alert_id=ctx.alert_id,
                status=failure.status.value,
                error_class=type(exc).__name__,
                latency_ms=latency,
                request_id=failure.request_id,
            )
            return self._assessment(
                ctx,
                requested_by,
                failure.status,
                error=failure.error,
                latency_ms=latency,
                request_id=failure.request_id,
            )
        latency = int((self._monotonic() - started) * 1000)

        model = getattr(response, "model", None)
        usage = getattr(response, "usage", None)
        input_tokens = _non_negative_int(getattr(usage, "input_tokens", None))
        output_tokens = _non_negative_int(getattr(usage, "output_tokens", None))
        request_id = _request_id(response)
        try:
            answers = parse_answers(response, qs)
            result = decide(answers, qs, has_related=bool(state.get("related_events")))
        except InvalidJevOutput as exc:
            _log.warning(
                "jev_invalid_output", alert_id=ctx.alert_id, reason=str(exc), request_id=request_id
            )
            return self._assessment(
                ctx,
                requested_by,
                AIStatus.INVALID_OUTPUT,
                model=model if isinstance(model, str) else None,
                error=f"invalid_output ({exc})",
                latency_ms=latency,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                request_id=request_id,
            )
        status = (
            AIStatus.INSUFFICIENT_CONTEXT
            if result.recommendation is R.INSUFFICIENT_CONTEXT
            else AIStatus.OK
        )
        _log.info(
            "jev_triage_completed",
            alert_id=ctx.alert_id,
            status=status.value,
            recommendation=result.recommendation.value,
            uncertain=result.uncertain,
            order_consistent=result.order_consistent,
            latency_ms=latency,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            request_id=request_id,
        )
        return self._assessment(
            ctx,
            requested_by,
            status,
            model=model if isinstance(model, str) else None,
            triage=result,
            latency_ms=latency,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            request_id=request_id,
        )


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _request_id(response: Any) -> str | None:
    try:
        value = response.request_id
    except Exception:  # noqa: BLE001 - the SDK raises when the header is absent
        return None
    if not isinstance(value, str) or not value:
        return None
    return clean_token(value) or None

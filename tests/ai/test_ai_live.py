"""Live, budgeted smoke test against the real Jev API (marker ``live_ai``).

The test makes EXACTLY ONE provider call on a SYNTHETIC context. It runs only when
selected explicitly AND opted in:

    EXTORQ_AI_LIVE=1 uv run pytest tests/ai/test_ai_live.py -m live_ai -q -s

The key comes from the normal resolution chain (``JEV_API_KEY_FILE`` -> env -> local
``.env`` dev fallback); its value is never printed. Provenance of the call (status, model
reported by the provider, latency, tokens, request id) is appended to
``eval/live/smoke-<UTC date>.jsonl`` for the evaluation record. Nothing is stored in
ClickHouse (synthetic input).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from ai_fakes import DATASET, load_dataset_records

from extorq.ai.jev import JevTriageProvider
from extorq.ai.settings import AISettings, get_provider_key
from extorq.contracts.ai import AIAssessment, AIStatus
from extorq.contracts.context import InvestigationContext

pytestmark = [
    pytest.mark.live_ai,
    pytest.mark.skipif(os.environ.get("EXTORQ_AI_LIVE") != "1", reason="set EXTORQ_AI_LIVE=1"),
]
LEDGER_DIR = Path(__file__).resolve().parents[2] / "eval" / "live"


def _record(test: str, a: AIAssessment) -> None:
    """Append call metadata (never the key, never the state) to the live-call ledger."""
    LEDGER_DIR.mkdir(parents=True, exist_ok=True)
    day = datetime.now(UTC).date().isoformat()
    entry: dict[str, Any] = {
        "synthetic_input": True,
        "test": test,
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "provider": a.provider.value,
        "status": a.status.value,
        "model": a.model,
        "prompt_version": a.prompt_version,
        "latency_ms": a.latency_ms,
        "input_tokens": a.input_tokens,
        "output_tokens": a.output_tokens,
        "provider_request_id": a.provider_request_id,
        "error": a.error,
        "context_input_hash": a.context_input_hash,
    }
    if a.triage is not None:
        entry["triage"] = a.triage.model_dump(mode="json")
    with (LEDGER_DIR / f"smoke-{day}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    print(json.dumps(entry, sort_keys=True))


def _dataset_context(case_id: str) -> InvestigationContext:
    for record in load_dataset_records():
        if record["case_id"] == case_id:
            return InvestigationContext.model_validate(record["context"])
    raise AssertionError(f"{case_id} not in {DATASET}")


def test_jev_live_smoke() -> None:
    key = get_provider_key("JEV_API_KEY")
    if not key.usable:
        pytest.skip(key.describe())
    provider = JevTriageProvider(AISettings(jev_enabled=True), key=key)
    assessment = provider.assess(_dataset_context("SSH-S1"), "system:live-smoke")
    _record("jev_live_smoke", assessment)
    assert assessment.status in (AIStatus.OK, AIStatus.INSUFFICIENT_CONTEXT), assessment.error
    assert assessment.triage is not None
    assert assessment.input_tokens and assessment.input_tokens > 0
    assert assessment.model.startswith("jev-")
    assert key.value is not None
    assert key.value.get_secret_value() not in assessment.model_dump_json()

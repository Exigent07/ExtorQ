"""Validates the synthetic prompt-injection corpus and, once available, A's sanitiser.

The corpus (``fixtures/prompt_injection_corpus.json``) is reused by E (AI), D2
(UI) and A (sanitiser); this test keeps it well-formed, labelled as synthetic
and internally consistent. When ``extorq.common.redaction.sanitize_untrusted``
exists, every payload is run through it to check the documented contract
(PLAN 5: "strip controls, truncate").
"""

from __future__ import annotations

import importlib
import json
import re
import unicodedata
from pathlib import Path
from typing import Any

import pytest

from extorq.contracts.catalog import SourceType

CORPUS_PATH = Path(__file__).resolve().parent / "fixtures" / "prompt_injection_corpus.json"
CORPUS: dict[str, Any] = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CASES: list[dict[str, Any]] = CORPUS["cases"]
VOCAB = CORPUS["vocabulary"]

REQUIRED_FIELDS = {
    "id",
    "synthetic",
    "category",
    "carrier",
    "source_type",
    "field",
    "payload",
    "expectations",
    "consumers",
    "attack_goal",
}
#: Control characters that must never survive sanitisation (C0 except TAB, DEL, C1).
FORBIDDEN_AFTER_SANITISE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")


def test_corpus_is_labelled_synthetic() -> None:
    assert CORPUS["schema"] == "extorq.security.prompt-injection-corpus/1"
    assert CORPUS["synthetic"] is True
    assert "SYNTHETIC" in CORPUS["description"]
    assert all(case["synthetic"] is True for case in CASES)


def test_corpus_file_is_ascii_only() -> None:
    raw = CORPUS_PATH.read_bytes()
    assert all(32 <= b < 127 or b in (9, 10, 13) for b in raw), "escape non-ASCII as \\uXXXX"


def test_cases_have_required_fields_and_unique_ids() -> None:
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for case in CASES:
        missing = REQUIRED_FIELDS - case.keys()
        assert not missing, f"{case.get('id')}: missing {sorted(missing)}"
        assert re.fullmatch(r"PI-\d{3}", case["id"]), case["id"]
        assert case["payload"], f"{case['id']}: empty payload"
        assert case["attack_goal"], f"{case['id']}: empty attack_goal"


def test_cases_use_the_declared_vocabulary() -> None:
    source_types = {s.value for s in SourceType}
    for case in CASES:
        assert case["category"] in VOCAB["categories"], case["id"]
        assert set(case["expectations"]) <= set(VOCAB["expectations"]), case["id"]
        assert set(case["consumers"]) <= set(VOCAB["consumers"]), case["id"]
        assert case["source_type"] in source_types, f"{case['id']}: unknown source type"


def test_every_category_is_covered() -> None:
    covered = {case["category"] for case in CASES}
    assert covered == set(VOCAB["categories"]), sorted(set(VOCAB["categories"]) - covered)


def test_canaries_are_embedded_in_their_payloads() -> None:
    for case in CASES:
        if "canary" in case:
            assert re.fullmatch(r"EXTORQ-CANARY-[0-9A-F]{8}", case["canary"]), case["id"]
            assert case["canary"] in case["payload"], case["id"]


def test_control_character_cases_really_contain_controls() -> None:
    for case in CASES:
        if case["category"] == "control_characters":
            assert any(unicodedata.category(ch) == "Cc" for ch in case["payload"]), case["id"]


def test_external_references_use_reserved_domains_only() -> None:
    url = re.compile(r"https?://([A-Za-z0-9.-]+)")
    for case in CASES:
        for host in url.findall(case["payload"]):
            assert host.endswith(".invalid"), (
                f"{case['id']}: {host} is not a reserved .invalid host"
            )


# ── sanitiser contract (A) ───────────────────────────────────────────────────


def _sanitizer() -> Any:
    try:
        module = importlib.import_module("extorq.common.redaction")
    except ModuleNotFoundError:
        return None
    return getattr(module, "sanitize_untrusted", None)


SANITIZE = _sanitizer()


@pytest.mark.skipif(
    SANITIZE is None, reason="extorq.common.redaction.sanitize_untrusted not present yet (owner: A)"
)
@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_sanitize_untrusted_strips_controls_and_bounds_length(case: dict[str, Any]) -> None:
    limit = 512
    assert SANITIZE is not None
    result = SANITIZE(case["payload"], limit)
    assert isinstance(result, str)
    assert len(result) <= limit, f"{case['id']}: {len(result)} > {limit}"
    leftover = FORBIDDEN_AFTER_SANITISE.findall(result)
    assert not leftover, (
        f"{case['id']}: control characters survived: {[hex(ord(c)) for c in leftover]}"
    )

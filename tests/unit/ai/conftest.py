"""Fixtures for AI unit tests (helpers live in ``ai_fakes``). No network calls."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from ai_fakes import isolate_ai_env, load_dataset_records

from extorq.contracts.context import InvestigationContext


@pytest.fixture(autouse=True)
def _isolate_ai_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    yield from isolate_ai_env(monkeypatch, tmp_path)


@pytest.fixture(scope="session")
def dataset_records() -> list[dict[str, Any]]:
    return load_dataset_records()


@pytest.fixture(scope="session")
def contexts(dataset_records: list[dict[str, Any]]) -> dict[str, InvestigationContext]:
    return {
        r["case_id"]: InvestigationContext.model_validate(r["context"]) for r in dataset_records
    }

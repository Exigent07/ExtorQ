"""Fixtures for AI adversarial and live tests (shares the fakes in tests/unit/ai/ai_fakes.py)."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

_UNIT_AI = Path(__file__).resolve().parents[1] / "unit" / "ai"
if str(_UNIT_AI) not in sys.path:
    sys.path.insert(0, str(_UNIT_AI))

from ai_fakes import isolate_ai_env  # noqa: E402 - path set up above


@pytest.fixture(autouse=True)
def _isolate_ai_env(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Iterator[None]:
    """Unit-style isolation for every test except live ones (which need the real keys)."""
    if request.node.get_closest_marker("live_ai") is not None:
        yield
        return
    yield from isolate_ai_env(monkeypatch, tmp_path)

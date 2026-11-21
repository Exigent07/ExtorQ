"""Shared helpers for the macOS collector unit tests (imported as ``macos_helpers``).

Fixtures under tests/fixtures/macos/ are REAL command output captured on the
reference Mac (macOS 27.0.1, 26A434, Mac16,8) with the account name replaced by
``testuser`` and public addresses replaced by documentation ranges. Records that
could not be captured (no such event in the retained log) are clearly marked
synthetic (``extorqSynthetic`` in unified_log/synthetic_auth_producers.ndjson).
"""

from __future__ import annotations

import shutil
from collections.abc import Callable, Sequence
from pathlib import Path

from extorq_collectors.macos.commands import CommandResult, validate_argv

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "macos"
ASSET = "macos:workstation-01"
COLLECTOR = "macos-workstation-01"

Response = CommandResult | Callable[[tuple[str, ...]], CommandResult]


def fixture_text(relative: str) -> str:
    return (FIXTURES / relative).read_text(encoding="utf-8")


def fixture_bytes(relative: str) -> bytes:
    return (FIXTURES / relative).read_bytes()


def ok(argv: Sequence[str], stdout: bytes | str, stderr: bytes = b"") -> CommandResult:
    data = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    return CommandResult(tuple(argv), 0, data, stderr, 0.01)


def failed(argv: Sequence[str], code: int = 1, stderr: bytes = b"failed") -> CommandResult:
    return CommandResult(tuple(argv), code, b"", stderr, 0.01)


class FakeRunner:
    """CommandRunner double: enforces the real argv policy, answers from fixtures."""

    def __init__(self) -> None:
        self.exact: dict[tuple[str, ...], Response] = {}
        self.prefixes: list[tuple[tuple[str, ...], Response]] = []
        self.calls: list[tuple[str, ...]] = []

    def add(self, argv: Sequence[str], response: Response) -> None:
        self.exact[tuple(argv)] = response

    def add_prefix(self, prefix: Sequence[str], response: Response) -> None:
        self.prefixes.append((tuple(prefix), response))

    def run(
        self, argv: Sequence[str], *, timeout: float, max_stdout: int = 4 * 1024 * 1024
    ) -> CommandResult:
        key = validate_argv(argv)  # the production policy applies to tests too
        assert timeout > 0
        self.calls.append(key)
        response: Response | None = self.exact.get(key)
        if response is None:
            for prefix, candidate in self.prefixes:
                if key[: len(prefix)] == prefix:
                    response = candidate
                    break
        if response is None:
            return failed(key, 1, b"not faked in test")
        return response(key) if callable(response) else response


def copy_fixture_dir(relative: str, target: Path) -> Path:
    target.mkdir(parents=True, exist_ok=True)
    for item in (FIXTURES / relative).iterdir():
        if item.is_file():
            shutil.copy2(item, target / item.name)
    return target

"""Private token-file policy, using only synthetic token-shaped values."""

from __future__ import annotations

from pathlib import Path

import pytest

from extorq_collectors.github.token import (
    TOKEN_FILE_ENV,
    TokenUnavailable,
    read_token_file,
    resolve_token,
)

FILE_TOKEN = "github_pat_" + "F" * 40


def write_token(path: Path, value: str = FILE_TOKEN, mode: int = 0o600) -> Path:
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def test_file_setting_precedence(tmp_path: Path) -> None:
    configured = tmp_path / "missing"
    override = write_token(tmp_path / "override")
    token = resolve_token(
        config_token_file=str(configured), environ={TOKEN_FILE_ENV: str(override)}
    )
    assert token.value == FILE_TOKEN
    assert token.source == "file" and token.kind == "fine_grained_pat"
    assert FILE_TOKEN not in repr(token)


def test_configured_private_file_when_override_unset(tmp_path: Path) -> None:
    path = write_token(tmp_path / "readonly-pat", mode=0o400)
    assert resolve_token(config_token_file=str(path), environ={}).value == FILE_TOKEN


def test_secret_environment_variables_are_ignored() -> None:
    with pytest.raises(TokenUnavailable, match=TOKEN_FILE_ENV):
        resolve_token(environ={"EXTORQ_GITHUB_TOKEN": FILE_TOKEN, "GH_TOKEN": FILE_TOKEN})


@pytest.mark.parametrize("mode", [0o644, 0o660, 0o700])
def test_invalid_token_file_permissions_are_rejected(tmp_path: Path, mode: int) -> None:
    with pytest.raises(TokenUnavailable, match="0600 or 0400"):
        read_token_file(write_token(tmp_path / "readonly-pat", mode=mode))


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ("", "is empty"),
        ("short", "unexpected token length"),
        ("github_pat_" + "x" * 20 + " " + "y" * 20, "whitespace"),
        ("ghp_" + "E" * 36, "requires a dedicated fine-grained"),
        ("gho_" + "C" * 36, "requires a dedicated fine-grained"),
    ],
)
def test_bad_token_files_fail_without_echoing_content(
    tmp_path: Path, content: str, reason: str
) -> None:
    with pytest.raises(TokenUnavailable, match=reason) as info:
        read_token_file(write_token(tmp_path / "readonly-pat", content))
    if content:
        assert content not in str(info.value)


def test_missing_directory_and_oversized_token_files(tmp_path: Path) -> None:
    with pytest.raises(TokenUnavailable, match="missing file"):
        read_token_file(tmp_path / "missing")
    with pytest.raises(TokenUnavailable, match="not a regular file"):
        read_token_file(tmp_path)
    with pytest.raises(TokenUnavailable, match="larger than"):
        read_token_file(write_token(tmp_path / "big", "g" * 5000))


def test_token_path_must_not_be_a_symlink(tmp_path: Path) -> None:
    link = tmp_path / "symlink"
    link.symlink_to(write_token(tmp_path / "readonly-pat"))
    with pytest.raises(TokenUnavailable, match="cannot be opened"):
        read_token_file(link)

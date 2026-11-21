"""Token provider: precedence, file checks, gh CLI opt-in, no leakage (synthetic tokens)."""

from __future__ import annotations

from pathlib import Path

import pytest

from extorq_collectors.github import token as token_mod
from extorq_collectors.github.token import (
    GH_CLI_WARNING,
    TOKEN_ENV,
    TOKEN_FILE_ENV,
    TokenUnavailable,
    gh_cli_token,
    read_token_file,
    resolve_token,
    scope_warnings,
    token_kind,
)

# Synthetic token-shaped values, never real credentials.
FILE_TOKEN = "github_pat_" + "F" * 40
ENV_TOKEN = "ghp_" + "E" * 36
CLI_TOKEN = "gho_" + "C" * 36


def write_token(tmp_path: Path, value: str = FILE_TOKEN, mode: int = 0o600) -> Path:
    path = tmp_path / "readonly-pat"
    path.write_text(value + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


def fail_gh(_host: str) -> str:
    raise AssertionError("gh CLI must not be consulted")


def test_file_has_precedence_over_env_and_cli(tmp_path: Path) -> None:
    path = write_token(tmp_path)
    token = resolve_token(
        environ={TOKEN_FILE_ENV: str(path), TOKEN_ENV: ENV_TOKEN},
        allow_gh_cli=True,
        gh_runner=fail_gh,
    )
    assert token.value == FILE_TOKEN
    assert token.source == "file" and token.kind == "fine_grained_pat"
    assert token.warnings == ()


def test_config_token_file_used_when_env_unset(tmp_path: Path) -> None:
    path = write_token(tmp_path)
    token = resolve_token(config_token_file=str(path), environ={}, gh_runner=fail_gh)
    assert token.source == "file" and token.value == FILE_TOKEN


def test_env_token_and_kind_warning() -> None:
    token = resolve_token(environ={TOKEN_ENV: ENV_TOKEN}, allow_gh_cli=True, gh_runner=fail_gh)
    assert token.source == "env" and token.kind == "classic_pat"
    assert any("coarse OAuth scopes" in w for w in token.warnings)


def test_gh_cli_only_when_allowed_and_always_warned() -> None:
    with pytest.raises(TokenUnavailable) as info:
        resolve_token(environ={}, allow_gh_cli=False, gh_runner=fail_gh)
    message = str(info.value)
    assert TOKEN_FILE_ENV in message and TOKEN_ENV in message
    token = resolve_token(environ={}, allow_gh_cli=True, gh_runner=lambda host: CLI_TOKEN)
    assert token.source == "gh_cli" and token.kind == "oauth"
    assert token.warnings == (GH_CLI_WARNING,)
    assert "broad" in GH_CLI_WARNING


def test_token_never_shown_by_repr_or_str(tmp_path: Path) -> None:
    token = resolve_token(environ={TOKEN_FILE_ENV: str(write_token(tmp_path))})
    assert FILE_TOKEN not in repr(token)
    assert FILE_TOKEN not in str(token)
    assert FILE_TOKEN not in f"{token}"


def test_group_readable_token_file_warns(tmp_path: Path) -> None:
    _value, warnings = read_token_file(write_token(tmp_path, mode=0o644))
    assert warnings and "0600" in warnings[0]


@pytest.mark.parametrize(
    ("content", "fragment"),
    [
        ("", "is empty"),
        ("short", "unexpected length"),
        ("ghp_" + "x" * 20 + " " + "y" * 20, "whitespace"),
    ],
)
def test_bad_token_files_fail_without_echoing_content(
    tmp_path: Path, content: str, fragment: str
) -> None:
    path = tmp_path / "tok"
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(TokenUnavailable) as info:
        read_token_file(path)
    assert fragment in str(info.value)
    if content:
        assert content not in str(info.value)


def test_missing_directory_and_oversized_token_files(tmp_path: Path) -> None:
    with pytest.raises(TokenUnavailable, match="missing file"):
        read_token_file(tmp_path / "nope")
    with pytest.raises(TokenUnavailable, match="not a regular file"):
        read_token_file(tmp_path)
    big = tmp_path / "big"
    big.write_text("g" * 5000, encoding="utf-8")
    with pytest.raises(TokenUnavailable, match="larger than"):
        read_token_file(big)


def test_gh_cli_hostname_is_validated_and_argv_is_fixed(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(TokenUnavailable, match="hostname"):
        gh_cli_token("github.com; rm -rf /")
    calls: list[list[str]] = []

    class Completed:
        returncode = 0
        stdout = CLI_TOKEN + "\n"

    def fake_run(argv: list[str], **kwargs: object) -> Completed:
        calls.append(argv)
        assert kwargs.get("shell") in (None, False)
        assert "timeout" in kwargs
        return Completed()

    monkeypatch.setattr(token_mod.shutil, "which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr(token_mod.subprocess, "run", fake_run)
    assert gh_cli_token("github.com") == CLI_TOKEN
    assert calls == [["/usr/bin/gh", "auth", "token", "--hostname", "github.com"]]


def test_gh_cli_failure_does_not_leak_output(monkeypatch: pytest.MonkeyPatch) -> None:
    class Completed:
        returncode = 1
        stdout = ""
        stderr = "not logged in to github.com account synthetic-user"

    monkeypatch.setattr(token_mod.shutil, "which", lambda name: "/usr/bin/gh")
    monkeypatch.setattr(token_mod.subprocess, "run", lambda *a, **k: Completed())
    with pytest.raises(TokenUnavailable) as info:
        gh_cli_token("github.com")
    assert "synthetic-user" not in str(info.value)
    monkeypatch.setattr(token_mod.shutil, "which", lambda name: None)
    with pytest.raises(TokenUnavailable, match="not installed"):
        gh_cli_token("github.com")


def test_token_kind_and_scope_warnings() -> None:
    assert token_kind(FILE_TOKEN) == "fine_grained_pat"
    assert token_kind("ghs_" + "x" * 36) == "app_installation"
    assert token_kind("x" * 40) == "unknown"
    assert scope_warnings(None) == ()
    assert scope_warnings(("read:org",)) == ()
    warning = scope_warnings(("repo", "workflow", "read:org", "admin:repo_hook"))
    assert warning and "repo" in warning[0] and "workflow" in warning[0]
    assert "admin:repo_hook" in warning[0] and "read:org" not in warning[0]

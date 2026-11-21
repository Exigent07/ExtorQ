"""extorq.common: configuration (+ ``_FILE`` secrets), redaction, sanitisation, logging.

Secret-looking values below are SYNTHETIC test strings built at runtime so that no
literal credential-shaped token is committed (secret scanners stay quiet).
"""

from __future__ import annotations

import io
import json
import logging
import unicodedata
from pathlib import Path

import pytest

from extorq.common import config as cfg
from extorq.common.logging import (
    REDACTED,
    configure_logging,
    get_logger,
    looks_like_token,
    redact_event_dict,
)
from extorq.common.redaction import (
    TRUNCATION_MARKER,
    redact_text,
    sanitize_untrusted,
    truncate_bytes,
)

# ── configuration ─────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "EXTORQ_API_SERVICE_TOKEN",
        "EXTORQ_API_SERVICE_TOKEN_FILE",
        "EXTORQ_GATEWAY_PORT",
        "JEV_API_KEY",
        "JEV_API_KEY_FILE",
    ):
        monkeypatch.delenv(name, raising=False)
    cfg.get_settings.cache_clear()


def test_env_prefix_and_secret_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    secret = tmp_path / "token"
    secret.write_text("synthetic-api-token-value\n")
    monkeypatch.setenv("EXTORQ_GATEWAY_PORT", "9443")
    monkeypatch.setenv("EXTORQ_API_SERVICE_TOKEN_FILE", str(secret))
    settings = cfg.Settings()
    assert settings.gateway_port == 9443
    assert settings.api_service_token is not None
    assert settings.api_service_token.get_secret_value() == "synthetic-api-token-value"
    assert "synthetic-api-token-value" not in repr(settings)


def test_unprefixed_ai_key_alias_and_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    key = tmp_path / "jev"
    key.write_text("synthetic-jev-key")
    monkeypatch.setenv("JEV_API_KEY_FILE", str(key))
    settings = cfg.Settings()
    assert settings.jev_api_key is not None
    assert settings.jev_api_key.get_secret_value() == "synthetic-jev-key"


def test_secret_and_secret_file_together_is_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "token"
    secret.write_text("a")
    monkeypatch.setenv("EXTORQ_API_SERVICE_TOKEN", "inline-synthetic")
    monkeypatch.setenv("EXTORQ_API_SERVICE_TOKEN_FILE", str(secret))
    with pytest.raises(cfg.ConfigError) as err:
        cfg.Settings()
    assert "inline-synthetic" not in str(err.value)


@pytest.mark.parametrize("content", ["", "   \n"])
def test_empty_or_unreadable_secret_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str
) -> None:
    secret = tmp_path / "token"
    secret.write_text(content)
    monkeypatch.setenv("EXTORQ_API_SERVICE_TOKEN_FILE", str(secret))
    with pytest.raises(cfg.ConfigError, match="empty"):
        cfg.Settings()
    monkeypatch.setenv("EXTORQ_API_SERVICE_TOKEN_FILE", str(tmp_path / "missing"))
    with pytest.raises(cfg.ConfigError, match="unreadable"):
        cfg.Settings()


def test_startup_check_names_missing_settings_never_values(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    settings = cfg.Settings(home=tmp_path)
    missing = cfg.check_startup(
        "unit",
        settings,
        required=["api_service_token"],
        required_files=["tls_cert_file"],
        clickhouse_roles=["ingest"],
    )
    assert "EXTORQ_API_SERVICE_TOKEN" in missing
    assert "EXTORQ_TLS_CERT_FILE" in missing
    assert any("extorq_ingest_password" in item for item in missing)


def test_read_secret_file_errors_name_the_file_only(tmp_path: Path) -> None:
    with pytest.raises(cfg.ConfigError, match="nope"):
        cfg.read_secret_file(tmp_path / "nope")


def test_clickhouse_password_file_per_role(tmp_path: Path) -> None:
    settings = cfg.Settings(home=tmp_path)
    assert settings.clickhouse_password_file("api_ro").name == "extorq_api_ro_password"
    with pytest.raises(cfg.ConfigError):
        settings.clickhouse_password_file("root")


# ── redaction ─────────────────────────────────────────────────────────


def _synthetic(prefix: str, body: str, repeat: int) -> str:
    """Build a credential-SHAPED test string at runtime (never a real or literal secret)."""
    return prefix + body * repeat


GH = _synthetic("ghp_", "Ab1", 12)
PAT = _synthetic("github_pat_", "A1b2_", 6)
AKIA = _synthetic("AKIA", "ABCD", 4)
AWS_SECRET = _synthetic("", "Synth/Key+", 4)
JWT = ".".join(["eyJ" + "hbGciOi" * 2, "eyJ" + "zdWIiOi" * 2, "c2lnbmF0" * 2])
SLACK = _synthetic("xoxb-", "12345-abcde", 2)
GOOGLE = _synthetic("AIza", "S", 35)
PEM_BODY = _synthetic("MII", "Synthetic", 3)
PEM = "-----BEGIN " + "PRIVATE KEY-----\n" + PEM_BODY + "\n-----END " + "PRIVATE KEY-----"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        (f"token {GH} used", GH),
        (f"pat={PAT}", PAT),
        (f"key {AKIA} here", AKIA),
        (f"aws_secret_access_key = {AWS_SECRET}", AWS_SECRET),
        (f"cookie {JWT}", JWT),
        (f"slack {SLACK}", SLACK),
        (f"google {GOOGLE}", GOOGLE),
        (f"key:\n{PEM}\nafter", PEM_BODY),
        ("Authorization: Bearer " + _synthetic("syn", "th", 8), _synthetic("syn", "th", 8)),
        ("Authorization: Token " + _synthetic("tok3n", "-x9", 4), _synthetic("tok3n", "-x9", 4)),
        ("password=hunter2-synthetic&x=1", "hunter2-synthetic"),
        ('{"api_key": "' + _synthetic("k", "-syn", 3) + '"}', _synthetic("k", "-syn", 3)),
        ("https://user:p4ss-synthetic@host/x", "p4ss-synthetic"),
        ("sudo curl --password s3cr3t-synthetic https://x", "s3cr3t-synthetic"),
        ("mysql -u root -pSynthPass1 db", "SynthPass1"),
        ("sshpass -p SynthPass2 ssh lab", "SynthPass2"),
        ("redis-server --requirepass SynthPass3 --port 6379", "SynthPass3"),
        ("redis-cli -h lab -a SynthPass4 ping", "SynthPass4"),
        (
            "curl -u " + ":".join(["admin", _synthetic("Synth", "Pass5", 1)]) + " https://lab",
            "SynthPass5",
        ),
        ("PGPASSWORD=SynthPass6 psql -h db", "SynthPass6"),
        ("MYSQL_PWD=SynthPass7 mysql", "SynthPass7"),
    ],
)
def test_redact_text_removes_secrets(text: str, secret: str) -> None:
    redacted, count = redact_text(text)
    assert secret not in redacted
    assert count >= 1
    assert "[REDACTED" in redacted


@pytest.mark.parametrize(
    "text",
    [
        "event 5f8e8e488e85df2511a7a2d0a948b8a8 sha256 " + "a" * 64,
        "ssh -p2222 lab@127.0.0.1",
        "mkdir -p /var/lib/extorq",
        "tool --password-file /run/secrets/x",
        "app.authz.denied authorization=denied route=/admin",
        "Failed password for invalid user admin from 10.0.2.2 port 50000 ssh2",
        "uuid 0b3925c6-ee76-4ffc-9053-90d120c5632d",
        "MAX_TOKENS=100 ./run",
        "redis-cli -n 2 get key",
        "curl -u admin https://lab",
    ],
)
def test_redact_text_keeps_ordinary_telemetry(text: str) -> None:
    assert redact_text(text) == (text, 0)


def test_redaction_is_idempotent() -> None:
    once, count = redact_text(f"Authorization: Bearer {GH}")
    assert count == 1
    assert redact_text(once) == (once, 0)


def test_sanitize_strips_controls_ansi_and_invisible_characters() -> None:
    rlo, zwsp, tag_a, shy = chr(0x202E), chr(0x200B), chr(0xE0041), chr(0x00AD)
    lsep, psep, mvs, bom, nel, pua = (
        chr(0x2028),
        chr(0x2029),
        chr(0x180E),
        chr(0xFEFF),
        chr(0x85),
        chr(0xE000),
    )
    hostile = (
        f"a\x1b[31mred\x1b[0m\x00b{rlo}c{zwsp}d{tag_a}e{shy}f{lsep}g{psep}h"
        f"{mvs}i{bom}j{nel}k\x07l{pua}m\tn"
    )
    clean = sanitize_untrusted(hostile, 200)
    assert clean == "aredbcdef g hij klm\tn"
    for ch in clean:
        assert unicodedata.category(ch) not in {"Cf", "Cs", "Co"}
        assert ch == "\t" or unicodedata.category(ch) != "Cc"


def test_sanitize_newlines_truncation_and_nfc() -> None:
    assert sanitize_untrusted("a\r\nb\nc", 50) == "a b c"
    assert sanitize_untrusted("a\r\nb", 50, keep_newlines=True) == "a\nb"
    assert sanitize_untrusted("é", 10) == "é"
    long = sanitize_untrusted("x" * 100, 20)
    assert len(long) == 20 and long.endswith(TRUNCATION_MARKER)
    assert sanitize_untrusted("abc", 0) == ""


def test_truncate_bytes_respects_utf8_boundaries() -> None:
    text = "é" * 100
    out = truncate_bytes(text, 50)
    assert len(out.encode("utf-8")) <= 50 and out.endswith(TRUNCATION_MARKER)
    assert truncate_bytes("short", 50) == "short"


# ── logging ───────────────────────────────────────────────────────────


def test_redact_event_dict_sensitive_keys_and_values() -> None:
    event = {
        "event": f"login with {GH}",
        "password": "hunter2-synthetic",
        "Authorization": "Bearer x",
        "x_api_key": "k",
        "nested": {"client_secret": "s", "ok": "value", "list": [GH]},
        "opaque": "Zm9vYmFyQmF6MTIzNDU2Nzg5MEFCQ0RFRkdISUpLTE1O",
        "event_id": "5f8e8e488e85df2511a7a2d0a948b8a8",
    }
    out = redact_event_dict(None, "info", dict(event))
    assert GH not in out["event"]
    assert out["password"] == REDACTED and out["Authorization"] == REDACTED
    assert out["x_api_key"] == REDACTED
    assert out["nested"]["client_secret"] == REDACTED and out["nested"]["ok"] == "value"
    assert GH not in json.dumps(out["nested"]["list"])
    assert out["opaque"] == REDACTED
    assert out["event_id"] == event["event_id"]
    assert looks_like_token("a" * 40) is False


def test_configure_logging_emits_json_with_component() -> None:
    stream = io.StringIO()
    configure_logging("unit-test", level="INFO")
    handler = logging.getLogger().handlers[0]
    handler.setStream(stream)  # type: ignore[attr-defined]
    get_logger("extorq.test").info("hello", token="synthetic-token-value", count=3)
    line = json.loads(stream.getvalue().strip().splitlines()[-1])
    assert line["component"] == "unit-test" and line["event"] == "hello"
    assert line["token"] == REDACTED and line["count"] == 3

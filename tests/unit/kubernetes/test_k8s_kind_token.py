"""``infra/kind/kind.sh token`` helpers: lifetime bounds and expiry display.

Pure shell functions are tested by sourcing the script in a fresh bash (its ``main`` only
runs when the script is executed). No cluster, docker, kind or kubectl is called: the one
test that executes ``kind.sh token`` runs with a PATH that contains none of them. Token
strings here are SYNTHETIC, unsigned JWT-shaped values.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
KIND_SH = ROOT / "infra" / "kind" / "kind.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")


def sourced(snippet: str) -> subprocess.CompletedProcess[str]:
    """Run ``snippet`` in a bash that sourced kind.sh (functions and constants only)."""
    return subprocess.run(
        ["bash", "-c", f'source "$1"; {snippet}', "kind-sh-test", str(KIND_SH)],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_default_lifetime_is_48_hours() -> None:
    result = sourced(
        'echo "$TOKEN_DURATION_DEFAULT"; token_duration_seconds "$TOKEN_DURATION_DEFAULT"'
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["48h", "172800"]


@pytest.mark.parametrize(
    ("duration", "seconds"),
    [("10m", 600), ("90m", 5400), ("08h", 28800), ("48h", 172800), ("168h", 604800)],
)
def test_lifetimes_within_bounds(duration: str, seconds: int) -> None:
    result = sourced(f"token_duration_seconds {duration}")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(seconds)


@pytest.mark.parametrize(
    "duration", ["9m", "169h", "0h", "48", "48x", "", "-1h", "2d", "48h;id", "1e3h", "48H"]
)
def test_malformed_or_out_of_bounds_lifetimes_are_refused(duration: str) -> None:
    result = sourced(f"token_duration_seconds '{duration}'")
    assert result.returncode != 0
    assert result.stdout == ""


def test_invalid_lifetime_fails_before_any_cluster_tool_runs(tmp_path: Path) -> None:
    """``kind.sh token`` validates first; this PATH holds no docker/kind/kubectl anyway."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("bash", "dirname"):
        found = shutil.which(tool)
        assert found is not None
        (bin_dir / tool).symlink_to(found)
    result = subprocess.run(
        [str(bin_dir / "bash"), str(KIND_SH), "token"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
        env={"PATH": str(bin_dir), "HOME": str(tmp_path), "EXTORQ_K8S_TOKEN_DURATION": "999h"},
    )
    assert result.returncode == 1
    assert "invalid EXTORQ_K8S_TOKEN_DURATION" in result.stderr
    assert "required tool not found" not in result.stderr


def synthetic_jwt(exp: datetime) -> str:
    def b64(data: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{b64({'alg': 'none'})}.{b64({'exp': int(exp.timestamp())})}.synthetic-signature"


@pytest.mark.skipif(shutil.which("python3") is None, reason="python3 is required")
def test_token_expiry_prints_exp_and_seconds_left_never_the_token(tmp_path: Path) -> None:
    exp = (datetime.now(UTC) + timedelta(hours=48)).replace(microsecond=0)
    token = tmp_path / "inventory.token"
    token.write_text(synthetic_jwt(exp))
    os.chmod(token, 0o600)
    result = sourced(f"token_expiry '{token}'")
    assert result.returncode == 0, result.stderr
    stamp, left = result.stdout.split()
    assert stamp == exp.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert 48 * 3600 - 120 <= int(left) <= 48 * 3600
    assert "synthetic-signature" not in result.stdout + result.stderr


@pytest.mark.skipif(shutil.which("python3") is None, reason="python3 is required")
@pytest.mark.parametrize("content", ["not-a-jwt", "a.%%%.b", ""])
def test_token_expiry_fails_quietly_for_unreadable_tokens(tmp_path: Path, content: str) -> None:
    token = tmp_path / "inventory.token"
    token.write_text(content)
    result = sourced(f"token_expiry '{token}'")
    assert result.returncode != 0
    assert result.stdout == "" and result.stderr == ""

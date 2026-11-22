"""Application-folder scan -> software.installed / software.removed (MAC-005 inputs).

codesign outputs under tests/fixtures/macos/software/ are REAL captures from the reference
Mac (macOS 27): Calculator.app as-is; one third-party Developer ID app with its identity
replaced by synthetic placeholders (``com.example.thirdparty.exampleapp``, team
``EXAMPLE001``); ad-hoc, unsigned and tampered minimal bundles built in a scratch folder
(never in /Applications, never executed) with the path replaced by an /Applications path.
"""

from __future__ import annotations

import os
import plistlib
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from macos_helpers import FakeRunner, failed, fixture_bytes, fixture_text, ok
from test_macos_collector import Harness

from extorq.contracts import validate_event_semantics
from extorq_collectors.macos import commands as commands_mod
from extorq_collectors.macos.commands import (
    CommandResult,
    CommandValidationError,
    validate_argv,
)
from extorq_collectors.macos.common import SourceContext
from extorq_collectors.macos.software import (
    AppLocation,
    Change,
    check_signature,
    codesign_argv,
    event_for,
    parse_codesign_display,
    read_bundle,
    scan_locations,
    settled,
)

APP = "/Applications/ExtorQ Test.app"


def make_bundle(path: Path, bundle_id: str | None, version: str = "1.0") -> Path:
    """A minimal application bundle (an Info.plist and a shell-script executable)."""
    (path / "Contents" / "MacOS").mkdir(parents=True, exist_ok=True)
    exe = path / "Contents" / "MacOS" / "run"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(0o755)
    info: dict[str, Any] = {
        "CFBundleExecutable": "run",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": "7",
    }
    if bundle_id is not None:
        info["CFBundleIdentifier"] = bundle_id
    (path / "Contents" / "Info.plist").write_bytes(plistlib.dumps(info))
    return path


def stderr_result(argv: list[str], code: int, stderr: bytes) -> Any:
    return failed(argv, code, stderr) if code else ok(argv, b"", stderr)


# ── codesign output parsing (real captures) ──────────────────────────


def test_display_apple_platform_app() -> None:
    info = parse_codesign_display(fixture_text("software/codesign_display_apple_platform.txt"))
    assert not info.adhoc and info.team_id is None  # "TeamIdentifier=not set"
    assert info.authorities[0] == "macOS Software Signing"
    assert info.identifier == "com.apple.calculator"


def test_display_developer_id_app() -> None:
    info = parse_codesign_display(fixture_text("software/codesign_display_developer_id.txt"))
    assert info.team_id == "EXAMPLE001"
    assert info.authorities == [
        "Developer ID Application: Example Developer (EXAMPLE001)",
        "Developer ID Certification Authority",
        "Apple Root CA",
    ]
    assert info.notarization_ticket == "stapled"


def test_display_adhoc_bundle() -> None:
    info = parse_codesign_display(fixture_text("software/codesign_display_adhoc.txt"))
    assert info.adhoc and info.team_id is None and info.authorities == []


# ── bounded signature check (fake runner, the real command policy) ───


def _runner(verify: tuple[int, bytes], display: tuple[int, bytes] | None) -> FakeRunner:
    runner = FakeRunner()
    runner.add(codesign_argv("verify", APP), stderr_result(codesign_argv("verify", APP), *verify))
    if display is not None:
        argv = codesign_argv("display", APP)
        runner.add(argv, stderr_result(argv, *display))
    return runner


def test_unsigned_bundle() -> None:
    sig = check_signature(
        _runner((1, fixture_bytes("software/codesign_verify_unsigned.txt")), None),
        APP,
        timeout=5,
    )
    assert sig.signed is False and sig.signature_type == "unsigned" and sig.valid is None
    assert sig.attributes()["signed"] is False and not sig.retry


def test_developer_id_bundle_verifies() -> None:
    sig = check_signature(
        _runner((0, b""), (0, fixture_bytes("software/codesign_display_developer_id.txt"))),
        APP,
        timeout=5,
    )
    assert sig.signed is True and sig.valid is True and sig.signature_type == "developer_id"
    attrs = sig.attributes()
    assert attrs["signature_team_id"] == "EXAMPLE001"
    assert attrs["signature_authority"].startswith("Developer ID Application:")


def test_adhoc_and_apple_platform_types() -> None:
    adhoc = check_signature(
        _runner((0, b""), (0, fixture_bytes("software/codesign_display_adhoc.txt"))),
        APP,
        timeout=5,
    )
    assert adhoc.signed is True and adhoc.signature_type == "adhoc" and adhoc.team_id is None
    apple = check_signature(
        _runner((0, b""), (0, fixture_bytes("software/codesign_display_apple_platform.txt"))),
        APP,
        timeout=5,
    )
    assert apple.signature_type == "apple_platform"


def test_tampered_bundle_is_signed_but_invalid() -> None:
    sig = check_signature(
        _runner(
            (1, fixture_bytes("software/codesign_verify_tampered.txt")),
            (0, fixture_bytes("software/codesign_display_adhoc.txt")),
        ),
        APP,
        timeout=5,
    )
    assert sig.signed is True and sig.valid is False and not sig.retry
    assert "invalid signature" in (sig.error or "")


def test_missing_sealed_resource_is_retried_and_timeout_is_unknown() -> None:
    # Shape of `codesign --verify` on a bundle still being copied.
    half = check_signature(
        _runner(
            (1, b"/Applications/ExtorQ Test.app: a sealed resource is missing or invalid\n"),
            (0, fixture_bytes("software/codesign_display_adhoc.txt")),
        ),
        APP,
        timeout=5,
    )
    assert half.valid is False and half.retry
    runner = FakeRunner()
    argv = codesign_argv("verify", APP)
    runner.add(argv, CommandResult(tuple(argv), None, b"", b"", 5.0, timed_out=True))
    unknown = check_signature(runner, APP, timeout=5)
    assert unknown.signed is None and unknown.attributes()["signed"] == "unknown"


def test_codesign_policy_admits_only_read_only_calls_on_app_bundles() -> None:
    validate_argv(codesign_argv("verify", APP))
    validate_argv(codesign_argv("display", "/Users/testuser/Applications/Tool.app"))
    validate_argv(codesign_argv("verify", "/Applications/Utilities/Terminal.app"))
    for argv in (
        ["/usr/bin/codesign", "-s", "-", APP],
        ["/usr/bin/codesign", "--remove-signature", APP],
        ["/usr/bin/codesign", "--verify", "--strict", "/tmp/x.app"],
        ["/usr/bin/codesign", "--verify", "--strict", "/Applications/../tmp/x.app"],
        ["/usr/bin/codesign", "--verify", "--strict", "/Applications/a/b/c.app"],
        ["/usr/bin/codesign", "--verify", "--strict", "/Applications/Tool"],
        ["/usr/bin/codesign", "--verify", APP],
    ):
        with pytest.raises(CommandValidationError):
            validate_argv(argv)
    # A path outside the policy never crashes the source: the result is "unknown".
    sig = check_signature(FakeRunner(), "/tmp/elsewhere.app", timeout=5)
    assert sig.signed is None and "policy" in (sig.error or "")


# ── scanning ─────────────────────────────────────────────────────────


def test_scan_finds_top_level_and_nested_bundles(tmp_path: Path) -> None:
    root = tmp_path / "Applications"
    make_bundle(root / "Top.app", "com.example.top")
    make_bundle(root / "Utilities" / "Nested.app", "com.example.nested")
    make_bundle(root / "Utilities" / "Deep" / "TooDeep.app", "com.example.deep")
    (root / "notes.txt").write_text("not a bundle")
    (root / "NoInfo.app" / "Contents").mkdir(parents=True)
    (root / "Broken.app" / "Contents").mkdir(parents=True)
    (root / "Broken.app" / "Contents" / "Info.plist").write_bytes(b"<plist><dict><key>")
    os.symlink(root / "Top.app", root / "Alias.app")
    result = scan_locations([AppLocation(root, "system")])
    names = sorted(os.path.relpath(p, root) for p in result.bundles)
    assert names == ["Alias.app", "Broken.app", "NoInfo.app", "Top.app", "Utilities/Nested.app"]
    top = result.bundles[str(root / "Top.app")]
    assert top.bundle_id == "com.example.top" and top.info["version"] == "1.0"
    assert top.info["build_version"] == "7" and top.info_sha256 is not None
    assert result.bundles[str(root / "NoInfo.app")].info_error == "Info.plist missing"
    assert result.bundles[str(root / "Broken.app")].info_error.startswith("Info.plist invalid")
    alias = result.bundles[str(root / "Alias.app")]
    assert alias.is_symlink and alias.bundle_id == "com.example.top"
    assert scan_locations([AppLocation(tmp_path / "absent", "user")]).bundles == {}


def test_settling_uses_inode_change_time(tmp_path: Path) -> None:
    bundle = read_bundle(make_bundle(tmp_path / "New.app", "com.example.new"), "system")
    assert bundle.changed_at is not None
    assert not settled(bundle, bundle.changed_at + 5, 30)
    assert settled(bundle, bundle.changed_at + 31, 30)
    assert not settled(bundle, bundle.changed_at - 1, 30)  # bounded by max_defer_scans


def test_events_satisfy_the_catalog(tmp_path: Path, src: SourceContext) -> None:
    bundle = read_bundle(make_bundle(tmp_path / "New.app", "com.example.new"), "system")
    sig = check_signature(
        _runner((1, fixture_bytes("software/codesign_verify_unsigned.txt")), None),
        APP,
        timeout=5,
    )
    installed = event_for(
        Change("installed", bundle.path, bundle, None), src, observed_at=_now(), snapshot="s"
    )
    assert installed.attributes["signed"] == "unknown"  # no signature passed: not checked
    installed = event_for(
        Change("installed", bundle.path, bundle, None),
        src,
        observed_at=_now(),
        snapshot="s",
        signature=sig,
    )
    removed = event_for(
        Change("removed", bundle.path, None, bundle.summary()),
        src,
        observed_at=_now(),
        snapshot="s2",
    )
    for event in (installed, removed):
        assert event.source.source_type.value == "macos.inventory"
        assert (
            validate_event_semantics(
                event.event_type, event.category.value, event.source.source_type.value
            )
            is None
        )
        assert event.resource is not None and event.resource.path == bundle.path
        assert event.attributes["bundle_id"] == "com.example.new"
    assert installed.event_type == "software.installed"
    assert installed.attributes["signed"] is False
    assert installed.attributes["signature_type"] == "unsigned"
    assert installed.attributes["version"] == "1.0"
    assert removed.event_type == "software.removed"


def _now() -> datetime:
    return datetime(2026, 11, 22, 12, 0, tzinfo=UTC)


# ── collector cycles ─────────────────────────────────────────────────


@pytest.fixture
def tmp_policy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Admit codesign on the test's temporary application folder (the real policy only
    admits /Applications and ~/Applications); everything else about the policy stays."""
    root = re.escape(str(tmp_path / "Applications"))
    monkeypatch.setattr(
        commands_mod, "_APP_BUNDLE", re.compile(rf"^{root}/(?:[^/]{{1,255}}/)?[^/]{{1,255}}\.app$")
    )


def _software_events(records: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [d for kind, d in records if kind == "event" and d["event_type"].startswith("software.")]


def _unsigned(h: Harness, path: Path) -> None:
    argv = codesign_argv("verify", str(path))
    h.runner.add(argv, failed(argv, 1, f"{path}: code object is not signed at all\n".encode()))


def test_install_and_removal_after_baseline(tmp_path: Path, tmp_policy: None) -> None:
    h = Harness(tmp_path, settings={"software": {"settle_seconds": 0}})
    make_bundle(h.applications / "Existing.app", "com.example.existing")
    assert _software_events(h.cycle()) == []  # baseline: nothing is "installed"
    test_app = make_bundle(h.applications / "ExtorQ Test.app", "com.extorq.test.app")
    _unsigned(h, test_app)
    (installed,) = _software_events(h.cycle())
    assert installed["event_type"] == "software.installed"
    assert installed["resource"]["path"] == str(test_app)
    attrs = installed["attributes"]
    assert attrs["bundle_id"] == "com.extorq.test.app" and attrs["signed"] is False
    assert attrs["signature_type"] == "unsigned" and attrs["scope"] == "system"
    # A version update of a known bundle is not an installation.
    make_bundle(h.applications / "Existing.app", "com.example.existing", version="2.0")
    assert _software_events(h.cycle()) == []
    shutil.rmtree(test_app)
    (removed,) = _software_events(h.cycle())
    assert removed["event_type"] == "software.removed"
    assert removed["attributes"]["bundle_id"] == "com.extorq.test.app"


def test_replaced_bundle_is_reported_as_installed(tmp_path: Path, tmp_policy: None) -> None:
    h = Harness(tmp_path, settings={"software": {"settle_seconds": 0}})
    app = make_bundle(h.applications / "Tool.app", "com.example.tool")
    h.cycle()
    make_bundle(app, "com.example.impostor")
    _unsigned(h, app)
    (event,) = _software_events(h.cycle())
    assert event["event_type"] == "software.installed"
    assert event["attributes"]["replaced"] is True
    assert event["attributes"]["previous_bundle_id"] == "com.example.tool"


def test_unsettled_bundle_waits_but_not_forever(tmp_path: Path, tmp_policy: None) -> None:
    h = Harness(tmp_path, settings={"software": {"settle_seconds": 600, "max_defer_scans": 2}})
    h.cycle()
    app = make_bundle(h.applications / "Slow Copy.app", "com.example.slow")
    _unsigned(h, app)
    assert _software_events(h.cycle()) == []  # just written: deferred (1)
    assert _software_events(h.cycle()) == []  # deferred (2)
    (event,) = _software_events(h.cycle())  # bound reached: reported anyway
    assert event["attributes"]["signed"] is False


def test_retryable_verification_failure_is_checked_again(tmp_path: Path, tmp_policy: None) -> None:
    h = Harness(tmp_path, settings={"software": {"settle_seconds": 0}})
    h.cycle()
    app = make_bundle(h.applications / "Copying.app", "com.example.copying")
    verify, display = codesign_argv("verify", str(app)), codesign_argv("display", str(app))
    h.runner.add(verify, failed(verify, 1, b"a sealed resource is missing or invalid\n"))
    h.runner.add(display, ok(display, b"", fixture_bytes("software/codesign_display_adhoc.txt")))
    assert _software_events(h.cycle()) == []  # looks half-copied: retried next scan
    h.runner.add(verify, ok(verify, b""))
    (event,) = _software_events(h.cycle())
    assert event["attributes"]["signed"] is True and event["attributes"]["signature_valid"] is True
    assert event["attributes"]["signature_type"] == "adhoc"

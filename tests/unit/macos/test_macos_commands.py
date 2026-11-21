"""Command execution policy, bounded execution, kernel paths and settings validation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from extorq_collectors.macos.commands import (
    ALLOWED_EXECUTABLES,
    CommandValidationError,
    run_command,
    validate_argv,
)
from extorq_collectors.macos.procinfo import pid_path
from extorq_collectors.macos.settings import MacOSSettings
from extorq_collectors.sdk.config import load_collector_configs

darwin = pytest.mark.skipif(sys.platform != "darwin", reason="macOS only")


@pytest.mark.parametrize(
    "argv",
    [
        ["/bin/launchctl", "print", "system"],
        ["/bin/launchctl", "print", "gui/501"],
        ["/bin/launchctl", "print", "system/com.openssh.sshd"],
        ["/bin/launchctl", "print-disabled", "system"],
        ["/usr/bin/defaults", "export", "/Library/Preferences/com.apple.SoftwareUpdate", "-"],
        ["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"],
        ["/usr/sbin/sysctl", "-n", "hw.model"],
        ["/usr/bin/csrutil", "authenticated-root", "status"],
        ["/usr/bin/log", "show", "--style", "ndjson"],
    ],
)
def test_read_only_commands_are_allowed(argv: list[str]) -> None:
    assert validate_argv(argv) == tuple(argv)


@pytest.mark.parametrize(
    "argv",
    [
        ["/bin/launchctl", "load", "/tmp/x.plist"],
        ["/bin/launchctl", "bootstrap", "gui/501", "/tmp/x.plist"],
        ["/bin/launchctl", "kickstart", "-k", "system/com.openssh.sshd"],
        ["/bin/launchctl", "print", "system; rm -rf /"],
        ["/usr/bin/defaults", "write", "com.apple.x", "k", "v"],
        ["/usr/bin/dscl", ".", "-create", "/Users/x"],
        ["/usr/bin/dscl", ".", "-passwd", "/Users/x"],
        ["/usr/sbin/sysctl", "-w", "kern.x=1"],
        ["/usr/sbin/sysctl", "-n", "kern.securelevel=0"],
        ["/usr/bin/csrutil", "disable"],
        ["/usr/bin/fdesetup", "disable"],
        ["/usr/sbin/spctl", "--master-disable"],
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off"],
        ["/usr/bin/log", "erase", "--all"],
        ["/bin/sh", "-c", "id"],
        ["log", "show"],
        ["/usr/bin/sw_vers", "bad\x00arg"],
    ],
)
def test_mutating_or_unknown_commands_are_refused(argv: list[str]) -> None:
    with pytest.raises(CommandValidationError):
        validate_argv(argv)


def test_policy_rejects_non_list_input() -> None:
    with pytest.raises(CommandValidationError):
        validate_argv("/usr/bin/sw_vers")  # type: ignore[arg-type]
    with pytest.raises(CommandValidationError):
        validate_argv([])
    assert all(p.startswith("/") for p in ALLOWED_EXECUTABLES)


@darwin
def test_run_command_success_and_output_bound() -> None:
    result = run_command(["/usr/bin/sw_vers"], timeout=10)
    assert result.ok and b"ProductVersion" in result.stdout
    bounded = run_command(["/bin/ps", "-axww", "-o", "pid=,comm="], timeout=10, max_stdout=64)
    assert bounded.stdout_truncated and not bounded.ok and len(bounded.stdout) <= 64
    assert "output limit exceeded" in bounded.summary()


def test_run_command_uses_a_minimal_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    from extorq_collectors.macos import commands

    monkeypatch.setenv("EXTORQ_TEST_SECRET", "must-not-leak")
    seen: dict[str, object] = {}

    class Capture(Exception):
        pass

    def fake_popen(args: object, **kwargs: object) -> None:
        seen.update(kwargs, args=args)
        raise Capture

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    with pytest.raises(Capture):
        commands.run_command(["/usr/bin/sw_vers"], timeout=5)
    assert seen["env"] == commands.SAFE_ENV and "EXTORQ_TEST_SECRET" not in seen["env"]  # type: ignore[operator]
    assert seen["stdin"] is subprocess.DEVNULL and seen["start_new_session"] is True
    assert "shell" not in seen and seen["args"] == ("/usr/bin/sw_vers",)


@darwin
def test_kernel_reported_executable_path() -> None:
    assert pid_path(1) == "/sbin/launchd"
    assert pid_path(os.getpid()) is not None
    assert pid_path(-5) is None and pid_path(0) is None


def test_settings_reject_unknown_keys_and_producers() -> None:
    with pytest.raises(ValueError):
        MacOSSettings.from_mapping({"unified_log": {"predicate": "anything"}})
    with pytest.raises(ValueError):
        MacOSSettings.from_mapping({"unified_log": {"producers": ["sudo", "evil"]}})
    with pytest.raises(ValueError):
        MacOSSettings.from_mapping({"posture": {"interval_seconds": 1}})
    with pytest.raises(ValueError, match="overlap_seconds"):
        MacOSSettings.from_mapping(
            {"unified_log": {"overlap_seconds": 60, "max_window_seconds": 60}}
        )
    with pytest.raises(ValueError):
        MacOSSettings.from_mapping({"unified_log": {"initial_lookback_seconds": 0}})
    defaults = MacOSSettings.from_mapping(None)
    assert defaults.inventory.include_process_args is False
    assert defaults.asset.hostname is None


def test_shipped_config_loads_through_the_sdk() -> None:
    root = Path(__file__).resolve().parents[3]
    configs = load_collector_configs(root / "config" / "collectors", include_disabled=True)
    macos = next(c for c in configs if c.collector_id == "macos-workstation-01")
    assert macos.module == "extorq_collectors.macos.collector:MacOSCollector"
    settings = MacOSSettings.from_mapping(macos.settings)
    assert settings.unified_log.interval_seconds == 60
    assert settings.launchd.interval_seconds == 60
    assert settings.posture.interval_seconds == 300
    assert settings.inventory.interval_seconds == 300
    assert settings.applications.interval_seconds == 3600

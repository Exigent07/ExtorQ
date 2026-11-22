"""macOS security posture checks (scanner ``extorq-posture-macos``).

Every check uses a supported, non-privileged interface and a fixed command:

* FileVault: ``fdesetup status``
* SIP and authenticated root (SSV): ``csrutil status``, ``csrutil authenticated-root status``
* Application Firewall and stealth mode: ``socketfilterfw --getglobalstate``,
  ``--getstealthmode``, ``--getallowsigned``
* Gatekeeper: ``spctl --status``
* Automatic / pending updates:
  ``defaults export /Library/Preferences/com.apple.SoftwareUpdate -``
* App Store automatic updates: ``defaults export /Library/Preferences/com.apple.commerce -``
* Guest account: ``defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled``
  (only that key is read; the domain also holds user names)
* Admin group: ``dscl . -read /Groups/admin GroupMembership``
* Sharing exposure: derived from listening sockets (netstat, lsof fallback);
  ``systemsetup`` would need admin rights and is not used
* OS version / model: ``sw_vers`` / ``sysctl -n hw.model``

Results: ``pass``, ``fail`` (a PostureFinding is emitted), ``not_set`` (the
preference key is absent: ExtorQ does not guess OS defaults; no finding) or
``error`` (the command failed or produced unrecognised output; the ScanRun
becomes ``partial`` so earlier findings are never resolved by an incomplete scan).
"""

from __future__ import annotations

import plistlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from extorq.contracts import (
    FindingCategory,
    Outcome,
    PostureFinding,
    Resource,
    ScanCoverage,
    ScanRun,
    ScanScope,
    ScanStatus,
    SecurityEvent,
    Severity,
    SkippedCheck,
    SourceType,
)
from extorq.contracts.identity import finding_id, scope_hash, stable_id
from extorq_collectors.macos.commands import CommandResult, CommandRunner
from extorq_collectors.macos.common import (
    COLLECTOR_VERSION,
    SourceContext,
    bounded_attributes,
    clean_text,
    make_event,
    to_ms,
)
from extorq_collectors.macos.inventory import Listener, ListenerSnapshot, collect_listeners

SCANNER = "extorq-posture-macos"
SCANNER_VERSION = COLLECTOR_VERSION
PARSER = "macos-posture"
SOURCE = SourceType.MACOS_POSTURE
CONFIG_SCOPE = ("configuration", "macOS host configuration posture (non-privileged checks)")
EXPOSURE_SCOPE = ("exposure", "macOS network exposure posture (listening sockets)")

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"
COMMANDS: dict[str, list[str]] = {
    "fdesetup": ["/usr/bin/fdesetup", "status"],
    "csrutil": ["/usr/bin/csrutil", "status"],
    "csrutil_authroot": ["/usr/bin/csrutil", "authenticated-root", "status"],
    "fw_global": [SOCKETFILTERFW, "--getglobalstate"],
    "fw_stealth": [SOCKETFILTERFW, "--getstealthmode"],
    "fw_allowsigned": [SOCKETFILTERFW, "--getallowsigned"],
    "spctl": ["/usr/sbin/spctl", "--status"],
    "su_prefs": [
        "/usr/bin/defaults",
        "export",
        "/Library/Preferences/com.apple.SoftwareUpdate",
        "-",
    ],
    "commerce_prefs": [
        "/usr/bin/defaults",
        "export",
        "/Library/Preferences/com.apple.commerce",
        "-",
    ],
    "guest": [
        "/usr/bin/defaults",
        "read",
        "/Library/Preferences/com.apple.loginwindow",
        "GuestEnabled",
    ],
    "admins": ["/usr/bin/dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
    "sw_vers": ["/usr/bin/sw_vers"],
    "hw_model": ["/usr/sbin/sysctl", "-n", "hw.model"],
}
#: System accounts that are members of ``admin`` on every Mac (not counted as human admins).
SYSTEM_ADMIN_ACCOUNTS = frozenset({"root", "_mbsetupuser"})

CIS = "https://www.cisecurity.org/benchmark/apple_os"

# ── pure parsers ─────────────────────────────────────────────────────


def parse_fdesetup(text: str) -> str | None:
    lowered = text.lower()
    if "decryption in progress" in lowered:
        return "decrypting"
    if "encryption in progress" in lowered:
        return "encrypting"
    if "filevault is on" in lowered:
        return "on"
    if "filevault is off" in lowered:
        return "off"
    return None


def parse_csrutil(text: str) -> str | None:
    match = re.search(r"System Integrity Protection status:\s*([^.\n]+)", text)
    if not match:
        return None
    value = match.group(1).strip().lower()
    if value.startswith("enabled"):
        return "enabled"
    if value.startswith("disabled"):
        return "disabled"
    if "custom" in value or value.startswith("unknown"):
        return "custom"
    return None


def parse_authenticated_root(text: str) -> str | None:
    match = re.search(r"Authenticated Root status:\s*(\w+)", text)
    if not match:
        return None
    value = match.group(1).lower()
    return value if value in ("enabled", "disabled") else None


def parse_firewall_global(text: str) -> str | None:
    state = re.search(r"\(State\s*=\s*(\d)\)", text)
    if state:
        return {"0": "disabled", "1": "enabled", "2": "block_all"}.get(state.group(1))
    lowered = text.lower()
    if "firewall is disabled" in lowered:
        return "disabled"
    if "firewall is enabled" in lowered:
        return "enabled"
    return None


def parse_firewall_stealth(text: str) -> str | None:
    lowered = text.lower()
    if re.search(r"stealth mode is on|stealth mode enabled", lowered):
        return "on"
    if re.search(r"stealth mode is off|stealth mode disabled", lowered):
        return "off"
    return None


def parse_firewall_allowsigned(text: str) -> tuple[bool | None, bool | None]:
    builtin = re.search(r"built-in signed software (ENABLED|DISABLED)", text)
    downloaded = re.search(r"downloaded signed software (ENABLED|DISABLED)", text)
    return (
        builtin.group(1) == "ENABLED" if builtin else None,
        downloaded.group(1) == "ENABLED" if downloaded else None,
    )


def parse_spctl(text: str) -> str | None:
    lowered = text.strip().lower()
    if "assessments enabled" in lowered:
        return "enabled"
    if "assessments disabled" in lowered:
        return "disabled"
    return None


def parse_plist_export(data: bytes) -> dict[str, Any]:
    parsed = plistlib.loads(data)
    if not isinstance(parsed, dict):
        raise ValueError("preference export is not a dictionary")
    return parsed


def parse_guest(result: CommandResult) -> str | None:
    """``defaults read ... GuestEnabled``: ``0``/``1``; missing key -> ``None``."""
    if result.returncode != 0:
        return None
    value = result.text().strip()
    if value == "1":
        return "enabled"
    if value == "0":
        return "disabled"
    return None


def parse_dscl_members(text: str) -> list[str] | None:
    match = re.search(r"^GroupMembership:(.*)$", text, re.MULTILINE)
    if match:
        return sorted(set(match.group(1).split()))
    if "No such key" in text:
        return []
    return None


def parse_sw_vers(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            out[key.strip()] = value.strip()
    return out


_MSU_KEY = re.compile(
    r"^MSU_UPDATE_(?P<build>[0-9A-Za-z]+)_[a-z]+_(?P<version>\d+(?:\.\d+){0,3})_(?P<kind>[a-z]+)$"
)


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split(".") if p.isdigit())


def offered_os_updates(
    prefs: Mapping[str, Any], current_version: str | None, now: datetime
) -> list[dict[str, Any]]:
    """macOS updates offered (per SoftwareUpdate preferences) but newer than the running OS.

    Derived from ``FirstOfferDateDictionary`` keys such as
    ``MSU_UPDATE_26B131_patch_27.2.1_minor``. These keys are undocumented; the
    result reflects the last background catalog scan, not a live query.
    """
    offers = prefs.get("FirstOfferDateDictionary")
    if not isinstance(offers, dict) or not current_version:
        return []
    installed = prefs.get("InstallDateDictionary")
    installed_builds = set(installed) if isinstance(installed, dict) else set()
    current = _version_tuple(current_version)
    out: list[dict[str, Any]] = []
    for key, offered_at in offers.items():
        match = _MSU_KEY.match(str(key))
        if not match:
            continue
        version = match.group("version")
        if _version_tuple(version) <= current or match.group("build") in installed_builds:
            continue
        offered_dt = (
            offered_at.replace(tzinfo=UTC)
            if isinstance(offered_at, datetime) and offered_at.tzinfo is None
            else offered_at
        )
        days = None
        if isinstance(offered_dt, datetime):
            days = max(0, (now - offered_dt).days)
        out.append(
            {
                "version": version,
                "build": match.group("build"),
                "kind": match.group("kind"),
                "days_offered": days,
            }
        )
    out.sort(key=lambda o: _version_tuple(o["version"]), reverse=True)
    return out


# ── results ──────────────────────────────────────────────────────────


@dataclass(slots=True)
class CheckResult:
    check_id: str
    title: str
    status: str  # pass | fail | not_set | error
    severity: Severity
    category: FindingCategory = FindingCategory.POSTURE
    setting: str | None = None
    value: Any = None
    evidence: str | None = None
    description: str | None = None
    remediation: str | None = None
    references: tuple[str, ...] = ()
    resource_key: str = "host"
    qualifier: str = ""
    error: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PostureRun:
    started_at: datetime
    finished_at: datetime
    results: list[CheckResult]
    settings: dict[str, Any]
    os_info: dict[str, str | None]
    listeners: dict[str, Listener]
    command_errors: list[str]
    #: netstat (full) | lsof (current user's processes only) | unavailable
    listener_method: str = "unavailable"

    @property
    def check_ids(self) -> list[str]:
        return sorted({r.check_id for r in self.results})


# Check catalogue: id -> (title, severity, description, remediation)
CHECKS: dict[str, tuple[str, Severity, str, str]] = {
    "macos.filevault.enabled": (
        "FileVault disk encryption is not enabled",
        Severity.HIGH,
        "The startup volume is not protected by FileVault; data at rest is readable if the "
        "device is lost or stolen.",
        "Enable FileVault in System Settings > Privacy & Security > FileVault.",
    ),
    "macos.sip.enabled": (
        "System Integrity Protection is not fully enabled",
        Severity.HIGH,
        "SIP protects system files and processes from modification, including by root.",
        "Re-enable SIP from Recovery: csrutil enable.",
    ),
    "macos.ssv.authenticated_root": (
        "Signed System Volume (authenticated root) is disabled",
        Severity.HIGH,
        "The sealed system volume is no longer cryptographically verified at boot.",
        "Re-enable from Recovery: csrutil authenticated-root enable.",
    ),
    "macos.firewall.enabled": (
        "Application Firewall is disabled",
        Severity.MEDIUM,
        "The macOS Application Firewall is off, so every listening service is reachable "
        "from connected networks.",
        "Enable the firewall in System Settings > Network > Firewall.",
    ),
    "macos.firewall.stealth_mode": (
        "Firewall stealth mode is disabled",
        Severity.LOW,
        "The host answers probes (ICMP echo, closed-port responses) that reveal its presence.",
        "Enable stealth mode in Firewall Options.",
    ),
    "macos.gatekeeper.enabled": (
        "Gatekeeper assessments are disabled",
        Severity.HIGH,
        "Downloaded applications are not checked for a valid signature or notarisation.",
        "Run 'spctl --master-enable' as an administrator.",
    ),
    "macos.softwareupdate.automatic_check": (
        "Automatic checking for software updates is disabled",
        Severity.MEDIUM,
        "AutomaticCheckEnabled is false in com.apple.SoftwareUpdate.",
        "Enable automatic update checks in System Settings > General > Software Update.",
    ),
    "macos.softwareupdate.critical_update_install": (
        "Automatic security responses / system data files are disabled",
        Severity.MEDIUM,
        "CriticalUpdateInstall is false: Rapid Security Responses and system data files are "
        "not installed automatically.",
        "Enable 'Install Security Responses and system files'.",
    ),
    "macos.softwareupdate.config_data_install": (
        "Automatic XProtect / configuration data updates are disabled",
        Severity.MEDIUM,
        "ConfigDataInstall is false: XProtect and other security configuration data are not "
        "updated automatically.",
        "Enable 'Install Security Responses and system files'.",
    ),
    "macos.softwareupdate.automatic_download": (
        "Automatic download of updates is disabled",
        Severity.LOW,
        "AutomaticDownload is false in com.apple.SoftwareUpdate.",
        "Enable 'Download new updates when available'.",
    ),
    "macos.softwareupdate.automatic_macos_install": (
        "Automatic installation of macOS updates is disabled",
        Severity.LOW,
        "AutomaticallyInstallMacOSUpdates is false in com.apple.SoftwareUpdate.",
        "Enable 'Install macOS updates'.",
    ),
    "macos.softwareupdate.os_update_pending": (
        "A newer macOS version has been offered but is not installed",
        Severity.LOW,
        "Derived from the SoftwareUpdate preference FirstOfferDateDictionary (undocumented "
        "keys, last background scan).",
        "Install the pending macOS update.",
    ),
    "macos.softwareupdate.recommended_pending": (
        "Recommended software updates are pending",
        Severity.LOW,
        "RecommendedUpdates (cached result of the last background scan) is not empty.",
        "Install the pending updates in System Settings > General > Software Update.",
    ),
    "macos.appstore.auto_update": (
        "App Store automatic app updates are disabled",
        Severity.LOW,
        "AutoUpdate is false in com.apple.commerce.",
        "Enable automatic updates in the App Store settings.",
    ),
    "macos.accounts.guest_enabled": (
        "Guest account is enabled",
        Severity.MEDIUM,
        "GuestEnabled is true in com.apple.loginwindow.",
        "Disable the guest user in System Settings > Users & Groups.",
    ),
    "macos.accounts.admin_count": (
        "More administrator accounts than expected",
        Severity.MEDIUM,
        "The admin group has more non-system members than the configured maximum.",
        "Review admin group membership; use standard accounts for daily work.",
    ),
    "macos.sharing.remote_login": (
        "Remote Login (SSH) is exposed on the network",
        Severity.MEDIUM,
        "A process listens on TCP port 22 on a non-loopback address.",
        "Disable Remote Login in System Settings > General > Sharing unless required.",
    ),
    "macos.sharing.screen_sharing": (
        "Screen Sharing (VNC) is exposed on the network",
        Severity.MEDIUM,
        "A process listens on TCP port 5900 on a non-loopback address.",
        "Disable Screen Sharing in System Settings > General > Sharing unless required.",
    ),
    "macos.sharing.remote_management": (
        "Remote Management (ARD) is exposed on the network",
        Severity.MEDIUM,
        "A process listens on port 3283 on a non-loopback address.",
        "Disable Remote Management in System Settings > General > Sharing unless required.",
    ),
    "macos.sharing.file_sharing_smb": (
        "File Sharing (SMB) is exposed on the network",
        Severity.MEDIUM,
        "A process listens on TCP port 445 on a non-loopback address.",
        "Disable File Sharing in System Settings > General > Sharing unless required.",
    ),
    "macos.sharing.airplay_receiver": (
        "AirPlay Receiver is exposed on the network",
        Severity.LOW,
        "ControlCenter listens on TCP 7000/5000 on a non-loopback address (AirPlay Receiver).",
        "Disable AirPlay Receiver in System Settings > General > AirDrop & Handoff.",
    ),
    "macos.network.exposed_listener": (
        "TCP service listening on a non-loopback address",
        Severity.LOW,
        "A TCP listener is bound to a wildcard or external address and is reachable from "
        "connected networks (subject to the Application Firewall state).",
        "Bind the service to 127.0.0.1 or stop it if it is not needed.",
    ),
}

_NAMED_PORTS: dict[str, tuple[set[int], set[str]]] = {
    "macos.sharing.remote_login": ({22}, {"tcp"}),
    "macos.sharing.screen_sharing": ({5900}, {"tcp"}),
    "macos.sharing.remote_management": ({3283}, {"tcp", "udp"}),
    "macos.sharing.file_sharing_smb": ({445}, {"tcp"}),
}


def _result(
    check_id: str,
    status: str,
    *,
    setting: str | None = None,
    value: Any = None,
    evidence: str | None = None,
    error: str | None = None,
    resource_key: str = "host",
    qualifier: str = "",
    category: FindingCategory = FindingCategory.POSTURE,
    attributes: Mapping[str, Any] | None = None,
    severity: Severity | None = None,
) -> CheckResult:
    title, default_severity, description, remediation = CHECKS[check_id]
    return CheckResult(
        check_id=check_id,
        title=title,
        status=status,
        severity=severity or default_severity,
        category=category,
        setting=setting,
        value=value,
        evidence=evidence,
        description=description,
        remediation=remediation,
        references=(CIS,),
        resource_key=resource_key,
        qualifier=qualifier,
        error=error,
        attributes=dict(attributes or {}),
    )


def _cmd_error(result: CommandResult) -> str:
    return result.summary()


def evaluate_simple(
    check_id: str,
    setting: str,
    result: CommandResult,
    parse: Callable[[str], str | None],
    passing: set[str],
) -> CheckResult:
    if result.error or result.timed_out:
        return _result(check_id, "error", setting=setting, error=_cmd_error(result))
    text = result.text().strip()
    value = parse(text)
    evidence, _ = clean_text(text, 512)
    if value is None:
        return _result(
            check_id,
            "error",
            setting=setting,
            evidence=evidence,
            error=f"unrecognised output (exit {result.returncode})",
        )
    return _result(
        check_id,
        "pass" if value in passing else "fail",
        setting=setting,
        value=value,
        evidence=evidence,
    )


def evaluate_preference_bool(
    check_id: str,
    setting: str,
    prefs: Mapping[str, Any] | None,
    key: str,
    domain: str,
    error: str | None,
) -> CheckResult:
    if prefs is None:
        return _result(check_id, "error", setting=setting, error=error or "preferences unavailable")
    if key not in prefs:
        return _result(
            check_id,
            "not_set",
            setting=setting,
            value=None,
            evidence=f"{domain} {key}: not set (OS default applies; not inferred)",
        )
    raw = prefs[key]
    if isinstance(raw, bool):
        value = raw
    elif isinstance(raw, int):
        value = raw != 0
    else:
        return _result(
            check_id,
            "error",
            setting=setting,
            error=f"{key} has unexpected type {type(raw).__name__}",
        )
    return _result(
        check_id,
        "pass" if value else "fail",
        setting=setting,
        value=value,
        evidence=f"{domain} {key} = {int(value)}",
    )


def evaluate_exposure(
    listeners: Mapping[str, Listener],
    firewall_state: str | None,
    airplay_process: str = "ControlCenter",
    *,
    full_visibility: bool = True,
) -> list[CheckResult]:
    """Exposure checks from listening sockets.

    With ``full_visibility=False`` (lsof fallback: only the current user's
    sockets are visible) absence of a listener proves nothing: the root-service
    checks report ``error`` and the generic check adds an ``error`` result, so the
    exposure ScanRun is ``partial`` and never resolves earlier findings.
    """
    results: list[CheckResult] = []
    named_keys: set[str] = set()
    exposed = {k: v for k, v in listeners.items() if v.exposed}
    restricted = "socket table withheld; root-owned listeners are not visible (lsof fallback)"
    for check_id, (ports, protocols) in _NAMED_PORTS.items():
        hits = sorted(k for k, v in exposed.items() if v.port in ports and v.protocol in protocols)
        named_keys.update(hits)
        setting = check_id.rsplit(".", 1)[1] + "_exposed"
        if not hits and not full_visibility:
            results.append(
                _result(
                    check_id,
                    "error",
                    setting=setting,
                    category=FindingCategory.EXPOSURE,
                    error=restricted,
                )
            )
            continue
        if hits:
            procs = sorted({p for k in hits for p in exposed[k].processes})
            results.append(
                _result(
                    check_id,
                    "fail",
                    setting=setting,
                    value=True,
                    category=FindingCategory.EXPOSURE,
                    evidence=f"listening: {', '.join(hits)}"
                    + (f" ({', '.join(procs)})" if procs else ""),
                    attributes={
                        "listeners": hits,
                        "processes": procs or None,
                        "application_firewall": firewall_state,
                    },
                )
            )
        else:
            results.append(
                _result(
                    check_id,
                    "pass",
                    setting=setting,
                    value=False,
                    category=FindingCategory.EXPOSURE,
                )
            )
    # AirPlay Receiver (ControlCenter) listens on TCP 7000 and 5000.
    airplay = sorted(
        k
        for k, v in exposed.items()
        if v.protocol == "tcp" and v.port in (7000, 5000) and airplay_process in v.processes
    )
    named_keys.update(airplay)
    if airplay:
        results.append(
            _result(
                "macos.sharing.airplay_receiver",
                "fail",
                setting="airplay_receiver_exposed",
                value=True,
                category=FindingCategory.EXPOSURE,
                evidence=f"listening: {', '.join(airplay)} ({airplay_process})",
                attributes={"listeners": airplay, "application_firewall": firewall_state},
            )
        )
    else:
        # ControlCenter runs as the logged-in user, so lsof sees it even in fallback mode.
        results.append(
            _result(
                "macos.sharing.airplay_receiver",
                "pass",
                setting="airplay_receiver_exposed",
                value=False,
                category=FindingCategory.EXPOSURE,
            )
        )
    generic = sorted(k for k, v in exposed.items() if v.protocol == "tcp" and k not in named_keys)
    for key in generic:
        listener = exposed[key]
        procs = sorted(listener.processes)
        results.append(
            _result(
                "macos.network.exposed_listener",
                "fail",
                category=FindingCategory.EXPOSURE,
                resource_key=key,
                qualifier=key,
                evidence=f"{key} bound to {listener.address} (exposure {listener.exposure})"
                + (f" by {', '.join(procs)}" if procs else " (process attribution unavailable)"),
                attributes={
                    "listener": key,
                    "processes": procs or None,
                    "executables": sorted(listener.executables) or None,
                    "exposure": listener.exposure,
                    "application_firewall": firewall_state,
                },
            )
        )
    if not full_visibility:
        results.append(
            _result(
                "macos.network.exposed_listener",
                "error",
                category=FindingCategory.EXPOSURE,
                qualifier="root-owned",
                error=restricted,
            )
        )
    elif not generic:
        results.append(
            _result("macos.network.exposed_listener", "pass", category=FindingCategory.EXPOSURE)
        )
    return results


@dataclass(frozen=True, slots=True)
class PostureOptions:
    max_admin_accounts: int = 1
    command_timeout: float = 20.0
    os_update_medium_after_days: int = 14


def run_posture(
    runner: CommandRunner,
    options: PostureOptions,
    now: Callable[[], datetime],
    *,
    listeners: ListenerSnapshot | None = None,
) -> PostureRun:
    """Execute every posture command and evaluate the checks (never raises on host errors).

    ``listeners`` reuses a snapshot the inventory source collected moments earlier
    in the same cycle; otherwise the listening sockets are collected here.
    """
    started = now()
    out: dict[str, CommandResult] = {}
    for name, argv in COMMANDS.items():
        out[name] = runner.run(argv, timeout=options.command_timeout, max_stdout=2 * 1024 * 1024)
    errors = [
        f"{name}: {res.summary()}"
        for name, res in out.items()
        if (res.error or res.timed_out) and name != "guest"
    ]
    results: list[CheckResult] = []

    results.append(
        evaluate_simple(
            "macos.filevault.enabled",
            "filevault",
            out["fdesetup"],
            parse_fdesetup,
            {"on", "encrypting"},
        )
    )
    results.append(
        evaluate_simple("macos.sip.enabled", "sip", out["csrutil"], parse_csrutil, {"enabled"})
    )
    results.append(
        evaluate_simple(
            "macos.ssv.authenticated_root",
            "authenticated_root",
            out["csrutil_authroot"],
            parse_authenticated_root,
            {"enabled"},
        )
    )
    fw = evaluate_simple(
        "macos.firewall.enabled",
        "application_firewall",
        out["fw_global"],
        parse_firewall_global,
        {"enabled", "block_all"},
    )
    results.append(fw)
    results.append(
        evaluate_simple(
            "macos.firewall.stealth_mode",
            "firewall_stealth_mode",
            out["fw_stealth"],
            parse_firewall_stealth,
            {"on"},
        )
    )
    results.append(
        evaluate_simple(
            "macos.gatekeeper.enabled", "gatekeeper", out["spctl"], parse_spctl, {"enabled"}
        )
    )

    # Software Update preferences
    su_prefs: dict[str, Any] | None = None
    su_error: str | None = None
    if out["su_prefs"].ok:
        try:
            su_prefs = parse_plist_export(out["su_prefs"].stdout)
        except (ValueError, plistlib.InvalidFileException) as exc:
            su_error = f"unparseable SoftwareUpdate preferences: {type(exc).__name__}"
    else:
        su_error = out["su_prefs"].summary()
    domain = "com.apple.SoftwareUpdate"
    for check_id, setting, key in (
        ("macos.softwareupdate.automatic_check", "su_automatic_check", "AutomaticCheckEnabled"),
        (
            "macos.softwareupdate.critical_update_install",
            "su_critical_update_install",
            "CriticalUpdateInstall",
        ),
        ("macos.softwareupdate.config_data_install", "su_config_data_install", "ConfigDataInstall"),
        ("macos.softwareupdate.automatic_download", "su_automatic_download", "AutomaticDownload"),
        (
            "macos.softwareupdate.automatic_macos_install",
            "su_automatic_macos_install",
            "AutomaticallyInstallMacOSUpdates",
        ),
    ):
        results.append(evaluate_preference_bool(check_id, setting, su_prefs, key, domain, su_error))

    sw = parse_sw_vers(out["sw_vers"].text()) if out["sw_vers"].ok else {}
    os_version = sw.get("ProductVersion")
    os_build = sw.get("BuildVersion")
    hw_model = out["hw_model"].text().strip() if out["hw_model"].ok else None
    current = now()
    if su_prefs is None:
        results.append(
            _result(
                "macos.softwareupdate.os_update_pending",
                "error",
                error=su_error or "preferences unavailable",
            )
        )
        results.append(
            _result(
                "macos.softwareupdate.recommended_pending",
                "error",
                error=su_error or "preferences unavailable",
            )
        )
    else:
        pending = offered_os_updates(su_prefs, os_version, current)
        if os_version is None:
            results.append(
                _result(
                    "macos.softwareupdate.os_update_pending", "error", error="sw_vers unavailable"
                )
            )
        elif pending:
            newest = pending[0]
            days = newest.get("days_offered")
            severity = (
                Severity.MEDIUM
                if isinstance(days, int) and days >= options.os_update_medium_after_days
                else Severity.LOW
            )
            results.append(
                _result(
                    "macos.softwareupdate.os_update_pending",
                    "fail",
                    severity=severity,
                    setting="os_update_pending",
                    value=newest["version"],
                    evidence=f"running macOS {os_version}; {newest['version']} ({newest['build']}) "
                    f"offered {days if days is not None else '?'} day(s) ago",
                    attributes={
                        "current_version": os_version,
                        "offered_versions": [p["version"] for p in pending],
                        "days_offered": days,
                        "source": "SoftwareUpdate FirstOfferDateDictionary",
                    },
                )
            )
        else:
            results.append(
                _result(
                    "macos.softwareupdate.os_update_pending",
                    "pass",
                    setting="os_update_pending",
                    value="none",
                )
            )
        recommended = su_prefs.get("RecommendedUpdates")
        if isinstance(recommended, list):
            names = sorted(
                {
                    str(u.get("Display Name") or u.get("Identifier") or "?")
                    for u in recommended
                    if isinstance(u, dict)
                }
            )
            results.append(
                _result(
                    "macos.softwareupdate.recommended_pending",
                    "fail" if names else "pass",
                    setting="recommended_updates",
                    value=names,
                    evidence=("pending: " + ", ".join(names)) if names else "none pending",
                    attributes={
                        "updates": names or None,
                        "last_successful_scan": str(su_prefs.get("LastSuccessfulDate") or "")
                        or None,
                    },
                )
            )
        else:
            results.append(
                _result(
                    "macos.softwareupdate.recommended_pending",
                    "not_set",
                    setting="recommended_updates",
                    evidence="RecommendedUpdates not present",
                )
            )

    commerce: dict[str, Any] | None = None
    commerce_error: str | None = None
    if out["commerce_prefs"].ok:
        try:
            commerce = parse_plist_export(out["commerce_prefs"].stdout)
        except (ValueError, plistlib.InvalidFileException) as exc:
            commerce_error = f"unparseable commerce preferences: {type(exc).__name__}"
    else:
        commerce_error = out["commerce_prefs"].summary()
    results.append(
        evaluate_preference_bool(
            "macos.appstore.auto_update",
            "appstore_auto_update",
            commerce,
            "AutoUpdate",
            "com.apple.commerce",
            commerce_error,
        )
    )

    guest_res = out["guest"]
    if guest_res.error or guest_res.timed_out:
        results.append(
            _result(
                "macos.accounts.guest_enabled",
                "error",
                setting="guest_account",
                error=guest_res.summary(),
            )
        )
    else:
        guest = parse_guest(guest_res)
        if guest is None:
            results.append(
                _result(
                    "macos.accounts.guest_enabled",
                    "not_set",
                    setting="guest_account",
                    evidence="GuestEnabled not set in com.apple.loginwindow",
                )
            )
        else:
            results.append(
                _result(
                    "macos.accounts.guest_enabled",
                    "fail" if guest == "enabled" else "pass",
                    setting="guest_account",
                    value=guest,
                    evidence=f"com.apple.loginwindow GuestEnabled = "
                    f"{1 if guest == 'enabled' else 0}",
                )
            )

    admins_res = out["admins"]
    members = (
        parse_dscl_members(admins_res.text())
        if not (admins_res.error or admins_res.timed_out)
        else None
    )
    if members is None:
        results.append(
            _result(
                "macos.accounts.admin_count",
                "error",
                setting="admin_members",
                error=admins_res.summary(),
            )
        )
    else:
        humans = [m for m in members if m not in SYSTEM_ADMIN_ACCOUNTS]
        status = "fail" if len(humans) > options.max_admin_accounts else "pass"
        results.append(
            _result(
                "macos.accounts.admin_count",
                status,
                setting="admin_members",
                value=members,
                evidence=f"{len(humans)} non-system admin account(s) (maximum "
                f"{options.max_admin_accounts})",
                attributes={
                    "admin_members": members,
                    "non_system_admins": len(humans),
                    "max_admin_accounts": options.max_admin_accounts,
                },
            )
        )

    snapshot: ListenerSnapshot = (
        listeners
        if listeners is not None
        else collect_listeners(runner, include_udp=True, timeout=options.command_timeout)
    )
    errors.extend(f"listeners: {e}" for e in snapshot.errors)
    if snapshot.method == "unavailable":
        for check_id in (
            *_NAMED_PORTS,
            "macos.sharing.airplay_receiver",
            "macos.network.exposed_listener",
        ):
            results.append(
                _result(
                    check_id,
                    "error",
                    category=FindingCategory.EXPOSURE,
                    error="; ".join(snapshot.errors) or "listeners unavailable",
                )
            )
    else:
        results.extend(
            evaluate_exposure(
                snapshot.listeners,
                fw.value if fw.status != "error" else None,
                full_visibility=snapshot.full_visibility,
            )
        )

    allow_builtin, allow_downloaded = (
        parse_firewall_allowsigned(out["fw_allowsigned"].text())
        if out["fw_allowsigned"].ok
        else (None, None)
    )
    settings: dict[str, Any] = {
        r.setting: r.value for r in results if r.setting and r.status in ("pass", "fail", "not_set")
    }
    settings["firewall_allow_signed_builtin"] = allow_builtin
    settings["firewall_allow_signed_downloaded"] = allow_downloaded
    if os_version:
        settings["os_version"] = f"{os_version} ({os_build})" if os_build else os_version
    finished = now()
    return PostureRun(
        started_at=started,
        finished_at=finished,
        results=results,
        settings=settings,
        os_info={
            "os_version": os_version,
            "os_build": os_build,
            "model_identifier": hw_model,
            "product_name": sw.get("ProductName"),
        },
        listeners=snapshot.listeners,
        command_errors=errors,
        listener_method=snapshot.method,
    )


# ── records ──────────────────────────────────────────────────────────


def scan_status(results: Sequence[CheckResult]) -> ScanStatus:
    if not results:
        return ScanStatus.FAILED
    errors = sum(1 for r in results if r.status == "error")
    if errors == len(results):
        return ScanStatus.FAILED
    return ScanStatus.PARTIAL if errors else ScanStatus.SUCCEEDED


EXPOSURE_CHECKS = frozenset(
    {*_NAMED_PORTS, "macos.sharing.airplay_receiver", "macos.network.exposed_listener"}
)
CONFIG_CHECKS = frozenset(set(CHECKS) - EXPOSURE_CHECKS)


def _scope_of(check_id: str) -> str:
    return EXPOSURE_SCOPE[0] if check_id in EXPOSURE_CHECKS else CONFIG_SCOPE[0]


def build_scan_records(
    run: PostureRun, ctx: SourceContext, *, producer_id: str
) -> tuple[list[ScanRun], list[PostureFinding]]:
    """One ScanRun per scope (configuration, exposure) plus findings for failed checks.

    Separate scopes keep finding lifecycles independent: an exposure scan that is
    ``partial`` (socket table withheld) cannot block resolution of configuration
    findings, and vice versa.
    """
    scans: list[ScanRun] = []
    findings: list[PostureFinding] = []
    observed = to_ms(run.finished_at)
    for (scope_name, description), checks in (
        (CONFIG_SCOPE, CONFIG_CHECKS),
        (EXPOSURE_SCOPE, EXPOSURE_CHECKS),
    ):
        results = [r for r in run.results if r.check_id in checks]
        targets = sorted(checks)
        scope = ScanScope(
            targets=targets, description=description, scope_hash=scope_hash(targets, description)
        )
        run_id = stable_id(
            "macos.posture.run.v1",
            ctx.collector_id,
            ctx.asset_id,
            scope_name,
            to_ms(run.started_at),
        )
        scope_findings: list[PostureFinding] = []
        for result in results:
            if result.status != "fail":
                continue
            evidence, _ = clean_text(result.evidence, 2048)
            scope_findings.append(
                PostureFinding(
                    finding_id=finding_id(
                        ctx.asset_id,
                        SCANNER,
                        result.check_id,
                        result.resource_key,
                        result.qualifier,
                    ),
                    scan_run_id=run_id,
                    asset_id=ctx.asset_id,
                    scanner=SCANNER,
                    check_id=result.check_id,
                    category=result.category,
                    severity=result.severity,
                    title=result.title,
                    description=result.description,
                    resource=Resource(
                        type="macos_host" if result.resource_key == "host" else "listener",
                        name=ctx.asset_id if result.resource_key == "host" else result.resource_key,
                    ),
                    evidence=evidence,
                    remediation=result.remediation,
                    references=list(result.references),
                    observed_at=observed,
                    attributes=bounded_attributes(
                        {
                            **result.attributes,
                            "scope": scope_name,
                            "observed_value": _scalar(result.value),
                        }
                    ),
                )
            )
        skipped = [
            SkippedCheck(
                check=r.check_id + (f"[{r.qualifier}]" if r.qualifier else ""),
                reason=(r.error or "error")[:2048],
            )
            for r in results
            if r.status == "error"
        ]
        counts: dict[str, int] = {}
        for r in results:
            counts[r.status] = counts.get(r.status, 0) + 1
        notes = [
            "Non-privileged checks only; absent preference keys are reported as not_set "
            "(OS defaults are not inferred)."
        ]
        if scope_name == EXPOSURE_SCOPE[0]:
            notes.append(
                f"Listening sockets collected via {run.listener_method}"
                + (
                    ""
                    if run.listener_method == "netstat"
                    else " (current user's processes only; root-owned listeners not visible)"
                )
            )
            notes.append(
                "Sharing exposure is derived from listening sockets; systemsetup "
                "requires admin rights and is not used."
            )
        scope_errors = [
            s
            for r in results
            if r.status == "error" and r.error
            for s in [f"{r.check_id}: {r.error}"]
        ]
        scans.append(
            ScanRun(
                scan_run_id=run_id,
                scanner=SCANNER,
                scanner_version=SCANNER_VERSION,
                asset_id=ctx.asset_id,
                scope=scope,
                started_at=to_ms(run.started_at),
                finished_at=observed,
                status=scan_status(results),
                coverage=ScanCoverage(
                    checks_total=len(results),
                    checks_run=sum(1 for r in results if r.status != "error"),
                    skipped=skipped[:256],
                    notes=notes,
                ),
                findings_count=len(scope_findings),
                error=("; ".join(scope_errors))[:2048] or None,
                producer_id=producer_id,
                attributes=bounded_attributes(
                    {
                        "scope_name": scope_name,
                        "result_counts": [f"{k}={v}" for k, v in sorted(counts.items())],
                        "os_version": run.os_info.get("os_version"),
                        "os_build": run.os_info.get("os_build"),
                        "listener_method": run.listener_method
                        if scope_name == EXPOSURE_SCOPE[0]
                        else None,
                    }
                ),
            )
        )
        findings.extend(scope_findings)
    return scans, findings


def _scalar(value: Any) -> Any:
    if isinstance(value, list):
        return [str(v) for v in value][:64]
    if isinstance(value, bool | int | float | str) or value is None:
        return value
    return str(value)


def _render(value: Any) -> Any:
    if isinstance(value, list):
        return [str(v) for v in value]
    return value


def settings_changes(
    previous: Mapping[str, Any], current: Mapping[str, Any]
) -> list[tuple[str, Any, Any]]:
    """(setting, previous, current) for settings known in both snapshots that differ."""
    changes = []
    for key in sorted(set(previous) & set(current)):
        before, after = previous[key], current[key]
        if before is None or after is None:
            continue
        if _render(before) != _render(after):
            changes.append((key, before, after))
    return changes


def setting_change_event(
    setting: str,
    before: Any,
    after: Any,
    ctx: SourceContext,
    *,
    observed_at: datetime,
    scan_run_id: str,
) -> SecurityEvent:
    attrs: dict[str, Any] = {
        "setting": setting,
        "previous_value": _scalar(before),
        "current_value": _scalar(after),
        "scan_run_id": scan_run_id,
    }
    if isinstance(before, list) and isinstance(after, list):
        attrs["added"] = sorted(set(map(str, after)) - set(map(str, before))) or None
        attrs["removed"] = sorted(set(map(str, before)) - set(map(str, after))) or None
    return make_event(
        ctx=ctx,
        event_type="config.security_setting.changed",
        source_type=SOURCE,
        native_key=f"setting:{setting}:{scan_run_id}",
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=f"security setting {setting} changed: {_render(before)} -> {_render(after)}",
        action="security_setting_changed",
        outcome=Outcome.SUCCESS,
        resource=Resource(type="macos_setting", name=setting),
        attributes=attrs,
    )

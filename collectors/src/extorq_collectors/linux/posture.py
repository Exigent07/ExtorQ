"""Linux posture checks (scanner ``extorq-posture-linux``) from the ``posture`` document.

One dispatch call yields one :class:`ScanRun` (fixed scope = the check list below, so
finding lifecycle comparisons are valid) and one :class:`PostureFinding` observation per
FAILED check. ``finding_id`` is stable per (asset, scanner, check, resource). Checks whose
input is unavailable are recorded as skipped (the scan is then PARTIAL and resolves
nothing). Values are taken from configuration files and kernel interfaces readable by the
unprivileged collector; sshd defaults are the documented OpenSSH 9.6 defaults and are
labelled as such in the evidence.

Changes of the monitored settings between scans produce
``config.security_setting.changed`` events (source ``linux.posture``).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
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
from extorq.contracts.identity import (
    canonical_json,
    finding_id,
    iso_utc,
    scope_hash,
    sha256_hex,
    stable_id,
)
from extorq_collectors.linux.common import ParseContext, build_event, clean

SCANNER = "extorq-posture-linux"
SCANNER_VERSION = "1.0.0"
SCOPE_DESCRIPTION = "extorq-posture-linux checks v1"
PARSER_POSTURE = "linux-posture"

#: OpenSSH 9.6 defaults (sshd_config(5)) used when a keyword is not configured.
SSHD_DEFAULTS = {
    "passwordauthentication": "yes",
    "permitrootlogin": "prohibit-password",
    "maxauthtries": "6",
    "permitemptypasswords": "no",
    "x11forwarding": "no",
    "loglevel": "INFO",
    "kbdinteractiveauthentication": "yes",
}


@dataclass(frozen=True)
class CheckResult:
    status: str  # "pass" | "fail" | "skip"
    evidence: str
    value: str | None = None
    reason: str | None = None  # skip reason
    attributes: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class Check:
    check_id: str
    group: str
    title: str
    severity: Severity
    category: FindingCategory
    resource_type: str
    resource_name: str
    #: systemd unit of the service the check applies to (service attribution), if any.
    service_unit: str | None
    remediation: str
    evaluate: Callable[[Mapping[str, Any]], CheckResult]
    references: tuple[str, ...] = ()


def _sshd_value(checks: Mapping[str, Any], keyword: str) -> tuple[str | None, str]:
    """Effective global sshd value and its basis (file or documented default)."""
    sshd = checks.get("sshd")
    if not isinstance(sshd, Mapping) or not sshd.get("files_read"):
        return None, "sshd configuration not readable"
    setting = (sshd.get("settings") or {}).get(keyword)
    if isinstance(setting, Mapping) and isinstance(setting.get("value"), str):
        return setting["value"], f"{keyword} {setting['value']} ({setting.get('file')})"
    default = SSHD_DEFAULTS.get(keyword)
    return default, f"{keyword} not set: OpenSSH default {default}"


def _sshd_check(
    keyword: str, bad: Callable[[str], bool]
) -> Callable[[Mapping[str, Any]], CheckResult]:
    def evaluate(checks: Mapping[str, Any]) -> CheckResult:
        value, basis = _sshd_value(checks, keyword)
        if value is None:
            return CheckResult("skip", basis, reason=basis)
        return CheckResult("fail" if bad(value.lower()) else "pass", basis, value)

    return evaluate


def _sysctl_check(
    name: str, good: Callable[[str], bool], expected: str
) -> Callable[[Mapping[str, Any]], CheckResult]:
    def evaluate(checks: Mapping[str, Any]) -> CheckResult:
        value = (checks.get("sysctl") or {}).get(name)
        if not isinstance(value, str):
            return CheckResult("skip", f"{name} unreadable", reason=f"{name} not readable")
        status = "pass" if good(value) else "fail"
        return CheckResult(status, f"{name} = {value} (expected {expected})", value)

    return evaluate


def _unattended(checks: Mapping[str, Any]) -> CheckResult:
    uu = checks.get("unattended_upgrades") or {}
    periodic = (checks.get("apt_periodic") or {}).get("APT::Periodic::Unattended-Upgrade")
    installed = uu.get("installed")
    service = uu.get("service_enabled")
    if installed is None:
        return CheckResult("skip", "unattended-upgrades state unknown", reason="state unknown")
    ok = installed is True and periodic not in (None, "0") and service == "enabled"
    evidence = (
        f"installed={installed} APT::Periodic::Unattended-Upgrade={periodic} "
        f"unattended-upgrades.service={service}"
    )
    return CheckResult("pass" if ok else "fail", evidence, "enabled" if ok else "disabled")


def _security_updates(checks: Mapping[str, Any]) -> CheckResult:
    updates = checks.get("security_updates") or {}
    if not updates.get("available"):
        reason = f"apt list --upgradable unavailable: {updates.get('error') or 'unknown'}"
        return CheckResult("skip", reason, reason=reason[:500])
    packages = [p for p in updates.get("packages") or [] if isinstance(p, Mapping)]
    names = sorted({str(p.get("name")) for p in packages if p.get("name")})
    evidence = f"{len(names)} package(s) with pending updates from *-security"
    if names:
        evidence += ": " + ", ".join(names[:20]) + (" ..." if len(names) > 20 else "")
    return CheckResult(
        "fail" if names else "pass",
        evidence,
        str(len(names)),
        attributes={
            "packages": names[:64],
            "pending_count": len(names),
            "apt_lists_mtime": updates.get("apt_lists_mtime"),
        },
    )


def _simple(
    path: tuple[str, str], good: Callable[[Any], bool], label: str
) -> Callable[[Mapping[str, Any]], CheckResult]:
    def evaluate(checks: Mapping[str, Any]) -> CheckResult:
        section = checks.get(path[0]) or {}
        value = section.get(path[1]) if isinstance(section, Mapping) else None
        if value is None:
            return CheckResult("skip", f"{label} unknown", reason=f"{label} not readable")
        return CheckResult("pass" if good(value) else "fail", f"{label} = {value}", str(value))

    return evaluate


def _reboot(checks: Mapping[str, Any]) -> CheckResult:
    reboot = checks.get("reboot_required") or {}
    required = reboot.get("required")
    if not isinstance(required, bool):
        return CheckResult("skip", "reboot flag unknown", reason="reboot flag unknown")
    pkgs = ", ".join(reboot.get("packages") or [])
    evidence = (
        "/var/run/reboot-required present" + (f" ({pkgs})" if pkgs else "")
        if required
        else "no reboot required"
    )
    return CheckResult("fail" if required else "pass", evidence, str(required).lower())


def _uid0(checks: Mapping[str, Any]) -> CheckResult:
    accounts = checks.get("uid0_accounts")
    if not isinstance(accounts, list):
        return CheckResult("skip", "uid 0 accounts unknown", reason="passwd unreadable")
    extra = sorted(a for a in accounts if a != "root")
    return CheckResult(
        "fail" if extra else "pass",
        f"uid 0 accounts: {', '.join(accounts)}",
        ",".join(extra) or "root-only",
    )


def _collector_access(checks: Mapping[str, Any]) -> CheckResult:
    access = checks.get("file_access")
    if not isinstance(access, Mapping):
        return CheckResult("skip", "access probe unavailable", reason="no data")
    readable = sorted(path for path, ok in access.items() if ok is True)
    evidence = (
        ("collector account can read: " + ", ".join(readable))
        if readable
        else "collector account cannot read shadow, gshadow, sudoers or the SSH host key"
    )
    return CheckResult("fail" if readable else "pass", evidence, ",".join(readable) or "none")


CHECKS: tuple[Check, ...] = (
    Check(
        "linux.ssh.password_authentication",
        "sshd",
        "SSH password authentication enabled",
        Severity.HIGH,
        FindingCategory.MISCONFIGURATION,
        "sshd_config",
        "sshd",
        "ssh.service",
        "Set 'PasswordAuthentication no' and use public-key authentication.",
        _sshd_check("passwordauthentication", lambda v: v != "no"),
    ),
    Check(
        "linux.ssh.permit_root_login",
        "sshd",
        "SSH root login permitted",
        Severity.MEDIUM,
        FindingCategory.MISCONFIGURATION,
        "sshd_config",
        "sshd",
        "ssh.service",
        "Set 'PermitRootLogin no'; administer through named accounts and sudo.",
        _sshd_check("permitrootlogin", lambda v: v != "no"),
    ),
    Check(
        "linux.ssh.max_auth_tries",
        "sshd",
        "SSH MaxAuthTries above 4",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sshd_config",
        "sshd",
        "ssh.service",
        "Set 'MaxAuthTries 4' (or lower) to slow down credential guessing.",
        _sshd_check("maxauthtries", lambda v: not v.isdigit() or int(v) > 4),
    ),
    Check(
        "linux.ssh.permit_empty_passwords",
        "sshd",
        "SSH empty passwords permitted",
        Severity.HIGH,
        FindingCategory.MISCONFIGURATION,
        "sshd_config",
        "sshd",
        "ssh.service",
        "Set 'PermitEmptyPasswords no'.",
        _sshd_check("permitemptypasswords", lambda v: v != "no"),
    ),
    Check(
        "linux.ssh.x11_forwarding",
        "sshd",
        "SSH X11 forwarding enabled",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sshd_config",
        "sshd",
        "ssh.service",
        "Set 'X11Forwarding no' unless explicitly required.",
        _sshd_check("x11forwarding", lambda v: v != "no"),
    ),
    Check(
        "linux.ssh.log_level",
        "sshd",
        "SSH authentication logging disabled",
        Severity.MEDIUM,
        FindingCategory.MISCONFIGURATION,
        "sshd_config",
        "sshd",
        "ssh.service",
        "Set 'LogLevel VERBOSE' (or at least INFO) so authentication attempts are logged.",
        _sshd_check("loglevel", lambda v: v.upper() in ("QUIET", "FATAL", "ERROR")),
    ),
    Check(
        "linux.updates.unattended_upgrades",
        "updates",
        "Automatic security updates disabled",
        Severity.MEDIUM,
        FindingCategory.POSTURE,
        "service",
        "unattended-upgrades",
        "unattended-upgrades.service",
        'Install and enable unattended-upgrades (APT::Periodic::Unattended-Upgrade "1").',
        _unattended,
    ),
    Check(
        "linux.updates.pending_security",
        "updates",
        "Pending security updates",
        Severity.MEDIUM,
        FindingCategory.POSTURE,
        "packages",
        "apt",
        None,
        "Apply pending updates from the -security pocket (apt-get upgrade) and reboot if required.",
        _security_updates,
    ),
    Check(
        "linux.audit.auditd_active",
        "auditd",
        "Audit daemon not active",
        Severity.HIGH,
        FindingCategory.POSTURE,
        "service",
        "auditd",
        "auditd.service",
        "Enable and start auditd so file-watch and exec audit rules are enforced.",
        _simple(("auditd", "active"), lambda v: v == "active", "auditd.service active"),
    ),
    Check(
        "linux.apparmor.enabled",
        "apparmor",
        "AppArmor disabled",
        Severity.MEDIUM,
        FindingCategory.POSTURE,
        "kernel",
        "apparmor",
        None,
        "Enable AppArmor (kernel parameter apparmor=1) and keep profiles in enforce mode.",
        _simple(("apparmor", "enabled"), lambda v: str(v).upper() == "Y", "apparmor"),
    ),
    Check(
        "linux.firewall.ufw_enabled",
        "ufw",
        "Host firewall (ufw) disabled",
        Severity.MEDIUM,
        FindingCategory.POSTURE,
        "firewall",
        "ufw",
        None,
        "Enable ufw with a default-deny inbound policy and explicit allow rules.",
        _simple(("ufw", "enabled"), lambda v: str(v).lower() == "yes", "ufw ENABLED"),
    ),
    Check(
        "linux.sysctl.randomize_va_space",
        "sysctl",
        "ASLR not fully enabled",
        Severity.MEDIUM,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "kernel.randomize_va_space",
        None,
        "Set kernel.randomize_va_space = 2.",
        _sysctl_check("kernel.randomize_va_space", lambda v: v == "2", "2"),
    ),
    Check(
        "linux.sysctl.ip_forward",
        "sysctl",
        "IPv4 forwarding enabled",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "net.ipv4.ip_forward",
        None,
        "Set net.ipv4.ip_forward = 0 unless the host routes traffic.",
        _sysctl_check("net.ipv4.ip_forward", lambda v: v == "0", "0"),
    ),
    Check(
        "linux.sysctl.accept_redirects",
        "sysctl",
        "ICMP redirects accepted (IPv4)",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "net.ipv4.conf.all.accept_redirects",
        None,
        "Set net.ipv4.conf.all.accept_redirects = 0.",
        _sysctl_check("net.ipv4.conf.all.accept_redirects", lambda v: v == "0", "0"),
    ),
    Check(
        "linux.sysctl.ipv6_accept_redirects",
        "sysctl",
        "ICMP redirects accepted (IPv6)",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "net.ipv6.conf.all.accept_redirects",
        None,
        "Set net.ipv6.conf.all.accept_redirects = 0.",
        _sysctl_check("net.ipv6.conf.all.accept_redirects", lambda v: v == "0", "0"),
    ),
    Check(
        "linux.sysctl.send_redirects",
        "sysctl",
        "ICMP redirects sent",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "net.ipv4.conf.all.send_redirects",
        None,
        "Set net.ipv4.conf.all.send_redirects = 0 on non-routers.",
        _sysctl_check("net.ipv4.conf.all.send_redirects", lambda v: v == "0", "0"),
    ),
    Check(
        "linux.sysctl.accept_source_route",
        "sysctl",
        "Source-routed packets accepted",
        Severity.MEDIUM,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "net.ipv4.conf.all.accept_source_route",
        None,
        "Set net.ipv4.conf.all.accept_source_route = 0.",
        _sysctl_check("net.ipv4.conf.all.accept_source_route", lambda v: v == "0", "0"),
    ),
    Check(
        "linux.sysctl.tcp_syncookies",
        "sysctl",
        "TCP SYN cookies disabled",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "net.ipv4.tcp_syncookies",
        None,
        "Set net.ipv4.tcp_syncookies = 1.",
        _sysctl_check("net.ipv4.tcp_syncookies", lambda v: v == "1", "1"),
    ),
    Check(
        "linux.sysctl.kptr_restrict",
        "sysctl",
        "Kernel pointers exposed",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "kernel.kptr_restrict",
        None,
        "Set kernel.kptr_restrict = 1 (or 2).",
        _sysctl_check("kernel.kptr_restrict", lambda v: v in ("1", "2"), "1 or 2"),
    ),
    Check(
        "linux.sysctl.dmesg_restrict",
        "sysctl",
        "Kernel log readable by all users",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "kernel.dmesg_restrict",
        None,
        "Set kernel.dmesg_restrict = 1.",
        _sysctl_check("kernel.dmesg_restrict", lambda v: v == "1", "1"),
    ),
    Check(
        "linux.sysctl.suid_dumpable",
        "sysctl",
        "Core dumps of setuid programs allowed",
        Severity.LOW,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "fs.suid_dumpable",
        None,
        "Set fs.suid_dumpable = 0.",
        _sysctl_check("fs.suid_dumpable", lambda v: v == "0", "0"),
    ),
    Check(
        "linux.sysctl.protected_links",
        "sysctl",
        "Symlink/hardlink protection disabled",
        Severity.MEDIUM,
        FindingCategory.MISCONFIGURATION,
        "sysctl",
        "fs.protected_symlinks",
        None,
        "Set fs.protected_symlinks = 1 and fs.protected_hardlinks = 1.",
        _sysctl_check("fs.protected_symlinks", lambda v: v == "1", "1"),
    ),
    Check(
        "linux.reboot_required",
        "reboot",
        "Reboot required to activate updates",
        Severity.LOW,
        FindingCategory.POSTURE,
        "host",
        "reboot-required",
        None,
        "Reboot during a maintenance window so updated kernels/libraries are in use.",
        _reboot,
    ),
    Check(
        "linux.accounts.extra_uid0",
        "accounts",
        "Additional accounts with uid 0",
        Severity.CRITICAL,
        FindingCategory.MISCONFIGURATION,
        "file",
        "/etc/passwd",
        None,
        "Remove or re-number every non-root account with uid 0.",
        _uid0,
    ),
    Check(
        "linux.access.collector_reads_secrets",
        "file_access",
        "Collector account can read credential files",
        Severity.HIGH,
        FindingCategory.MISCONFIGURATION,
        "account",
        "extorq-collector",
        None,
        "Remove the collector account from groups that grant access to shadow, sudoers or "
        "host keys.",
        _collector_access,
    ),
)
SCOPE_TARGETS = sorted({check.group for check in CHECKS})


@dataclass
class PostureResult:
    scan_run: ScanRun
    findings: list[PostureFinding]
    #: setting -> value, input of the config.security_setting.changed diff.
    settings: dict[str, Any]
    results: dict[str, CheckResult]


def scan_run_id(asset_id: str, started_at: datetime) -> str:
    return stable_id("scan_run.linux_posture.v1", asset_id, SCANNER, iso_utc(started_at))


def evaluate(
    doc: Mapping[str, Any],
    *,
    asset_id: str,
    producer_id: str,
    started_at: datetime,
    finished_at: datetime,
    service_ids: Mapping[str, str],
) -> PostureResult:
    """Evaluate every check; ``service_ids`` maps discovered units to service ids."""
    raw_checks = doc.get("checks")
    checks: Mapping[str, Any] = raw_checks if isinstance(raw_checks, Mapping) else {}
    observed = _observed_time(doc) or finished_at
    run_id = scan_run_id(asset_id, started_at)
    results: dict[str, CheckResult] = {}
    findings: list[PostureFinding] = []
    skipped: list[SkippedCheck] = []
    for check in CHECKS:
        try:
            result = check.evaluate(checks)
        except (TypeError, ValueError, AttributeError) as exc:
            result = CheckResult(
                "skip", "evaluation error", reason=f"invalid input ({type(exc).__name__})"
            )
        results[check.check_id] = result
        if result.status == "skip":
            skipped.append(SkippedCheck(check=check.check_id, reason=(result.reason or "")[:2048]))
            continue
        if result.status != "fail":
            continue
        resource_key = f"{check.resource_type}:{check.resource_name}"
        findings.append(
            PostureFinding(
                finding_id=finding_id(asset_id, SCANNER, check.check_id, resource_key),
                scan_run_id=run_id,
                asset_id=asset_id,
                scanner=SCANNER,
                check_id=check.check_id,
                category=check.category,
                severity=check.severity,
                title=check.title,
                description=f"{check.title}. Observed: {clean(result.evidence, 1800)}",
                resource=Resource(type=check.resource_type, name=check.resource_name),
                service_id=service_ids.get(check.service_unit) if check.service_unit else None,
                evidence=clean(result.evidence, 2048),
                remediation=check.remediation,
                references=list(check.references),
                observed_at=observed,
                attributes={k: v for k, v in (result.attributes or {}).items() if v is not None},
            )
        )
    status = ScanStatus.PARTIAL if skipped else ScanStatus.SUCCEEDED
    scan = ScanRun(
        scan_run_id=run_id,
        scanner=SCANNER,
        scanner_version=SCANNER_VERSION,
        asset_id=asset_id,
        scope=ScanScope(
            targets=SCOPE_TARGETS,
            description=SCOPE_DESCRIPTION,
            scope_hash=scope_hash(SCOPE_TARGETS, SCOPE_DESCRIPTION),
        ),
        started_at=started_at,
        finished_at=finished_at,
        status=status,
        coverage=ScanCoverage(
            checks_total=len(CHECKS), checks_run=len(CHECKS) - len(skipped), skipped=skipped
        ),
        findings_count=len(findings),
        producer_id=producer_id,
        attributes={"failed_checks": [f.check_id for f in findings][:64]},
    )
    return PostureResult(
        scan_run=scan, findings=findings, settings=settings_of(checks, results), results=results
    )


def failed_scan(
    *, asset_id: str, producer_id: str, started_at: datetime, finished_at: datetime, error: str
) -> ScanRun:
    """A posture scan that could not run (resolves nothing; findings stay as they were)."""
    return ScanRun(
        scan_run_id=scan_run_id(asset_id, started_at),
        scanner=SCANNER,
        scanner_version=SCANNER_VERSION,
        asset_id=asset_id,
        scope=ScanScope(
            targets=SCOPE_TARGETS,
            description=SCOPE_DESCRIPTION,
            scope_hash=scope_hash(SCOPE_TARGETS, SCOPE_DESCRIPTION),
        ),
        started_at=started_at,
        finished_at=finished_at,
        status=ScanStatus.FAILED,
        coverage=ScanCoverage(checks_total=len(CHECKS), checks_run=0),
        findings_count=None,
        error=clean(error, 2048),
        producer_id=producer_id,
    )


def settings_of(checks: Mapping[str, Any], results: Mapping[str, CheckResult]) -> dict[str, Any]:
    """Monitored settings (flat) for change detection between scans."""
    settings: dict[str, Any] = {}
    for check in CHECKS:
        result = results.get(check.check_id)
        if result is not None and result.value is not None and check.group != "updates":
            settings[check.check_id] = result.value
    for name, value in (checks.get("sysctl") or {}).items():
        if isinstance(value, str):
            settings[f"sysctl.{name}"] = value
    return settings


def setting_events(
    diff: Any, ctx: ParseContext, event_time: datetime, service_ids: Mapping[str, str]
) -> list[SecurityEvent]:
    """``config.security_setting.changed`` for every setting that changed between scans."""
    events: list[SecurityEvent] = []
    check_units = {c.check_id: c.service_unit for c in CHECKS}
    keys = sorted(set(diff.added) | set(diff.changed) | set(diff.removed))
    stored = diff.previous
    for key in keys:
        if key in diff.added and getattr(diff, "baseline", False):
            continue
        current = diff.added.get(key, diff.changed.get(key))
        previous = stored.get(key)
        cur_value = current.get("value") if isinstance(current, Mapping) else None
        prev_value = previous.get("value") if isinstance(previous, Mapping) else None
        unit = check_units.get(key)
        item = {"setting": key, "previous": prev_value, "current": cur_value}
        events.append(
            build_event(
                ctx,
                event_type="config.security_setting.changed",
                source_type=SourceType.LINUX_POSTURE,
                native_key=f"{key}:changed:{sha256_hex(canonical_json(item))}",
                event_time=event_time,
                parser=PARSER_POSTURE,
                action="setting.changed",
                outcome=Outcome.SUCCESS,
                resource=Resource(type="setting", name=clean(key)),
                message=f"security setting {key} changed: {prev_value} -> {cur_value}",
                attributes={
                    "setting": key,
                    "previous_value": prev_value,
                    "current_value": cur_value,
                    "subject_service_id": service_ids.get(unit) if unit else None,
                },
            )
        )
    return events


def _observed_time(doc: Mapping[str, Any]) -> datetime | None:
    value = doc.get("collected_at")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None

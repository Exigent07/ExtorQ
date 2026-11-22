"""Event catalog: the cross-team semantic contract for SecurityEvent types.

The ingestion gateway quarantines events whose ``event_type`` is not registered
here, whose ``category`` does not match, or whose ``source.source_type`` is not
an allowed producer of that type. Detection rules declare their required
telemetry against this catalog and the rule loader validates it.

To add an event type: add it here (with documented key fields), add a parser
test in the producing collector, record it in
docs/team/interface-changes/<agent>.md (PLAN.md §8) and
docs/telemetry-sources.md. Never repurpose an existing type's meaning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from extorq.contracts.common import EventCategory


class SourceType(StrEnum):
    # Linux VM (agentless SSH collection)
    LINUX_JOURNALD = "linux.journald"
    LINUX_AUDITD = "linux.auditd"
    LINUX_NGINX = "linux.nginx"
    LINUX_APACHE = "linux.apache"
    LINUX_APP = "linux.app"
    LINUX_INVENTORY = "linux.inventory"
    LINUX_POSTURE = "linux.posture"
    # macOS endpoint (native collector)
    MACOS_UNIFIED_LOG = "macos.unified_log"
    MACOS_LAUNCHD = "macos.launchd"
    MACOS_INVENTORY = "macos.inventory"
    MACOS_POSTURE = "macos.posture"
    # Kubernetes
    K8S_AUDIT = "k8s.audit"
    K8S_API_INVENTORY = "k8s.api_inventory"
    K8S_EVENTS = "k8s.events"
    K8S_CONTAINER_LOG = "k8s.container_log"
    K8S_POSTURE = "k8s.posture"
    # GitHub
    GITHUB_API = "github.api"
    GITHUB_POSTURE = "github.posture"
    # Scanners
    SCANNER_TRIVY = "scanner.trivy"
    SCANNER_GITLEAKS = "scanner.gitleaks"
    SCANNER_SEMGREP = "scanner.semgrep"
    # ExtorQ itself
    EXTORQ_PIPELINE = "extorq.pipeline"


S = SourceType
C = EventCategory


@dataclass(frozen=True)
class EventTypeSpec:
    event_type: str
    category: EventCategory
    sources: frozenset[SourceType]
    description: str
    #: Dotted paths into SecurityEvent that producers SHOULD populate when the
    #: source genuinely provides them (documentation + parser tests; unknown
    #: values must stay None rather than be invented).
    key_fields: tuple[str, ...] = field(default_factory=tuple)


def _spec(
    event_type: str,
    category: EventCategory,
    sources: set[SourceType],
    description: str,
    key_fields: tuple[str, ...] = (),
) -> EventTypeSpec:
    return EventTypeSpec(event_type, category, frozenset(sources), description, key_fields)


_SPECS: list[EventTypeSpec] = [
    # ── SSH / PAM / sudo ─────────────────────────────────────────────
    _spec(
        "auth.ssh.login_failed",
        C.AUTHENTICATION,
        {S.LINUX_JOURNALD, S.MACOS_UNIFIED_LOG},
        "sshd 'Failed <method> for [invalid user] X from IP port P' line.",
        (
            "actor.name",
            "network.src_ip",
            "network.src_port",
            "attributes.auth_method",
            "attributes.invalid_user",
            "process.pid",
        ),
    ),
    _spec(
        "auth.ssh.invalid_user",
        C.AUTHENTICATION,
        {S.LINUX_JOURNALD, S.MACOS_UNIFIED_LOG},
        "sshd 'Invalid user X from IP port P' line.",
        ("actor.name", "network.src_ip", "network.src_port", "process.pid"),
    ),
    _spec(
        "auth.ssh.preauth_closed",
        C.AUTHENTICATION,
        {S.LINUX_JOURNALD, S.MACOS_UNIFIED_LOG},
        "sshd 'Connection closed/reset by (authenticating|invalid) user X IP port P [preauth]'.",
        ("actor.name", "network.src_ip", "network.src_port", "attributes.invalid_user"),
    ),
    _spec(
        "auth.ssh.max_auth_exceeded",
        C.AUTHENTICATION,
        {S.LINUX_JOURNALD, S.MACOS_UNIFIED_LOG},
        "sshd 'maximum authentication attempts exceeded' / 'Too many authentication failures'.",
        ("actor.name", "network.src_ip", "network.src_port"),
    ),
    _spec(
        "auth.ssh.login_succeeded",
        C.AUTHENTICATION,
        {S.LINUX_JOURNALD, S.MACOS_UNIFIED_LOG},
        "sshd 'Accepted <method> for X from IP port P'.",
        (
            "actor.name",
            "network.src_ip",
            "network.src_port",
            "attributes.auth_method",
            "attributes.key_fingerprint",
        ),
    ),
    _spec(
        "auth.pam.failure",
        C.AUTHENTICATION,
        {S.LINUX_JOURNALD},
        "pam_unix authentication failure (service, ruser, rhost, user).",
        ("actor.name", "network.src_ip", "attributes.pam_service"),
    ),
    _spec(
        "auth.sudo.command",
        C.AUTHORIZATION,
        {S.LINUX_JOURNALD, S.MACOS_UNIFIED_LOG},
        "sudo command execution record.",
        (
            "actor.name",
            "attributes.run_as",
            "process.command_line",
            "attributes.tty",
            "attributes.cwd",
        ),
    ),
    _spec(
        "auth.sudo.failure",
        C.AUTHORIZATION,
        {S.LINUX_JOURNALD, S.MACOS_UNIFIED_LOG},
        "sudo denial (not in sudoers, incorrect password attempts).",
        ("actor.name", "attributes.reason"),
    ),
    _spec(
        "auth.local.failure",
        C.AUTHENTICATION,
        {S.MACOS_UNIFIED_LOG},
        "Local authentication failure reported by macOS (authd/opendirectoryd).",
        ("actor.name", "attributes.subsystem"),
    ),
    # ── Application security telemetry ───────────────────────────────
    _spec(
        "app.auth.login_failed",
        C.AUTHENTICATION,
        {S.LINUX_APP, S.K8S_CONTAINER_LOG},
        "Application login failure emitted by an instrumented web application.",
        ("actor.name", "network.src_ip", "http.request_id", "http.route", "attributes.reason"),
    ),
    _spec(
        "app.auth.login_succeeded",
        C.AUTHENTICATION,
        {S.LINUX_APP, S.K8S_CONTAINER_LOG},
        "Application login success.",
        ("actor.name", "network.src_ip", "http.request_id"),
    ),
    _spec(
        "app.authz.denied",
        C.AUTHORIZATION,
        {S.LINUX_APP, S.K8S_CONTAINER_LOG},
        "Application authorization denial (e.g. 401/403 on a protected route).",
        ("actor.name", "network.src_ip", "http.request_id", "http.route"),
    ),
    _spec(
        "http.request",
        C.HTTP,
        {S.LINUX_NGINX, S.LINUX_APACHE, S.LINUX_APP, S.K8S_CONTAINER_LOG},
        "HTTP access record (method, sanitized route without query, status, request id).",
        (
            "network.src_ip",
            "http.method",
            "http.route",
            "http.status_code",
            "http.request_id",
            "http.user_agent",
        ),
    ),
    # ── Persistence ──────────────────────────────────────────────────
    _spec(
        "persistence.systemd.unit_created",
        C.PERSISTENCE,
        {S.LINUX_INVENTORY},
        "New systemd unit file observed in a persistence location (snapshot diff).",
        (
            "resource.path",
            "resource.name",
            "attributes.sha256",
            "attributes.exec_start",
            "attributes.vendor_unit",
        ),
    ),
    _spec(
        "persistence.systemd.unit_modified",
        C.PERSISTENCE,
        {S.LINUX_INVENTORY},
        "Existing systemd unit file content changed (snapshot diff).",
        ("resource.path", "resource.name", "attributes.sha256", "attributes.previous_sha256"),
    ),
    _spec(
        "persistence.systemd.unit_deleted",
        C.PERSISTENCE,
        {S.LINUX_INVENTORY},
        "systemd unit file removed (snapshot diff).",
        ("resource.path", "resource.name"),
    ),
    _spec(
        "persistence.systemd.unit_enabled",
        C.PERSISTENCE,
        {S.LINUX_INVENTORY},
        "Unit newly enabled (symlink appeared in a *.wants/ directory).",
        ("resource.name", "attributes.wanted_by"),
    ),
    _spec(
        "persistence.cron.changed",
        C.PERSISTENCE,
        {S.LINUX_INVENTORY},
        "Cron configuration content changed.",
        ("resource.path", "attributes.sha256"),
    ),
    _spec(
        "persistence.launchd.item_created",
        C.PERSISTENCE,
        {S.MACOS_LAUNCHD},
        "New LaunchAgent/LaunchDaemon plist observed.",
        (
            "resource.path",
            "attributes.label",
            "attributes.program",
            "attributes.run_at_load",
            "attributes.sha256",
            "attributes.scope",
        ),
    ),
    _spec(
        "persistence.launchd.item_modified",
        C.PERSISTENCE,
        {S.MACOS_LAUNCHD},
        "LaunchAgent/LaunchDaemon plist content changed.",
        ("resource.path", "attributes.label", "attributes.sha256", "attributes.previous_sha256"),
    ),
    _spec(
        "persistence.launchd.item_deleted",
        C.PERSISTENCE,
        {S.MACOS_LAUNCHD},
        "LaunchAgent/LaunchDaemon plist removed.",
        ("resource.path", "attributes.label"),
    ),
    # ── File / process (auditd) ──────────────────────────────────────
    _spec(
        "file.audit.watch",
        C.FILE,
        {S.LINUX_AUDITD},
        "auditd watch hit on a sensitive path (key, path, exe, auid/uid, syscall).",
        (
            "resource.path",
            "attributes.audit_key",
            "process.executable",
            "actor.id",
            "attributes.syscall",
            "attributes.audit_serial",
        ),
    ),
    _spec(
        "process.audit.exec",
        C.PROCESS,
        {S.LINUX_AUDITD},
        "auditd execve record (only when exec auditing rules are configured).",
        ("process.executable", "process.command_line", "actor.id", "attributes.audit_key"),
    ),
    # ── System configuration / inventory diffs ───────────────────────
    _spec(
        "system.service.state_changed",
        C.CONFIGURATION,
        {S.LINUX_JOURNALD},
        "systemd unit started/stopped/failed message.",
        ("resource.name", "attributes.state"),
    ),
    _spec(
        "system.systemd.daemon_reload",
        C.CONFIGURATION,
        {S.LINUX_JOURNALD},
        "systemd manager reload requested.",
        ("process.pid", "attributes.requested_by_pid"),
    ),
    _spec(
        "config.file.changed",
        C.CONFIGURATION,
        {S.LINUX_INVENTORY},
        "Monitored sensitive configuration file hash changed (snapshot diff).",
        ("resource.path", "attributes.sha256", "attributes.previous_sha256"),
    ),
    _spec(
        "config.security_setting.changed",
        C.CONFIGURATION,
        {S.MACOS_POSTURE, S.LINUX_POSTURE, S.GITHUB_POSTURE, S.K8S_POSTURE},
        "Security-relevant setting changed between posture snapshots (e.g. firewall disabled).",
        (
            "resource.name",
            "attributes.setting",
            "attributes.previous_value",
            "attributes.current_value",
        ),
    ),
    _spec(
        "network.listener.opened",
        C.NETWORK,
        {S.LINUX_INVENTORY, S.MACOS_INVENTORY},
        "New listening socket observed (snapshot diff).",
        ("network.dst_ip", "network.dst_port", "network.protocol", "process.name"),
    ),
    _spec(
        "network.listener.closed",
        C.NETWORK,
        {S.LINUX_INVENTORY, S.MACOS_INVENTORY},
        "Listening socket no longer observed (snapshot diff).",
        ("network.dst_ip", "network.dst_port", "network.protocol"),
    ),
    _spec(
        "package.installed",
        C.PACKAGE,
        {S.LINUX_INVENTORY},
        "Package newly installed (snapshot diff).",
        ("resource.name", "attributes.version"),
    ),
    _spec(
        "package.removed",
        C.PACKAGE,
        {S.LINUX_INVENTORY},
        "Package removed (snapshot diff).",
        ("resource.name", "attributes.version"),
    ),
    _spec(
        "package.upgraded",
        C.PACKAGE,
        {S.LINUX_INVENTORY},
        "Package version changed (snapshot diff).",
        ("resource.name", "attributes.version", "attributes.previous_version"),
    ),
    _spec(
        "security.xprotect.event",
        C.SECURITY_PRODUCT,
        {S.MACOS_UNIFIED_LOG},
        "XProtect / malware-protection related unified-log event.",
        ("attributes.subsystem",),
    ),
    _spec(
        "security.gatekeeper.event",
        C.SECURITY_PRODUCT,
        {S.MACOS_UNIFIED_LOG},
        "Gatekeeper / syspolicy assessment event.",
        ("attributes.subsystem",),
    ),
    _spec(
        "system.log.notable",
        C.OTHER,
        {S.MACOS_UNIFIED_LOG, S.LINUX_JOURNALD, S.LINUX_AUDITD},
        "Security-relevant log line not matching a more specific type (kept for context).",
        ("attributes.subsystem", "process.name"),
    ),
    # ── Kubernetes ───────────────────────────────────────────────────
    _spec(
        "k8s.api.request",
        C.KUBERNETES_API,
        {S.K8S_AUDIT},
        "Kubernetes API audit event (ResponseComplete/Panic stage).",
        (
            "kubernetes.verb",
            "kubernetes.resource",
            "kubernetes.namespace",
            "kubernetes.object_name",
            "kubernetes.user",
            "kubernetes.user_groups",
            "kubernetes.source_ips",
            "kubernetes.response_code",
            "kubernetes.audit_id",
            "attributes.request_summary",
            "attributes.pod_security_violation",
        ),
    ),
    _spec(
        "k8s.resource.created",
        C.KUBERNETES_API,
        {S.K8S_API_INVENTORY},
        "Kubernetes object observed for the first time (inventory diff).",
        ("resource.type", "resource.name", "resource.namespace", "attributes.risk_flags"),
    ),
    _spec(
        "k8s.resource.updated",
        C.KUBERNETES_API,
        {S.K8S_API_INVENTORY},
        "Kubernetes object spec changed (inventory diff).",
        (
            "resource.type",
            "resource.name",
            "resource.namespace",
            "attributes.risk_flags",
            "attributes.changed_fields",
        ),
    ),
    _spec(
        "k8s.resource.deleted",
        C.KUBERNETES_API,
        {S.K8S_API_INVENTORY},
        "Kubernetes object no longer present (inventory diff).",
        ("resource.type", "resource.name", "resource.namespace"),
    ),
    _spec(
        "k8s.event.observed",
        C.KUBERNETES_WORKLOAD,
        {S.K8S_EVENTS},
        "core/v1 Event (reason, type, involved object, message).",
        (
            "attributes.reason",
            "attributes.event_type",
            "resource.type",
            "resource.name",
            "resource.namespace",
        ),
    ),
    _spec(
        "k8s.container.log",
        C.KUBERNETES_WORKLOAD,
        {S.K8S_CONTAINER_LOG},
        "Container stdout/stderr line not parsed into a more specific type.",
        (
            "kubernetes.namespace",
            "kubernetes.pod_name",
            "kubernetes.pod_uid",
            "kubernetes.container_name",
            "attributes.stream",
        ),
    ),
    # ── GitHub ───────────────────────────────────────────────────────
    _spec(
        "github.commit.observed",
        C.SOURCE_CONTROL,
        {S.GITHUB_API},
        "Commit observed on a monitored branch (changed files summarised).",
        (
            "github.repository",
            "github.commit_sha",
            "github.ref",
            "github.actor_login",
            "attributes.files_changed",
            "attributes.workflow_files_changed",
            "attributes.signature_verified",
        ),
    ),
    _spec(
        "github.workflow.modified",
        C.CI_CD,
        {S.GITHUB_API},
        "Commit changed a GitHub Actions workflow; includes before/after permission analysis.",
        (
            "github.repository",
            "github.commit_sha",
            "github.workflow_path",
            "attributes.permissions_before",
            "attributes.permissions_after",
            "attributes.write_all_added",
            "attributes.added_write_scopes",
            "attributes.triggers_added",
            "attributes.risk_flags",
        ),
    ),
    _spec(
        "github.workflow_run.observed",
        C.CI_CD,
        {S.GITHUB_API},
        "GitHub Actions workflow run state (run id, attempt, head sha, conclusion).",
        (
            "github.repository",
            "github.workflow_run_id",
            "github.workflow_path",
            "github.commit_sha",
            "github.event_name",
            "github.conclusion",
        ),
    ),
    _spec(
        "github.repo.settings_changed",
        C.CONFIGURATION,
        {S.GITHUB_API},
        "Repository security-relevant settings changed between polls.",
        ("github.repository", "attributes.changed_fields"),
    ),
    _spec(
        "github.branch_protection.changed",
        C.CONFIGURATION,
        {S.GITHUB_API},
        "Branch protection / ruleset state changed between polls.",
        ("github.repository", "github.ref", "attributes.changed_fields"),
    ),
    # ── Service model (schema 1.1) ───────────────────────────────────
    _spec(
        "service.discovered",
        C.CONFIGURATION,
        {S.LINUX_INVENTORY, S.MACOS_INVENTORY, S.K8S_API_INVENTORY},
        "A service appeared in discovery (systemd unit / launchd job / process / socket / "
        "k8s workload or Service), with its evidence and coverage state.",
        (
            "service.service_id",
            "service.name",
            "attributes.service_kind",
            "attributes.category",
            "attributes.discovered_via",
            "attributes.adapter_support",
            "attributes.monitoring_status",
        ),
    ),
    _spec(
        "service.removed",
        C.CONFIGURATION,
        {S.LINUX_INVENTORY, S.MACOS_INVENTORY, S.K8S_API_INVENTORY},
        "A previously discovered service is no longer observed.",
        ("service.service_id", "service.name"),
    ),
    _spec(
        "service.exposure.changed",
        C.NETWORK,
        {S.LINUX_INVENTORY, S.MACOS_INVENTORY, S.K8S_API_INVENTORY},
        "A service's listening endpoints / exposure changed (with port attribution confidence).",
        (
            "service.service_id",
            "attributes.endpoints_added",
            "attributes.endpoints_removed",
            "attributes.attribution",
        ),
    ),
    _spec(
        "http.server.error",
        C.HTTP,
        {S.LINUX_NGINX, S.LINUX_APACHE},
        "Web-server error-log record (access denied by rule, client errors, upstream failures).",
        ("network.src_ip", "http.route", "attributes.error_class", "attributes.log_level"),
    ),
    _spec(
        "audit.config.changed",
        C.CONFIGURATION,
        {S.LINUX_AUDITD},
        "auditd CONFIG_CHANGE / DAEMON_END records (rules changed or audit stopped): "
        "possible defence evasion.",
        ("attributes.audit_record_type", "attributes.audit_op", "actor.id"),
    ),
    _spec(
        "account.user.created",
        C.CONFIGURATION,
        {S.LINUX_INVENTORY, S.MACOS_INVENTORY},
        "Local account appeared between inventory snapshots.",
        ("actor.name", "attributes.uid", "attributes.shell", "attributes.groups"),
    ),
    _spec(
        "account.user.deleted",
        C.CONFIGURATION,
        {S.LINUX_INVENTORY, S.MACOS_INVENTORY},
        "Local account disappeared between inventory snapshots.",
        ("actor.name", "attributes.uid"),
    ),
    # ── Detection-test additions (schema 2.0) ────────────────────────
    _spec(
        "github.secret.exposed",
        C.SOURCE_CONTROL,
        {S.GITHUB_API},
        "A commit added a credential-shaped string (matched by the redaction patterns). Only the "
        "pattern name, file, line and a redacted match are stored; never the value.",
        (
            "github.repository",
            "github.commit_sha",
            "resource.path",
            "attributes.pattern",
            "attributes.line",
            "attributes.redacted_match",
        ),
    ),
    _spec(
        "software.installed",
        C.PACKAGE,
        {S.MACOS_INVENTORY},
        "Application bundle appeared in an inventoried application directory (snapshot diff), "
        "with its code-signature status when determinable.",
        (
            "resource.path",
            "resource.name",
            "attributes.bundle_id",
            "attributes.version",
            "attributes.signed",
            "attributes.signature_team_id",
        ),
    ),
    _spec(
        "software.removed",
        C.PACKAGE,
        {S.MACOS_INVENTORY},
        "Application bundle no longer present (snapshot diff).",
        ("resource.path", "resource.name", "attributes.bundle_id"),
    ),
    # ── ExtorQ pipeline ──────────────────────────────────────────────
    _spec(
        "extorq.collector.gap_detected",
        C.COLLECTOR,
        {
            S.EXTORQ_PIPELINE,
            S.LINUX_JOURNALD,
            S.LINUX_AUDITD,
            S.LINUX_INVENTORY,
            S.LINUX_NGINX,
            S.LINUX_APACHE,
            S.MACOS_UNIFIED_LOG,
            S.MACOS_LAUNCHD,
            S.MACOS_INVENTORY,
            S.K8S_API_INVENTORY,
            S.K8S_EVENTS,
            S.K8S_AUDIT,
            S.K8S_CONTAINER_LOG,
            S.GITHUB_API,
        },
        "A collector detected a telemetry gap (cursor invalidated, log rotated past offset, "
        "API history truncated).",
        ("attributes.collector_id", "attributes.source_type", "attributes.gap_reason"),
    ),
]

EVENT_CATALOG: dict[str, EventTypeSpec] = {spec.event_type: spec for spec in _SPECS}


def get_spec(event_type: str) -> EventTypeSpec | None:
    return EVENT_CATALOG.get(event_type)


def validate_event_semantics(event_type: str, category: str, source_type: str) -> str | None:
    """Return a quarantine reason if the triple violates the catalog, else ``None``."""
    spec = EVENT_CATALOG.get(event_type)
    if spec is None:
        return f"unknown_event_type:{event_type}"
    if spec.category.value != category:
        return f"category_mismatch:{event_type} expects {spec.category.value}, got {category}"
    if source_type not in {s.value for s in spec.sources}:
        return f"source_not_allowed:{source_type} may not emit {event_type}"
    return None

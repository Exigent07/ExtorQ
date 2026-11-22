"""Linux detection tests on the Ubuntu VM ``linux:lab-vm-01`` (QEMU, user-mode networking).

Access paths (from the Mac): SSH ``127.0.0.1:2222`` and HTTP ``127.0.0.1:8088`` (nginx in
front of the lab-portal app). Inside the VM every connection from the Mac comes from the
QEMU gateway ``10.0.2.2``, which is why the source-address rules report confidence medium.

Changes on the VM are made as the operator account ``extorq-admin`` (key
``var/vm/keys/extorq-admin``, host key pinned in ``var/vm/known_hosts``, passwordless
sudo). Each change is a FIXED shell script sent on stdin to ``sudo -n /bin/sh -s -- <action>
<name>``: the only variable parts are the action (from a fixed set) and an artefact name
validated on both sides (``extorq-test-`` + 6 hex), so nothing from outside can reach the
remote shell. Every created object (unit, account, cron file, temp file) is removed and its
absence verified by the same script.

Order matters inside this suite (``build_suite``): the CORR-002 test needs a clean 30-minute
history without HTTP probing for its negative control, so the standalone HTTP-001 and APP-001
tests run after it, and the standalone SSH burst (VM-001) and unit creation (VM-002) run
before any probing so that they never form an accidental probing -> SSH -> systemd chain.
"""

from __future__ import annotations

import shutil
import tempfile
from collections.abc import Sequence
from datetime import timedelta
from pathlib import Path

from detection_tests.model import (
    ActionFailed,
    ActionRecord,
    AssetRef,
    CleanupStack,
    DetectionTest,
    LatencySource,
    PreconditionFailed,
    StepResult,
    TelemetryExpectation,
    TestSpec,
    validate_artefact_name,
)
from detection_tests.proc import ProcResult, display, run, which
from detection_tests.runner import AssetSuite, TestContext
from detection_tests.web import DEMO_USER, failed_logins, get_all, login, random_password
from detection_tests.windows import parse_time

ASSET = AssetRef("linux", "linux:lab-vm-01", "Ubuntu 24.04 VM lab-vm-01")
SSH_HOST = "127.0.0.1"
SSH_PORT = 2222
HTTP_BASE = "http://127.0.0.1:8088"
#: Every connection from the Mac reaches the VM through the QEMU user-mode gateway.
MAC_SOURCE_IP = "10.0.2.2"
ADMIN_USER = "extorq-admin"
ADMIN_KEY = "var/vm/keys/extorq-admin"
KNOWN_HOSTS = "var/vm/known_hosts"
COLLECTOR_ID = "linux-ssh-lab-vm-01"
CONFIG_FILE = "config/collectors/linux.yaml"
#: Account names guessed by every SSH brute-force tool.
GUESSED_USERS = ("root", "admin", "oracle", "test", "ubuntu")
#: Paths requested by web scanners (each matches HTTP-001's probe-route pattern).
PROBE_PATHS = (
    "/.env",
    "/.git/config",
    "/wp-login.php",
    "/phpmyadmin/",
    "/server-status",
    "/admin",
    "/actuator/health",
    "/.aws/credentials",
    "/config.php",
    "/backup.zip",
    "/cgi-bin/test.cgi",
    "/xmlrpc.php",
    "/.svn/entries",
    "/jenkins/login",
)
#: Ordinary pages answered 200 by the lab portal (negative control of HTTP-001).
NORMAL_PATHS = ("/", "/healthz")

JOURNAL = LatencySource(
    description="journald on the VM (sshd, nginx, lab-portal), read every collector cycle",
    config_file=CONFIG_FILE,
    collector_id=COLLECTOR_ID,
    interval_keys=(),
    default_seconds=30,
)
INVENTORY = LatencySource(
    description="VM inventory diff (systemd units, local accounts, cron) plus auditd",
    config_file=CONFIG_FILE,
    collector_id=COLLECTOR_ID,
    interval_keys=("settings", "inventory", "interval_seconds"),
    default_seconds=60,
)

# ── remote scripts (fixed text; run with `sh -s -- <action> <name>`) ──────────────────

_NAME_GLOB = "extorq-test-" + "[0-9a-f]" * 6
_NAME_CHECK = f"""case "$2" in
  {_NAME_GLOB}) ;;
  *) echo "refusing artefact name" >&2; exit 2 ;;
esac"""

#: VM-002 / CORR-002: a harmless oneshot unit (ExecStart=/bin/true), enabled, never started.
UNIT_SCRIPT = f"""set -eu
{_NAME_CHECK}
unit="$2.service"
path="/etc/systemd/system/$unit"
case "$1" in
  create)
    if [ -e "$path" ]; then echo "unit already exists" >&2; exit 3; fi
    umask 022
    printf '%s\\n' '[Unit]' 'Description=Nightly cache warm-up' '' '[Service]' \\
      'Type=oneshot' 'ExecStart=/bin/true' '' '[Install]' 'WantedBy=multi-user.target' >"$path"
    systemctl daemon-reload
    systemctl enable "$unit" >/dev/null 2>&1
    echo "created $path, enabled=$(systemctl is-enabled "$unit" 2>/dev/null || true)"
    ;;
  remove)
    systemctl disable "$unit" >/dev/null 2>&1 || true
    rm -f -- "$path"
    systemctl daemon-reload
    if [ -e "$path" ] || [ -e "/etc/systemd/system/multi-user.target.wants/$unit" ]; then
      echo "unit still present" >&2; exit 4
    fi
    echo "removed $path (verified absent)"
    ;;
  *) echo "unknown action" >&2; exit 2 ;;
esac
"""

#: VM-003: a local account without home directory and with a non-login shell.
ACCOUNT_SCRIPT = f"""set -eu
{_NAME_CHECK}
case "$1" in
  add)
    if getent passwd "$2" >/dev/null; then echo "account already exists" >&2; exit 3; fi
    useradd --no-create-home --shell /usr/sbin/nologin --comment "Build agent" "$2"
    echo "created account $(getent passwd "$2" | cut -d: -f1,3,7)"
    ;;
  remove)
    if getent passwd "$2" >/dev/null; then userdel "$2"; fi
    if getent group "$2" >/dev/null; then groupdel "$2"; fi
    if getent passwd "$2" >/dev/null; then echo "account still present" >&2; exit 4; fi
    echo "removed account $2 (verified absent)"
    ;;
  *) echo "unknown action" >&2; exit 2 ;;
esac
"""

#: VM-004: a system cron file whose only job (/bin/true) runs once a year, at 03:17 on 1 Jan.
CRON_SCRIPT = f"""set -eu
{_NAME_CHECK}
path="/etc/cron.d/$2"
case "$1" in
  add)
    if [ -e "$path" ]; then echo "cron file already exists" >&2; exit 3; fi
    umask 022
    printf '%s\\n' '# Rotate application cache' 'SHELL=/bin/sh' \\
      'PATH=/usr/sbin:/usr/bin:/sbin:/bin' '17 3 1 1 * root /bin/true' >"$path"
    echo "created $path"
    ;;
  remove)
    rm -f -- "$path"
    if [ -e "$path" ]; then echo "cron file still present" >&2; exit 4; fi
    echo "removed $path (verified absent)"
    ;;
  *) echo "unknown action" >&2; exit 2 ;;
esac
"""

#: VM-003 negative control (runs as extorq-admin, no sudo): an ordinary temp file.
TMPFILE_SCRIPT = f"""set -eu
{_NAME_CHECK}
path="/tmp/$2"
case "$1" in
  create)
    if [ -e "$path" ]; then echo "file already exists" >&2; exit 3; fi
    umask 077
    printf 'export cache\\n' >"$path"
    echo "created $path"
    ;;
  remove)
    rm -f -- "$path"
    if [ -e "$path" ]; then echo "file still present" >&2; exit 4; fi
    echo "removed $path (verified absent)"
    ;;
  *) echo "unknown action" >&2; exit 2 ;;
esac
"""

#: VM-002 negative control (root): a state change of an existing unit, no file change.
RESTART_SCRIPT = """set -eu
systemctl restart cron.service
echo "cron.service $(systemctl is-active cron.service)"
"""

#: VM-004 negative control (extorq-admin, no sudo): read-only cron listing.
CRON_LIST_SCRIPT = """set -eu
crontab -l >/dev/null 2>&1 || true
ls -l /etc/cron.d >/dev/null
echo "listed the user crontab and /etc/cron.d (read-only)"
"""

#: APP-001 negative control (root python on the VM): ONE successful login with the demo
#: credential, which is generated inside the VM and never leaves it: only the status prints.
APP_LOGIN_PY = """import json
import urllib.error
import urllib.request

fields = {}
with open("/etc/extorq/lab-portal/demo-credentials", encoding="utf-8") as handle:
    for line in handle:
        key, sep, value = line.rstrip("\\n").partition("=")
        if sep:
            fields[key] = value
body = json.dumps({"username": fields.get("username", ""), "password": fields.get("password", "")})
fields.clear()
request = urllib.request.Request(
    "http://127.0.0.1/login",
    data=body.encode("utf-8"),
    method="POST",
    headers={"Content-Type": "application/json", "Accept": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status = response.status
except urllib.error.HTTPError as exc:
    status = exc.code
print(f"status={status}")
"""

#: `cleanup` subcommand (root): removes leftovers of interrupted runs, exact names only.
SWEEP_SCRIPT = f"""set -u
for path in /etc/systemd/system/extorq-test-*.service; do
  [ -e "$path" ] || continue
  unit="${{path##*/}}"
  case "$unit" in {_NAME_GLOB}.service) ;; *) continue ;; esac
  systemctl disable "$unit" >/dev/null 2>&1 || true
  rm -f -- "$path" && echo "removed unit $unit"
done
systemctl daemon-reload
for user in $(getent passwd | cut -d: -f1); do
  case "$user" in {_NAME_GLOB}) userdel "$user" && echo "removed account $user" ;; esac
done
for path in /etc/cron.d/extorq-test-* /tmp/extorq-test-*; do
  [ -e "$path" ] || continue
  case "${{path##*/}}" in {_NAME_GLOB}) rm -f -- "$path" && echo "removed $path" ;; esac
done
echo "sweep complete"
"""


# ── VM access ──────────────────────────────────────────────────────────────────────────


class LinuxVM:
    """SSH and HTTP access to the VM with pinned host key and fixed options."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.admin_key = root / ADMIN_KEY
        self.known_hosts = root / KNOWN_HOSTS

    def ssh_argv(
        self, *, user: str, identities: Sequence[Path], remote: Sequence[str] = ()
    ) -> list[str]:
        """``ssh`` argv: no user config, no agent, public keys only, host key pinned."""
        argv = [
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "LogLevel=ERROR",
            "-p",
            str(SSH_PORT),
        ]
        for identity in identities:
            argv += ["-i", str(identity)]
        return [*argv, "-l", user, SSH_HOST, *remote]

    def admin(self, remote: Sequence[str], *, input_text: str | None = None) -> ProcResult:
        return run(
            self.ssh_argv(user=ADMIN_USER, identities=[self.admin_key], remote=remote),
            timeout=90,
            input_text=input_text,
            what="ssh extorq-admin",
        )

    def script(self, script: str, *args: str, root: bool = True) -> str:
        """Run a fixed script (root via ``sudo -n``) with validated args; return its stdout."""
        for value in args:
            if value not in ("create", "remove", "add") and not _is_name(value):
                raise ValueError(f"invalid remote script argument {value!r}")
        prefix = ["sudo", "-n"] if root else []
        result = self.admin([*prefix, "/bin/sh", "-s", "--", *args], input_text=script)
        if not result.ok:
            raise ActionFailed(
                f"remote script exit {result.returncode}: {display(result.stderr or result.stdout)}"
            )
        return display(result.stdout.strip(), 200)

    def root_python(self, program: str) -> str:
        result = self.admin(["sudo", "-n", "/usr/bin/python3", "-I", "-"], input_text=program)
        if not result.ok:
            raise ActionFailed(f"remote python exit {result.returncode}: {display(result.stderr)}")
        return display(result.stdout.strip(), 200)

    def check(self, _ctx: TestContext) -> list[StepResult]:
        checks: list[StepResult] = []
        for tool in ("ssh", "ssh-keygen"):
            checks.append(StepResult(f"{tool} on PATH", which(tool) is not None, tool))
        for path in (self.admin_key, self.known_hosts):
            checks.append(
                StepResult(
                    f"file {path.relative_to(self.root)}",
                    path.is_file(),
                    "present" if path.is_file() else "missing: run `make vm-up`",
                )
            )
        if not all(c.ok for c in checks):
            return checks
        result = self.admin(["true"])
        checks.append(
            StepResult(
                f"SSH {ADMIN_USER}@{SSH_HOST}:{SSH_PORT}",
                result.ok,
                "reachable" if result.ok else f"failed: {display(result.stderr)}",
            )
        )
        try:
            status = get_all(HTTP_BASE, ["/healthz"])[0][1]
        except ActionFailed as exc:
            checks.append(StepResult(f"HTTP {HTTP_BASE}/healthz", False, str(exc)))
        else:
            checks.append(StepResult(f"HTTP {HTTP_BASE}/healthz", status == 200, f"HTTP {status}"))
        return checks

    def sweep(self, _ctx: TestContext) -> list[StepResult]:
        try:
            output = self.script(SWEEP_SCRIPT)
        except ActionFailed as exc:
            return [
                StepResult(
                    "VM leftovers (units, accounts, cron files, temp files)", False, str(exc)
                )
            ]
        return [StepResult("VM leftovers (units, accounts, cron files, temp files)", True, output)]


def _is_name(value: str) -> bool:
    try:
        validate_artefact_name(value)
    except ValueError:
        return False
    return True


def _auth_rejected(result: ProcResult) -> bool:
    """True when sshd itself refused the login (as opposed to an unreachable VM)."""
    text = result.stderr
    return not result.ok and (
        "Permission denied" in text
        or "Too many authentication failures" in text
        or "Authentication failed" in text
    )


def ssh_failure_burst(vm: LinuxVM, ctx: TestContext, cleanup: CleanupStack) -> list[str]:
    """10 failed public-key logins as commonly guessed users, plus one exceeding MaxAuthTries.

    The keys are generated for this burst and deleted afterwards: they are not authorised
    anywhere, so no attempt can succeed (if one did, the action stops and says so).
    """
    keydir = Path(tempfile.mkdtemp(prefix="extorq-test-keys-"))
    cleanup.push("delete the throwaway SSH keys", lambda: _remove_tree(keydir))
    keys = [keydir / f"id_{index}" for index in range(5)]
    for key in keys:
        run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(key)],
            timeout=30,
            check=True,
        )
    rejected: list[str] = []
    for index in range(10):
        ctx.check_cancelled()
        user = GUESSED_USERS[index % len(GUESSED_USERS)]
        result = run(vm.ssh_argv(user=user, identities=[keys[0]], remote=["true"]), timeout=30)
        if result.ok:
            raise ActionFailed(f"a throwaway key logged in as {user}: investigate the VM")
        if _auth_rejected(result):
            rejected.append(user)
        ctx.clock.sleep(0.3)
    multi = run(vm.ssh_argv(user="admin", identities=keys[1:], remote=["true"]), timeout=30)
    if multi.ok:
        raise ActionFailed("a throwaway key logged in as admin: investigate the VM")
    if len(rejected) < 8:
        raise ActionFailed(
            f"only {len(rejected)} of 10 connections reached sshd authentication "
            f"(last error: {display(multi.stderr)})"
        )
    return [
        f"{len(rejected)} connections from the Mac rejected by sshd "
        f"(users {', '.join(GUESSED_USERS)})",
        "1 connection as admin offering 4 throwaway keys (exceeds MaxAuthTries 3)",
    ]


def _remove_tree(path: Path) -> str:
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        raise OSError(f"{path} still exists")
    return "deleted"


def probe(ctx: TestContext) -> list[str]:
    """Request every probe path once; at least 12 must be answered with a client error."""
    ctx.check_cancelled()
    answers = get_all(HTTP_BASE, PROBE_PATHS)
    client_errors = [path for path, status in answers if 400 <= status < 500]
    if len(client_errors) < 12:
        summary = ", ".join(f"{p} {s}" for p, s in answers)
        raise ActionFailed(f"only {len(client_errors)} probes answered 4xx: {summary}")
    return [f"GET {len(PROBE_PATHS)} probe paths -> {len(client_errors)} client errors (4xx)"]


def ssh_rejections(min_count: int) -> TelemetryExpectation:
    return TelemetryExpectation(
        "sshd closed the rejected connections from 10.0.2.2 (journald)",
        "auth.ssh.preauth_closed",
        src_ip=MAC_SOURCE_IP,
        min_count=min_count,
    )


def unit_created(unit_path: str) -> TelemetryExpectation:
    return TelemetryExpectation(
        f"inventory diff saw {unit_path}",
        "persistence.systemd.unit_created",
        equals=(("resource_path", unit_path),),
    )


# ── tests ──────────────────────────────────────────────────────────────────────────────


class _LinuxTest(DetectionTest):
    def __init__(self, vm: LinuxVM) -> None:
        self.vm = vm


class SshBurstTest(_LinuxTest):
    spec = TestSpec(
        test_id="linux.vm-001",
        asset=ASSET,
        rule_id="VM-001",
        title="Burst of failed SSH authentication",
        positive=(
            "From the Mac: 10 SSH connections to 127.0.0.1:2222 as root, admin, oracle, test and "
            "ubuntu, each offering a freshly generated throwaway key, plus one connection "
            "offering four keys (exceeds MaxAuthTries 3)."
        ),
        negative="Three successful key logins of the operator account extorq-admin.",
        cleanup="The throwaway keys are deleted; nothing is created on the VM.",
        expected_alert=(
            "VM-001 on linux:lab-vm-01, src_ip 10.0.2.2, confidence medium (shared QEMU NAT "
            "address: the burst is real, its origin is not attributable)."
        ),
        safety=(
            "Keys are random and authorised nowhere; password and keyboard-interactive "
            "authentication are disabled on both sides; any unexpected success stops the test."
        ),
        source=JOURNAL,
        # Successful logins are never counted by VM-001: no separation from the burst needed.
        phase_gap_seconds=0,
    )

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        details = ssh_failure_burst(self.vm, ctx, cleanup)
        return ActionRecord(
            "11 failed SSH logins from the Mac (10.0.2.2)",
            details=details,
            telemetry=[ssh_rejections(8)],
            artefact_hint=MAC_SOURCE_IP,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        for _ in range(3):
            ctx.check_cancelled()
            result = self.vm.admin(["true"])
            if not result.ok:
                raise ActionFailed(f"operator login failed: {display(result.stderr)}")
        return ActionRecord(
            "3 successful key logins as extorq-admin",
            telemetry=[
                TelemetryExpectation(
                    "3 accepted logins of extorq-admin (journald)",
                    "auth.ssh.login_succeeded",
                    actor=ADMIN_USER,
                    min_count=3,
                )
            ],
        )


class SystemdUnitTest(_LinuxTest):
    spec = TestSpec(
        test_id="linux.vm-002",
        asset=ASSET,
        rule_id="VM-002",
        title="systemd unit created and enabled (persistence)",
        positive=(
            "As extorq-admin with sudo: write /etc/systemd/system/extorq-test-<id>.service "
            "(Type=oneshot, ExecStart=/bin/true), daemon-reload, enable. The unit is never started."
        ),
        negative="Restart the existing cron.service (a state change, no unit file changes).",
        cleanup="Disable and delete the unit, daemon-reload, verify the file and symlink are gone.",
        expected_alert=(
            "VM-002 on linux:lab-vm-01 for the new unit, confidence high when the auditd write "
            "and the inventory diff agree on the path."
        ),
        safety="The unit only runs /bin/true and is never started; it exists for minutes.",
        source=INVENTORY,
    )

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        result = self.vm.admin(["systemctl", "is-active", "cron.service"])
        if result.stdout.strip() != "active":
            raise PreconditionFailed("cron.service is not active on the VM (negative control)")
        return [StepResult("cron.service active", True, "negative control target present")]

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        name = ctx.new_name()
        cleanup.push(
            f"remove unit {name}.service", lambda: self.vm.script(UNIT_SCRIPT, "remove", name)
        )
        output = self.vm.script(UNIT_SCRIPT, "create", name)
        path = f"/etc/systemd/system/{name}.service"
        return ActionRecord(
            f"created and enabled {path}",
            details=[output],
            artefacts=[path],
            telemetry=[unit_created(path)],
            artefact_hint=name,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        output = self.vm.script(RESTART_SCRIPT)
        return ActionRecord(
            "restarted cron.service",
            details=[output],
            telemetry=[
                TelemetryExpectation(
                    "systemd reported the cron.service restart (journald)",
                    "system.service.state_changed",
                    equals=(("resource_name", "cron.service"),),
                )
            ],
        )


class LocalAccountTest(_LinuxTest):
    spec = TestSpec(
        test_id="linux.vm-003",
        asset=ASSET,
        rule_id="VM-003",
        title="Local account created",
        positive=(
            "As extorq-admin with sudo: useradd --no-create-home --shell /usr/sbin/nologin "
            "extorq-test-<id>."
        ),
        negative="Create an ordinary file /tmp/extorq-test-<id> (no account change).",
        cleanup="userdel (and groupdel of a leftover private group); delete the temp file.",
        expected_alert="VM-003 on linux:lab-vm-01 for the new account (inventory diff).",
        safety="The account has no password, no home directory and a non-login shell.",
        source=INVENTORY,
    )

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        name = ctx.new_name()
        cleanup.push(
            f"remove account {name}", lambda: self.vm.script(ACCOUNT_SCRIPT, "remove", name)
        )
        output = self.vm.script(ACCOUNT_SCRIPT, "add", name)
        return ActionRecord(
            f"created local account {name}",
            details=[output],
            artefacts=[f"account {name}"],
            telemetry=[
                TelemetryExpectation(
                    f"inventory diff saw account {name}",
                    "account.user.created",
                    equals=(("actor_name", name),),
                )
            ],
            artefact_hint=name,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        name = ctx.new_name()
        cleanup.push(
            f"remove /tmp/{name}",
            lambda: self.vm.script(TMPFILE_SCRIPT, "remove", name, root=False),
        )
        output = self.vm.script(TMPFILE_SCRIPT, "create", name, root=False)
        remote_path = f"/tmp/{name}"  # noqa: S108 - a file on the VM, created by the script
        return ActionRecord(
            f"created {remote_path} as extorq-admin (kept for the whole detection bound)",
            details=[output],
            artefacts=[remote_path],
        )


class CronFileTest(_LinuxTest):
    spec = TestSpec(
        test_id="linux.vm-004",
        asset=ASSET,
        rule_id="VM-004",
        title="Cron persistence file added",
        positive=(
            "As extorq-admin with sudo: write /etc/cron.d/extorq-test-<id> with one job that "
            "runs /bin/true once a year (03:17 on 1 January)."
        ),
        negative="crontab -l and a listing of /etc/cron.d (read-only).",
        cleanup="Delete the cron file and verify it is gone.",
        expected_alert="VM-004 on linux:lab-vm-01 for the added cron file (inventory diff).",
        safety="The job only runs /bin/true and is scheduled far outside the test window.",
        source=INVENTORY,
    )

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        name = ctx.new_name()
        path = f"/etc/cron.d/{name}"
        cleanup.push(f"remove {path}", lambda: self.vm.script(CRON_SCRIPT, "remove", name))
        output = self.vm.script(CRON_SCRIPT, "add", name)
        return ActionRecord(
            f"created {path}",
            details=[output],
            artefacts=[path],
            telemetry=[
                TelemetryExpectation(
                    f"inventory diff saw {path}",
                    "persistence.cron.changed",
                    equals=(("resource_path", path),),
                )
            ],
            artefact_hint=name,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        output = self.vm.script(CRON_LIST_SCRIPT, root=False)
        return ActionRecord("listed cron configuration (read-only)", details=[output])


class WebProbeTest(_LinuxTest):
    spec = TestSpec(
        test_id="linux.http-001",
        asset=ASSET,
        rule_id="HTTP-001",
        title="Web probing from one source",
        positive=(
            "From the Mac: GET 14 paths web scanners request (/.env, /.git/config, "
            "/wp-login.php, /phpmyadmin/, /server-status, /admin, ...) on 127.0.0.1:8088; "
            "at least 12 must be answered with 4xx."
        ),
        negative="20 ordinary requests (/ and /healthz) answered 200.",
        cleanup="Nothing to remove (requests only).",
        expected_alert="HTTP-001 on linux:lab-vm-01, src_ip 10.0.2.2, confidence medium.",
        safety="Read-only GET requests to the lab portal; nothing on the VM changes.",
        source=JOURNAL,
        # 2xx answers are never counted by HTTP-001: no separation from the probing needed.
        phase_gap_seconds=0,
    )

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        details = probe(ctx)
        return ActionRecord(
            "probed 14 scanner paths",
            details=details,
            telemetry=[
                TelemetryExpectation(
                    "nginx logged the probes from 10.0.2.2",
                    "http.request",
                    src_ip=MAC_SOURCE_IP,
                    source_type="linux.nginx",
                    min_count=12,
                )
            ],
            artefact_hint=MAC_SOURCE_IP,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        answers = get_all(HTTP_BASE, [NORMAL_PATHS[i % 2] for i in range(20)])
        bad = [f"{p} {s}" for p, s in answers if not 200 <= s < 300]
        if bad:
            raise ActionFailed(f"ordinary requests were not answered 2xx: {', '.join(bad)}")
        return ActionRecord(
            "20 ordinary GET requests answered 200",
            telemetry=[
                TelemetryExpectation(
                    "nginx logged the ordinary 200 requests from 10.0.2.2",
                    "http.request",
                    equals=(("http_status", 200),),
                    src_ip=MAC_SOURCE_IP,
                    source_type="linux.nginx",
                    min_count=10,
                )
            ],
        )


class WebLoginTest(_LinuxTest):
    spec = TestSpec(
        test_id="linux.app-001",
        asset=ASSET,
        rule_id="APP-001",
        title="Burst of failed web application logins",
        positive=(
            "From the Mac: 6 failed POST /login for the demo account lab-admin with random "
            "wrong passwords (127.0.0.1:8088, JSON)."
        ),
        negative=(
            "1 failed login from the Mac, then 1 successful login performed inside the VM "
            "(the demo credential never leaves the VM)."
        ),
        cleanup="Nothing to remove (one portal session expires on its own).",
        expected_alert="APP-001 on linux:lab-vm-01, variant guessing, user lab-admin.",
        safety=(
            "Wrong passwords are random; the real credential is read by root on the VM and only "
            "the HTTP status is printed."
        ),
        source=JOURNAL,
    )

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        result = self.vm.admin(
            ["sudo", "-n", "test", "-r", "/etc/extorq/lab-portal/demo-credentials"]
        )
        if not result.ok:
            raise PreconditionFailed("the lab-portal demo credential is missing on the VM")
        return [StepResult("lab-portal demo credential on the VM", True, "present")]

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        statuses = failed_logins(HTTP_BASE, 6)
        if any(status != 401 for status in statuses):
            raise ActionFailed(f"failed logins were answered {statuses} (expected 401 each)")
        return ActionRecord(
            "6 failed logins for lab-admin",
            details=[f"POST /login x6 -> {statuses}"],
            telemetry=[
                TelemetryExpectation(
                    "lab-portal reported 6 failed logins of lab-admin",
                    "app.auth.login_failed",
                    actor=DEMO_USER,
                    source_type="linux.app",
                    min_count=6,
                )
            ],
            artefact_hint=DEMO_USER,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        failed = login(HTTP_BASE, DEMO_USER, random_password())
        if failed != 401:
            raise ActionFailed(f"the failed login was answered {failed} (expected 401)")
        output = self.vm.root_python(APP_LOGIN_PY)
        if output != "status=200":
            raise ActionFailed(f"the successful login inside the VM returned {output}")
        return ActionRecord(
            "1 failed login (Mac) and 1 successful login (inside the VM)",
            details=["POST /login (wrong password) -> 401", f"POST /login on the VM -> {output}"],
            telemetry=[
                TelemetryExpectation(
                    "lab-portal reported the failed login",
                    "app.auth.login_failed",
                    actor=DEMO_USER,
                    source_type="linux.app",
                ),
                TelemetryExpectation(
                    "lab-portal reported the successful login",
                    "app.auth.login_succeeded",
                    actor=DEMO_USER,
                    source_type="linux.app",
                ),
            ],
        )


class SequenceTest(_LinuxTest):
    spec = TestSpec(
        test_id="linux.corr-002",
        asset=ASSET,
        rule_id="CORR-002",
        title="Ordered probing, SSH failures and systemd persistence on one host",
        positive=(
            "Within a few minutes, in this order: the HTTP-001 probe requests, the VM-001 SSH "
            "burst, and the VM-002 unit creation (extorq-test-<id>.service)."
        ),
        negative=(
            "Run FIRST: the VM-001 SSH burst alone (no probing in the preceding 30 minutes, no "
            "persistence after it)."
        ),
        cleanup="Disable and delete the unit; delete the throwaway SSH keys.",
        expected_alert=(
            "CORR-002 on linux:lab-vm-01, confidence low (all stages come from the shared NAT "
            "address 10.0.2.2: ordered co-occurrence, never causation). HTTP-001, VM-001 and "
            "VM-002 alert as well."
        ),
        safety="The union of the HTTP-001, VM-001 and VM-002 safety properties.",
        source=INVENTORY,
        positive_overlaps=frozenset({"HTTP-001", "VM-001", "VM-002"}),
        negative_overlaps=frozenset({"VM-001"}),
        negative_first=True,
        # The two SSH bursts must fall into different 5-minute SSH stage windows, otherwise
        # the earlier (negative) burst would set the stage-2 time before the probing.
        phase_gap_seconds=300,
    )

    #: CORR-002 ``sequence_seconds``: probing older than this cannot start a chain.
    SEQUENCE_SECONDS = 1800

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        now = ctx.clock.now()
        since = now - timedelta(seconds=self.SEQUENCE_SECONDS + ctx.options.clock_skew_seconds)
        alerts = ctx.api.alerts(
            asset_id=ASSET.asset_id, rule_id="HTTP-001", since=since, until=now + timedelta(days=1)
        )
        recent = [
            t
            for t in (parse_time(a.get("last_seen")) for a in alerts)
            if t is not None and t >= since
        ]
        if recent:
            ready = max(recent) + timedelta(
                seconds=self.SEQUENCE_SECONDS + ctx.options.clock_skew_seconds
            )
            raise PreconditionFailed(
                "HTTP probing was detected on linux:lab-vm-01 within the last 30 minutes, so an "
                "SSH burst now would be a valid second CORR-002 stage and the negative control "
                f"would be meaningless; retry after {ready:%H:%M:%SZ}"
            )
        return [
            StepResult("no HTTP probing in the last 30 minutes", True, "negative control valid")
        ]

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        details = ssh_failure_burst(self.vm, ctx, cleanup)
        return ActionRecord(
            "SSH burst alone (no probing before, no persistence after)",
            details=details,
            telemetry=[ssh_rejections(8)],
        )

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        details = probe(ctx)
        details += ssh_failure_burst(self.vm, ctx, cleanup)
        name = ctx.new_name()
        cleanup.push(
            f"remove unit {name}.service", lambda: self.vm.script(UNIT_SCRIPT, "remove", name)
        )
        details.append(self.vm.script(UNIT_SCRIPT, "create", name))
        path = f"/etc/systemd/system/{name}.service"
        return ActionRecord(
            "probing -> SSH burst -> unit created, in order",
            details=details,
            artefacts=[path],
            telemetry=[ssh_rejections(8), unit_created(path)],
            artefact_hint=name,
        )


def build_suite(root: Path) -> AssetSuite:
    vm = LinuxVM(root)
    tests: list[DetectionTest] = [
        SshBurstTest(vm),
        SystemdUnitTest(vm),
        LocalAccountTest(vm),
        CronFileTest(vm),
        SequenceTest(vm),
        WebProbeTest(vm),
        WebLoginTest(vm),
    ]
    return AssetSuite(
        asset=ASSET,
        tests=tests,
        check=vm.check,
        sweep=vm.sweep,
        collector_ids=(COLLECTOR_ID,),
    )

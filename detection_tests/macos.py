"""macOS detection tests on the host itself (asset ``macos:workstation-01``).

Hard limits (``docs/team/PLAN.md`` section 12): no successful sudo, no launch item is ever
loaded (``launchctl`` is never called), no security setting is changed. Everything happens
as the logged-in user:

* launch agent property lists are written to ``~/Library/LaunchAgents`` (temp file, ``plutil
  -lint``, then an exclusive hard link so an existing file is never overwritten) with
  ``RunAtLoad`` false, and removed only after their ``Label`` is verified;
* the listener is a child Python process that accepts and immediately closes connections
  and exits by itself after its lifetime even if the runner dies;
* sudo is called only with a random wrong password after ``sudo -k``; if sudo ever accepts
  (a NOPASSWD rule), the test stops, says so, and invalidates the timestamp again. The test
  refuses to run when Touch ID is configured for sudo (a fingerprint would succeed);
* application bundles are built next to ``/Applications`` under a hidden temporary name and
  renamed into place complete (``/Applications`` is writable by admin users without sudo);
  the unsigned one is never executed.

macOS may show a "Background Items Added" notification for the launch agents and, if the
application firewall is on, ask whether Python may accept incoming connections (answer
Deny: the listener does not need inbound traffic to be observed).
"""

from __future__ import annotations

import os
import plistlib
import pwd
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from detection_tests.model import (
    ARTEFACT_PREFIX,
    REVERSE_DNS_PREFIX,
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
from detection_tests.proc import display, run
from detection_tests.runner import AssetSuite, TestContext
from detection_tests.web import random_password

ASSET = AssetRef("macos", "macos:workstation-01", "macOS host workstation-01")
COLLECTOR_ID = "macos-workstation-01"
CONFIG_FILE = "config/collectors/macos.yaml"
APPLICATIONS = Path("/Applications")
UNSIGNED_APP = APPLICATIONS / "ExtorQ Test.app"
SIGNED_COPY = APPLICATIONS / "ExtorQ Test Signed Copy.app"
#: Largest source considered for the MAC-005 negative control (it is copied, then deleted).
SIGNED_SOURCE_MAX_KB = 50_000
SUDO = "/usr/bin/sudo"
CODESIGN = "/usr/bin/codesign"
PLUTIL = "/usr/bin/plutil"
DITTO = "/usr/bin/ditto"
#: PAM modules that would let sudo succeed without a password (fingerprint, watch).
_BIOMETRIC_PAM = re.compile(r"^\s*auth\s+\S+\s+(pam_tid\.so|pam_watchid\.so)", re.MULTILINE)
_LABEL_RE = re.compile(r"^com\.extorq\.test\.[0-9a-f]{6}$")

LAUNCHD = LatencySource(
    description="launchd property-list scan (macos.launchd)",
    config_file=CONFIG_FILE,
    collector_id=COLLECTOR_ID,
    interval_keys=("settings", "launchd", "interval_seconds"),
    default_seconds=60,
)
LISTENERS = LatencySource(
    description="listening sockets in the host inventory (macos.inventory), up to 3 cycles",
    config_file=CONFIG_FILE,
    collector_id=COLLECTOR_ID,
    interval_keys=("settings", "inventory", "interval_seconds"),
    default_seconds=300,
    cycles=3,
)
UNIFIED_LOG = LatencySource(
    description="sudo records in the unified log (macos.unified_log)",
    config_file=CONFIG_FILE,
    collector_id=COLLECTOR_ID,
    interval_keys=("settings", "unified_log", "interval_seconds"),
    default_seconds=60,
)
SOFTWARE = LatencySource(
    description="application bundle scan with code-signature check (macos.inventory)",
    config_file=CONFIG_FILE,
    collector_id=COLLECTOR_ID,
    interval_keys=("settings", "software", "interval_seconds"),
    default_seconds=60,
    # A new bundle is reported once it has been quiet for a settle period (next scan).
    cycles=2,
)

#: Child process of MAC-003: accept-and-close TCP listener with a hard lifetime.
LISTENER_PROGRAM = """import socket
import sys
import time

host, port, lifetime = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
deadline = time.monotonic() + lifetime
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((host, port))
server.listen(8)
server.settimeout(1.0)
while time.monotonic() < deadline:
    try:
        connection, _peer = server.accept()
    except OSError:
        continue
    connection.close()
server.close()
"""


def launch_agents_dir() -> Path:
    return Path.home() / "Library" / "LaunchAgents"


def label_for(name: str) -> str:
    """``extorq-test-1a2b3c`` -> ``com.extorq.test.1a2b3c`` (launchd label / bundle id form)."""
    return REVERSE_DNS_PREFIX + validate_artefact_name(name).removeprefix(ARTEFACT_PREFIX)


def launch_agent_plist(label: str, program_arguments: Sequence[str]) -> bytes:
    """A launch agent that is never loaded: RunAtLoad false, no KeepAlive, no schedule."""
    if not _LABEL_RE.fullmatch(label):
        raise ValueError(f"invalid test label {label!r}")
    document = {"Label": label, "ProgramArguments": list(program_arguments), "RunAtLoad": False}
    return plistlib.dumps(document, fmt=plistlib.FMT_XML)


def app_version(bundle_id: str) -> str:
    """A build version unique to the run (``1.0.<n>`` from the id's 6 hex characters).

    MAC-005 identifies an alert by (path, version): a fixed version would make every run's
    install the SAME alert as the first one instead of a new detection.
    """
    if not _LABEL_RE.fullmatch(bundle_id):
        raise ValueError(f"invalid test bundle id {bundle_id!r}")
    return f"1.0.{int(bundle_id.rsplit('.', 1)[1], 16)}"


def app_info_plist(bundle_id: str) -> bytes:
    """Info.plist of the minimal unsigned test application."""
    version = app_version(bundle_id)
    document = {
        "CFBundleIdentifier": bundle_id,
        "CFBundleName": "ExtorQ Test",
        "CFBundleDisplayName": "ExtorQ Test",
        "CFBundleExecutable": "extorq-test",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version.rsplit(".", 1)[1],
        "LSMinimumSystemVersion": "13.0",
    }
    return plistlib.dumps(document, fmt=plistlib.FMT_XML)


def sudo_argv() -> list[str]:
    """``sudo -k -S -p '' -v``: ignore cached credentials, read the password from stdin."""
    return [SUDO, "-k", "-S", "-p", "", "-v"]


def biometric_sudo(texts: Sequence[str]) -> bool:
    """True when a PAM file enables Touch ID / Apple Watch for sudo (non-comment line)."""
    return any(_BIOMETRIC_PAM.search(text) for text in texts)


# ── file helpers ───────────────────────────────────────────────────────────────────────


def write_launch_agent(directory: Path, label: str, program_arguments: Sequence[str]) -> Path:
    """Write ``<label>.plist`` atomically and exclusively; never follows or replaces files."""
    if directory.is_symlink() or not directory.is_dir():
        raise ActionFailed(f"{directory} is missing or a symbolic link: refusing to write")
    target = directory / f"{label}.plist"
    if target.exists() or target.is_symlink():
        raise ActionFailed(f"{target} already exists")
    fd, tmp_name = tempfile.mkstemp(prefix=".extorq-test-", suffix=".tmp", dir=directory)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(launch_agent_plist(label, program_arguments))
        if not run([PLUTIL, "-lint", "-s", str(tmp)], timeout=30).ok:
            raise ActionFailed("generated property list failed plutil -lint")
        tmp.chmod(0o644)
        os.link(tmp, target)  # fails if the name appeared meanwhile: nothing is replaced
    finally:
        tmp.unlink(missing_ok=True)
    return target


def remove_launch_agent(path: Path, label: str) -> str:
    """Delete the plist only if it is a regular file carrying ``label``; verify absence."""
    if path.is_symlink():
        raise ActionFailed(f"{path} is a symbolic link: not created by the tests, not deleted")
    if not path.exists():
        return "already absent"
    if not path.is_file():
        raise ActionFailed(f"{path} is not a regular file: not deleted")
    try:
        found = plistlib.loads(path.read_bytes()).get("Label")
    except (plistlib.InvalidFileException, ValueError, OSError):
        found = None
    if found != label:
        raise ActionFailed(f"{path} does not carry Label {label}: not deleted")
    path.unlink()
    if path.exists() or path.is_symlink():
        raise ActionFailed(f"{path} still exists")
    return "deleted (verified absent)"


def bundle_id(app: Path) -> str | None:
    try:
        data = plistlib.loads((app / "Contents" / "Info.plist").read_bytes())
    except (plistlib.InvalidFileException, ValueError, OSError):
        return None
    value = data.get("CFBundleIdentifier") if isinstance(data, dict) else None
    return value if isinstance(value, str) else None


def remove_bundle(app: Path, expected_bundle_id: str | re.Pattern[str]) -> str:
    """Delete an application bundle created by the tests (bundle id verified first)."""
    if app.is_symlink():
        raise ActionFailed(f"{app} is a symbolic link: not deleted")
    if not app.exists():
        return "already absent"
    found = bundle_id(app)
    matches = (
        expected_bundle_id.fullmatch(found or "") is not None
        if isinstance(expected_bundle_id, re.Pattern)
        else found == expected_bundle_id
    )
    if not matches:
        raise ActionFailed(f"{app} has bundle id {found!r}: not created by the tests, not deleted")
    shutil.rmtree(app)
    if app.exists():
        raise ActionFailed(f"{app} still exists")
    return "deleted (verified absent)"


def codesign_verify(app: Path) -> tuple[bool, str]:
    result = run([CODESIGN, "--verify", "--strict", str(app)], timeout=120)
    return result.ok, display(result.stderr.strip() or "valid signature", 160)


_signed_source_cache: tuple[Path, str] | None = None


def signed_source() -> tuple[Path, str]:
    """(path, bundle id) of the control source for the MAC-005 negative.

    Apple's own apps cannot serve: SIP-protected bundles refuse to be copied at all. The
    control is a small, genuinely signed, NON-system application already installed in
    /Applications (the smallest that verifies under ``codesign --verify --strict``). It is only
    read; the copy is removed afterwards. Raises PreconditionFailed when none exists.
    """
    global _signed_source_cache
    if _signed_source_cache is not None:
        return _signed_source_cache
    best: tuple[int, Path] | None = None
    for app in sorted(APPLICATIONS.glob("*.app")):
        if app.is_symlink() or app in (UNSIGNED_APP, SIGNED_COPY):
            continue
        try:
            size = int(run(["/usr/bin/du", "-sk", str(app)], timeout=60).stdout.split()[0])
        except (ValueError, IndexError):
            continue
        if size == 0 or size > SIGNED_SOURCE_MAX_KB:
            continue  # 0 KB = firmlinked system app (e.g. Safari); too large = slow copy
        if best is not None and size >= best[0]:
            continue
        if codesign_verify(app)[0] and bundle_id(app):
            best = (size, app)
    if best is None:
        raise PreconditionFailed(
            f"no signed third-party application under {SIGNED_SOURCE_MAX_KB // 1000} MB found in "
            f"{APPLICATIONS}: the MAC-005 negative control needs one"
        )
    _signed_source_cache = (best[1], bundle_id(best[1]) or "")
    return _signed_source_cache


# ── listener ───────────────────────────────────────────────────────────────────────────


def free_port(rng: random.Random | None = None) -> int:
    """A TCP port in 42000-48999 that is free on 0.0.0.0 and 127.0.0.1 right now."""
    chooser = rng or random.SystemRandom()
    for _ in range(50):
        port = chooser.randint(42000, 48999)
        try:
            for host in ("0.0.0.0", "127.0.0.1"):  # noqa: S104 - probing, closed at once
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.bind((host, port))
        except OSError:
            continue
        return port
    raise ActionFailed("no free TCP port found in 42000-48999")


class Listener:
    """A self-terminating accept-and-close TCP listener (child process)."""

    def __init__(self, host: str, port: int, lifetime_seconds: int) -> None:
        self.host, self.port, self.lifetime = host, port, lifetime_seconds
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                "-c",
                LISTENER_PROGRAM,
                self.host,
                str(self.port),
                str(self.lifetime),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise ActionFailed(f"listener on {self.host}:{self.port} exited at start")
            if self._accepting():
                return
            time.sleep(0.2)
        raise ActionFailed(f"listener on {self.host}:{self.port} did not start")

    def _accepting(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                return True
        except OSError:
            return False

    def stop(self) -> str:
        process = self.process
        if process is None:
            return "never started"
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        if self._accepting():
            raise ActionFailed(f"port {self.port} still accepts connections")
        return f"listener on {self.host}:{self.port} stopped (verified closed)"


# ── tests ──────────────────────────────────────────────────────────────────────────────


def _launchd_created(path: Path) -> TelemetryExpectation:
    return TelemetryExpectation(
        f"launchd scan saw {path.name}",
        "persistence.launchd.item_created",
        equals=(("resource_path", str(path)),),
        source_type="macos.launchd",
    )


class LaunchAgentTest(DetectionTest):
    spec = TestSpec(
        test_id="macos.mac-001",
        asset=ASSET,
        rule_id="MAC-001",
        title="New launch agent property list",
        positive=(
            "Write ~/Library/LaunchAgents/com.extorq.test.<id>.plist running /usr/bin/true "
            "(RunAtLoad false, never loaded)."
        ),
        negative=(
            "Remove the positive's plist (the cleanup of the positive phase): MAC-001 fires on "
            "creation or modification, never on removal, and the launchd scan must report it."
        ),
        cleanup="Delete the plist after verifying it is ours (Label / regular file).",
        positive_first_in_batch=True,
        phase_gap_seconds=0,
        expected_alert="MAC-001 on macos:workstation-01 for the new plist.",
        safety="launchctl is never called; the job would only run /usr/bin/true.",
        source=LAUNCHD,
    )

    _created: Path | None = None

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        label = label_for(ctx.new_name())
        path = launch_agents_dir() / f"{label}.plist"
        cleanup.push(f"delete {path}", lambda: remove_launch_agent(path, label))
        write_launch_agent(launch_agents_dir(), label, ["/usr/bin/true"])
        self._created = path
        return ActionRecord(
            f"created {path} (/usr/bin/true, not loaded)",
            artefacts=[str(path)],
            telemetry=[_launchd_created(path)],
            artefact_hint=label,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        path = self._created
        if path is None:
            raise ActionFailed("the removal control needs the positive action to have run")
        if path.exists():
            raise ActionFailed(
                f"{path} still exists: the positive phase's cleanup did not remove it"
            )
        return ActionRecord(
            f"{path} was removed by the positive phase's cleanup; waiting for the removal event",
            artefacts=[str(path)],
            telemetry=[
                TelemetryExpectation(
                    "launchd scan reported the removal",
                    "persistence.launchd.item_deleted",
                    equals=(("resource_path", str(path)),),
                    source_type="macos.launchd",
                )
            ],
        )


class ShellLaunchAgentTest(DetectionTest):
    spec = TestSpec(
        test_id="macos.mac-002",
        asset=ASSET,
        rule_id="MAC-002",
        title="Launch agent running a shell / user-writable path",
        positive=(
            'Write a launch agent whose ProgramArguments are ["/bin/sh", "-c", '
            '"/tmp/extorq-test-<id>"] (never loaded; the script does not exist).'
        ),
        negative="A launch agent running /usr/bin/true (raises MAC-001 only).",
        cleanup="Delete both plists after verifying their Label.",
        expected_alert="MAC-002 on macos:workstation-01; MAC-001 alerts as well (overlap).",
        safety="Never loaded; RunAtLoad false; the referenced script never exists.",
        source=LAUNCHD,
        positive_overlaps=frozenset({"MAC-001"}),
        negative_overlaps=frozenset({"MAC-001"}),
    )

    def _write(self, ctx: TestContext, cleanup: CleanupStack, arguments: Sequence[str]) -> Path:
        label = label_for(ctx.new_name())
        path = launch_agents_dir() / f"{label}.plist"
        cleanup.push(f"delete {path}", lambda: remove_launch_agent(path, label))
        write_launch_agent(launch_agents_dir(), label, arguments)
        return path

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        # Never created: the agent is never loaded and the path is only its argument.
        script = f"/tmp/{ctx.new_name()}"  # noqa: S108
        path = self._write(ctx, cleanup, ["/bin/sh", "-c", script])
        return ActionRecord(
            f"created {path} (/bin/sh -c {script}, not loaded)",
            artefacts=[str(path)],
            telemetry=[_launchd_created(path)],
            artefact_hint=path.stem,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        path = self._write(ctx, cleanup, ["/usr/bin/true"])
        return ActionRecord(
            f"created {path} (/usr/bin/true, not loaded)",
            artefacts=[str(path)],
            telemetry=[_launchd_created(path)],
        )


class ExposedListenerTest(DetectionTest):
    spec = TestSpec(
        test_id="macos.mac-003",
        asset=ASSET,
        rule_id="MAC-003",
        title="Listener exposed on all interfaces by a non-allowlisted process",
        positive=(
            "A Python child process listens on 0.0.0.0:<free port 42000-48999>, accepting and "
            "closing connections, for up to 3 inventory cycles."
        ),
        negative="The same listener bound to 127.0.0.1.",
        cleanup="Terminate the listener and verify the port is closed (it also exits by itself).",
        expected_alert="MAC-003 on macos:workstation-01 naming the port and the process.",
        safety=(
            "No data is served (connections are closed on accept); the process has a hard "
            "lifetime; the macOS firewall settings are not touched."
        ),
        source=LISTENERS,
        # MAC-003 groups by port and every run picks a new random port.
        fresh_group=True,
    )

    def __init__(self) -> None:
        self.port: int | None = None

    def _listen(self, ctx: TestContext, cleanup: CleanupStack, host: str) -> tuple[Listener, int]:
        if self.port is None:
            self.port = free_port()
        # The listener outlives the wait by 5 minutes at most, even if the runner is killed:
        # cleanup normally stops it as soon as the phase ends.
        lifetime = (ctx.bound_seconds or 1800) + 300
        listener = Listener(host, self.port, lifetime)
        cleanup.push(f"stop listener {host}:{self.port}", listener.stop)
        listener.start()
        return listener, self.port

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        _listener, port = self._listen(ctx, cleanup, "0.0.0.0")  # noqa: S104 - the point of the test
        return ActionRecord(
            f"listening on 0.0.0.0:{port} (python, accept-and-close)",
            artefacts=[f"tcp 0.0.0.0:{port}"],
            telemetry=[
                TelemetryExpectation(
                    f"inventory saw the listener on port {port}",
                    "network.listener.opened",
                    equals=(("dst_port", port),),
                    source_type="macos.inventory",
                )
            ],
            artefact_hint=str(port),
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        _listener, port = self._listen(ctx, cleanup, "127.0.0.1")
        return ActionRecord(
            f"listening on 127.0.0.1:{port} (loopback only)",
            artefacts=[f"tcp 127.0.0.1:{port}"],
            telemetry=[
                TelemetryExpectation(
                    f"inventory saw the loopback listener on port {port}",
                    "network.listener.opened",
                    equals=(("dst_port", port), ("dst_ip", "127.0.0.1")),
                    source_type="macos.inventory",
                )
            ],
        )


class SudoFailureTest(DetectionTest):
    spec = TestSpec(
        test_id="macos.mac-004",
        asset=ASSET,
        rule_id="MAC-004",
        title="Burst of sudo authentication failures",
        positive="sudo -k, then three `sudo -k -S -v` calls, each with a random wrong password.",
        negative="A single `sudo -k -S -v` call with a random wrong password.",
        cleanup="sudo -k (invalidate any cached sudo timestamp).",
        expected_alert="MAC-004 on macos:workstation-01 for the current user.",
        safety=(
            "No privilege is obtained: passwords are random; cached credentials are ignored; "
            "the test refuses to run with Touch ID for sudo and stops if sudo ever accepts. "
            "Four failed attempts per run: do not run it where an account lockout policy is "
            "lower."
        ),
        source=UNIFIED_LOG,
    )

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        if not Path(SUDO).is_file():
            raise PreconditionFailed(f"{SUDO} not found")
        texts = []
        for name in ("/etc/pam.d/sudo", "/etc/pam.d/sudo_local"):
            try:
                texts.append(Path(name).read_text(encoding="utf-8"))
            except OSError:
                continue
        if biometric_sudo(texts):
            raise PreconditionFailed(
                "Touch ID / Apple Watch is enabled for sudo (pam_tid/pam_watchid): a prompt "
                "could make sudo succeed; MAC-004 does not run on this host"
            )
        return [StepResult("sudo requires a password (no biometric PAM module)", True, "ok")]

    def _failures(self, ctx: TestContext, cleanup: CleanupStack, count: int) -> list[str]:
        cleanup.push("sudo -k (invalidate cached credentials)", self._invalidate)
        self._invalidate()
        details: list[str] = []
        for attempt in range(1, count + 1):
            ctx.check_cancelled()
            result = run(sudo_argv(), timeout=60, input_text=random_password() + "\n", what="sudo")
            if result.ok:
                raise ActionFailed(
                    "sudo ACCEPTED a random password (NOPASSWD rule?): stopped; the timestamp "
                    "is invalidated by cleanup"
                )
            details.append(f"sudo -v attempt {attempt}: refused (exit {result.returncode})")
        return details

    @staticmethod
    def _invalidate() -> str:
        run([SUDO, "-k"], timeout=30, what="sudo -k")
        return "cached sudo credentials invalidated"

    def _expectation(self, count: int) -> TelemetryExpectation:
        user = pwd.getpwuid(os.getuid()).pw_name
        return TelemetryExpectation(
            f"unified log reported {count} sudo failure(s) of {user}",
            "auth.sudo.failure",
            actor=user,
            source_type="macos.unified_log",
            min_count=count,
        )

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        details = self._failures(ctx, cleanup, 3)
        return ActionRecord(
            "3 failed sudo authentications",
            details=details,
            telemetry=[self._expectation(3)],
            artefact_hint=pwd.getpwuid(os.getuid()).pw_name,
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        details = self._failures(ctx, cleanup, 1)
        return ActionRecord(
            "1 failed sudo authentication", details=details, telemetry=[self._expectation(1)]
        )


class UnsignedAppTest(DetectionTest):
    spec = TestSpec(
        test_id="macos.mac-005",
        asset=ASSET,
        rule_id="MAC-005",
        title="Unsigned application installed",
        positive=(
            "Create the minimal unsigned bundle '/Applications/ExtorQ Test.app' (Info.plist and a "
            "two-line shell script as executable); it is never executed."
        ),
        negative=(
            "Copy a small signed third-party app to '/Applications/ExtorQ Test Signed Copy.app' "
            "(signature verified intact)."
        ),
        cleanup="Delete both bundles after verifying their bundle identifiers.",
        expected_alert="MAC-005 on macos:workstation-01 for the unsigned bundle.",
        safety="Nothing is executed; no sudo (admin users may write /Applications).",
        source=SOFTWARE,
    )

    def preconditions(self, ctx: TestContext) -> list[StepResult]:
        if not os.access(APPLICATIONS, os.W_OK):
            raise PreconditionFailed("/Applications is not writable by this user (admin needed)")
        for app in (UNSIGNED_APP, SIGNED_COPY):
            if app.exists() or app.is_symlink():
                raise PreconditionFailed(
                    f"{app} already exists; run `uv run python -m detection_tests cleanup "
                    "--asset macos`"
                )
        source, _ = signed_source()
        valid, detail = codesign_verify(source)
        if not valid:
            raise PreconditionFailed(f"{source} does not verify ({detail})")
        return [StepResult(f"{source} signature", True, "valid (negative control source)")]

    def positive(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        identifier = label_for(ctx.new_name())
        cleanup.push(f"delete {UNSIGNED_APP}", lambda: remove_bundle(UNSIGNED_APP, identifier))
        staging = Path(tempfile.mkdtemp(prefix=".extorq-test-", suffix=".tmp", dir=APPLICATIONS))
        cleanup.push(f"delete {staging}", lambda: _remove_staging(staging))
        contents = staging / "Contents"
        (contents / "MacOS").mkdir(parents=True)
        (contents / "Info.plist").write_bytes(app_info_plist(identifier))
        executable = contents / "MacOS" / "extorq-test"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        staging.chmod(0o755)
        os.rename(staging, UNSIGNED_APP)
        signed, detail = codesign_verify(UNSIGNED_APP)
        if signed:
            raise ActionFailed(f"{UNSIGNED_APP} unexpectedly verifies as signed")
        return ActionRecord(
            f"created {UNSIGNED_APP} (bundle id {identifier}, unsigned)",
            details=[f"codesign --verify: {detail}"],
            artefacts=[str(UNSIGNED_APP)],
            telemetry=[
                TelemetryExpectation(
                    "software scan saw the unsigned bundle",
                    "software.installed",
                    equals=(("resource_path", str(UNSIGNED_APP)),),
                    source_type="macos.inventory",
                )
            ],
            artefact_hint="ExtorQ Test.app",
        )

    def negative(self, ctx: TestContext, cleanup: CleanupStack) -> ActionRecord:
        cleanup.push(
            f"delete {SIGNED_COPY}", lambda: remove_bundle(SIGNED_COPY, signed_source()[1])
        )
        staging = APPLICATIONS / f".{ctx.new_name()}.tmp"
        cleanup.push(f"delete {staging}", lambda: _remove_staging(staging))
        source, _ = signed_source()
        run([DITTO, str(source), str(staging)], timeout=300, check=True, what="ditto")
        os.rename(staging, SIGNED_COPY)
        signed, detail = codesign_verify(SIGNED_COPY)
        if not signed:
            raise ActionFailed(f"the copy does not verify ({detail}): negative control invalid")
        return ActionRecord(
            f"copied {source} to {SIGNED_COPY} (signature verified)",
            details=[f"codesign --verify: {detail}"],
            artefacts=[str(SIGNED_COPY)],
            telemetry=[
                TelemetryExpectation(
                    "software scan saw the signed copy",
                    "software.installed",
                    equals=(("resource_path", str(SIGNED_COPY)),),
                    source_type="macos.inventory",
                )
            ],
        )


def _remove_staging(staging: Path) -> str:
    """Remove a hidden staging directory of the tests (only ``/Applications/.extorq-test-*``)."""
    if staging.parent != APPLICATIONS or not staging.name.startswith(f".{ARTEFACT_PREFIX}"):
        raise ActionFailed(f"refusing to delete {staging}")
    if staging.is_symlink():
        raise ActionFailed(f"{staging} is a symbolic link: not deleted")
    if staging.exists():
        shutil.rmtree(staging)
    return "absent"


def _sweep(_ctx: TestContext) -> list[StepResult]:
    """Remove leftovers of interrupted runs (exact names and verified identifiers only)."""
    results: list[StepResult] = []
    agents = launch_agents_dir()
    for path in sorted(agents.glob(f"{REVERSE_DNS_PREFIX}*.plist")):
        label = path.name.removesuffix(".plist")
        if _LABEL_RE.fullmatch(label):
            results.append(
                _attempt(f"delete {path}", lambda p=path, lbl=label: remove_launch_agent(p, lbl))
            )
    for path in sorted(agents.glob(f"{ARTEFACT_PREFIX}*.txt")) + sorted(
        agents.glob(f".{ARTEFACT_PREFIX}*.tmp")
    ):
        if path.is_file() and not path.is_symlink():
            results.append(_attempt(f"delete {path}", lambda p=path: _unlink(p)))
    results.append(
        _attempt(f"delete {UNSIGNED_APP}", lambda: remove_bundle(UNSIGNED_APP, _LABEL_RE))
    )
    results.append(
        _attempt(f"delete {SIGNED_COPY}", lambda: remove_bundle(SIGNED_COPY, signed_source()[1]))
    )
    for staging in sorted(APPLICATIONS.glob(f".{ARTEFACT_PREFIX}*.tmp")):
        results.append(_attempt(f"delete {staging}", lambda s=staging: _remove_staging(s)))
    return results


def _unlink(path: Path) -> str:
    path.unlink(missing_ok=True)
    return "deleted"


def _attempt(description: str, action: Any) -> StepResult:
    try:
        return StepResult(description, True, str(action()))
    except (ActionFailed, OSError) as exc:
        return StepResult(description, False, str(exc))


def _check(_ctx: TestContext) -> list[StepResult]:
    agents = launch_agents_dir()
    return [
        StepResult("platform macOS", sys.platform == "darwin", sys.platform),
        StepResult(
            "~/Library/LaunchAgents",
            agents.is_dir() and not agents.is_symlink(),
            "present" if agents.is_dir() else "missing",
        ),
    ]


def build_suite(_root: Path) -> AssetSuite:
    tests: list[DetectionTest] = [
        LaunchAgentTest(),
        ShellLaunchAgentTest(),
        ExposedListenerTest(),
        SudoFailureTest(),
        UnsignedAppTest(),
    ]
    return AssetSuite(
        asset=ASSET,
        tests=tests,
        check=_check,
        sweep=_sweep,
        collector_ids=(COLLECTOR_ID,),
    )

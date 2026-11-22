"""Application bundles -> ``software.installed`` / ``software.removed`` (snapshot diff).

Why a directory scan and not ``system_profiler``: the ``applications`` source
(``system_profiler SPApplicationsDataType``) takes tens of seconds and runs hourly, far too
slow to notice an application dropped into ``/Applications`` and launched minutes later.
This source lists the application folders every minute instead:

* ``/Applications`` (scope ``system``) and ``~/Applications`` (scope ``user``);
* ``*.app`` bundles at the top level and one folder deep (``/Applications/Utilities``,
  vendor folders), so a bundle tucked into a sub-folder is not missed;
* for each bundle only ``Contents/Info.plist`` is read (size-capped, parsed with
  :mod:`plistlib`): bundle identifier, versions, name, executable. Nothing else in the
  bundle is opened by Python.

Code signatures are checked only for bundles that are NEW (or that now hold a different
bundle identifier at the same path), with two read-only, time-bounded ``codesign`` calls:

* ``codesign --verify --strict <bundle>``: exit 0 = the signature and the sealed resources
  verify; "code object is not signed at all" = unsigned; anything else = invalid.
  ``--deep`` is deliberately not used (it can take minutes on large bundles); nested code
  is still covered as sealed resources of the outer signature.
* ``codesign -dv --verbose=2 <bundle>`` (writes to stderr): ``Signature=adhoc``,
  ``TeamIdentifier`` (``not set`` for Apple platform and ad-hoc code) and the
  ``Authority=`` chain (leaf first).

Attributes reported (catalog key fields in bold): **bundle_id**, **version**
(``CFBundleShortVersionString``), build_version, **signed** (``true`` / ``false`` /
``"unknown"``), signature_valid, signature_type (``unsigned`` | ``adhoc`` |
``apple_platform`` | ``app_store`` | ``developer_id`` | ``apple_development`` | ``other``),
**signature_team_id**, signature_authority (leaf) and signature_authorities.

False positives considered:

* A bundle that is still being copied (Finder drag-copy, installer) can fail verification
  because sealed resources are missing. A new bundle is therefore only reported once its
  directory entries have been quiet for ``settle_seconds`` (by inode *change* time, which a
  user cannot set, unlike mtime), and a failed verification of a just-settled bundle is
  re-checked on the next scan. Both deferrals are bounded (``max_defer_scans``) so a bundle
  kept "busy" on purpose is still reported.
* Version updates of an installed application (same path, same bundle identifier) are not
  installations and produce no event.

Gaps (reported in health): Gatekeeper/notarization assessment is not run (``spctl
--assess`` may contact Apple); applications outside these folders are covered only by the
hourly ``system_profiler`` inventory; a bundle added and removed between two scans is
missed.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from extorq.contracts import Outcome, Resource, SecurityEvent, SourceType
from extorq_collectors.macos.commands import CommandRunner, CommandValidationError
from extorq_collectors.macos.common import SourceContext, bounded_attributes, make_event

PARSER = "macos-software"
SOURCE = SourceType.MACOS_INVENTORY
CODESIGN = "/usr/bin/codesign"
MAX_INFO_PLIST_BYTES = 1024 * 1024
MAX_BUNDLES = 2000
MAX_AUTHORITIES = 4
#: Info.plist keys copied into the event (string values only, bounded).
_INFO_KEYS = {
    "CFBundleIdentifier": "bundle_id",
    "CFBundleShortVersionString": "version",
    "CFBundleVersion": "build_version",
    "CFBundleName": "bundle_name",
    "CFBundleDisplayName": "display_name",
    "CFBundleExecutable": "executable",
}
_TEAM_ID = re.compile(r"^[A-Z0-9]{10}$")


@dataclass(frozen=True, slots=True)
class AppLocation:
    path: Path
    scope: str  # system | user


def default_locations(home: Path | None = None, *, include_user: bool = True) -> list[AppLocation]:
    locations = [AppLocation(Path("/Applications"), "system")]
    if include_user:
        locations.append(AppLocation((home or Path.home()) / "Applications", "user"))
    return locations


@dataclass(slots=True)
class Bundle:
    """One application bundle as seen on disk (all values untrusted)."""

    path: str
    scope: str
    info: dict[str, str] = field(default_factory=dict)
    info_sha256: str | None = None
    info_error: str | None = None
    is_symlink: bool = False
    symlink_target: str | None = None
    owner_uid: int | None = None
    mode: str | None = None
    #: Newest inode change time of the bundle's top entries (UTC epoch seconds).
    changed_at: float | None = None

    @property
    def bundle_id(self) -> str | None:
        return self.info.get("bundle_id")

    @property
    def name(self) -> str:
        return os.path.basename(self.path).removesuffix(".app") or self.path

    def summary(self) -> dict[str, Any]:
        """State kept between scans (enough to describe a removal)."""
        return {
            "bundle_id": self.bundle_id,
            "version": self.info.get("version"),
            "name": self.name,
            "scope": self.scope,
            "fp": self.info_sha256 or f"unreadable:{self.info_error or 'unknown'}",
        }


def _str_or_none(value: Any, limit: int = 256) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def read_bundle(path: Path, scope: str) -> Bundle:
    """Inspect one ``*.app`` path (never raises; problems are recorded on the bundle)."""
    bundle = Bundle(path=str(path), scope=scope)
    try:
        lst = os.lstat(path)
    except OSError as exc:
        bundle.info_error = f"lstat failed: {exc.strerror}"
        return bundle
    bundle.is_symlink = stat.S_ISLNK(lst.st_mode)
    if bundle.is_symlink:
        try:
            bundle.symlink_target = os.readlink(path)[:1024]
        except OSError:
            bundle.symlink_target = None
    try:
        st = os.stat(path)
    except OSError as exc:
        bundle.info_error = f"stat failed: {exc.strerror}"
        return bundle
    bundle.owner_uid = st.st_uid
    bundle.mode = oct(stat.S_IMODE(st.st_mode))
    changed = [st.st_ctime]
    for sub in ("Contents", "Contents/MacOS", "Contents/Info.plist"):
        try:
            changed.append(os.stat(path / sub).st_ctime)
        except OSError:
            continue
    bundle.changed_at = max(changed)
    info_path = path / "Contents" / "Info.plist"
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(info_path, flags)
    except FileNotFoundError:
        bundle.info_error = "Info.plist missing"
        return bundle
    except OSError as exc:
        bundle.info_error = f"Info.plist unreadable: {exc.strerror}"
        return bundle
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode):
            bundle.info_error = "Info.plist is not a regular file"
            return bundle
        if fst.st_size > MAX_INFO_PLIST_BYTES:
            bundle.info_error = "Info.plist too large"
            return bundle
        data = os.read(fd, MAX_INFO_PLIST_BYTES + 1)
    except OSError as exc:
        bundle.info_error = f"Info.plist read failed: {exc.strerror}"
        return bundle
    finally:
        os.close(fd)
    bundle.info_sha256 = hashlib.sha256(data).hexdigest()
    try:
        parsed = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001 - expat/plistlib raise varied errors on hostile input
        bundle.info_error = f"Info.plist invalid: {type(exc).__name__}"
        return bundle
    if not isinstance(parsed, dict):
        bundle.info_error = "Info.plist root is not a dictionary"
        return bundle
    for key, attr in _INFO_KEYS.items():
        value = _str_or_none(parsed.get(key))
        if value is not None:
            bundle.info[attr] = value
    return bundle


@dataclass(slots=True)
class ScanResult:
    bundles: dict[str, Bundle] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    truncated: bool = False


def _is_bundle_dir(entry: os.DirEntry[str]) -> bool:
    if not entry.name.endswith(".app"):
        return False
    try:
        return entry.is_dir(follow_symlinks=True)
    except OSError:
        return False


def scan_locations(locations: Sequence[AppLocation]) -> ScanResult:
    """``*.app`` bundles at the top level of each folder and one (non-bundle) folder deep."""
    result = ScanResult()
    for location in locations:
        try:
            with os.scandir(location.path) as entries:
                top = sorted(entries, key=lambda e: e.name)
        except FileNotFoundError:
            continue  # ~/Applications does not exist on many Macs
        except OSError as exc:
            result.errors.append(f"{location.path}: {exc.strerror}")
            continue
        candidates: list[Path] = []
        for entry in top:
            if _is_bundle_dir(entry):
                candidates.append(Path(entry.path))
            elif entry.is_dir(follow_symlinks=False):
                try:
                    with os.scandir(entry.path) as nested:
                        candidates.extend(
                            Path(n.path)
                            for n in sorted(nested, key=lambda e: e.name)
                            if _is_bundle_dir(n)
                        )
                except OSError:
                    continue  # unreadable vendor folder: its bundles stay unknown
        for path in candidates:
            if len(result.bundles) >= MAX_BUNDLES:
                result.truncated = True
                break
            result.bundles[str(path)] = read_bundle(path, location.scope)
    return result


# ── code signature (bounded, new bundles only) ───────────────────────


@dataclass(slots=True)
class Signature:
    #: True / False when determined, None when unknown (reported as ``"unknown"``).
    signed: bool | None = None
    valid: bool | None = None
    signature_type: str | None = None
    team_id: str | None = None
    identifier: str | None = None
    authorities: list[str] = field(default_factory=list)
    #: ``codesign -dv`` "Notarization Ticket=" value (``stapled``) when present.
    notarization_ticket: str | None = None
    error: str | None = None
    #: The verification failed in a way a half-copied bundle also produces: retry later.
    retry: bool = False

    def attributes(self) -> dict[str, Any]:
        return {
            "signed": self.signed if self.signed is not None else "unknown",
            "signature_valid": self.valid,
            "signature_type": self.signature_type,
            "signature_team_id": self.team_id,
            "signature_identifier": self.identifier,
            "signature_authority": self.authorities[0] if self.authorities else None,
            "signature_authorities": self.authorities or None,
            "notarization_ticket": self.notarization_ticket,
            "signature_error": self.error,
        }


def codesign_argv(mode: str, bundle_path: str) -> list[str]:
    """The two fixed codesign invocations (``verify`` or ``display``)."""
    if mode == "verify":
        return [CODESIGN, "--verify", "--strict", bundle_path]
    if mode == "display":
        return [CODESIGN, "-dv", "--verbose=2", bundle_path]
    raise ValueError(f"unknown codesign mode {mode!r}")


def _signature_type(authorities: Sequence[str], adhoc: bool) -> str:
    if adhoc:
        return "adhoc"
    leaf = authorities[0] if authorities else ""
    if leaf.startswith("Developer ID Application:"):
        return "developer_id"
    if leaf in ("Software Signing", "macOS Software Signing"):
        return "apple_platform"
    if leaf.startswith(("Apple Mac OS Application Signing", "3rd Party Mac Developer")):
        return "app_store"
    if leaf.startswith(("Apple Development:", "Mac Developer:")):
        return "apple_development"
    return "other"


@dataclass(frozen=True, slots=True)
class DisplayInfo:
    """The parts of ``codesign -dv --verbose=2`` output the event uses."""

    adhoc: bool
    team_id: str | None
    identifier: str | None
    authorities: list[str]
    notarization_ticket: str | None


def parse_codesign_display(text: str) -> DisplayInfo:
    """Parse ``codesign -dv --verbose=2`` (stderr) output; unknown lines are ignored."""
    adhoc = False
    team: str | None = None
    identifier: str | None = None
    authorities: list[str] = []
    ticket: str | None = None
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        value = value.strip()
        # "Signature=adhoc" and the CodeDirectory "flags=0x2(adhoc)" both mark ad-hoc code.
        if (key == "Signature" and value == "adhoc") or (
            key == "CodeDirectory v" and "(adhoc)" in value
        ):
            adhoc = True
        elif key == "TeamIdentifier" and _TEAM_ID.match(value):
            team = value
        elif key == "Identifier" and value:
            identifier = value[:256]
        elif key == "Authority" and value and len(authorities) < MAX_AUTHORITIES:
            authorities.append(value[:256])
        elif key == "Notarization Ticket" and value:
            ticket = value[:32]
    return DisplayInfo(adhoc, team, identifier, authorities, ticket)


def check_signature(runner: CommandRunner, bundle_path: str, *, timeout: float) -> Signature:
    """Bounded, read-only signature check of one bundle (never raises)."""
    try:
        verify = runner.run(codesign_argv("verify", bundle_path), timeout=timeout, max_stdout=65536)
    except CommandValidationError:
        # The command policy only admits bundles in the application folders.
        return Signature(error="codesign refused by the command policy for this path")
    verify_text = (verify.stderr_text() + verify.text()).strip()
    if verify.error is not None or verify.timed_out:
        return Signature(error=f"codesign verify: {verify.summary(200)}")
    if "not signed at all" in verify_text:
        return Signature(signed=False, valid=None, signature_type="unsigned")
    display = runner.run(
        codesign_argv("display", bundle_path), timeout=min(timeout, 15.0), max_stdout=65536
    )
    if display.error is not None or display.timed_out or display.returncode != 0:
        sig = Signature(error=f"codesign display: {display.summary(200)}")
    else:
        info = parse_codesign_display(display.stderr_text())
        sig = Signature(
            signed=True,
            signature_type=_signature_type(info.authorities, info.adhoc),
            team_id=info.team_id,
            identifier=info.identifier,
            authorities=info.authorities,
            notarization_ticket=info.notarization_ticket,
        )
    if verify.returncode == 0:
        sig.valid = True
    else:
        sig.valid = False
        sig.error = verify.summary(200)
        # Missing/changed sealed resources are also what a bundle mid-copy looks like.
        sig.retry = "sealed resource" in verify_text or "No such file" in verify_text
    return sig


# ── diff and events ──────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Change:
    kind: str  # installed | removed
    path: str
    bundle: Bundle | None
    previous: Mapping[str, Any] | None
    replaced: bool = False


def settled(bundle: Bundle, now_epoch: float, settle_seconds: float) -> bool:
    """True when the bundle's entries have not changed for ``settle_seconds``.

    Uses inode change time (ctime), which ordinary users cannot set (unlike mtime). A ctime
    "in the future" (clock change, millisecond rounding of ``now``) is not settled; the
    caller bounds how many scans a bundle may wait, so nothing is deferred forever.
    """
    if settle_seconds <= 0 or bundle.changed_at is None:
        return True
    return now_epoch - bundle.changed_at >= settle_seconds


def event_for(
    change: Change,
    ctx: SourceContext,
    *,
    observed_at: datetime,
    snapshot: str,
    signature: Signature | None = None,
) -> SecurityEvent:
    """``software.installed`` (with signature attributes) or ``software.removed``."""
    if change.kind == "installed" and change.bundle is not None:
        bundle = change.bundle
        attrs: dict[str, Any] = {
            "bundle_id": bundle.bundle_id,
            "version": bundle.info.get("version"),
            "build_version": bundle.info.get("build_version"),
            "bundle_name": bundle.info.get("bundle_name"),
            "display_name": bundle.info.get("display_name"),
            "executable": bundle.info.get("executable"),
            "scope": bundle.scope,
            "app_dir": os.path.dirname(bundle.path),
            "info_plist_sha256": bundle.info_sha256,
            "info_plist_error": bundle.info_error,
            "is_symlink": bundle.is_symlink or None,
            "symlink_target": bundle.symlink_target,
            "owner_uid": bundle.owner_uid,
            "mode": bundle.mode,
            "replaced": True if change.replaced else None,
            "previous_bundle_id": (change.previous or {}).get("bundle_id")
            if change.replaced
            else None,
        }
        attrs.update((signature or Signature(error="not checked")).attributes())
        name = bundle.name
        fingerprint = bundle.summary()["fp"]
        signed = attrs["signed"]
        detail = (
            "unsigned"
            if signed is False
            else f"signed ({attrs.get('signature_type')})"
            if signed is True
            else "signature unknown"
        )
        message = f"application installed: {bundle.path} ({bundle.bundle_id or 'no bundle id'}, "
        message += f"{detail})"
        action = "software_installed"
    else:
        previous = change.previous or {}
        name = str(previous.get("name") or os.path.basename(change.path).removesuffix(".app"))
        attrs = {
            "bundle_id": previous.get("bundle_id"),
            "version": previous.get("version"),
            "scope": previous.get("scope"),
            "app_dir": os.path.dirname(change.path),
        }
        fingerprint = str(previous.get("fp") or "")
        message = f"application removed: {change.path}"
        action = "software_removed"
    return make_event(
        ctx=ctx,
        event_type=f"software.{change.kind}",
        source_type=SOURCE,
        # The snapshot id disambiguates a re-install of identical content later on.
        native_key=f"software:{change.path}:{change.kind}:{fingerprint}:{snapshot}",
        event_time=observed_at,
        observed_time=observed_at,
        parser=PARSER,
        message=message,
        action=action,
        outcome=Outcome.SUCCESS,
        resource=Resource(type="application_bundle", name=name[:256], path=change.path[:2048]),
        attributes=bounded_attributes(attrs),
    )

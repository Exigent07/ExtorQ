"""Linux package inventory -> CycloneDX SBOM for ``trivy sbom``.

Input: B1's dispatch command ``packages`` (schema ``extorq.linux.packages.v1``,
docs/team/interface-changes/B1.md). Output: a CycloneDX 1.6 document with an
``operating-system`` component (``ubuntu`` / ``24.04``) and one ``library``
component per dpkg package, using the same purl and property conventions Trivy
emits for Ubuntu images (``pkg:deb/ubuntu/<name>@<version>?arch=..&distro=ubuntu-24.04
[&epoch=N]`` plus ``aquasecurity:trivy:SrcName/SrcVersion/SrcRelease/SrcEpoch``),
because Ubuntu security data is keyed by *source* package and version.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import quote

from extorq.contracts.identity import iso_utc
from extorq_scanners import __version__
from extorq_scanners.sanitize import obj

SCHEMA = "extorq.linux.packages.v1"
MAX_PACKAGES = 20_000
_NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,127}$")
_VERSION = re.compile(r"^(?:[0-9]+:)?[0-9A-Za-z][0-9A-Za-z.+~:-]{0,127}$")
_ARCH = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
_OS_VERSION = re.compile(r"^[0-9]{2}\.[0-9]{2}$")
#: dpkg Status-Abbrev: desired action + current status (+ error flag). Present on disk:
_PRESENT_STATUS = frozenset("iUFWtH")


class InventoryError(ValueError):
    """The inventory document is unusable for SBOM generation."""


@dataclass(frozen=True)
class DebVersion:
    epoch: int
    upstream: str
    revision: str | None

    @property
    def without_epoch(self) -> str:
        return f"{self.upstream}-{self.revision}" if self.revision else self.upstream


def split_deb_version(version: str) -> DebVersion:
    """Split ``[epoch:]upstream[-revision]`` (revision = text after the LAST hyphen)."""
    epoch = 0
    rest = version
    head, sep, tail = version.partition(":")
    if sep and head.isdigit():
        epoch, rest = int(head), tail
    upstream, sep, revision = rest.rpartition("-")
    if not sep:
        return DebVersion(epoch, rest, None)
    return DebVersion(epoch, upstream, revision)


@dataclass(frozen=True)
class DpkgPackage:
    name: str
    version: str
    architecture: str
    source_name: str
    source_version: str
    status: str


@dataclass
class Inventory:
    os_id: str
    os_version: str
    hostname: str | None
    collected_at: str | None
    architecture: str | None
    packages: list[DpkgPackage]
    truncated: bool = False
    errors: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def parse_inventory(doc: object) -> Inventory:
    """Validate B1's ``packages`` JSON document. Raises InventoryError if unusable."""
    if not isinstance(doc, dict):
        raise InventoryError("packages document is not a JSON object")
    if doc.get("schema") != SCHEMA or doc.get("type") != "packages":
        raise InventoryError(f"unexpected packages schema {doc.get('schema')!r}")
    os_release = obj(doc, "os_release")
    os_id = os_release.get("ID")
    os_version = os_release.get("VERSION_ID")
    if os_id != "ubuntu" or not isinstance(os_version, str) or not _OS_VERSION.match(os_version):
        raise InventoryError(f"unsupported OS {os_id!r} {os_version!r} (only Ubuntu is supported)")
    raw_packages = doc.get("packages")
    if not isinstance(raw_packages, list):
        raise InventoryError("packages document has no 'packages' list")
    if len(raw_packages) > MAX_PACKAGES:
        raise InventoryError(f"more than {MAX_PACKAGES} packages")
    inv = Inventory(
        os_id=os_id,
        os_version=os_version,
        hostname=doc.get("hostname") if isinstance(doc.get("hostname"), str) else None,
        collected_at=doc.get("collected_at") if isinstance(doc.get("collected_at"), str) else None,
        architecture=(
            doc.get("dpkg_architecture") if isinstance(doc.get("dpkg_architecture"), str) else None
        ),
        packages=[],
        truncated=doc.get("truncated") is True,
    )
    for err in doc.get("errors") or []:
        if isinstance(err, str) and len(inv.errors) < 20:
            inv.errors.append(err[:300])
    seen: set[tuple[str, str]] = set()
    for item in raw_packages:
        if not isinstance(item, dict):
            inv.skipped.append("non-object package entry")
            continue
        name, version, arch = item.get("name"), item.get("version"), item.get("architecture")
        raw_status = item.get("status")
        status = raw_status if isinstance(raw_status, str) else ""
        if not (
            isinstance(name, str)
            and _NAME.match(name)
            and isinstance(version, str)
            and _VERSION.match(version)
            and isinstance(arch, str)
            and _ARCH.match(arch)
        ):
            inv.skipped.append(f"invalid package entry {str(name)[:64]!r}")
            continue
        if len(status) >= 2 and status[1] not in _PRESENT_STATUS:
            inv.skipped.append(f"{name}: status {status!r} (not installed)")
            continue
        src_name = item.get("source_name")
        src_version = item.get("source_version")
        if not (isinstance(src_name, str) and _NAME.match(src_name)):
            src_name = name
        if not (isinstance(src_version, str) and _VERSION.match(src_version)):
            src_version = version
        if (name, arch) in seen:
            continue
        seen.add((name, arch))
        inv.packages.append(DpkgPackage(name, version, arch, src_name, src_version, status))
    count = doc.get("count")
    if isinstance(count, int) and count != len(raw_packages):
        inv.errors.append(f"count {count} does not match {len(raw_packages)} package entries")
    if not inv.packages:
        raise InventoryError("inventory contains no installed packages")
    return inv


def purl(pkg: DpkgPackage, distro: str) -> str:
    v = split_deb_version(pkg.version)
    qualifiers = [f"arch={quote(pkg.architecture, safe='')}", f"distro={quote(distro, safe='')}"]
    if v.epoch:
        qualifiers.append(f"epoch={v.epoch}")
    return (
        f"pkg:deb/ubuntu/{quote(pkg.name, safe='.-_~')}@{quote(v.without_epoch, safe='.-_~')}"
        f"?{'&'.join(qualifiers)}"
    )


def _component(pkg: DpkgPackage, distro: str) -> dict[str, Any]:
    ref = purl(pkg, distro)
    src = split_deb_version(pkg.source_version)
    props = [
        {"name": "aquasecurity:trivy:PkgID", "value": f"{pkg.name}@{pkg.version}"},
        {"name": "aquasecurity:trivy:PkgType", "value": "ubuntu"},
        {"name": "aquasecurity:trivy:SrcName", "value": pkg.source_name},
    ]
    if src.epoch:
        props.append({"name": "aquasecurity:trivy:SrcEpoch", "value": str(src.epoch)})
    if src.revision:
        props.append({"name": "aquasecurity:trivy:SrcRelease", "value": src.revision})
    props.append({"name": "aquasecurity:trivy:SrcVersion", "value": src.upstream})
    props.append({"name": "extorq:dpkg_status", "value": pkg.status or "unknown"})
    return {
        "bom-ref": ref,
        "type": "library",
        "name": pkg.name,
        "version": pkg.version,
        "purl": ref,
        "properties": props,
    }


def build_cyclonedx(
    inv: Inventory, *, asset_id: str, generated_at: datetime, serial: uuid.UUID | None = None
) -> dict[str, Any]:
    """CycloneDX 1.6 SBOM (dict) for the inventory. Deterministic for a given serial."""
    distro = f"{inv.os_id}-{inv.os_version}"
    root_ref = f"extorq-asset:{asset_id}"
    os_ref = f"extorq-os:{asset_id}:{distro}"
    components = [
        {
            "bom-ref": os_ref,
            "type": "operating-system",
            "name": inv.os_id,
            "version": inv.os_version,
            "properties": [
                {"name": "aquasecurity:trivy:Class", "value": "os-pkgs"},
                {"name": "aquasecurity:trivy:Type", "value": inv.os_id},
            ],
        }
    ]
    packages = sorted(inv.packages, key=lambda p: (p.name, p.architecture))
    components += [_component(p, distro) for p in packages]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{serial or uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": iso_utc(generated_at),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "group": "extorq",
                        "name": "extorq-scanners",
                        "version": __version__,
                    }
                ]
            },
            "component": {
                "bom-ref": root_ref,
                "type": "platform",
                "name": inv.hostname or asset_id,
                "properties": [
                    {"name": "extorq:asset_id", "value": asset_id},
                    {"name": "extorq:inventory_source", "value": "ssh-dispatch:packages"},
                ]
                + (
                    [{"name": "extorq:inventory_collected_at", "value": inv.collected_at}]
                    if inv.collected_at
                    else []
                ),
            },
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": [os_ref]},
            {"ref": os_ref, "dependsOn": [c["bom-ref"] for c in components[1:]]},
        ],
    }


def inventory_from_dpkg_tsv(text: str, *, os_version: str = "24.04") -> dict[str, Any]:
    """Build an ``extorq.linux.packages.v1`` document from dpkg-query TSV output.

    Used for tests and for cross-validating the SBOM path against Trivy's native
    image detection. Columns: Package, Version, Architecture, source:Package,
    source:Version, db:Status-Abbrev.
    """
    packages = []
    for line in text.splitlines():
        cols = line.rstrip("\n").split("\t")
        if len(cols) < 6:
            continue
        packages.append(
            {
                "name": cols[0],
                "version": cols[1],
                "architecture": cols[2],
                "source_name": cols[3],
                "source_version": cols[4],
                "status": cols[5].strip(),
            }
        )
    return {
        "type": "packages",
        "protocol": 1,
        "schema": SCHEMA,
        "collected_at": None,
        "hostname": None,
        "os_release": {"ID": "ubuntu", "VERSION_ID": os_version},
        "dpkg_architecture": packages[0]["architecture"] if packages else None,
        "packages": packages,
        "count": len(packages),
        "truncated": False,
        "errors": [],
    }

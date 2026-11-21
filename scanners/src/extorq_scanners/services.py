"""Evidence-gated attribution of package findings to host services (contract 1.1).

``PostureFinding.service_id`` is set only when BOTH hold:

1. a configured rule says the vulnerable binary package ships the service's
   systemd unit (packaging fact, e.g. ``openssh-server`` ships ``ssh.service``);
2. that unit is present, and not masked, in the VM's systemd unit inventory
   collected through B1's restricted dispatch command ``inventory`` during the
   same scan (the same evidence B1's service discovery uses).

The id is ``identity.service_id(asset_id, "host_service", <unit name>)``, i.e.
the identity B1's discovery assigns to a systemd unit service. The attribution
is labelled *inferred* in the finding attributes: a package shipping a unit does
not prove that the vulnerable code is loaded by the running service. Without
evidence the finding keeps ``service_id = None`` (unknown stays unknown).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from extorq.contracts import ServiceKind
from extorq.contracts.identity import service_id

#: systemd unit search path in precedence order (the dispatcher reports these dirs).
UNIT_DIR_PRECEDENCE = (
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
)
ATTRIBUTION_BASIS = "inferred:package-ships-unit"


class UnitInventoryError(ValueError):
    """The ``inventory`` document has no usable systemd unit list."""


@dataclass(frozen=True)
class UnitState:
    name: str
    unit_dir: str
    masked: bool


@dataclass(frozen=True)
class ServiceHint:
    service_id: str
    unit: str
    package: str


def unit_states(doc: object) -> dict[str, UnitState]:
    """Effective unit file per unit name from B1's ``inventory`` output.

    The highest-precedence directory wins (as in systemd); a symlink to
    ``/dev/null`` there means the unit is masked. Drop-ins are ignored.
    """
    if not isinstance(doc, dict) or doc.get("type") != "inventory":
        raise UnitInventoryError("not an inventory document")
    units = doc.get("systemd_units")
    if not isinstance(units, list):
        raise UnitInventoryError("inventory has no systemd_units list")
    rank = {d: i for i, d in enumerate(UNIT_DIR_PRECEDENCE)}
    best: dict[str, tuple[int, UnitState]] = {}
    for entry in units:
        if not isinstance(entry, dict) or entry.get("role") != "unit":
            continue
        name, unit_dir = entry.get("name"), entry.get("unit_dir")
        if not isinstance(name, str) or not isinstance(unit_dir, str):
            continue
        if entry.get("exists") is False:
            continue
        masked = entry.get("kind") == "symlink" and entry.get("symlink_target") == "/dev/null"
        position = rank.get(unit_dir, len(rank))
        current = best.get(name)
        if current is None or position < current[0]:
            best[name] = (position, UnitState(name, unit_dir, masked))
    return {name: state for name, (_pos, state) in best.items()}


def package_service_map(
    asset_id: str,
    rules: Iterable[tuple[Iterable[str], str]],
    units: Mapping[str, UnitState],
) -> tuple[dict[str, ServiceHint], list[str]]:
    """(package -> hint, notes). Only rules whose unit is present and unmasked apply."""
    hints: dict[str, ServiceHint] = {}
    notes: list[str] = []
    for packages, unit in rules:
        state = units.get(unit)
        if state is None:
            notes.append(f"service attribution: unit {unit} not present on the asset; not applied")
            continue
        if state.masked:
            notes.append(f"service attribution: unit {unit} is masked; not applied")
            continue
        sid = service_id(asset_id, ServiceKind.HOST_SERVICE.value, unit)
        for package in packages:
            hints.setdefault(package, ServiceHint(sid, unit, package))
    return hints, notes

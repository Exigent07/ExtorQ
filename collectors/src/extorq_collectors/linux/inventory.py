"""Inventory snapshots of the Linux host -> snapshot items, diff events and InventoryItems.

The dispatch boundary's ``inventory`` and ``packages`` documents are turned into flat,
stable item maps per category. The SDK snapshot helper (``ctx.diff_snapshot``) diffs
them against the last committed state; this module maps the differences to catalog
events (all ``source_type = linux.inventory``):

=====================  ==========================================================
category               events
=====================  ==========================================================
units                  persistence.systemd.unit_created / unit_modified / unit_deleted
enablement             persistence.systemd.unit_enabled
listeners              network.listener.opened / network.listener.closed
users                  account.user.created / account.user.deleted
cron                   persistence.cron.changed
files                  config.file.changed (``/etc/group`` carries privileged-group
                       membership changes)
packages               package.installed / package.removed / package.upgraded
=====================  ==========================================================

The first (baseline) snapshot of a category produces no events: a unit that existed
before ExtorQ looked is not "created". Removals carry the last known content hash as
``previous_sha256`` (``sha256`` is absent: nothing exists any more), so a rule keyed on
``sha256`` never mistakes a deletion for new content.

Accounts: the dispatcher lists ``getpwall()``, which on Ubuntu (``passwd: files systemd``)
also returns systemd *DynamicUser* identities while their service runs. Those are not
local accounts: they appear and vanish with the service (``lab-portal`` restarting would
otherwise read as an account deleted and created, a false VM-003 detection). An account is
treated as dynamic only with evidence: its uid lies in systemd's dynamic range
(61184-65519) AND a unit file with ``DynamicUser=yes`` names it (``User=`` or the unit
name). Dynamic accounts stay in the inventory (``dynamic_user=true``) but produce no
``account.user.*`` events; an ordinary ``useradd`` in that uid range still does.

Event identities follow the snapshot-diff convention
``<item key>:<change>:<content sha256>`` (identity.event_id), so a re-sent diff
collapses to the same event. Item contents are flat scalars/lists so the same dict is
both the diff input and the ``InventoryItem.attributes``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from extorq.common.redaction import redact_text, sanitize_untrusted
from extorq.contracts import (
    Actor,
    ActorType,
    InventoryItem,
    InventoryItemType,
    Network,
    Outcome,
    Resource,
    SecurityEvent,
    ServiceRef,
    SourceType,
)
from extorq.contracts.identity import canonical_json, sha256_hex
from extorq_collectors.linux.common import ParseContext, build_event, clean, unit_exec_paths
from extorq_collectors.linux.discovery import (
    LOCAL_UNIT_DIRS,
    ListenerFact,
    ProcessFact,
    is_host_cgroup,
    unit_from_cgroup,
)
from extorq_collectors.services.base import exposure_of

PARSER_INVENTORY = "linux-inventory-diff"
NOLOGIN_SHELLS = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"})
#: systemd's uid range for DynamicUser= services (systemd.exec(5), "DynamicUser=").
DYNAMIC_UID_RANGE = range(61184, 65520)

Item = dict[str, Any]
Items = dict[str, Item]


def _flat(values: Mapping[str, Any]) -> Item:
    """Drop unknown values; keep scalars and short scalar lists."""
    out: Item = {}
    for key, value in values.items():
        if value is None:
            continue
        if isinstance(value, bool | int | float):
            out[key] = value
        elif isinstance(value, str):
            out[key] = sanitize_untrusted(value, 2048)
        elif isinstance(value, list | tuple):
            items = [
                v if isinstance(v, bool | int | float) else sanitize_untrusted(str(v), 512)
                for v in list(value)[:64]
                if v is not None
            ]
            out[key] = items
    return out


def _redacted(text: str, limit: int = 512) -> str:
    return sanitize_untrusted(redact_text(text)[0], limit)


# ── item extraction ─────────────────────────────────────────────────────────────


def unit_items(doc: Mapping[str, Any]) -> Items:
    """Unit files and drop-ins keyed by path (content identity: sha256 / symlink target)."""
    items: Items = {}
    for unit in doc.get("systemd_units") or []:
        if not isinstance(unit, Mapping) or unit.get("role") not in ("unit", "dropin"):
            continue
        path = unit.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        raw_directives = unit.get("directives")
        directives: Mapping[str, Any] = (
            raw_directives if isinstance(raw_directives, Mapping) else {}
        )
        exec_start = unit_exec_paths(unit.get("exec_start"))
        item = _flat(
            {
                "name": unit.get("name"),
                "role": unit.get("role"),
                "unit_dir": unit.get("unit_dir"),
                "kind": unit.get("kind"),
                "sha256": unit.get("sha256"),
                "symlink_target": unit.get("symlink_target"),
                "mode": unit.get("mode"),
                "owner_uid": unit.get("uid"),
                "owner_gid": unit.get("gid"),
                "readable": unit.get("readable"),
                "exec_start": exec_start or None,
                "description": unit.get("description"),
                "unit_type": (directives.get("Type") or [None])[0],
                "run_as_user": (directives.get("User") or [None])[0],
                "wanted_by": directives.get("WantedBy"),
            }
        )
        if unit.get("readable") is False:  # no hash: size/mtime are the only change signal
            item.update(_flat({"size": unit.get("size"), "mtime": unit.get("mtime")}))
        items[path] = item
    return items


def enablement_items(doc: Mapping[str, Any]) -> Items:
    items: Items = {}
    for entry in doc.get("enablement") or []:
        if not isinstance(entry, Mapping):
            continue
        unit, target, relation, directory = (
            entry.get("unit"),
            entry.get("target"),
            entry.get("relation"),
            entry.get("dir"),
        )
        if not all(isinstance(v, str) for v in (unit, target, relation, directory)):
            continue
        key = f"{directory}/{target}.{relation}/{unit}"
        items[key] = _flat(
            {
                "unit": unit,
                "target": target,
                "relation": relation,
                "enablement_dir": directory,
                "link_target": entry.get("link_target"),
            }
        )
    return items


def listener_items(doc: Mapping[str, Any]) -> Items:
    items: Items = {}
    for raw in doc.get("listeners") or []:
        listener = ListenerFact.from_doc(raw) if isinstance(raw, Mapping) else None
        if listener is None:
            continue
        unit = unit_from_cgroup(listener.cgroup) if is_host_cgroup(listener.cgroup) else None
        items[listener.key] = _flat(
            {
                "proto": listener.proto,
                "address": listener.address,
                "port": listener.port,
                "interface": listener.interface,
                "socket_uid": listener.uid,
                "cgroup": listener.cgroup,
                "unit": unit,
            }
        )
    return items


def dynamic_user_names(doc: Mapping[str, Any]) -> frozenset[str]:
    """Account names declared by unit files with ``DynamicUser=yes`` (User= or unit stem)."""
    names: set[str] = set()
    for unit in doc.get("systemd_units") or []:
        if not isinstance(unit, Mapping) or unit.get("role") != "unit":
            continue
        directives = unit.get("directives")
        if not isinstance(directives, Mapping):
            continue
        dynamic = [str(v).lower() for v in directives.get("DynamicUser") or []]
        if not dynamic or dynamic[-1] not in ("yes", "true", "1", "on"):
            continue
        user = (directives.get("User") or [None])[-1]
        stem = str(unit.get("name") or "").removesuffix(".service")
        names.add(str(user) if user else stem)
    return frozenset(n for n in names if n)


def user_items(doc: Mapping[str, Any]) -> Items:
    items: Items = {}
    dynamic = dynamic_user_names(doc)
    for user in doc.get("users") or []:
        if isinstance(user, Mapping) and isinstance(user.get("name"), str):
            uid = user.get("uid")
            items[user["name"]] = _flat(
                {
                    "uid": uid,
                    "gid": user.get("gid"),
                    "home": user.get("home"),
                    "shell": user.get("shell"),
                    "groups": sorted(user.get("groups") or []),
                    "dynamic_user": True
                    if isinstance(uid, int) and uid in DYNAMIC_UID_RANGE and user["name"] in dynamic
                    else None,
                }
            )
    return items


def privileged_group_items(doc: Mapping[str, Any]) -> Items:
    groups = doc.get("privileged_groups")
    if not isinstance(groups, Mapping):
        return {}
    return {
        str(name): {"members": sorted(str(m) for m in members or [])[:200]}
        for name, members in groups.items()
        if isinstance(members, list)
    }


def _file_item(facts: Mapping[str, Any]) -> Item:
    item = _flat(
        {
            "exists": facts.get("exists"),
            "kind": facts.get("kind"),
            "readable": facts.get("readable"),
            "sha256": facts.get("sha256"),
            "mode": facts.get("mode"),
            "owner_uid": facts.get("uid"),
            "owner_gid": facts.get("gid"),
            "symlink_target": facts.get("symlink_target"),
        }
    )
    if facts.get("readable") is False and facts.get("kind") == "file":
        item.update(_flat({"size": facts.get("size"), "mtime": facts.get("mtime")}))
    return item


def file_items(doc: Mapping[str, Any], section: str) -> Items:
    items: Items = {}
    for facts in doc.get(section) or []:
        if isinstance(facts, Mapping) and isinstance(facts.get("path"), str):
            items[facts["path"]] = _file_item(facts)
    return items


def package_items(doc: Mapping[str, Any]) -> Items:
    items: Items = {}
    for pkg in doc.get("packages") or []:
        if not isinstance(pkg, Mapping) or not isinstance(pkg.get("name"), str):
            continue
        arch = pkg.get("architecture") or "-"
        items[f"{pkg['name']}:{arch}"] = _flat(
            {
                "name": pkg.get("name"),
                "version": pkg.get("version"),
                "architecture": arch,
                "source_name": pkg.get("source_name"),
                "source_version": pkg.get("source_version"),
                "status": pkg.get("status"),
            }
        )
    return items


def process_items(doc: Mapping[str, Any]) -> Items:
    """Processes (full snapshots only: pids churn too much for diffs)."""
    items: Items = {}
    for raw in doc.get("processes") or []:
        proc = ProcessFact.from_doc(raw) if isinstance(raw, Mapping) else None
        if proc is None:
            continue
        items[f"{proc.pid}:{proc.start_ticks}"] = _flat(
            {
                "pid": proc.pid,
                "ppid": proc.ppid,
                "uid": proc.uid,
                "user": proc.user,
                "comm": proc.comm,
                "executable": _redacted(proc.executable, 1024) if proc.executable else None,
                "cgroup": proc.cgroup,
                "unit": proc.unit,
            }
        )
    return items


#: category -> (extractor, document, InventoryItemType)
CATEGORIES: dict[str, tuple[Callable[[Mapping[str, Any]], Items], str, InventoryItemType]] = {
    "units": (unit_items, "inventory", InventoryItemType.SYSTEMD_UNIT),
    "enablement": (enablement_items, "inventory", InventoryItemType.SYSTEMD_UNIT),
    "listeners": (listener_items, "inventory", InventoryItemType.LISTENER),
    "users": (user_items, "inventory", InventoryItemType.USER),
    "privileged_groups": (privileged_group_items, "inventory", InventoryItemType.GROUP),
    "cron": (lambda d: file_items(d, "cron"), "inventory", InventoryItemType.CONFIG_FILE),
    "files": (
        lambda d: file_items(d, "sensitive_files"),
        "inventory",
        InventoryItemType.CONFIG_FILE,
    ),
    "packages": (package_items, "packages", InventoryItemType.PACKAGE),
}
#: Prefix of InventoryItem keys per category (distinct keys within one item type).
KEY_PREFIX = {"enablement": "enabled:", "cron": "cron:", "files": "file:"}


def item_key(category: str, key: str) -> str:
    return KEY_PREFIX.get(category, "") + key


# ── diff -> events ─────────────────────────────────────────────────────────────


@dataclass
class DiffContext:
    """Everything the diff-to-event mapping needs besides the diff itself."""

    parse: ParseContext
    event_time: datetime
    #: unit name -> ServiceRef of discovered services (subject attribution).
    services_by_unit: Mapping[str, ServiceRef] = field(default_factory=dict)
    #: ServiceRef of the systemd manager (producer of persistence telemetry), if discovered.
    systemd_ref: ServiceRef | None = None

    def subject_service_id(self, unit: str | None) -> str | None:
        ref = self.services_by_unit.get(unit or "")
        return ref.service_id if ref else None


def _content_sha(item: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(item))


def _event(
    dctx: DiffContext,
    *,
    event_type: str,
    key: str,
    change: str,
    item: Mapping[str, Any],
    service: ServiceRef | None = None,
    **kwargs: Any,
) -> SecurityEvent:
    pctx = ParseContext(
        asset_id=dctx.parse.asset_id,
        collector_id=dctx.parse.collector_id,
        collector_version=dctx.parse.collector_version,
        self_user=dctx.parse.self_user,
        self_uid=dctx.parse.self_uid,
        observed_time=dctx.parse.observed_time,
        service=service,
    )
    return build_event(
        pctx,
        event_type=event_type,
        source_type=SourceType.LINUX_INVENTORY,
        native_key=f"{key}:{change}:{_content_sha(item)}",
        event_time=dctx.event_time,
        parser=PARSER_INVENTORY,
        **kwargs,
    )


def unit_events(diff: Any, dctx: DiffContext) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    changes = [("created", diff.added), ("modified", diff.changed), ("deleted", diff.removed)]
    for change, items in changes:
        for path, item in sorted(items.items()):
            item = _minimize_saved_unit(item)
            name = item.get("name") or path.rsplit("/", 1)[-1]
            unit_name = name if item.get("role") == "unit" else None
            previous = diff.previous.get(path, {}) if change == "modified" else {}
            if change == "modified" and _minimize_saved_unit(previous) == item:
                # Reformatting the inventory on upgrade is not a unit file change.
                continue
            exec_start = (item.get("exec_start") or [None])[0]
            attrs = {
                # A deleted unit has no content any more: its last hash is the previous one.
                "sha256": item.get("sha256") if change != "deleted" else None,
                "previous_sha256": previous.get("sha256")
                if previous
                else (item.get("sha256") if change == "deleted" else None),
                "exec_start": exec_start,
                "vendor_unit": item.get("unit_dir") not in LOCAL_UNIT_DIRS,
                "unit_dir": item.get("unit_dir"),
                "role": item.get("role"),
                "kind": item.get("kind"),
                "symlink_target": item.get("symlink_target"),
                "description": item.get("description"),
                "wanted_by": item.get("wanted_by"),
                "unit_type": item.get("unit_type"),
                "file_mode": item.get("mode"),
                "owner_uid": item.get("owner_uid"),
                "subject_service_id": dctx.subject_service_id(unit_name),
            }
            verb = {"created": "created", "modified": "modified", "deleted": "deleted"}[change]
            events.append(
                _event(
                    dctx,
                    event_type=f"persistence.systemd.unit_{verb}",
                    key=path,
                    change=change,
                    item=item,
                    service=dctx.systemd_ref,
                    action=f"systemd.unit_{verb}",
                    outcome=Outcome.SUCCESS,
                    resource=Resource(type="systemd_unit", name=clean(name), path=path),
                    message=f"systemd unit {verb}: {path}"
                    + (f" (ExecStart={exec_start})" if exec_start and change != "deleted" else ""),
                    attributes=attrs,
                )
            )
    return events


def _minimize_saved_unit(item: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(item)
    executables = unit_exec_paths(result.pop("exec_start", None))
    if executables:
        result["exec_start"] = executables
    return result


def enablement_events(diff: Any, dctx: DiffContext) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for key, item in sorted(diff.added.items()):
        unit = item.get("unit")
        events.append(
            _event(
                dctx,
                event_type="persistence.systemd.unit_enabled",
                key=key,
                change="enabled",
                item=item,
                service=dctx.systemd_ref,
                action="systemd.unit_enabled",
                outcome=Outcome.SUCCESS,
                resource=Resource(
                    type="systemd_unit", name=clean(unit), path=clean(item.get("link_target"), 2048)
                ),
                message=f"systemd unit enabled: {unit} ({item.get('relation')} of "
                f"{item.get('target')})",
                attributes={
                    "wanted_by": item.get("target"),
                    "relation": item.get("relation"),
                    "enablement_dir": item.get("enablement_dir"),
                    "link_target": item.get("link_target"),
                    "subject_service_id": dctx.subject_service_id(unit),
                },
            )
        )
    return events


def listener_events(diff: Any, dctx: DiffContext) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for change, items in (
        ("opened", diff.added),
        ("opened", diff.changed),
        ("closed", diff.removed),
    ):
        for key, item in sorted(items.items()):
            unit = item.get("unit")
            previous = diff.previous.get(key) if key in diff.changed else None
            address = item.get("address")
            events.append(
                _event(
                    dctx,
                    event_type=f"network.listener.{change}",
                    key=key,
                    change=change,
                    item=item,
                    action=f"listener.{change}",
                    outcome=Outcome.SUCCESS,
                    network=Network(
                        dst_ip=address,
                        dst_port=item.get("port"),
                        protocol=item.get("proto"),
                        direction="inbound",
                    ),
                    message=f"listener {change}: {item.get('proto')} {address or '*'}:"
                    f"{item.get('port')}" + (f" ({unit})" if unit else " (owner unknown)"),
                    attributes={
                        "bind_address": address,
                        # Contract ServiceEndpoint vocabulary: any (all interfaces) | loopback
                        # | private | unknown; identical on macOS.
                        "exposure": exposure_of(address),
                        "port": item.get("port"),
                        "protocol": item.get("proto"),
                        "cgroup": item.get("cgroup"),
                        "unit": unit,
                        "socket_uid": item.get("socket_uid"),
                        "interface": item.get("interface"),
                        "owner_attribution": "socket_cgroup" if unit else "unknown",
                        "previous_unit": previous.get("unit") if previous else None,
                        "subject_service_id": dctx.subject_service_id(unit),
                    },
                )
            )
    return events


def user_events(diff: Any, dctx: DiffContext) -> list[SecurityEvent]:
    """``account.user.created`` / ``account.user.deleted`` (systemd dynamic users excluded)."""
    events: list[SecurityEvent] = []
    for change, items in (("created", diff.added), ("deleted", diff.removed)):
        for name, item in sorted(items.items()):
            if item.get("dynamic_user"):
                continue  # a DynamicUser service started or stopped: not an account change
            shell = item.get("shell")
            events.append(
                _event(
                    dctx,
                    event_type=f"account.user.{change}",
                    key=name,
                    change=change,
                    item=item,
                    action=f"account.{change}",
                    outcome=Outcome.SUCCESS,
                    actor=Actor(
                        type=ActorType.USER,
                        name=clean(name),
                        id=str(item["uid"]) if isinstance(item.get("uid"), int) else None,
                    ),
                    message=(
                        f"local account {change}: {name} (uid {item.get('uid')}, shell {shell})"
                    ),
                    attributes={
                        "uid": item.get("uid"),
                        "gid": item.get("gid"),
                        "shell": shell,
                        "home": item.get("home"),
                        "groups": item.get("groups"),
                        "interactive_shell": shell not in NOLOGIN_SHELLS if shell else None,
                    },
                )
            )
    return events


def cron_events(diff: Any, dctx: DiffContext) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for change, items in (
        ("added", diff.added),
        ("modified", diff.changed),
        ("removed", diff.removed),
    ):
        for path, item in sorted(items.items()):
            previous = diff.previous.get(path, {}) if change == "modified" else {}
            events.append(
                _event(
                    dctx,
                    event_type="persistence.cron.changed",
                    key=path,
                    change=change,
                    item=item,
                    action=f"cron.{change}",
                    outcome=Outcome.SUCCESS,
                    resource=Resource(type="cron", name=clean(path.rsplit("/", 1)[-1]), path=path),
                    message=f"cron configuration {change}: {path}",
                    attributes={
                        "change": change,
                        "sha256": item.get("sha256") if change != "removed" else None,
                        "previous_sha256": previous.get("sha256")
                        if previous
                        else (item.get("sha256") if change == "removed" else None),
                        "readable": item.get("readable"),
                        "file_mode": item.get("mode"),
                        "owner_uid": item.get("owner_uid"),
                    },
                )
            )
    return events


def file_events(
    diff: Any, dctx: DiffContext, group_changes: Mapping[str, Any] | None = None
) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for change, items in (
        ("added", diff.added),
        ("modified", diff.changed),
        ("removed", diff.removed),
    ):
        for path, item in sorted(items.items()):
            previous = diff.previous.get(path, {}) if change == "modified" else {}
            attrs: dict[str, Any] = {
                "change": change,
                "sha256": item.get("sha256") if change != "removed" else None,
                "previous_sha256": previous.get("sha256")
                if previous
                else (item.get("sha256") if change == "removed" else None),
                "readable": item.get("readable"),
                "file_mode": item.get("mode"),
                "previous_file_mode": previous.get("mode") if previous else None,
                "owner_uid": item.get("owner_uid"),
            }
            if path == "/etc/group" and group_changes:
                attrs.update(group_changes)
            events.append(
                _event(
                    dctx,
                    event_type="config.file.changed",
                    key=path,
                    change=change,
                    item=item,
                    action=f"file.{change}",
                    outcome=Outcome.SUCCESS,
                    resource=Resource(type="file", name=clean(path.rsplit("/", 1)[-1]), path=path),
                    message=f"sensitive file {change}: {path}",
                    attributes=attrs,
                )
            )
    return events


def privileged_group_changes(diff: Any) -> dict[str, Any]:
    """Membership changes of privileged groups (sudo, adm, ...) as event attributes."""
    added: list[str] = []
    removed: list[str] = []
    for group, item in list(diff.added.items()) + list(diff.changed.items()):
        before = set((diff.previous.get(group) or {}).get("members") or [])
        after = set(item.get("members") or [])
        added.extend(f"{group}:{m}" for m in sorted(after - before))
        removed.extend(f"{group}:{m}" for m in sorted(before - after))
    for group, item in diff.removed.items():
        removed.extend(f"{group}:{m}" for m in item.get("members") or [])
    changes: dict[str, Any] = {}
    if added:
        changes["privileged_members_added"] = added[:64]
    if removed:
        changes["privileged_members_removed"] = removed[:64]
    return changes


def package_events(diff: Any, dctx: DiffContext) -> list[SecurityEvent]:
    events: list[SecurityEvent] = []
    for change, items in (
        ("installed", diff.added),
        ("upgraded", diff.changed),
        ("removed", diff.removed),
    ):
        for key, item in sorted(items.items()):
            previous = diff.previous.get(key, {}) if change == "upgraded" else {}
            if change == "upgraded" and previous.get("version") == item.get("version"):
                continue  # status-only change (e.g. half-configured): not an upgrade
            name = item.get("name") or key.split(":", 1)[0]
            events.append(
                _event(
                    dctx,
                    event_type=f"package.{change}",
                    key=key,
                    change=change,
                    item=item,
                    action=f"package.{change}",
                    outcome=Outcome.SUCCESS,
                    resource=Resource(type="package", name=clean(name)),
                    message=f"package {change}: {name} {item.get('version')}"
                    + (f" (was {previous.get('version')})" if previous else ""),
                    attributes={
                        "version": item.get("version"),
                        "previous_version": previous.get("version") if previous else None,
                        "architecture": item.get("architecture"),
                        "source_name": item.get("source_name"),
                        "dpkg_status": item.get("status"),
                    },
                )
            )
    return events


def inventory_records(
    category: str,
    diff: Any,
    current: Items,
    *,
    asset_id: str,
    collector_id: str,
    snapshot_id: str,
    observed_at: datetime,
    full: bool,
) -> list[InventoryItem]:
    """Changed items (present) + tombstones, or every item for a full snapshot."""
    item_type = CATEGORIES[category][2]
    records: list[InventoryItem] = []
    source = current if full else {**diff.added, **diff.changed}
    for key, item in sorted(source.items()):
        records.append(
            InventoryItem(
                asset_id=asset_id,
                item_type=item_type,
                item_key=item_key(category, key)[:2048],
                attributes=item,
                snapshot_id=snapshot_id,
                observed_at=observed_at,
                present=True,
                collector_id=collector_id,
            )
        )
    for key, item in sorted(diff.removed.items()):
        records.append(
            InventoryItem(
                asset_id=asset_id,
                item_type=item_type,
                item_key=item_key(category, key)[:2048],
                attributes=_minimize_saved_unit(item) if category == "units" else item,
                snapshot_id=snapshot_id,
                observed_at=observed_at,
                present=False,
                collector_id=collector_id,
            )
        )
    return records

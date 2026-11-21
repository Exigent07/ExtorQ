"""LaunchAgent/LaunchDaemon parsing, scanning, diffing and launchctl parsing (real fixtures)."""

from __future__ import annotations

import hashlib
import os
import plistlib
from datetime import UTC, datetime
from pathlib import Path

from macos_helpers import FIXTURES, copy_fixture_dir, fixture_text

from extorq.contracts import validate_event_semantics
from extorq_collectors.macos.common import SourceContext
from extorq_collectors.macos.launchctl import NOT_FOUND_EXIT, parse_domain_print
from extorq_collectors.macos.launchd import (
    Change,
    LabelAllowlist,
    LaunchItem,
    Location,
    change_to_event,
    diff,
    parse_plist_bytes,
    parse_sockets,
    read_launch_item,
    scan_locations,
    to_inventory,
    tombstone,
)

OBSERVED = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def item_for(relative: str, allowlist: LabelAllowlist | None = None) -> LaunchItem:
    path = FIXTURES / relative
    return read_launch_item(
        path, Location(path.parent, "user", "agent"), allowlist or LabelAllowlist()
    )


def test_homebrew_agent_plist_fields_and_hash() -> None:
    item = item_for("launchd/user_agents/sh.brew.redis.plist")
    raw = (FIXTURES / "launchd/user_agents/sh.brew.redis.plist").read_bytes()
    assert item.label == "sh.brew.redis"
    assert item.program == "/opt/homebrew/opt/redis/bin/redis-server"
    assert item.program_arguments == [
        "/opt/homebrew/opt/redis/bin/redis-server",
        "/opt/homebrew/etc/redis.conf",
    ]
    assert item.run_at_load is True
    assert item.keep_alive == "true"
    assert item.sha256 == hashlib.sha256(raw).hexdigest()
    assert item.session_types[:2] == ["Aqua", "Background"]
    assert item.parse_error is None and item.read_error is None


def test_empty_dictionary_plist_has_no_label() -> None:
    item = item_for("launchd/user_agents/com.google.keystone.agent.plist")
    assert item.label is None and item.parse_error is None and item.sha256 is not None


def test_system_daemon_fixture_and_start_interval(tmp_path: Path) -> None:
    item = item_for("launchd/system_daemons/com.docker.vmnetd.plist")
    assert item.label == "com.docker.vmnetd"
    data = plistlib.dumps({"Label": "x.interval", "Program": "/bin/true", "StartInterval": 300})
    probe = LaunchItem(path="p", scope="user", kind="agent")
    parse_plist_bytes(probe, data)
    assert probe.start_interval == 300 and probe.program == "/bin/true"


def test_environment_values_never_kept_and_args_redacted() -> None:
    data = plistlib.dumps(
        {
            "Label": "com.example.agent",
            "ProgramArguments": ["/usr/local/bin/agent", "--token=ghp_" + "a" * 36],
            "EnvironmentVariables": {"API_KEY": "super-secret-value", "PATH": "/usr/bin"},
        }
    )
    item = LaunchItem(path="p", scope="user", kind="agent")
    parse_plist_bytes(item, data)
    assert item.env_var_names == ["API_KEY", "PATH"]
    assert "super-secret-value" not in repr(item.attributes())
    assert "ghp_" not in " ".join(item.program_arguments)
    assert item.redactions >= 1


def test_hostile_and_invalid_plists_never_raise() -> None:
    for data in (b"not a plist", b"<?xml version='1.0'?><plist><array/></plist>", b"\x00" * 64):
        item = LaunchItem(path="p", scope="user", kind="agent")
        parse_plist_bytes(item, data)
        assert item.parse_error is not None


def test_apple_socket_specs_from_real_definitions() -> None:
    ssh = plistlib.loads((FIXTURES / "launchd/apple/ssh.plist").read_bytes())
    specs = parse_sockets(ssh["Sockets"])
    assert [(s.service, s.node, s.sock_type) for s in specs] == [("ssh", None, "stream")]
    proxy = plistlib.loads((FIXTURES / "launchd/apple/com.apple.ftp-proxy.plist").read_bytes())
    assert [s.render() for s in parse_sockets(proxy["Sockets"])] == ["tcp:localhost:8021"]
    cups = plistlib.loads((FIXTURES / "launchd/apple/org.cups.cupsd.plist").read_bytes())
    assert parse_sockets(cups["Sockets"])[0].path == "/private/var/run/cupsd"


def test_scan_diff_created_modified_deleted_and_allowlist(
    tmp_path: Path, src: SourceContext
) -> None:
    agents = copy_fixture_dir("launchd/user_agents", tmp_path / "LaunchAgents")
    location = Location(agents, "user", "agent")
    allow = LabelAllowlist(["sh.brew.*"])
    first = scan_locations([location], allow)
    assert len(first.items) == 7
    previous = {path: item.summary() for path, item in first.items.items()}
    assert first.items[str(agents / "sh.brew.redis.plist")].allowlisted is True

    new = agents / "com.extorq.sim.abcd1234.plist"
    new.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.extorq.sim.abcd1234",
                "ProgramArguments": ["/usr/bin/true"],
                "RunAtLoad": False,
            }
        )
    )
    (agents / "sh.brew.php.plist").unlink()
    redis = agents / "sh.brew.redis.plist"
    redis.write_bytes(redis.read_bytes().replace(b"redis.conf", b"redis-alt.conf"))
    second = scan_locations([location], allow)
    changes = diff(previous, second.items)
    assert [(c.kind, os.path.basename(c.path)) for c in changes] == [
        ("created", "com.extorq.sim.abcd1234.plist"),
        ("deleted", "sh.brew.php.plist"),
        ("modified", "sh.brew.redis.plist"),
    ]
    events = [change_to_event(c, src, observed_at=OBSERVED, snapshot="s1") for c in changes]
    created, deleted, modified = events
    assert created.event_type == "persistence.launchd.item_created"
    assert created.attributes["scope"] == "user"
    assert created.attributes["run_at_load"] is False
    assert created.simulation is not None and created.simulation.run_id == "abcd1234"
    assert deleted.event_type == "persistence.launchd.item_deleted"
    assert deleted.attributes["label"] == "sh.brew.php"
    assert modified.attributes["allowlisted"] is True  # flagged, never suppressed
    assert modified.attributes["previous_sha256"] == previous[str(redis)]["fp"]
    for event in events:
        assert event.resource is not None and event.resource.path is not None
        assert (
            validate_event_semantics(event.event_type, event.category.value, "macos.launchd")
            is None
        )
    item = second.items[str(new)]
    inv = to_inventory(item, src, observed_at=OBSERVED, snapshot="s1")
    assert inv.item_type.value == "launch_item" and inv.present
    gone = tombstone(
        str(agents / "sh.brew.php.plist"),
        previous[str(agents / "sh.brew.php.plist")],
        src,
        observed_at=OBSERVED,
        snapshot="s1",
    )
    assert gone.present is False


def test_identical_recreation_gets_a_new_event_id(src: SourceContext) -> None:
    item = item_for("launchd/user_agents/sh.brew.mysql.plist")
    change = Change("created", item.path, item, None)
    a = change_to_event(change, src, observed_at=OBSERVED, snapshot="s1")
    b = change_to_event(change, src, observed_at=OBSERVED, snapshot="s2")
    again = change_to_event(change, src, observed_at=OBSERVED, snapshot="s1")
    assert a.event_id != b.event_id and a.event_id == again.event_id


def test_symlink_and_unreadable_entries(tmp_path: Path) -> None:
    target = tmp_path / "real.plist"
    target.write_bytes(plistlib.dumps({"Label": "com.example.linked", "Program": "/bin/true"}))
    link = tmp_path / "linked.plist"
    link.symlink_to(target)
    fifo = tmp_path / "fifo.plist"
    os.mkfifo(fifo)
    location = Location(tmp_path, "user", "agent")
    linked = read_launch_item(link, location, LabelAllowlist())
    assert linked.is_symlink and linked.label == "com.example.linked"
    blocked = read_launch_item(fifo, location, LabelAllowlist())  # must not hang on a FIFO
    assert blocked.read_error == "not a regular file" and blocked.sha256 is None
    assert blocked.fingerprint.startswith("unreadable:")


def test_missing_directory_is_not_an_error(tmp_path: Path) -> None:
    result = scan_locations([Location(tmp_path / "absent", "user", "agent")], LabelAllowlist())
    assert result.items == {} and result.errors == []


# ── launchctl print parsing (real, scrubbed output) ──────────────────


def test_launchctl_system_domain_listing() -> None:
    listing = parse_domain_print(fixture_text("services/launchctl_print_system.txt"), "system")
    assert listing.ok and len(listing.jobs) > 400
    vmnetd = listing.jobs["com.docker.vmnetd"]
    assert vmnetd.running and vmnetd.pid == 516
    assert listing.jobs["com.apple.ftp-proxy"].pid is None  # loaded, idle (socket-activated)
    assert "com.openssh.sshd" not in listing.jobs  # Remote Login off on the reference host
    assert listing.overrides["com.apple.ftp-proxy"] is True
    assert listing.overrides["com.apple.ftpd"] is False


def test_launchctl_gui_domain_listing_ignores_other_blocks() -> None:
    text = fixture_text("services/launchctl_print_gui.txt")
    listing = parse_domain_print(text, "gui/501")
    assert listing.jobs["sh.brew.redis"].pid == 904
    assert listing.jobs["com.apple.controlcenter"].pid == 656
    assert listing.overrides["sh.brew.mysql"] is True
    # endpoint rows ("0x... M D label") and environment values are never parsed as jobs
    assert all(" " not in label for label in listing.jobs)
    assert "SSH_AUTH_SOCK" not in repr(listing)


def test_launchctl_missing_service_and_garbage() -> None:
    assert "Could not find service" in fixture_text("services/launchctl_print_sshd_missing.txt")
    assert NOT_FOUND_EXIT == 113
    broken = parse_domain_print("nonsense", "system")
    assert not broken.ok and broken.jobs == {}

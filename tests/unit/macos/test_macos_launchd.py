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
    # Synthetic third-party agent with a Homebrew-layout program path (fixtures README).
    item = item_for("launchd/user_agents/com.example.thirdparty.redis.plist")
    raw = (FIXTURES / "launchd/user_agents/com.example.thirdparty.redis.plist").read_bytes()
    assert item.label == "com.example.thirdparty.redis"
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
    item = item_for("launchd/user_agents/com.example.thirdparty.labelless.plist")
    assert item.label is None and item.parse_error is None and item.sha256 is not None


def test_system_daemon_fixture_and_start_interval(tmp_path: Path) -> None:
    item = item_for("launchd/system_daemons/com.example.thirdparty.helper.plist")
    assert item.label == "com.example.thirdparty.helper"
    assert [s.path for s in item.socket_specs] == ["/var/run/com.example.thirdparty.helper.sock"]
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
    allow = LabelAllowlist(["com.example.thirdparty.redis"])
    first = scan_locations([location], allow)
    assert len(first.items) == 4
    previous = {path: item.summary() for path, item in first.items.items()}
    assert first.items[str(agents / "com.example.thirdparty.redis.plist")].allowlisted is True
    assert first.items[str(agents / "com.example.thirdparty.php.plist")].allowlisted is False

    # The MAC-001 detection-test artefact: a real plist, never loaded.
    new = agents / "com.extorq.test.abcd1234.plist"
    new.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.extorq.test.abcd1234",
                "ProgramArguments": ["/usr/bin/true"],
                "RunAtLoad": False,
            }
        )
    )
    (agents / "com.example.thirdparty.php.plist").unlink()
    redis = agents / "com.example.thirdparty.redis.plist"
    redis.write_bytes(redis.read_bytes().replace(b"redis.conf", b"redis-alt.conf"))
    second = scan_locations([location], allow)
    changes = diff(previous, second.items)
    assert [(c.kind, os.path.basename(c.path)) for c in changes] == [  # sorted by path
        ("deleted", "com.example.thirdparty.php.plist"),
        ("modified", "com.example.thirdparty.redis.plist"),
        ("created", "com.extorq.test.abcd1234.plist"),
    ]
    events = [change_to_event(c, src, observed_at=OBSERVED, snapshot="s1") for c in changes]
    deleted, modified, created = events
    assert created.event_type == "persistence.launchd.item_created"
    assert created.attributes["scope"] == "user"
    assert created.attributes["run_at_load"] is False
    assert created.attributes["program"] == "/usr/bin/true"
    assert created.attributes["program_arguments"] == ["/usr/bin/true"]
    assert created.labels == {}  # a detection-test artefact is ordinary telemetry
    assert deleted.event_type == "persistence.launchd.item_deleted"
    assert deleted.attributes["label"] == "com.example.thirdparty.php"
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
        str(agents / "com.example.thirdparty.php.plist"),
        previous[str(agents / "com.example.thirdparty.php.plist")],
        src,
        observed_at=OBSERVED,
        snapshot="s1",
    )
    assert gone.present is False


def test_identical_recreation_gets_a_new_event_id(src: SourceContext) -> None:
    item = item_for("launchd/user_agents/com.example.thirdparty.mysql.plist")
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


# ── launchctl print parsing (real output, trimmed; third-party rows synthetic) ──


def test_launchctl_system_domain_listing() -> None:
    listing = parse_domain_print(fixture_text("services/launchctl_print_system.txt"), "system")
    assert listing.ok and len(listing.jobs) == 11
    helper = listing.jobs["com.example.thirdparty.helper"]
    assert helper.running and helper.pid == 516
    assert listing.jobs["com.apple.lskdd"].last_exit == "(pe)"  # status column marker kept
    assert "com.apple.logd.admin" not in listing.jobs  # endpoint rows are not jobs
    assert listing.jobs["com.apple.ftp-proxy"].pid is None  # loaded, idle (socket-activated)
    assert "com.openssh.sshd" not in listing.jobs  # Remote Login off on the reference host
    assert listing.overrides["com.apple.ftp-proxy"] is True
    assert listing.overrides["com.apple.ftpd"] is False


def test_launchctl_gui_domain_listing_ignores_other_blocks() -> None:
    text = fixture_text("services/launchctl_print_gui.txt")
    listing = parse_domain_print(text, "gui/501")
    assert listing.jobs["com.example.thirdparty.redis"].pid == 904
    assert listing.jobs["com.apple.controlcenter"].pid == 656
    assert listing.overrides["com.example.thirdparty.mysql"] is True
    assert listing.overrides["com.apple.ScriptMenuApp"] is False
    # endpoint rows ("0x... M D label"), unmanaged-process blocks and environment values are
    # never parsed as jobs
    assert all(" " not in label for label in listing.jobs)
    assert "com.apple.BKAgentService" not in listing.jobs
    assert not any("unmanaged" in label for label in listing.jobs)
    assert len(listing.jobs) == 11
    assert "SSH_AUTH_SOCK" not in repr(listing)


def test_launchctl_missing_service_and_garbage() -> None:
    assert "Could not find service" in fixture_text("services/launchctl_print_sshd_missing.txt")
    assert NOT_FOUND_EXIT == 113
    broken = parse_domain_print("nonsense", "system")
    assert not broken.ok and broken.jobs == {}


def test_detection_test_shapes_mac001_and_mac002(tmp_path: Path, src: SourceContext) -> None:
    """The matrix artefacts: MAC-001 (/usr/bin/true) and MAC-002 (shell running a /tmp path)."""
    agents = tmp_path / "LaunchAgents"
    agents.mkdir()
    location = Location(agents, "user", "agent")
    first = scan_locations([location], LabelAllowlist())
    plain = agents / "com.extorq.test.plain.plist"
    plain.write_bytes(
        plistlib.dumps({"Label": "com.extorq.test.plain", "ProgramArguments": ["/usr/bin/true"]})
    )
    shell = agents / "com.extorq.test.shell.plist"
    shell.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.extorq.test.shell",
                "ProgramArguments": ["/bin/sh", "-c", "/tmp/extorq-test-abcd"],
                "RunAtLoad": True,
            }
        )
    )
    dropped = tmp_path / "bin" / "agent"
    dropped.parent.mkdir()
    dropped.write_text("#!/bin/sh\n")
    writable = agents / "com.extorq.test.writable.plist"
    writable.write_bytes(
        plistlib.dumps({"Label": "com.extorq.test.writable", "Program": str(dropped)})
    )
    second = scan_locations([location], LabelAllowlist())
    changes = diff({p: i.summary() for p, i in first.items.items()}, second.items)
    events = {
        os.path.basename(c.path): change_to_event(c, src, observed_at=OBSERVED, snapshot="s")
        for c in changes
    }
    mac001 = events["com.extorq.test.plain.plist"].attributes
    assert mac001["program"] == "/usr/bin/true" and mac001["program_exists"] is True
    assert mac001["program_user_writable"] is False  # sealed system volume
    assert "run_at_load" not in mac001  # absent key stays unknown
    mac002 = events["com.extorq.test.shell.plist"].attributes
    assert mac002["program"] == "/bin/sh" and mac002["run_at_load"] is True
    assert mac002["program_arguments"] == ["/bin/sh", "-c", "/tmp/extorq-test-abcd"]
    assert mac002["program_arguments_count"] == 3
    assert mac002["scope"] == "user" and mac002["allowlisted"] is False
    user_owned = events["com.extorq.test.writable.plist"].attributes
    assert user_owned["program_user_writable"] is True  # a file the user can swap


def test_program_arguments_keep_only_the_first_entries(tmp_path: Path) -> None:
    agents = tmp_path / "LaunchAgents"
    agents.mkdir()
    many = agents / "com.example.many.plist"
    many.write_bytes(
        plistlib.dumps(
            {"Label": "com.example.many", "ProgramArguments": [f"a{i}" for i in range(40)]}
        )
    )
    item = scan_locations([Location(agents, "user", "agent")], LabelAllowlist()).items[str(many)]
    attrs = item.attributes()
    assert len(attrs["program_arguments"]) == 16 and attrs["program_arguments_count"] == 40
    assert "program_exists" not in attrs  # relative program: launchd resolves it, not us

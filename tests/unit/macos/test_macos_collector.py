"""MacOSCollector cycles on the real SDK context/state store with a fixture-backed runner."""

from __future__ import annotations

import json
import plistlib
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from macos_helpers import (
    ASSET,
    COLLECTOR,
    FIXTURES,
    FakeRunner,
    copy_fixture_dir,
    failed,
    fixture_bytes,
    ok,
)

from extorq_collectors.macos import collector as collector_mod
from extorq_collectors.macos import launchd as launchd_mod
from extorq_collectors.macos import software as software_mod
from extorq_collectors.macos.collector import (
    KV_SOURCES,
    UNIFIED_LOG_CHECKPOINT,
    MacOSCollector,
    MacOSCollectorError,
)
from extorq_collectors.macos.inventory import (
    DSCL_USERS_SHELL,
    DSCL_USERS_UID,
    LSOF_TCP_LISTEN_ARGV,
    LSOF_UDP_ARGV,
    NETSTAT_TCP,
    PS_ARGV,
    SYSTEM_PROFILER_APPS,
)
from extorq_collectors.macos.posture import COMMANDS
from extorq_collectors.macos.procinfo import no_paths
from extorq_collectors.sdk import CollectorConfig, CollectorContext, StateStore


def build_runner() -> FakeRunner:
    runner = FakeRunner()
    runner.add_prefix(
        ["/usr/bin/log", "show"],
        ok(
            ["/usr/bin/log"],
            fixture_bytes("unified_log/gatekeeper_prompt_flow.ndjson")
            + b'{"count":5,"finished":1}\n',
        ),
    )
    runner.add(PS_ARGV, ok(PS_ARGV, fixture_bytes("services/ps_services.txt")))
    runner.add(NETSTAT_TCP, ok(NETSTAT_TCP, b""))  # socket table withheld (as under uv)
    runner.add(
        LSOF_TCP_LISTEN_ARGV,
        ok(LSOF_TCP_LISTEN_ARGV, fixture_bytes("services/lsof_tcp_services.txt")),
    )
    runner.add(LSOF_UDP_ARGV, ok(LSOF_UDP_ARGV, fixture_bytes("services/lsof_udp_services.txt")))
    runner.add(
        ["/bin/launchctl", "print", "system"],
        ok([], fixture_bytes("services/launchctl_print_system.txt")),
    )
    runner.add(
        ["/bin/launchctl", "print", "gui/501"],
        ok([], fixture_bytes("services/launchctl_print_gui.txt")),
    )
    runner.add(DSCL_USERS_UID, ok(DSCL_USERS_UID, fixture_bytes("inventory/dscl_users_uid.txt")))
    runner.add(
        DSCL_USERS_SHELL, ok(DSCL_USERS_SHELL, fixture_bytes("inventory/dscl_users_shell.txt"))
    )
    files = {
        "fdesetup": "posture/fdesetup_status.txt",
        "csrutil": "posture/csrutil_status.txt",
        "csrutil_authroot": "posture/csrutil_authenticated_root.txt",
        "fw_global": "posture/socketfilterfw_globalstate.txt",
        "fw_stealth": "posture/socketfilterfw_stealthmode.txt",
        "fw_allowsigned": "posture/socketfilterfw_allowsigned.txt",
        "spctl": "posture/spctl_status.txt",
        "su_prefs": "posture/softwareupdate_export.plist",
        "commerce_prefs": "posture/commerce_export.plist",
        "guest": "posture/loginwindow_guestenabled.txt",
        "admins": "posture/dscl_admin.txt",
        "sw_vers": "posture/sw_vers.txt",
        "hw_model": "posture/sysctl_hw_model.txt",
    }
    for name, rel in files.items():
        runner.add(COMMANDS[name], ok(COMMANDS[name], fixture_bytes(rel)))
    runner.add(
        SYSTEM_PROFILER_APPS,
        ok(SYSTEM_PROFILER_APPS, fixture_bytes("inventory/system_profiler_apps.json")),
    )
    return runner


class Harness:
    def __init__(self, tmp_path: Path, settings: dict[str, Any] | None = None) -> None:
        self.agents = copy_fixture_dir(
            "launchd/user_agents", tmp_path / "home/Library/LaunchAgents"
        )
        self.daemons = copy_fixture_dir(
            "launchd/system_daemons", tmp_path / "Library/LaunchDaemons"
        )
        # Application folder of the software source (never the real /Applications).
        self.applications = tmp_path / "Applications"
        self.applications.mkdir()
        apple = tmp_path / "apple/System/Library/LaunchDaemons"
        apple.mkdir(parents=True)
        for name in (
            "ssh.plist",
            "com.apple.ftp-proxy.plist",
            "com.apple.screensharing.plist",
            "org.cups.cupsd.plist",
        ):
            shutil.copy2(FIXTURES / "launchd/apple" / name, apple / name)
        self.runner = build_runner()
        self.collector = MacOSCollector(
            runner=self.runner,
            path_resolver=no_paths,
            uid=501,
            launch_locations=[
                launchd_mod.Location(self.agents, "user", "agent"),
                launchd_mod.Location(self.daemons, "system", "daemon"),
            ],
            app_locations=[software_mod.AppLocation(self.applications, "system")],
            apple_definitions_root=tmp_path / "apple",
            system_count_dirs=(str(tmp_path / "none-a"), str(tmp_path / "none-b")),
            require_macos=False,
        )
        config = CollectorConfig(
            collector_id=COLLECTOR,
            producer_id="macos-workstation-01",
            asset_id=ASSET,
            module="extorq_collectors.macos.collector:MacOSCollector",
            interval_seconds=60,
            settings=settings or {"launchd": {"allowlist": ["com.example.thirdparty.redis"]}},
        )
        self.store = StateStore(tmp_path / "state.db")
        self.ctx = CollectorContext(config, self.store, collector_version="0.1.0")
        self.collector.setup(self.ctx)

    def cycle(self, *, force: bool = True) -> list[tuple[str, dict[str, Any]]]:
        if force:
            self.ctx.state.delete(KV_SOURCES)  # make every source due
        before = {row[0] for row in self.store._conn.execute("SELECT seq FROM outbox")}
        self.ctx.begin_cycle()
        self.collector.collect(self.ctx)
        rows = self.store._conn.execute(
            "SELECT seq, kind, record FROM outbox ORDER BY seq"
        ).fetchall()
        return [(kind, json.loads(rec)["data"]) for seq, kind, rec in rows if seq not in before]


def kinds(records: list[tuple[str, dict[str, Any]]]) -> Counter[str]:
    return Counter(kind for kind, _ in records)


def event_types(records: list[tuple[str, dict[str, Any]]]) -> Counter[str]:
    return Counter(data["event_type"] for kind, data in records if kind == "event")


def test_first_cycle_is_a_baseline_with_complete_records(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    records = h.cycle()
    k, types = kinds(records), event_types(records)
    assert k["scan_run"] == 2 and k["asset"] == 1 and k["finding"] >= 1
    # exact counts of the minimised snapshot (tests/fixtures/macos/README.md)
    assert k["service"] == 13 and k["service_instance"] == 10
    items = Counter(d["item_type"] for kind, d in records if kind == "inventory_item")
    assert items["process"] == 19 and items["user"] == 8 and items["launch_item"] == 5
    assert items["listener"] == 14 and items["software"] == 6
    assert types["security.gatekeeper.event"] == 5
    assert types["service.discovered"] == k["service"]  # baseline: flagged discoveries
    assert not any(
        t.startswith("persistence.launchd") for t in types
    )  # baseline: no persistence noise
    assert not any(t.startswith("network.listener") or t.startswith("account.user") for t in types)
    discovered = [
        d for kind, d in records if kind == "event" and d["event_type"] == "service.discovered"
    ]
    assert all(
        d["attributes"]["baseline"] is True and d["service"]["service_id"] for d in discovered
    )
    firewall = [
        d for kind, d in records if kind == "finding" and d["check_id"] == "macos.firewall.enabled"
    ]
    assert firewall and firewall[0]["severity"] == "medium"
    airplay = [
        d
        for kind, d in records
        if kind == "finding" and d["check_id"] == "macos.sharing.airplay_receiver"
    ]
    assert airplay and airplay[0]["service_id"]  # attributed to com.apple.controlcenter
    asset = next(d for kind, d in records if kind == "asset")
    assert (
        asset["attributes"]["os_version"] == "27.0.1"
        and asset["attributes"]["model_identifier"] == "Mac16,8"
    )
    assert "hostname" not in asset["attributes"] and asset["display_name"] is None
    assert "serial" not in json.dumps(asset).lower()
    ssh = next(
        d for kind, d in records if kind == "service" and d["service_key"] == "com.openssh.sshd"
    )
    assert ssh["monitoring_status"] == "unmonitored" and ssh["adapter_id"] == "macos-sshd"
    checkpoint = json.loads(h.ctx.checkpoints.get(UNIFIED_LOG_CHECKPOINT) or "{}")
    assert isinstance(checkpoint["end"], int)
    details = h.ctx.health_details
    assert all(s.endswith("=ok") for s in details["sources"])
    assert any("Endpoint Security" in g for g in details["gaps"])
    assert any("lsof" in g for g in details["gaps"])  # listener visibility gap is explicit


def test_persistence_changes_after_baseline(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.cycle()
    test_agent = h.agents / "com.extorq.test.abcd1234ef.plist"
    test_agent.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.extorq.test.abcd1234ef",
                "ProgramArguments": ["/usr/bin/true"],
                "RunAtLoad": False,
            }
        )
    )
    redis = h.agents / "com.example.thirdparty.redis.plist"
    redis.write_bytes(redis.read_bytes().replace(b"redis.conf", b"redis-other.conf"))
    (h.agents / "com.example.thirdparty.php.plist").unlink()
    records = h.cycle()
    events = {
        (d["event_type"], d["resource"]["path"].rsplit("/", 1)[-1]): d
        for kind, d in records
        if kind == "event" and d["event_type"].startswith("persistence.")
    }
    created = events[("persistence.launchd.item_created", "com.extorq.test.abcd1234ef.plist")]
    assert (
        created["attributes"]["scope"] == "user" and created["attributes"]["run_at_load"] is False
    )
    assert "simulation" not in created and created["labels"] == {}
    assert created["service"]["name"] == "com.extorq.test.abcd1234ef"
    modified = events[("persistence.launchd.item_modified", "com.example.thirdparty.redis.plist")]
    assert (
        modified["attributes"]["allowlisted"] is True and modified["attributes"]["previous_sha256"]
    )
    assert ("persistence.launchd.item_deleted", "com.example.thirdparty.php.plist") in events
    tombstones = [
        d
        for kind, d in records
        if kind == "inventory_item" and not d["present"] and d["item_type"] == "launch_item"
    ]
    assert [t["item_key"].rsplit("/", 1)[-1] for t in tombstones] == [
        "com.example.thirdparty.php.plist"
    ]
    services = event_types(records)
    assert services["service.discovered"] == 1  # the new (not loaded) job
    third = h.cycle()
    assert not any(t.startswith("persistence.") for t in event_types(third))  # no repeats


def test_failing_source_is_isolated_and_never_advances_its_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = Harness(tmp_path)
    h.cycle()
    (h.agents / "com.example.thirdparty.mysql.plist").unlink()

    def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("injected failure after the diff was staged")

    monkeypatch.setattr(launchd_mod, "tombstone", broken)
    h.runner.add(PS_ARGV, failed(PS_ARGV, 1, b"ps: boom"))
    records = h.cycle()
    sources = dict(s.split("=") for s in h.ctx.health_details["sources"])
    assert sources["launchd"] == "error" and sources["inventory"] == "error"
    assert sources["unified_log"] == "ok" and sources["posture"] == "ok"
    assert not any(t.startswith("persistence.") for t in event_types(records))
    monkeypatch.undo()
    h.runner.add(PS_ARGV, ok(PS_ARGV, fixture_bytes("services/ps_services.txt")))
    retry = h.cycle()
    assert ("persistence.launchd.item_deleted") in event_types(retry)  # detected again, not lost


def test_cycle_fails_only_when_every_due_source_failed(tmp_path: Path) -> None:
    only_log = {
        name: {"enabled": False}
        for name in (
            "launchd",
            "listeners",
            "inventory",
            "posture",
            "applications",
            "software",
            "asset",
        )
    }
    h = Harness(tmp_path, settings=only_log)
    h.runner.prefixes.clear()
    h.runner.add_prefix(
        ["/usr/bin/log", "show"], failed(["/usr/bin/log"], 64, b"log: bad predicate")
    )
    with pytest.raises(MacOSCollectorError, match="all due sources failed"):
        h.cycle()
    assert h.ctx.checkpoints.get(UNIFIED_LOG_CHECKPOINT) is None  # nothing advanced


def test_sources_respect_their_own_intervals(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.cycle()
    calls_before = len(h.runner.calls)
    records = h.cycle(force=False)  # immediately again: nothing is due yet
    assert records == [] and len(h.runner.calls) == calls_before


def test_collector_declares_its_source_types() -> None:
    assert set(MacOSCollector.source_types) == {
        "macos.unified_log",
        "macos.launchd",
        "macos.inventory",
        "macos.posture",
    }
    assert collector_mod.COLLECTOR_TYPE == "macos"


def test_second_instance_on_the_same_state_is_refused(tmp_path: Path) -> None:
    first = Harness(tmp_path)
    second = MacOSCollector(
        runner=build_runner(), path_resolver=no_paths, uid=501, require_macos=False
    )
    with pytest.raises(MacOSCollectorError, match="another macOS collector instance"):
        second.setup(first.ctx)
    first.collector.close()
    second.setup(first.ctx)  # released on close
    second.close()


def test_sshd_records_become_auth_ssh_events_bound_to_remote_login(tmp_path: Path) -> None:
    from extorq.contracts.identity import service_id

    h = Harness(
        tmp_path,
        settings={
            n: {"enabled": False}
            for n in ("launchd", "inventory", "posture", "applications", "asset")
        },
    )
    h.runner.prefixes.clear()
    h.runner.add_prefix(
        ["/usr/bin/log", "show"],
        ok(
            ["/usr/bin/log"],
            fixture_bytes("unified_log/synthetic_sshd_auth.ndjson")
            + b'{"count":14,"finished":1}\n',
        ),
    )
    records = h.cycle()
    events = [d for kind, d in records if kind == "event"]
    assert len(events) == 14
    ssh_service = service_id(ASSET, "host_service", "com.openssh.sshd")
    bound = [e for e in events if e["service"] is not None]
    assert len(bound) == 13 and all(
        e["service"]["service_id"] == ssh_service and e["service"]["adapter_id"] == "macos-sshd"
        for e in bound
    )
    unbound = [e for e in events if e["service"] is None]
    assert [e["attributes"]["source_verified"] for e in unbound] == [False]
    types = Counter(e["event_type"] for e in events)
    assert types == {
        "auth.ssh.login_failed": 5,
        "auth.ssh.preauth_closed": 3,
        "auth.ssh.max_auth_exceeded": 2,
        "auth.ssh.invalid_user": 1,
        "auth.ssh.login_succeeded": 1,
        "system.log.notable": 2,
    }
    # the adapter's newest event time feeds the Remote Login service's last_telemetry_at
    last = h.ctx.state.get(collector_mod.KV_ADAPTER_LAST_EVENT)
    assert last == {"macos-sshd": "2026-11-21T11:00:13.000Z"}


def test_generated_uid_is_resolved_with_dscl_search() -> None:
    guid = "A1B2C3D4-0000-4000-8000-000000000001"
    argv = ["/usr/bin/dscl", ".", "-search", "/Users", "GeneratedUID", guid]
    runner = FakeRunner()
    runner.add(argv, ok(argv, fixture_bytes("posture/dscl_search_generateduid.txt")))
    collector = MacOSCollector(runner=runner, path_resolver=no_paths, uid=501, require_macos=False)
    assert collector._resolve_guid(guid.lower()) == "testuser"
    assert collector._resolve_guid(guid) == "testuser"  # cached
    assert collector._resolve_guid("not-a-guid; rm -rf /") is None  # never reaches dscl
    assert runner.calls == [tuple(argv)]


def test_label_less_plist_events_reference_the_path_keyed_service(tmp_path: Path) -> None:
    from extorq.contracts.identity import service_id

    h = Harness(tmp_path)
    h.cycle()
    path = h.agents / "com.example.thirdparty.labelless.plist"  # plist without a Label
    path.write_bytes(path.read_bytes() + b"\n")
    records = h.cycle()
    modified = [
        d
        for kind, d in records
        if kind == "event" and d["event_type"] == "persistence.launchd.item_modified"
    ]
    assert len(modified) == 1
    assert modified[0]["service"]["service_id"] == service_id(ASSET, "host_service", str(path))
    assert modified[0]["service"]["name"] == "com.example.thirdparty.labelless.plist"


def test_listener_source_reports_new_and_closed_listeners(tmp_path: Path) -> None:
    """The 60 s listeners source (MAC-003 input) diffs sockets independently of inventory."""
    from test_macos_inventory import MAC003_LSOF

    h = Harness(tmp_path)
    h.cycle()
    base = fixture_bytes("services/lsof_tcp_services.txt")
    h.runner.add(LSOF_TCP_LISTEN_ARGV, ok(LSOF_TCP_LISTEN_ARGV, base + MAC003_LSOF.encode()))
    records = h.cycle()
    opened = {
        d["resource"]["name"]: d
        for kind, d in records
        if kind == "event" and d["event_type"] == "network.listener.opened"
    }
    assert set(opened) == {"tcp:0.0.0.0:48765", "tcp:127.0.0.1:48766"}
    wide = opened["tcp:0.0.0.0:48765"]["attributes"]
    assert wide["exposure"] == "any" and wide["listener_method"] == "lsof"
    assert opened["tcp:127.0.0.1:48766"]["attributes"]["exposure"] == "loopback"
    h.runner.add(LSOF_TCP_LISTEN_ARGV, ok(LSOF_TCP_LISTEN_ARGV, base))
    closed = [
        d["resource"]["name"]
        for kind, d in h.cycle()
        if kind == "event" and d["event_type"] == "network.listener.closed"
    ]
    assert sorted(closed) == ["tcp:0.0.0.0:48765", "tcp:127.0.0.1:48766"]
    assert any(s.startswith("listeners_last_run") for s in h.ctx.health_details)

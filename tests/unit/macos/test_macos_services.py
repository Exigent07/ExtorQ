"""Service discovery, adapter matching and coverage over a real, consistent host snapshot.

services/*.txt were captured at the same moment on the reference Mac:
``launchctl print system`` / ``gui/501``, ``ps`` and ``lsof`` (account name scrubbed).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from macos_helpers import ASSET, FIXTURES, fixture_text

from extorq.contracts import validate_event_semantics
from extorq.contracts.identity import service_id
from extorq.contracts.service import (
    AdapterSupport,
    DiscoveryEvidence,
    MonitoringStatus,
    PortAttribution,
    ServiceCategory,
    ServiceKind,
)
from extorq_collectors.macos.adapters import MACOS_ADAPTERS, MacOSSshdAdapter
from extorq_collectors.macos.common import SourceContext
from extorq_collectors.macos.inventory import listeners_from_lsof, parse_lsof_fields, parse_ps
from extorq_collectors.macos.launchctl import parse_domain_print
from extorq_collectors.macos.launchd import (
    LabelAllowlist,
    Location,
    read_launch_item,
    scan_locations,
)
from extorq_collectors.macos.services import (
    CoverageInputs,
    DiscoveryInputs,
    ServiceSummary,
    build_records,
    discover,
    discovered_event,
    exposure_event,
    homebrew_product,
    match_macos_adapter,
    removed_event,
    service_tombstone,
)
from extorq_collectors.services import ServiceCandidate, registry
from extorq_collectors.services.base import ServiceAdapter

NOW = datetime(2026, 11, 21, 15, 0, tzinfo=UTC)
APPLE = {
    "com.openssh.sshd": "launchd/apple/ssh.plist",
    "com.apple.ftp-proxy": "launchd/apple/com.apple.ftp-proxy.plist",
    "com.apple.screensharing": "launchd/apple/com.apple.screensharing.plist",
    "org.cups.cupsd": "launchd/apple/org.cups.cupsd.plist",
}


def apple_definitions() -> dict:
    out = {}
    for label, rel in APPLE.items():
        path = FIXTURES / rel
        out[label] = read_launch_item(
            path, Location(path.parent, "apple", "daemon"), LabelAllowlist()
        )
    return out


def inputs(listeners_text: str | None = None) -> DiscoveryInputs:
    processes = {p.pid: p for p in parse_ps(fixture_text("services/ps_services.txt"))}
    listeners = listeners_from_lsof(
        parse_lsof_fields(listeners_text or fixture_text("services/lsof_tcp_services.txt"))
    )
    agents = FIXTURES / "launchd/user_agents"
    launch_items = scan_locations([Location(agents, "user", "agent")], LabelAllowlist()).items
    return DiscoveryInputs(
        asset_id=ASSET,
        launch_items=launch_items,
        apple_definitions=apple_definitions(),
        domains=[
            parse_domain_print(fixture_text("services/launchctl_print_system.txt"), "system"),
            parse_domain_print(fixture_text("services/launchctl_print_gui.txt"), "gui/501"),
        ],
        processes=processes,
        listeners=listeners,
        listener_method="lsof",
    )


def coverage(**overrides) -> CoverageInputs:
    base = {
        "enabled_producers": frozenset({"sshd", "screensharing"}),
        "unified_log_fresh_until": NOW - timedelta(seconds=30),
        "unified_log_failing": False,
        "stale_after_seconds": 600,
        "adapter_last_event": {},
    }
    base.update(overrides)
    return CoverageInputs(**base)


@pytest.fixture(scope="module")
def discovered():
    return discover(inputs())


def by_key(result, key):
    return next(d for d in result.services.values() if d.candidate.service_key == key)


def test_remote_login_off_is_reported_not_hidden(discovered, src: SourceContext) -> None:
    ssh = by_key(discovered, "com.openssh.sshd")
    assert ssh.state == "not_loaded" and ssh.instance_pids == []
    assert ssh.candidate.evidence == frozenset({DiscoveryEvidence.LAUNCHD_JOB})
    assert ssh.candidate.endpoints == ()  # not loaded: launchd holds no socket
    services, _ = build_records(
        discovered, ctx=src, now=NOW, first_seen={}, coverage=coverage(), processes={}
    )
    record = next(s for s in services if s.service_key == "com.openssh.sshd")
    assert record.category is ServiceCategory.SSH
    assert (
        record.adapter_id == "macos-sshd" and record.adapter_support is AdapterSupport.IMPLEMENTED
    )
    assert record.monitoring_status is MonitoringStatus.UNMONITORED
    assert "not loaded" in (record.coverage_note or "")
    assert record.attributes["sharing_enabled"] is False
    assert record.service_id == service_id(ASSET, "host_service", "com.openssh.sshd")


def test_planned_adapters_via_homebrew_evidence_and_confirmed_ports(discovered, src) -> None:
    redis = by_key(discovered, "sh.brew.redis")
    assert redis.candidate.product == "redis"
    assert redis.job is not None and redis.job.pid == 904
    ports = {(e.address, e.port, e.attribution) for e in redis.candidate.endpoints}
    assert ports == {
        ("127.0.0.1", 6379, PortAttribution.CONFIRMED),
        ("::1", 6379, PortAttribution.CONFIRMED),
    }
    assert {e.exposure for e in redis.candidate.endpoints} == {"loopback"}
    mysql = by_key(discovered, "sh.brew.mysql")
    # mysqld (pid 1068) is a child of the job's mysqld_safe: still confirmed for the job
    assert any(e.port == 3306 for e in mysql.candidate.endpoints)
    assert len(mysql.instance_pids) >= 2
    services, _ = build_records(
        discovered, ctx=src, now=NOW, first_seen={}, coverage=coverage(), processes={}
    )
    redis_record = next(s for s in services if s.service_key == "sh.brew.redis")
    assert redis_record.adapter_id == "redis"
    assert redis_record.adapter_support is AdapterSupport.PLANNED
    assert redis_record.monitoring_status is MonitoringStatus.UNMONITORED
    assert redis_record.category is ServiceCategory.CACHE


def test_socket_activated_job_has_only_inferred_endpoints(discovered) -> None:
    proxy = by_key(discovered, "com.apple.ftp-proxy")
    assert proxy.state == "loaded_idle"
    endpoints = {(e.address, e.port, e.attribution) for e in proxy.candidate.endpoints}
    assert endpoints == {
        ("127.0.0.1", 8021, PortAttribution.INFERRED),
        ("::1", 8021, PortAttribution.INFERRED),
    }
    assert DiscoveryEvidence.CONFIGURATION in proxy.candidate.evidence


def test_unix_socket_job_has_no_network_endpoint(discovered) -> None:
    cups = by_key(discovered, "org.cups.cupsd")
    assert cups.candidate.endpoints == ()
    assert DiscoveryEvidence.CONFIGURATION not in cups.candidate.evidence


def test_apple_agent_listener_maps_to_its_launchd_job(discovered) -> None:
    control = by_key(discovered, "com.apple.controlcenter")
    assert control.candidate.service_kind is ServiceKind.HOST_SERVICE
    assert {
        DiscoveryEvidence.LAUNCHD_JOB,
        DiscoveryEvidence.LISTENING_SOCKET,
    } <= control.candidate.evidence
    assert {e.exposure for e in control.candidate.endpoints} == {"any"}
    key = "tcp:0.0.0.0:7000"
    assert discovered.listener_service[key] == control.candidate.service_id


def test_application_listener_without_job_and_unverified_paths(discovered) -> None:
    docker = next(
        d
        for d in discovered.services.values()
        if d.candidate.service_kind is ServiceKind.APPLICATION
        and d.candidate.name == "com.docker.backend"
    )
    assert {
        DiscoveryEvidence.PROCESS,
        DiscoveryEvidence.LISTENING_SOCKET,
    } <= docker.candidate.evidence
    assert docker.candidate.attributes["app_bundle"] == "Docker.app"
    # Owners whose ps command is a bare argv[0] are not turned into services without a
    # verified path; the listener is reported as unattributed instead of guessed.
    assert "tcp:127.0.0.1:2222" in discovered.unattributed_listeners


def test_verified_paths_attribute_the_remaining_listeners() -> None:
    base = inputs()
    paths = {95469: "/opt/homebrew/Cellar/qemu/11.1.1/bin/qemu-system-aarch64"}
    from dataclasses import replace

    processes = {pid: replace(p, path=paths.get(pid)) for pid, p in base.processes.items()}
    result = discover(replace(base, processes=processes))
    qemu = next(d for d in result.services.values() if d.candidate.name == "qemu-system-aarch64")
    assert qemu.candidate.product == "qemu" and qemu.version == "11.1.1"
    assert qemu.candidate.attributes["version_evidence"] == "running executable (proc_pidpath)"
    assert "tcp:127.0.0.1:2222" not in result.unattributed_listeners


def test_processes_are_not_assumed_to_be_network_services(discovered) -> None:
    for d in discovered.services.values():
        if DiscoveryEvidence.LISTENING_SOCKET not in d.candidate.evidence and d.apple is None:
            assert all(
                e.attribution is not PortAttribution.CONFIRMED for e in d.candidate.endpoints
            )
        assert d.candidate.evidence  # every service has evidence
    assert not any(
        d.candidate.service_key.startswith("application.") for d in discovered.services.values()
    )


def test_label_less_plist_uses_file_name(discovered) -> None:
    keystone = [
        d
        for d in discovered.services.values()
        if d.candidate.service_key.endswith("com.google.keystone.agent.plist")
    ]
    assert keystone and keystone[0].candidate.name == "com.google.keystone.agent.plist"


def test_coverage_when_remote_login_is_enabled(src: SourceContext) -> None:
    base = inputs()
    system = parse_domain_print(fixture_text("services/launchctl_print_system.txt"), "system")
    from extorq_collectors.macos.launchctl import LoadedJob

    system.jobs["com.openssh.sshd"] = LoadedJob("com.openssh.sshd", "system", None, None)
    from dataclasses import replace

    enabled = discover(replace(base, domains=[system, base.domains[1]]))
    ssh = by_key(enabled, "com.openssh.sshd")
    assert ssh.state == "loaded_idle"
    assert {(e.address, e.port, e.attribution, e.exposure) for e in ssh.candidate.endpoints} == {
        (None, 22, PortAttribution.INFERRED, "any")
    }

    def status(cov):
        services, _ = build_records(
            enabled, ctx=src, now=NOW, first_seen={}, coverage=cov, processes={}
        )
        return next(s for s in services if s.service_key == "com.openssh.sshd")

    assert status(coverage()).monitoring_status is MonitoringStatus.MONITORED
    stale = status(coverage(unified_log_fresh_until=NOW - timedelta(hours=1)))
    assert stale.monitoring_status is MonitoringStatus.DEGRADED
    failing = status(coverage(unified_log_failing=True))
    assert failing.monitoring_status is MonitoringStatus.DEGRADED
    disabled = status(coverage(enabled_producers=frozenset()))
    assert disabled.monitoring_status is MonitoringStatus.UNMONITORED
    seen = status(coverage(adapter_last_event={"macos-sshd": NOW - timedelta(minutes=5)}))
    assert seen.last_telemetry_at == NOW - timedelta(minutes=5)


def test_other_platform_implemented_adapters_are_never_claimed(monkeypatch) -> None:
    class LinuxNginx(ServiceAdapter):
        adapter_id = "nginx"
        support = AdapterSupport.IMPLEMENTED
        executables = frozenset({"nginx"})

    monkeypatch.setitem(registry._REGISTRY, "nginx", LinuxNginx())
    candidate = ServiceCandidate(
        asset_id=ASSET,
        service_kind=ServiceKind.APPLICATION,
        service_key="/opt/homebrew/bin/nginx",
        name="nginx",
        evidence=frozenset({DiscoveryEvidence.PROCESS}),
        executable="/opt/homebrew/bin/nginx",
    )
    adapter, other = match_macos_adapter(candidate)
    assert adapter is None and other == "nginx"


def test_macos_adapters_never_match_linux_candidates() -> None:
    linux_sshd = ServiceCandidate(
        asset_id="linux:lab-vm-01",
        service_kind=ServiceKind.HOST_SERVICE,
        service_key="ssh.service",
        name="ssh",
        evidence=frozenset({DiscoveryEvidence.SYSTEMD_UNIT}),
        unit="ssh.service",
        executable="/usr/sbin/sshd",
        product="openssh",
    )
    assert not any(a.matches(linux_sshd) for a in MACOS_ADAPTERS.values())


def test_service_events_and_tombstones(discovered, src: SourceContext) -> None:
    services, instances = build_records(
        discovered,
        ctx=src,
        now=NOW,
        first_seen={},
        coverage=coverage(),
        processes=inputs().processes,
    )
    assert instances and all(i.asset_id == ASSET for i in instances)
    redis = next(s for s in services if s.service_key == "sh.brew.redis")
    event = discovered_event(redis, src, observed_at=NOW, snapshot="s1", baseline=True)
    assert event.event_type == "service.discovered" and event.service is not None
    assert event.service.service_id == redis.service_id
    assert event.attributes["adapter_support"] == "planned"
    summary = ServiceSummary.of(redis)
    previous = {**summary, "endpoints": ["tcp:127.0.0.1:6379 loopback confirmed"]}
    change = exposure_event(redis, previous, src, observed_at=NOW, snapshot="s2")
    assert change is not None and change.attributes["endpoints_added"] == [
        "tcp:[::1]:6379 loopback confirmed"
    ]
    assert exposure_event(redis, summary, src, observed_at=NOW, snapshot="s2") is None
    gone = removed_event(redis.service_id, summary, src, observed_at=NOW, snapshot="s3")
    tomb = service_tombstone(redis.service_id, json.loads(json.dumps(summary)), src, NOW)
    assert tomb is not None and tomb.present is False and tomb.endpoints == []
    for ev in (event, change, gone):
        assert validate_event_semantics(ev.event_type, ev.category.value, "macos.inventory") is None


def test_homebrew_product_evidence() -> None:
    assert homebrew_product("/opt/homebrew/opt/redis/bin/redis-server") == ("redis", None)
    assert homebrew_product("/opt/homebrew/Cellar/redis/8.10.1/bin/redis-server") == (
        "redis",
        "8.10.1",
    )
    assert homebrew_product("/opt/homebrew/opt/mysql@8.4/bin/mysqld") == ("mysql", None)
    assert homebrew_product("/usr/sbin/sshd") == (None, None)


def test_sshd_adapter_attaches_service_ref_via_generic_interface(src: SourceContext) -> None:
    from extorq_collectors.macos.services import adapter_service_ref
    from extorq_collectors.services import AdapterContext

    line = next(
        line
        for line in (FIXTURES / "unified_log/synthetic_auth_producers.ndjson")
        .read_text()
        .splitlines()
        if '"processImagePath": "/usr/sbin/sshd"' in line
    )
    raw = json.loads(line)
    adapter = MacOSSshdAdapter()
    assert adapter.accepts(raw) and not adapter.accepts({"processImagePath": "/usr/bin/sudo"})
    ref = adapter_service_ref(ASSET, "macos-sshd")
    events = adapter.parse(
        raw,
        AdapterContext(
            asset_id=ASSET,
            asset_type="macos_host",
            collector_id=src.collector_id,
            collector_version="0.1.0",
            service=ref,
            observed_time=NOW,
        ),
    )
    assert len(events) == 1 and events[0].service == ref
    assert events[0].service.adapter_id == "macos-sshd"
    assert events[0].service.service_id == service_id(ASSET, "host_service", "com.openssh.sshd")
    assert "file contents" not in " ".join(adapter.collects)
    assert adapter.never_collects


def test_fixture_paths_exist() -> None:
    for rel in APPLE.values():
        assert Path(FIXTURES / rel).is_file()


def test_instances_link_parents_only_within_the_same_service(discovered, src) -> None:
    processes = inputs().processes
    _, instances = build_records(
        discovered, ctx=src, now=NOW, first_seen={}, coverage=coverage(), processes=processes
    )
    ids = {i.instance_id for i in instances}
    linked = [i for i in instances if i.parent_instance_id is not None]
    assert linked  # e.g. php-fpm workers under the php-fpm master, mysqld under mysqld_safe
    assert all(i.parent_instance_id in ids for i in linked)


def test_running_version_only_from_a_verified_cellar_path() -> None:
    from dataclasses import replace

    base = inputs()
    unverified = by_key(discover(base), "sh.brew.redis")
    assert unverified.candidate.product == "redis" and unverified.version is None
    paths = {904: "/opt/homebrew/Cellar/redis/8.10.1/bin/redis-server"}
    processes = {pid: replace(p, path=paths.get(pid)) for pid, p in base.processes.items()}
    redis = by_key(discover(replace(base, processes=processes)), "sh.brew.redis")
    assert redis.version == "8.10.1"
    assert redis.candidate.attributes["version_evidence"] == "running executable (proc_pidpath)"

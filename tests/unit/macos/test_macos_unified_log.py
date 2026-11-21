"""Unified-log parsing, classification, identity and window planning (real fixtures)."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from macos_helpers import ASSET, fixture_bytes

from extorq.contracts import EVENT_CATALOG, Outcome, Severity, validate_event_semantics
from extorq_collectors.macos.common import SourceContext
from extorq_collectors.macos.unified_log import (
    PRODUCERS,
    DedupState,
    WindowPlan,
    build_log_show_argv,
    build_predicate,
    classify,
    native_key,
    next_checkpoint,
    parse_ndjson,
    parse_timestamp,
    plan_window,
    to_event,
)

OBSERVED = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)


def records(name: str):
    parsed, stats = parse_ndjson(fixture_bytes(f"unified_log/{name}"), max_records=1000)
    return parsed, stats


def events(name: str, src: SourceContext):
    parsed, _ = records(name)
    return [to_event(r, classify(r), src, observed_time=OBSERVED) for r in parsed]


def test_predicate_is_built_from_fixed_fragments_only() -> None:
    predicate = build_predicate(["sudo", "gatekeeper", "sudo"])
    assert predicate.count('process == "sudo"') == 1
    assert "com.apple.syspolicy.exec" in predicate
    with pytest.raises(ValueError, match="unknown unified-log producer"):
        build_predicate(['sudo" OR 1==1'])
    with pytest.raises(ValueError):
        build_predicate([])


def test_log_show_argv_is_a_fixed_argument_list() -> None:
    argv = build_log_show_argv(100, 160, build_predicate(PRODUCERS))
    assert argv[:4] == ["/usr/bin/log", "show", "--style", "ndjson"]
    assert argv[argv.index("--start") + 1] == "@100"
    assert argv[argv.index("--end") + 1] == "@160"
    with pytest.raises(ValueError):
        build_log_show_argv(200, 100, "x")


def test_timestamp_parsing_normalises_offsets_to_utc() -> None:
    parsed = parse_timestamp("2026-11-20 17:36:13.221593+0530")
    assert parsed == datetime(2026, 11, 20, 12, 6, 13, 221593, tzinfo=UTC)
    assert parse_timestamp("not a time") is None


def test_trailer_and_truncated_final_line() -> None:
    parsed, stats = records("trailer_empty.ndjson")
    assert parsed == [] and stats.finished and stats.trailer_count == 0
    data = fixture_bytes("unified_log/gatekeeper_evaluate.ndjson")
    cut = data[: len(data) - 40]  # output cut at the byte limit mid-line
    parsed, stats = parse_ndjson(cut, max_records=100)
    assert len(parsed) == 2 and stats.invalid_json == 0 and not stats.finished


def test_native_key_uses_boot_uuid_mach_time_thread_and_trace() -> None:
    parsed, _ = records("opendirectoryd_auth_failed.ndjson")
    key = native_key(parsed[0])
    assert key.startswith("B122BAB5-1E0C-4127-A385-45040BF9E5D1:10648801034604:1795815:")
    assert len({native_key(r) for r in parsed}) == len(parsed)


def test_native_key_falls_back_to_content_key() -> None:
    line = json.dumps(
        {"timestamp": "2026-11-21 10:00:00.000000+0000", "eventMessage": "x", "processID": 1}
    ).encode()
    parsed, _ = parse_ndjson(line + b"\n", max_records=10)
    assert native_key(parsed[0]).startswith("content:")


def test_opendirectory_failures_keep_private_name_unknown(src: SourceContext) -> None:
    evs = events("opendirectoryd_auth_failed.ndjson", src)
    assert len(evs) == 3
    for event in evs:
        assert event.event_type == "auth.local.failure"
        assert event.outcome is Outcome.FAILURE
        assert event.actor is not None and event.actor.name is None  # <private>: never guessed
        assert event.actor.id == "A1B2C3D4-0000-4000-8000-000000000001"
        assert event.attributes["private_redaction"] is True
        assert event.attributes["reason"] == "ODErrorCredentialsInvalid"
        assert event.asset_id == ASSET
        assert event.source.source_type.value == "macos.unified_log"
        assert event.provenance.raw_sha256 is not None


def test_generated_uid_resolution_is_explicit(src: SourceContext) -> None:
    parsed, _ = records("opendirectoryd_auth_failed.ndjson")
    event = to_event(
        parsed[0],
        classify(parsed[0]),
        src,
        observed_time=OBSERVED,
        resolve_actor=lambda guid: "testuser" if guid.startswith("A1B2") else None,
    )
    assert event.actor is not None and event.actor.name == "testuser"
    assert event.attributes["actor_name_source"] == "dscl_generated_uid"


def test_screen_lock_failures(src: SourceContext) -> None:
    evs = events("loginwindow_screenlock_failed.ndjson", src)
    assert [e.action for e in evs] == ["screen_unlock_failed"] * 3
    assert {e.event_type for e in evs} == {"auth.local.failure"}
    assert evs[0].attributes["reason"] == "INCORRECT password"


def test_gatekeeper_assessment_and_prompt_flow(src: SourceContext) -> None:
    evs = events("gatekeeper_evaluate.ndjson", src)
    assert {e.event_type for e in evs} == {"security.gatekeeper.event"}
    first = evs[0]
    assert first.attributes["scan_result"] == 3
    assert first.attributes["team_id"] == "2DC432GLL2"
    assert first.attributes["path_hash"] == "a5ad9a24e03cb072"  # syspolicyd logs a hash, not a path
    flow = events("gatekeeper_prompt_flow.ndjson", src)
    assert [e.action for e in flow] == [
        "gk_perform_scan",
        "gk_evaluate_scan_result",
        "gk_prompt_shown",
        "gk_code_allowed",
        "gk_marked_user_approved",
    ]
    assert flow[-1].attributes["approved"] is True


def test_xprotect_results(src: SourceContext) -> None:
    remediator = events("xprotect_remediator.ndjson", src)
    assert {e.event_type for e in remediator} == {"security.xprotect.event"}
    assert remediator[0].attributes["plugin"] == "Bundlore"
    assert remediator[0].attributes["threat_detected"] is False
    assert remediator[0].outcome is Outcome.SUCCESS
    badsig = events("xprotect_remediator_badsig.ndjson", src)[0]
    assert badsig.attributes["status_message"] == "BadPluginServiceSignature"
    assert "threat_detected" not in badsig.attributes  # unknown stays absent, not "no threat"
    assert badsig.outcome is Outcome.FAILURE
    lifecycle = events("xprotect_scan_lifecycle.ndjson", src)
    assert [e.action for e in lifecycle] == ["system_scan_started", "system_scan_finished"]
    forwarded = events("xprotect_behavior_forwarded.ndjson", src)[0]
    assert forwarded.action == "behavior_detection_forwarded"


def test_synthetic_auth_producers_are_labelled_and_classified(src: SourceContext) -> None:
    raw = fixture_bytes("unified_log/synthetic_auth_producers.ndjson")
    for line in raw.splitlines():
        if line.strip():
            assert "SYNTHETIC" in json.loads(line)["extorqSynthetic"]
    evs = events("synthetic_auth_producers.ndjson", src)
    by_action = {e.action: e for e in evs}
    sudo = by_action["sudo_command"]
    assert sudo.event_type == "auth.sudo.command"
    assert sudo.actor is not None and sudo.actor.name == "testuser"
    assert sudo.attributes["run_as"] == "root"
    assert sudo.process is not None and sudo.process.command_line == "/usr/bin/true"
    denied = [e for e in evs if e.event_type == "auth.sudo.failure"]
    assert {e.attributes["reason"] for e in denied} == {
        "3 incorrect password attempts",
        "user NOT in sudoers",
    }
    ssh_failed = [e for e in evs if e.action == "ssh_login_failed"]
    assert len(ssh_failed) == 2
    assert ssh_failed[0].network is not None and ssh_failed[0].network.src_ip == "192.0.2.44"
    assert ssh_failed[0].attributes["invalid_user"] is True
    assert ssh_failed[1].network is not None and ssh_failed[1].network.src_ip == "2001:db8::44"
    assert by_action["ssh_login_succeeded"].event_type == "system.log.notable"
    assert by_action["screensharing_auth_failed"].event_type == "auth.local.failure"
    authz = [e for e in evs if e.action == "authorization_denied"]
    assert authz and authz[0].attributes["right"] == "system.preferences.security"


def test_every_event_satisfies_the_catalog(src: SourceContext) -> None:
    names = [
        "gatekeeper_evaluate.ndjson",
        "gatekeeper_prompt_flow.ndjson",
        "loginwindow_screenlock_failed.ndjson",
        "opendirectoryd_auth_failed.ndjson",
        "synthetic_auth_producers.ndjson",
        "xprotect_behavior_forwarded.ndjson",
        "xprotect_remediator.ndjson",
        "xprotect_remediator_badsig.ndjson",
        "xprotect_scan_lifecycle.ndjson",
    ]
    for name in names:
        for event in events(name, src):
            assert event.event_type in EVENT_CATALOG
            assert (
                validate_event_semantics(
                    event.event_type, event.category.value, event.source.source_type.value
                )
                is None
            )


def test_message_type_maps_to_source_severity_hint(src: SourceContext) -> None:
    event = events("opendirectoryd_auth_failed.ndjson", src)[0]
    assert event.severity_hint is Severity.MEDIUM  # messageType "Error"


def test_window_planning_first_run_overlap_and_backfill_limit() -> None:
    first = plan_window(
        now_epoch=10_000,
        checkpoint_end=None,
        overlap_seconds=10,
        settle_seconds=5,
        max_window_seconds=900,
        max_backfill_seconds=86_400,
        initial_lookback_seconds=900,
    )
    assert first == WindowPlan(start=10_000 - 5 - 900, end=10_000 - 5)
    nxt = plan_window(
        now_epoch=10_060,
        checkpoint_end=9_995,
        overlap_seconds=10,
        settle_seconds=5,
        max_window_seconds=900,
        max_backfill_seconds=86_400,
        initial_lookback_seconds=900,
    )
    assert nxt == WindowPlan(start=9_985, end=10_055)
    assert (
        plan_window(
            now_epoch=10_000,
            checkpoint_end=9_995,
            overlap_seconds=10,
            settle_seconds=5,
            max_window_seconds=900,
            max_backfill_seconds=86_400,
            initial_lookback_seconds=900,
        )
        is None
    )
    stale = plan_window(
        now_epoch=200_000,
        checkpoint_end=1_000,
        overlap_seconds=10,
        settle_seconds=5,
        max_window_seconds=900,
        max_backfill_seconds=86_400,
        initial_lookback_seconds=900,
    )
    assert stale is not None and stale.skipped_seconds == 200_000 - 5 - 86_400 - 1_000
    assert stale.end - stale.start == 900  # bounded per cycle


def test_checkpoint_advances_and_remembers_overlap_ids() -> None:
    parsed, _ = records("loginwindow_screenlock_failed.ndjson")
    times = [int(r.timestamp.timestamp()) for r in parsed]
    plan = WindowPlan(start=times[0] - 30, end=times[-1] + 1)
    ids = [f"id{i}" for i in range(len(parsed))]
    end, remember, forced = next_checkpoint(
        plan=plan, records=parsed, event_ids=ids, truncated=False, overlap_seconds=10
    )
    assert end == plan.end and not forced
    assert set(remember) == {i for i, t in zip(ids, times, strict=True) if t >= end - 10}
    end_t, _, forced_t = next_checkpoint(
        plan=plan, records=parsed, event_ids=ids, truncated=True, overlap_seconds=10
    )
    assert end_t == times[-1] and not forced_t  # re-read the rest next cycle
    end_f, _, forced_f = next_checkpoint(
        plan=plan, records=[], event_ids=[], truncated=True, overlap_seconds=10
    )
    assert end_f == plan.end and forced_f  # no progress possible: skip and report a gap


def test_dedup_state_round_trip_and_bad_input() -> None:
    state = DedupState(end=123, seen=["a", "b"])
    assert DedupState.from_json(state.to_json()) == state
    assert DedupState.from_json("not json") == DedupState()
    assert DedupState.from_json('{"end": true, "seen": [1, "x"]}') == DedupState(None, ["x"])

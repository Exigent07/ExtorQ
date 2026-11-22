"""Offline checks of action-to-alert evidence verification."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from detection_tests.model import AlertObservation, TelemetryExpectation
from detection_tests.runner import Output, Runner, RunOptions
from detection_tests.windows import conclusive_run

NOW = datetime(2026, 11, 22, 10, tzinfo=UTC)
ASSET = "linux:lab-vm-01"
EVENT_ID = "a" * 32
ALERT_ID = "b" * 32
PRODUCER = "linux-ssh-lab-vm-01"
SOURCE = "linux.journald"
ROOT = Path(__file__).resolve().parents[3]


def test_positive_requires_matching_cited_evidence_and_authenticated_producer() -> None:
    api = MagicMock()
    runner = Runner(root=ROOT, api=api, clock=MagicMock(), options=RunOptions(), output=Output())
    observation = AlertObservation(ALERT_ID, "VM-001", ASSET, "medium", "medium", NOW, NOW, 1)
    action = TelemetryExpectation(
        "controlled SSH observation",
        "auth.ssh.login_failed",
        actor="test-account",
        source_type=SOURCE,
    )
    row = {
        "event_id": EVENT_ID,
        "event_type": action.event_type,
        "asset_id": ASSET,
        "source_type": SOURCE,
        "actor_name": "test-account",
        "event_time": NOW.isoformat(),
        "ingested_time": NOW.isoformat(),
    }
    detail = {
        "alert": {
            "alert_id": ALERT_ID,
            "rule_id": "VM-001",
            "asset_id": ASSET,
            "rule_version": "1.1",
        },
        "evidence": [row],
    }
    event = {
        "event_id": EVENT_ID,
        "asset_id": ASSET,
        "source": {"source_type": SOURCE, "source_native_id": "native-record-1"},
    }

    def verify(version: str = "1.1") -> dict[str, dict[str, str]]:
        return runner._verify_evidence(detail, [action], observation, NOW, NOW, version)

    api.event_detail.return_value = {"event": event, "ingest": {"producer_id": PRODUCER}}
    assert verify()[EVENT_ID]["source_native_id"] == "native-record-1"
    assert verify("2.0") == {}
    row["actor_name"] = "another-account"
    assert verify() == {}
    row["actor_name"] = "test-account"
    api.event_detail.return_value["ingest"]["producer_id"] = "different-producer"
    assert verify() == {}


def test_completed_run_must_cover_all_control_events() -> None:
    earlier = NOW - timedelta(seconds=30)
    run = {
        "status": "succeeded",
        "started_at": (NOW + timedelta(seconds=15)).isoformat(),
        "finished_at": (NOW + timedelta(seconds=16)).isoformat(),
        "window_start": NOW.isoformat(),
        "window_end": (NOW + timedelta(seconds=5)).isoformat(),
    }
    args = {"ingested_after": NOW, "event_time": NOW, "earliest_event_time": earlier}
    assert conclusive_run([run], **args) is None
    run["window_start"] = earlier.isoformat()
    assert conclusive_run([run], **args) is run

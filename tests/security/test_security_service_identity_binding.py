"""Service identities must be bound to the authorised asset (F-19 / F-IC-6; owner: agent F).

A producer authorised for one asset must not be able to publish a ``service`` row
that carries another asset's ``service_id`` (ids are computable from public facts),
nor an instance whose ``instance_id`` does not derive from its declared parts.

The gateway recomputes both identities from the record's own fields and
quarantines a mismatch (``identity_mismatch``; owner A, F-19 gateway part,
implemented in build session 2). The negative cases were ``xfail`` until then
and are now hard requirements; the positive case (a correctly derived record is
accepted) guards against over-blocking. All records are SYNTHETIC.

Residual (owner D1, not covered here): the analyst API reads service instances
and events by ``service_id`` alone, so an instance that an authorised producer
attaches to another asset's service id is shown under that service.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Any

import pytest

processing = pytest.importorskip("extorq.ingest.processing")
registry = pytest.importorskip("extorq.ingest.registry")

from extorq.contracts.identity import instance_id, service_id  # noqa: E402

NOW = datetime(2026, 11, 21, 12, 0, tzinfo=UTC)
NOW_ISO = NOW.isoformat()
HOST = "linux:lab-vm-01"
OTHER = "macos:workstation-01"


def _producer() -> Any:
    return registry.ProducerEntry(
        producer_id="linux-ssh-lab-vm-01",
        token_sha256=registry.token_digest(secrets.token_hex(16)),
        allowed_kinds=["service", "service_instance"],
        allowed_source_types=["linux.*"],
        allowed_asset_patterns=[HOST],
    )


def _service(sid: str, key: str = "ssh.service") -> dict[str, Any]:
    return {
        "kind": "service",
        "data": {
            "service_id": sid,
            "asset_id": HOST,
            "service_kind": "host_service",
            "service_key": key,
            "name": key.removesuffix(".service"),
            "category": "ssh",
            "discovered_via": ["systemd_unit"],
            "adapter_support": "implemented",
            "monitoring_status": "monitored",
            "first_seen": NOW_ISO,
            "last_seen": NOW_ISO,
            "observed_by": "f-security-test",
        },
    }


def _instance(sid: str, iid: str) -> dict[str, Any]:
    return {
        "kind": "service_instance",
        "data": {
            "instance_id": iid,
            "service_id": sid,
            "asset_id": HOST,
            "instance_kind": "process",
            "instance_key": "4242:1",
            "observed_at": NOW_ISO,
            "observed_by": "f-security-test",
        },
    }


def _prepare(record: dict[str, Any]) -> Any:
    return processing.prepare_batch([record], _producer(), batch_id="b" * 32, now=NOW)


def _accepted(record: dict[str, Any]) -> bool:
    batch = _prepare(record)
    return bool(batch.candidates) and not batch.denials


def _quarantined_for_identity(record: dict[str, Any]) -> bool:
    """Rejected for the right reason: quarantined as an identity mismatch, not denied."""
    batch = _prepare(record)
    reasons = [entry.reason for entry in batch.quarantined]
    return (
        not batch.candidates
        and not batch.denials
        and len(reasons) == 1
        and reasons[0].startswith("identity_mismatch")
    )


def test_correctly_derived_service_and_instance_are_accepted() -> None:
    sid = service_id(HOST, "host_service", "ssh.service")
    assert _accepted(_service(sid))
    assert _accepted(_instance(sid, instance_id(sid, "process", "4242:1")))


def test_service_carrying_another_assets_id_is_rejected() -> None:
    foreign = service_id(OTHER, "host_service", "com.openssh.sshd")
    assert not _accepted(_service(foreign))
    assert _quarantined_for_identity(_service(foreign))


def test_instance_with_underived_id_is_rejected() -> None:
    sid = service_id(HOST, "host_service", "ssh.service")
    forged = instance_id(sid, "process", "9999:1")  # does not match instance_key 4242:1
    assert not _accepted(_instance(sid, forged))
    assert _quarantined_for_identity(_instance(sid, forged))

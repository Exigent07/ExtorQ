"""Service identities must be bound to the authorised asset (F-19 / F-IC-6; owner: agent F).

A producer authorised for one asset must not be able to publish a ``service`` row
that carries another asset's ``service_id`` (ids are computable from public facts),
nor an instance whose ``instance_id`` does not derive from its declared parts.

The negative cases are marked ``xfail`` (non-strict) until the gateway recomputes
the identities (owner A, F-IC-6): they document the expected behaviour and turn
into XPASS when it lands. The positive case (a correctly derived record is
accepted) must always pass. All records are SYNTHETIC.
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

F19 = (
    "F-19 / F-IC-6 (owner A): the gateway does not yet recompute service_id/instance_id "
    "from the record's own fields"
)


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


def _accepted(record: dict[str, Any]) -> bool:
    batch = processing.prepare_batch([record], _producer(), batch_id="b" * 32, now=NOW)
    return bool(batch.candidates) and not batch.denials


def test_correctly_derived_service_and_instance_are_accepted() -> None:
    sid = service_id(HOST, "host_service", "ssh.service")
    assert _accepted(_service(sid))
    assert _accepted(_instance(sid, instance_id(sid, "process", "4242:1")))


@pytest.mark.xfail(reason=F19, strict=False)
def test_service_carrying_another_assets_id_is_rejected() -> None:
    foreign = service_id(OTHER, "host_service", "com.openssh.sshd")
    assert not _accepted(_service(foreign))


@pytest.mark.xfail(reason=F19, strict=False)
def test_instance_with_underived_id_is_rejected() -> None:
    sid = service_id(HOST, "host_service", "ssh.service")
    forged = instance_id(sid, "process", "9999:1")  # does not match instance_key 4242:1
    assert not _accepted(_instance(sid, forged))

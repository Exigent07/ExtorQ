"""Relationship classification between an alert's evidence and other events (pure logic).

Bases (contracts.context.RelationshipBasis) are collected first, then mapped to a type:

DIRECT (verified shared identifier; strength strong, or moderate for a unit-name match)
    shared_request_id   propagated HTTP request id (nginx ``$request_id``)
    shared_pod_uid      same Kubernetes pod
    shared_audit_id     same kube-apiserver request (another audit stage)
    shared_commit_sha   same commit in the same repository
    shared_workflow_run same GitHub Actions run
    shared_resource     same resource on the same asset (file path, systemd unit,
                        Kubernetes object, workflow file)
CANDIDATE (plausible but inferred: same asset + context window + a shared
non-identifying attribute)
    shared_source_ip    same source IP that is NOT a shared NAT/gateway address
    shared_principal    same principal name (across assets: only authenticated names)
    simulation_run      same ExtorQ simulation marker (a lab scenario tag, attacker-
                        controllable text, never proof)
UNESTABLISHED (considered, shown for completeness, no supported link)
    shared_nat_source_ip  IP match only through a shared NAT/gateway/loopback address
    same_asset_time_window / same_service / same_service_instance alone

Service-aware bases describe topology and never upgrade a relationship by themselves:
``same_service``, ``same_service_instance``, ``cross_service_same_asset`` (another
service on the alert's asset) and ``cross_asset`` (another asset; considered only with
identity evidence or a shared identifier, and through NAT addresses it stays
UNESTABLISHED).

Correlation never asserts causation; explanations say what is shared, not why.
Explanations contain only fixed phrases, validated IP addresses and asset ids.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from extorq.contracts.context import Relationship, RelationshipBasis, RelationshipType
from extorq.correlation.records import EventRecord

B = RelationshipBasis

IDENTIFIER_BASES: tuple[RelationshipBasis, ...] = (
    B.SHARED_REQUEST_ID,
    B.SHARED_POD_UID,
    B.SHARED_AUDIT_ID,
    B.SHARED_COMMIT_SHA,
    B.SHARED_WORKFLOW_RUN,
    B.SHARED_RESOURCE,
)
ATTRIBUTE_BASES: tuple[RelationshipBasis, ...] = (
    B.SHARED_SOURCE_IP,
    B.SHARED_PRINCIPAL,
    B.SIMULATION_RUN,
)
#: Fixed output order of bases (deterministic, most specific first).
BASIS_ORDER: tuple[RelationshipBasis, ...] = (
    *IDENTIFIER_BASES,
    *ATTRIBUTE_BASES,
    B.SHARED_NAT_SOURCE_IP,
    B.SAME_SERVICE_INSTANCE,
    B.SAME_SERVICE,
    B.CROSS_SERVICE_SAME_ASSET,
    B.CROSS_ASSET,
    B.SAME_ASSET_TIME_WINDOW,
)
TYPE_RANK = {
    RelationshipType.DIRECT: 0,
    RelationshipType.CANDIDATE: 1,
    RelationshipType.UNESTABLISHED: 2,
}
STRENGTH_RANK = {"strong": 0, "moderate": 1, "weak": 2}

_PHRASES: dict[RelationshipBasis, str] = {
    B.SHARED_REQUEST_ID: "the propagated HTTP request id",
    B.SHARED_POD_UID: "the Kubernetes pod (pod uid)",
    B.SHARED_AUDIT_ID: "the kube-apiserver audit id (same API request)",
    B.SHARED_COMMIT_SHA: "the commit SHA",
    B.SHARED_WORKFLOW_RUN: "the GitHub Actions workflow run",
    B.SHARED_RESOURCE: "the resource (path, unit or object)",
}


@dataclass(frozen=True)
class EvidenceProfile:
    """Identifiers and attributes of an alert's evidence events."""

    asset_id: str
    anchor: datetime
    event_ids: frozenset[str]
    request_ids: frozenset[str]
    pod_uids: frozenset[str]
    audit_ids: frozenset[str]
    commit_shas: frozenset[tuple[str, str]]
    run_ids: frozenset[int]
    resource_keys: frozenset[tuple[str, ...]]
    source_ips: frozenset[str]
    principals: frozenset[str]
    authenticated_principals: frozenset[str]
    service_ids: frozenset[str]
    instance_ids: frozenset[str]
    simulation_run_ids: frozenset[str]
    nat_ips: frozenset[str]

    @property
    def non_nat_ips(self) -> frozenset[str]:
        return self.source_ips - self.nat_ips

    @classmethod
    def from_events(
        cls,
        asset_id: str,
        anchor: datetime,
        events: Iterable[EventRecord],
        *,
        nat_ips: Iterable[str],
        simulation_run_ids: Iterable[str] = (),
    ) -> EvidenceProfile:
        items = list(events)
        unit_keys = {k for e in items for k in e.resource_keys() if e.asset_id == asset_id}
        return cls(
            asset_id=asset_id,
            anchor=anchor,
            event_ids=frozenset(e.event_id for e in items),
            request_ids=frozenset(e.http_request_id for e in items if e.http_request_id),
            pod_uids=frozenset(e.k8s_pod_uid for e in items if e.k8s_pod_uid),
            audit_ids=frozenset(e.k8s_audit_id for e in items if e.k8s_audit_id),
            commit_shas=frozenset(
                (e.gh_repository or e.asset_id, e.gh_commit_sha) for e in items if e.gh_commit_sha
            ),
            run_ids=frozenset(
                e.gh_workflow_run_id for e in items if e.gh_workflow_run_id is not None
            ),
            resource_keys=frozenset(unit_keys),
            source_ips=frozenset(ip for e in items for ip in e.ips),
            principals=frozenset(p for e in items for p in e.principals()),
            authenticated_principals=frozenset(
                p for e in items for p in e.authenticated_principals()
            ),
            service_ids=frozenset(sid for e in items for sid in e.all_service_ids),
            instance_ids=frozenset(e.service_instance_id for e in items if e.service_instance_id),
            simulation_run_ids=frozenset(
                {*simulation_run_ids, *(e.simulation_run_id for e in items if e.simulation_run_id)}
            ),
            nat_ips=frozenset(nat_ips),
        )


def collect_bases(event: EventRecord, profile: EvidenceProfile) -> set[RelationshipBasis]:
    """Every basis that holds between ``event`` and the evidence profile."""
    bases: set[RelationshipBasis] = set()
    same_asset = event.asset_id == profile.asset_id
    if event.http_request_id and event.http_request_id in profile.request_ids:
        bases.add(B.SHARED_REQUEST_ID)
    if event.k8s_pod_uid and event.k8s_pod_uid in profile.pod_uids:
        bases.add(B.SHARED_POD_UID)
    if event.k8s_audit_id and event.k8s_audit_id in profile.audit_ids:
        bases.add(B.SHARED_AUDIT_ID)
    if event.gh_commit_sha and (event.gh_repository or event.asset_id, event.gh_commit_sha) in (
        profile.commit_shas
    ):
        bases.add(B.SHARED_COMMIT_SHA)
    if event.gh_workflow_run_id is not None and event.gh_workflow_run_id in profile.run_ids:
        bases.add(B.SHARED_WORKFLOW_RUN)
    if same_asset and event.resource_keys() & profile.resource_keys:
        bases.add(B.SHARED_RESOURCE)

    shared_ips = event.ips & profile.source_ips
    if shared_ips - profile.nat_ips:
        bases.add(B.SHARED_SOURCE_IP)
    if shared_ips & profile.nat_ips:
        bases.add(B.SHARED_NAT_SOURCE_IP)
    if same_asset:
        if event.principals() & profile.principals:
            bases.add(B.SHARED_PRINCIPAL)
    elif event.authenticated_principals() & profile.authenticated_principals:
        bases.add(B.SHARED_PRINCIPAL)
    if event.simulation_run_id and event.simulation_run_id in profile.simulation_run_ids:
        bases.add(B.SIMULATION_RUN)

    if event.service_instance_id and event.service_instance_id in profile.instance_ids:
        bases.add(B.SAME_SERVICE_INSTANCE)
    event_services = event.all_service_ids
    if event_services & profile.service_ids:
        bases.add(B.SAME_SERVICE)
    elif same_asset and event_services and profile.service_ids:
        bases.add(B.CROSS_SERVICE_SAME_ASSET)
    if same_asset:
        bases.add(B.SAME_ASSET_TIME_WINDOW)
    else:
        bases.add(B.CROSS_ASSET)
    return bases


Strength = Literal["strong", "moderate", "weak"]


def _type_and_strength(
    bases: set[RelationshipBasis], *, cross_asset: bool
) -> tuple[RelationshipType, Strength]:
    identifiers = [b for b in IDENTIFIER_BASES if b in bases]
    if identifiers:
        # A unit/resource match alone is an exact name on the same asset: strong when it
        # is a full path or object identity, which resource_keys guarantees.
        return RelationshipType.DIRECT, "strong"
    attributes = [b for b in ATTRIBUTE_BASES if b in bases]
    if not attributes:
        return RelationshipType.UNESTABLISHED, "weak"
    if cross_asset:
        identity = [b for b in attributes if b in (B.SHARED_SOURCE_IP, B.SHARED_PRINCIPAL)]
        if not identity:
            # e.g. only a simulation tag across assets: shown, but not an identity link.
            return RelationshipType.UNESTABLISHED, "weak"
        return RelationshipType.CANDIDATE, "moderate" if len(identity) >= 2 else "weak"
    if B.SHARED_SOURCE_IP in bases or len(attributes) >= 2:
        return RelationshipType.CANDIDATE, "moderate"
    return RelationshipType.CANDIDATE, "weak"


def _explain(
    event: EventRecord,
    profile: EvidenceProfile,
    bases: set[RelationshipBasis],
    rtype: RelationshipType,
) -> str:
    parts: list[str] = []
    identifiers = [b for b in IDENTIFIER_BASES if b in bases]
    if identifiers:
        shared = ", ".join(_PHRASES[b] for b in identifiers)
        parts.append(f"Shares {shared} with the alert evidence (verified identifier).")
    shared_ips = sorted(event.ips & profile.source_ips)
    non_nat = [ip for ip in shared_ips if ip not in profile.nat_ips]
    nat = [ip for ip in shared_ips if ip in profile.nat_ips]
    if non_nat:
        parts.append(f"Same source IP {', '.join(non_nat[:3])} (not a shared NAT address).")
    if nat:
        parts.append(
            f"Source IP {', '.join(nat[:3])} is a shared NAT/gateway address: the match does "
            "not establish a common origin."
        )
    if B.SHARED_PRINCIPAL in bases:
        parts.append(
            "Same authenticated principal name as the evidence (names are not globally unique)."
            if B.CROSS_ASSET in bases
            else "Same principal name as the evidence."
        )
    if B.SIMULATION_RUN in bases:
        parts.append("Carries the same ExtorQ simulation marker (lab scenario tag, not proof).")
    if B.SAME_SERVICE_INSTANCE in bases:
        parts.append("Same service instance as the evidence.")
    elif B.SAME_SERVICE in bases:
        parts.append("Same service as the evidence.")
    if B.CROSS_SERVICE_SAME_ASSET in bases:
        parts.append("Different service on the same asset.")
    if B.CROSS_ASSET in bases:
        parts.append(f"On another asset ({event.asset_id}).")
    if rtype is RelationshipType.UNESTABLISHED and not identifiers and not non_nat:
        parts.append("Only temporal proximity in the context window; no supported link.")
    elif rtype is RelationshipType.CANDIDATE:
        parts.append("Plausible but inferred; not a verified link.")
    return " ".join(parts)[:2048]


def classify(event: EventRecord, profile: EvidenceProfile) -> Relationship | None:
    """Relationship of ``event`` to the evidence, or ``None`` for evidence events."""
    if event.event_id in profile.event_ids:
        return None
    bases = collect_bases(event, profile)
    cross_asset = B.CROSS_ASSET in bases
    if cross_asset and not (bases & {*IDENTIFIER_BASES, *ATTRIBUTE_BASES, B.SHARED_NAT_SOURCE_IP}):
        return None  # other assets are only considered with an identity link
    rtype, strength = _type_and_strength(bases, cross_asset=cross_asset)
    ordered = [b for b in BASIS_ORDER if b in bases][:8]
    delta = round((event.event_time - profile.anchor).total_seconds(), 3)
    return Relationship(
        event_id=event.event_id,
        relationship_type=rtype,
        bases=ordered,
        strength=strength,
        time_delta_seconds=delta,
        explanation=_explain(event, profile, bases, rtype),
    )


def rank_key(rel: Relationship) -> tuple[int, int, float, str]:
    """Most informative first: type, strength, closeness to the alert, id (deterministic)."""
    return (
        TYPE_RANK[rel.relationship_type],
        STRENGTH_RANK.get(rel.strength, 3),
        abs(rel.time_delta_seconds),
        rel.event_id,
    )

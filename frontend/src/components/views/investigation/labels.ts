/**
 * Console wording for the correlation layer's tokens (contracts/context.py). Console text
 * only: safe for hints. Unknown tokens are shown as reported (humanised), never mapped onto
 * a known meaning.
 */
import { humanize } from "@/lib/format";

export const RELATIONSHIP_LABEL: Record<string, { label: string; detail: string }> = {
  evidence: { label: "Evidence", detail: "Cited by the detection rule as evidence for this alert." },
  direct: {
    label: "Direct",
    detail: "A verified shared identifier links this event to the alert (request id, Pod UID, audit id, commit, workflow run).",
  },
  candidate: {
    label: "Candidate",
    detail:
      "Plausible but inferred: same asset and time window plus a shared non-identifying attribute (such as a principal name or source IP).",
  },
  unestablished: {
    label: "Unestablished",
    detail: "Considered and shown for completeness; no supported link exists (for example an IP shared through NAT).",
  },
};

export function relationshipLabel(type: string): string {
  return RELATIONSHIP_LABEL[type]?.label ?? humanize(type);
}

export function relationshipDetail(type: string): string {
  return RELATIONSHIP_LABEL[type]?.detail ?? "Relationship type reported by the correlation layer.";
}

const BASIS_LABEL: Record<string, string> = {
  evidence: "cited as evidence",
  shared_request_id: "shared HTTP request id",
  shared_pod_uid: "shared Pod UID",
  shared_audit_id: "shared audit id",
  shared_commit_sha: "shared commit",
  shared_workflow_run: "shared workflow run",
  shared_resource: "same resource",
  shared_principal: "same principal",
  shared_source_ip: "same source IP",
  shared_nat_source_ip: "source IP shared through NAT",
  same_asset_time_window: "same asset and window",
  same_service: "same service",
  same_service_instance: "same service instance",
  cross_service_same_asset: "other service, same asset",
  cross_asset: "another asset",
  simulation_run: "same simulation run",
};

export function basisLabel(basis: string): string {
  return BASIS_LABEL[basis] ?? humanize(basis);
}

/** Bases that carry identity evidence (shown first; the rest only narrows the window). */
const IDENTIFYING = new Set([
  "shared_request_id",
  "shared_pod_uid",
  "shared_audit_id",
  "shared_commit_sha",
  "shared_workflow_run",
  "shared_resource",
  "shared_principal",
  "simulation_run",
  "shared_source_ip",
]);

/** Bases ordered by how much they say: identifiers first, then context, NAT last. */
export function orderedBases(bases: readonly string[]): string[] {
  const rank = (b: string) => (IDENTIFYING.has(b) ? 0 : b === "shared_nat_source_ip" ? 2 : 1);
  return [...bases].sort((a, b) => rank(a) - rank(b));
}

export const STRENGTH_LABEL: Record<string, string> = {
  strong: "Strong",
  moderate: "Moderate",
  weak: "Weak",
};

export function strengthLabel(strength: string): string {
  return STRENGTH_LABEL[strength] ?? humanize(strength);
}

export const ROLE_LABEL: Record<string, string> = {
  trigger: "Trigger",
  supporting: "Supporting",
  context: "Context",
};

export function evidenceRoleLabel(role: string | null | undefined): string | null {
  if (!role) return null;
  return ROLE_LABEL[role] ?? humanize(role);
}

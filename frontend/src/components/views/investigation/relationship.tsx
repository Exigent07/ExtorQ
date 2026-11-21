import { cn } from "cn";

import { humanize } from "@/lib/format";

/**
 * Relationship of an observation to the alert (contracts/context.py). The type is told by
 * its word and its outline (solid / dashed / dotted), not by colour alone. Correlation never
 * asserts causation, and the explanations say so.
 */
export const RELATIONSHIP: Record<string, { label: string; detail: string; className: string }> = {
  direct: {
    label: "Direct",
    detail: "A verified shared identifier links this event to the alert (request id, Pod UID, audit id, commit, workflow run).",
    className: "border-solid border-ink-2 text-ink",
  },
  candidate: {
    label: "Candidate",
    detail:
      "Plausible but inferred: same asset and time window plus a shared non-identifying attribute (such as a source IP or principal name).",
    className: "border-dashed border-control text-ink-2",
  },
  unestablished: {
    label: "Unestablished",
    detail: "Considered and shown for completeness, but no supported link exists (for example an IP shared through NAT).",
    className: "border-dotted border-control text-muted-foreground",
  },
};

export function RelationshipBadge({ type }: { type: string | null | undefined }) {
  if (!type) return null;
  const rel = RELATIONSHIP[type];
  return (
    <span
      title={rel?.detail ?? "Relationship type reported by the correlation layer."}
      className={cn(
        "inline-flex h-5 flex-none items-center rounded-sm border px-1.5 text-xs whitespace-nowrap",
        rel?.className ?? "border-control text-muted-foreground",
      )}
    >
      {rel?.label ?? humanize(type)}
    </span>
  );
}

/** The evidence mark: events the detector cited (not a correlation). */
export function EvidenceMark() {
  return (
    <span
      title="Cited by the detection rule as evidence for this alert."
      className="inline-flex h-5 flex-none items-center rounded-sm bg-raised px-1.5 text-xs font-medium whitespace-nowrap text-ink"
    >
      Evidence
    </span>
  );
}

const BASIS_LABEL: Record<string, string> = {
  evidence: "cited as evidence",
  shared_request_id: "shared HTTP request id",
  shared_pod_uid: "shared Pod UID",
  shared_audit_id: "shared Kubernetes audit id",
  shared_commit_sha: "shared commit",
  shared_workflow_run: "shared workflow run",
  shared_resource: "same resource",
  shared_principal: "same principal name",
  shared_source_ip: "same source IP",
  shared_nat_source_ip: "same source IP behind NAT (not identifying)",
  same_asset_time_window: "same asset and time window",
  same_service: "same service",
  same_service_instance: "same service instance",
  cross_service_same_asset: "another service on the same asset",
  cross_asset: "another asset (identity evidence required)",
  simulation_run: "same simulation run",
};

export function basisLabel(basis: string): string {
  return BASIS_LABEL[basis] ?? humanize(basis);
}

export const STRENGTH_LABEL: Record<string, string> = {
  strong: "strong link",
  moderate: "moderate link",
  weak: "weak link",
};

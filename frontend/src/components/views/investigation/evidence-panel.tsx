import { FileSearch } from "lucide-react";

import { SectionCard } from "@/components/console/section-card";
import { EmptyState, Notice } from "@/components/console/states";
import type { AlertDetailResponse } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

import { EvidenceTable } from "./evidence-table";

/**
 * Evidence tab: the stored events the detector cited (resolved by the API, capped there),
 * as a data table with a detail sheet per row. Unresolved ids are counted, never hidden.
 */
export function EvidencePanel({ detail }: { detail: AlertDetailResponse }) {
  const shown = detail.evidence.length;
  return (
    <SectionCard
      title="Supporting evidence"
      titleId="evidence-title"
      icon={FileSearch}
      description="Stored events the detector cited, oldest first. Select a row for every field and the raw excerpt."
      meta={
        <span className="tabular-nums">
          {formatCount(shown)} of {formatCount(detail.evidence_total)} shown{detail.evidence_capped ? " (capped by the API)" : ""}
        </span>
      }
      flush
    >
      {shown === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No evidence event could be resolved from storage for this alert.</EmptyState>
        </div>
      ) : (
        <EvidenceTable evidence={detail.evidence} />
      )}
      {detail.unresolved_evidence_ids.length > 0 || detail.alert.evidence_truncated ? (
        <div className="grid gap-2 px-5 pt-3 pb-1">
          {detail.unresolved_evidence_ids.length > 0 ? (
            <Notice tone="warn">
              {formatCount(detail.unresolved_evidence_ids.length)} cited evidence id
              {detail.unresolved_evidence_ids.length === 1 ? " was" : "s were"} not found in storage (retention or not yet written).
            </Notice>
          ) : null}
          {detail.alert.evidence_truncated ? (
            <Notice>The detector truncated this alert&apos;s evidence list; the event count in the header is the full count.</Notice>
          ) : null}
        </div>
      ) : null}
    </SectionCard>
  );
}

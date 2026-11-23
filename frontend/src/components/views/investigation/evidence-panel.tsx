import { FileSearch } from "lucide-react";

import { SectionCard } from "@/components/console/section-card";
import { EmptyState, Notice } from "@/components/console/states";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AlertDetailResponse } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { unresolvedEvidenceByRetention } from "@/lib/investigation";

import { EvidenceTable } from "./evidence-table";

/**
 * Evidence tab: the stored events the detector cited (resolved by the API, capped there),
 * as a data table with a detail sheet per row. Unresolved ids are counted, never hidden.
 */
export function EvidencePanel({ detail }: { detail: AlertDetailResponse }) {
  const shown = detail.evidence.length;
  const { expired, unavailable } = unresolvedEvidenceByRetention(detail.unresolved_evidence_ids, detail.expired_evidence_ids);
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
          <EmptyState>No cited events are available in storage for this alert.</EmptyState>
        </div>
      ) : (
        <EvidenceTable evidence={detail.evidence} />
      )}
      {expired.length > 0 || unavailable.length > 0 || detail.alert.evidence_truncated ? (
        <div className="grid gap-2 px-5 pt-3 pb-1">
          <MissingReferences ids={expired} status="Outside event retention" />
          <MissingReferences ids={unavailable} status="Unavailable in storage" />
          {detail.alert.evidence_truncated ? (
            <Notice>The detector truncated this alert&apos;s evidence list; the event count in the header is the full count.</Notice>
          ) : null}
        </div>
      ) : null}
    </SectionCard>
  );
}

function MissingReferences({ ids, status }: { ids: string[]; status: string }) {
  if (ids.length === 0) return null;
  return (
    <details className="rounded-lg bg-health-warn/[0.06] px-3 py-2 text-xs leading-relaxed text-fg-2 ring-1 ring-health-warn/20 ring-inset">
      <summary className="cursor-pointer">
        {status} · {formatCount(ids.length)} evidence reference{ids.length === 1 ? "" : "s"}
      </summary>
      <ul className="mt-2 max-h-40 space-y-1 overflow-y-auto break-all" aria-label={status}>
        {ids.map((id) => (
          <li key={id}><UntrustedText value={id} plain mono /></li>
        ))}
      </ul>
    </details>
  );
}

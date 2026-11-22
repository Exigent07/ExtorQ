import { Waypoints } from "lucide-react";

import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import type { ApiFailure } from "@/lib/api/result";
import type { InvestigationContext } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

import { CorrelationView } from "./correlation-table";
import { relatedRows, relationshipGroups } from "./model";

/**
 * Correlation tab: what the correlation layer relates to the alert, grouped by relationship
 * type with counts and link strength, then every observation with its basis and the layer's
 * explanation. Co-occurrence and shared attributes, never causation.
 */
export function CorrelationPanel({
  context,
  contextError,
}: {
  context: InvestigationContext | null;
  contextError: ApiFailure | null;
}) {
  if (!context) {
    return (
      <SectionCard title="Correlated observations" titleId="correlations-title" icon={Waypoints}>
        <ErrorState what="the investigation context" error={contextError ?? { kind: "server", message: "No context was returned.", requestId: "-" }} />
      </SectionCard>
    );
  }
  const rows = relatedRows(context);
  const groups = relationshipGroups(rows);
  return (
    <SectionCard
      title="Correlated observations"
      titleId="correlations-title"
      icon={Waypoints}
      description="How the correlation layer relates other events to this alert. Temporal proximity alone is never treated as causation."
      meta={<span className="tabular-nums">{formatCount(rows.length)} related</span>}
      flush
    >
      {context.truncated.related ? (
        <div className="px-5 pb-4">
          <Notice>The context builder capped the related observations; the list below is what the stored context holds.</Notice>
        </div>
      ) : null}
      {rows.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>The correlation layer found no related observation for this alert.</EmptyState>
        </div>
      ) : (
        <CorrelationView rows={rows} groups={groups} />
      )}
    </SectionCard>
  );
}

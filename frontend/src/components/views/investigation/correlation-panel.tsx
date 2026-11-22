import { TriangleAlert, Waypoints } from "lucide-react";

import { SplitBar } from "@/components/console/kpi-card";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import type { ApiFailure } from "@/lib/api/result";
import type { InvestigationContext } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

import { CorrelationTable } from "./correlation-table";
import { relationshipDetail, relationshipLabel } from "./labels";
import { natSharedCount, type RelationshipGroup, relatedRows, relationshipGroups } from "./model";
import { RelationshipMarker } from "./relationship";

const STRENGTH_PARTS = [
  { key: "strong", label: "strong", className: "bg-foreground/80" },
  { key: "moderate", label: "moderate", className: "bg-fg-2/60" },
  { key: "weak", label: "weak", className: "bg-fg-faint" },
] as const;

function GroupTile({ group, total }: { group: RelationshipGroup; total: number }) {
  const parts = STRENGTH_PARTS.map((p) => ({ key: p.key, value: group[p.key], className: p.className }));
  const words = STRENGTH_PARTS.filter((p) => group[p.key] > 0).map((p) => `${formatCount(group[p.key])} ${p.label}`);
  return (
    <div className="flex min-w-0 flex-col gap-3 rounded-lg bg-white/[0.02] p-4 ring-1 ring-hairline ring-inset">
      <div className="flex items-start justify-between gap-3">
        <span className="inline-flex items-center gap-2 text-sm font-medium text-foreground">
          <RelationshipMarker type={group.type} />
          {relationshipLabel(group.type)}
        </span>
        <span className="text-3xl leading-none font-semibold tracking-tight text-foreground tabular-nums">
          {formatCount(group.count)}
        </span>
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">{relationshipDetail(group.type)}</p>
      <div className="mt-auto grid gap-1.5">
        <SplitBar
          parts={parts}
          label={group.count === 0 ? `No ${relationshipLabel(group.type).toLowerCase()} links` : `Link strength: ${words.join(", ")}`}
        />
        <span className="text-xs text-muted-foreground tabular-nums">
          {group.count === 0 ? "None in this context" : `${words.join(" · ")} · of ${formatCount(total)} related`}
        </span>
      </div>
    </div>
  );
}

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
  const nat = natSharedCount(rows);
  return (
    <SectionCard
      title="Correlated observations"
      titleId="correlations-title"
      icon={Waypoints}
      description="How the correlation layer relates other events to this alert. Temporal proximity alone is never treated as causation."
      meta={<span className="tabular-nums">{formatCount(rows.length)} related</span>}
      flush
    >
      <div className="grid gap-4 px-5 pb-4">
        <div className="grid gap-3 sm:grid-cols-3">
          {groups.map((group) => (
            <GroupTile key={group.type} group={group} total={rows.length} />
          ))}
        </div>
        {nat > 0 ? (
          <Notice tone="warn" icon={TriangleAlert}>
            {formatCount(nat)} of these share the evidence&apos;s source IP through NAT or a gateway. That address does not identify one
            origin, so it never establishes a link on its own: any direct or candidate link here rests on another basis.
          </Notice>
        ) : null}
        {context.truncated.related ? (
          <Notice>The context builder capped the related observations; the list below is what the stored context holds.</Notice>
        ) : null}
      </div>
      {rows.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>The correlation layer found no related observation for this alert.</EmptyState>
        </div>
      ) : (
        <CorrelationTable rows={rows} />
      )}
    </SectionCard>
  );
}

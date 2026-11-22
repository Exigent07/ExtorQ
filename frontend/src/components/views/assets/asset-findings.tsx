import { FileWarning, Info } from "lucide-react";
import Link from "next/link";

import { SplitBar } from "@/components/console/kpi-card";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ApiResult } from "@/lib/api/result";
import type { FindingListResponse, FindingsSummary } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

import { FindingsDataTable } from "./findings-data-table";
import { partsInWords, severityParts } from "./model";

/** Says when finding states cannot be derived (no lifecycle view): counts are observations. */
export function LifecycleUnavailable({ note }: { note?: string | null }) {
  return (
    <Notice tone="warn" icon={Info}>
      Finding lifecycle is unavailable: counts are distinct findings observed within retention, not their open or
      resolved state.
      {note ? <span className="mt-1 block text-muted-foreground">{note}</span> : null}
    </Notice>
  );
}

/** Open findings by severity across the whole asset (API summary, not just the loaded rows). */
function SeveritySummary({ summary }: { summary: FindingsSummary }) {
  const parts = severityParts(summary.counts);
  const unverified = summary.unverified?.total ?? 0;
  return (
    <div className="grid gap-2 px-5">
      <SplitBar className="h-2" parts={parts} label={`Open findings by severity: ${partsInWords(parts) || "none"}`} />
      <p className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {parts.map((p) => (
          <span key={p.key} className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span aria-hidden="true" className={`size-1.5 rounded-full ${p.className}`} />
            <span className={p.value > 0 ? "text-fg-2 tabular-nums" : "tabular-nums"}>{formatCount(p.value)}</span>
            <span className="capitalize">{p.label}</span>
          </span>
        ))}
        {unverified > 0 ? (
          <span className="whitespace-nowrap">
            <span className="text-fg-2 tabular-nums">{formatCount(unverified)}</span> unverified
          </span>
        ) : null}
      </p>
    </div>
  );
}

/**
 * The Findings tab of an asset: the asset-wide severity summary, then the findings the API
 * returned (open first, most severe first, at most `limit`) as a data table with facets and a
 * details sheet per row. A capped list says so; filters apply to the loaded rows only.
 */
export function AssetFindingsTab({
  result,
  summary,
  limit,
  now,
  clusterFindingsHref,
}: {
  result: ApiResult<FindingListResponse>;
  summary: FindingsSummary;
  limit: number;
  now: string;
  /** For a Kubernetes node: the cluster's findings tab (its scans report under the cluster). */
  clusterFindingsHref?: string | null;
}) {
  const total = summary.counts.total + (summary.unverified?.total ?? 0);
  return (
    <SectionCard
      title="Vulnerabilities and misconfigurations"
      titleId="findings-title"
      icon={FileWarning}
      description={
        summary.lifecycle_available ? (
          <>
            <span className="text-fg-2 tabular-nums">{formatCount(summary.counts.total)}</span> open
            {summary.unverified && summary.unverified.total > 0 ? (
              <>
                {" · "}
                <span className="text-fg-2 tabular-nums">{formatCount(summary.unverified.total)}</span> unverified
              </>
            ) : null}{" "}
            · resolved findings are listed after them
          </>
        ) : (
          "Distinct findings observed within retention"
        )
      }
      meta={
        result.ok && result.data.items.length > 0 ? (
          <span>
            <UntrustedText value={[...new Set(result.data.items.map((f) => f.scanner))].sort().join(" · ")} limit={120} plain />
          </span>
        ) : null
      }
      flush
    >
      {!result.ok ? (
        <div className="px-5 pb-3">
          <ErrorState what="the findings of this asset" error={result.error} />
        </div>
      ) : (
        <div className="grid gap-4">
          <SeveritySummary summary={summary} />
          {!result.data.lifecycle_available || result.data.page.has_more ? (
            <div className="grid gap-2 px-5">
              {!result.data.lifecycle_available ? <LifecycleUnavailable note={result.data.note} /> : null}
              {result.data.page.has_more ? (
                <Notice icon={Info}>
                  Showing the first {formatCount(result.data.items.length)} findings in the API&apos;s order (open first, most
                  severe first)
                  {total > result.data.items.length ? ` of ${formatCount(total)} open or unverified` : ""}. Filters and
                  search apply to these {formatCount(Math.min(limit, result.data.items.length))} rows.
                </Notice>
              ) : null}
            </div>
          ) : null}
          {result.data.items.length === 0 ? (
            <div className="px-5 pb-3">
              {clusterFindingsHref ? (
                <EmptyState>
                  No finding carries this node&apos;s own id: the cluster&apos;s configuration and image scans store their
                  findings under the cluster.{" "}
                  <Link href={clusterFindingsHref} className="whitespace-nowrap text-fg-2 underline decoration-fg-faint underline-offset-4 transition-colors duration-150 hover:text-foreground hover:decoration-foreground">
                    Open the cluster&apos;s findings →
                  </Link>
                </EmptyState>
              ) : (
                <EmptyState>
                  No finding is stored for this asset. Findings appear after a scanner run covers it; an asset that was never
                  scanned also shows none.
                </EmptyState>
              )}
            </div>
          ) : (
            <FindingsDataTable findings={result.data.items} now={now} label="Findings of this asset" />
          )}
        </div>
      )}
    </SectionCard>
  );
}

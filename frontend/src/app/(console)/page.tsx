import type { Metadata } from "next";
import Link from "next/link";

import { Freshness } from "@/components/console/freshness";
import { PageHeader } from "@/components/console/page-header";
import { Panel } from "@/components/console/panel";
import { EmptyState, ErrorState } from "@/components/console/states";
import { AlertRows } from "@/components/views/alerts/alert-rows";
import { CollectionHealthPanel } from "@/components/views/overview/collection-health";
import { CoverageLanes } from "@/components/views/overview/coverage-lanes";
import { PosturePanel } from "@/components/views/overview/posture-panel";
import { SeverityLanes } from "@/components/views/overview/severity-lanes";
import type { OverviewResponse } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount, formatDuration } from "@/lib/format";
import { buildSeverityLanes } from "@/lib/series";
import { getOverview } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "Overview" };

/** One line, computed from the data: what most needs attention right now. */
function finding(data: OverviewResponse): string {
  const parts: string[] = [];
  const open = data.open_alerts;
  const serious = open.critical + open.high;
  if (open.total === 0) parts.push("No open alerts");
  else
    parts.push(
      `${formatCount(open.total)} open alert${open.total === 1 ? "" : "s"}` +
        (serious > 0 ? `, ${formatCount(serious)} high or critical` : ""),
    );
  const unhealthy = data.asset_coverage.filter((c) => c.expected && c.status !== "ok");
  if (unhealthy.length === 0 && data.asset_coverage.length > 0) parts.push("all monitored classes reporting");
  else
    for (const c of unhealthy.slice(0, 2)) {
      parts.push(`${assetTypeLabel(c.asset_type)} coverage ${c.status}`);
    }
  if (unhealthy.length > 2) parts.push(`${unhealthy.length - 2} more classes degraded`);
  return parts.join(" · ");
}

export default async function OverviewPage() {
  const session = await requireSession();
  const result = await getOverview(session);

  if (!result.ok) {
    return (
      <>
        <PageHeader title="Overview" />
        <ErrorState what="the overview" error={result.error} />
      </>
    );
  }

  const data = result.data;
  const now = data.generated_at;
  const lanes = buildSeverityLanes(data.alerts_over_time);
  const rangeSeconds =
    (Date.parse(data.alerts_over_time.range.until) - Date.parse(data.alerts_over_time.range.since)) / 1000;
  const rangeLabel = formatDuration(rangeSeconds).replace(/ 0+ (s|m|h)$/, "");
  const totalInRange = lanes.lanes.reduce((sum, lane) => sum + lane.total, 0);

  return (
    <>
      <PageHeader title="Overview" finding={finding(data)} actions={<Freshness at={result.receivedAt} />} />
      <div className="grid gap-6">
        <CoverageLanes coverage={data.asset_coverage} now={now} />

        <div className="grid gap-6 xl:grid-cols-3">
          <Panel
            titleId="alerts-time-title"
            title="Detection alerts over time"
            className="xl:col-span-2"
            meta={
              <span>
                {formatCount(totalInRange)} created in the last {rangeLabel}
                {data.alerts_over_time.truncated ? " (series truncated)" : ""}
              </span>
            }
            action={
              <Link href="/detections" className="hover:text-ink">
                Alert history
              </Link>
            }
          >
            <SeverityLanes data={lanes} rangeLabel={rangeLabel} />
          </Panel>
          <PosturePanel summary={data.open_findings} />
        </div>

        <div className="grid gap-6 xl:grid-cols-3">
          <Panel
            titleId="recent-alerts-title"
            title="Recent important alerts"
            className="xl:col-span-2"
            meta={<span>{formatCount(data.open_alerts.total)} open</span>}
            action={
              <Link href="/detections" className="hover:text-ink">
                View all
              </Link>
            }
          >
            {data.recent_important_alerts.length === 0 ? (
              <EmptyState>No important alerts. Detections that fire appear here first.</EmptyState>
            ) : (
              <AlertRows alerts={data.recent_important_alerts.slice(0, 6)} now={now} />
            )}
          </Panel>
          <CollectionHealthPanel summary={data.collection_health} />
        </div>
      </div>
    </>
  );
}

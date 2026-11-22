import { Info, ScrollText } from "lucide-react";
import Link from "next/link";

import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import type { ApiResult } from "@/lib/api/result";
import type { EventListResponse } from "@/lib/api/schemas";
import { formatCount, formatUtcShort } from "@/lib/format";

import { EventsDataTable } from "./events-data-table";
import { windowLabel } from "./model";
import { type RangeOption, RangeToggle } from "./range-toggle";

/**
 * The Events tab of an asset: the newest stored events of the chosen window (24 h, 7 d or
 * 30 d; the toggle reloads the page for that window) as a data table with facets and a details
 * sheet per event (raw excerpt read on demand). The window and any cap are stated; a node's
 * empty list points to the cluster, under which Kubernetes events are stored.
 */
export function AssetEventsTab({
  result,
  now,
  limit,
  range,
  ranges,
  clusterEventsHref,
}: {
  result: ApiResult<EventListResponse>;
  now: string;
  /** Rows requested from the API (the newest first). */
  limit: number;
  /** Key of the selected window. */
  range: string;
  ranges: RangeOption[];
  /** For a Kubernetes node: the cluster's events tab (its events carry the cluster's id). */
  clusterEventsHref?: string | null;
}) {
  const data = result.ok ? result.data : null;
  const capped = data ? data.page.has_more || (data.page.total !== null && data.page.total !== undefined && data.page.total > data.items.length) : false;
  return (
    <SectionCard
      title="Recent events"
      titleId="events-title"
      icon={ScrollText}
      description={
        data && data.items.length === 0 ? (
          <>
            No stored event, {windowLabel(data.range, now)} (since {formatUtcShort(data.range.since)} UTC)
          </>
        ) : data ? (
          <>
            Newest <span className="text-fg-2 tabular-nums">{formatCount(data.items.length)}</span>
            {data.page.total !== null && data.page.total !== undefined && data.page.total > data.items.length
              ? ` of ${formatCount(data.page.total)}`
              : ""}{" "}
            stored events, {windowLabel(data.range, now)} (since {formatUtcShort(data.range.since)} UTC)
          </>
        ) : (
          "Stored events of this asset"
        )
      }
      action={<RangeToggle options={ranges} value={range} label="Event window" />}
      flush
    >
      {!result.ok ? (
        <div className="px-5 pb-3">
          <ErrorState what="the events of this asset" error={result.error} />
        </div>
      ) : result.data.items.length === 0 ? (
        <div className="px-5 pb-3">
          {clusterEventsHref ? (
            <EmptyState>
              No event carries this node&apos;s own id in this window: the cluster&apos;s audit, container-log and inventory
              events are stored under the cluster.{" "}
              <Link href={clusterEventsHref} className="whitespace-nowrap text-fg-2 underline decoration-fg-faint underline-offset-4 transition-colors duration-150 hover:text-foreground hover:decoration-foreground">
                Open the cluster&apos;s events →
              </Link>
            </EmptyState>
          ) : (
            <EmptyState>No event from this asset was stored in this window.</EmptyState>
          )}
        </div>
      ) : (
        <div className="grid gap-3">
          {capped ? (
            <div className="px-5">
              <Notice icon={Info}>
                More events were stored in this window than one request returns: these are the newest{" "}
                {formatCount(Math.min(limit, result.data.items.length))}, and filters and search apply to them only.
              </Notice>
            </div>
          ) : null}
          <EventsDataTable events={result.data.items} label="Recent events of this asset" />
        </div>
      )}
    </SectionCard>
  );
}

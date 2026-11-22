import { ScrollText } from "lucide-react";

import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState } from "@/components/console/states";
import type { ApiResult } from "@/lib/api/result";
import type { EventListResponse } from "@/lib/api/schemas";
import { formatCount, formatUtcShort } from "@/lib/format";

import { EventsDataTable } from "./events-data-table";
import { windowLabel } from "./model";

/**
 * The Events tab of an asset: the newest stored events of the API window as a data table with
 * a details sheet per event (raw excerpt read on demand). The window and any cap are stated.
 */
export function AssetEventsTab({ result, now }: { result: ApiResult<EventListResponse>; now: string }) {
  return (
    <SectionCard
      title="Recent events"
      titleId="events-title"
      icon={ScrollText}
      description={
        result.ok ? (
          <>
            Newest <span className="text-fg-2 tabular-nums">{formatCount(result.data.items.length)}</span>
            {result.data.page.total !== null && result.data.page.total !== undefined && result.data.page.total > result.data.items.length
              ? ` of ${formatCount(result.data.page.total)}`
              : ""}{" "}
            stored events, {windowLabel(result.data.range, now)} (since {formatUtcShort(result.data.range.since)} UTC)
          </>
        ) : (
          "Stored events of this asset"
        )
      }
      flush
    >
      {!result.ok ? (
        <div className="px-5 pb-3">
          <ErrorState what="the events of this asset" error={result.error} />
        </div>
      ) : result.data.items.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No event from this asset was stored in this window.</EmptyState>
        </div>
      ) : (
        <EventsDataTable events={result.data.items} label="Recent events of this asset" />
      )}
    </SectionCard>
  );
}

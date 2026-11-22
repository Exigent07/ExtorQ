"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "cn";
import { TriangleAlert } from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";

import { DataTable, type FacetOption } from "@/components/console/data-table";
import { Hint } from "@/components/console/hint";
import { HealthBadge, LifecycleBadge, StaleBadge, type Tone } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { Progress } from "@/components/ui/progress";
import { RelativeTime } from "@/components/console/time";
import type { CollectorStatus } from "@/lib/api/schemas";
import { DASH, formatCount, formatDuration, formatInterval, formatVersion } from "@/lib/format";
import { assetHref, isAssetId } from "@/lib/security/ids";

import { collectorFreshness, STALE_INTERVALS } from "./model";

type HealthKey = "failed" | "stale" | "degraded" | "other" | "healthy";

const HEALTH_RANK: Record<HealthKey, number> = { failed: 4, stale: 3, degraded: 2, other: 1, healthy: 0 };
const HEALTH_LABEL: Record<HealthKey, string> = {
  failed: "Failed",
  stale: "Stale",
  degraded: "Degraded",
  other: "Disabled or unknown",
  healthy: "Healthy",
};
const HEALTH_DOT: Record<HealthKey, string> = {
  failed: "bg-health-bad",
  stale: "bg-health-warn",
  degraded: "bg-health-warn",
  other: "bg-health-off",
  healthy: "bg-health-ok",
};

/** The same partition as the KPI (each collector in exactly one group). */
function healthKey(c: CollectorStatus): HealthKey {
  if (c.status === "failed") return "failed";
  if (c.stale) return "stale";
  if (c.status === "ok") return "healthy";
  if (c.status === "degraded") return "degraded";
  return "other";
}

const BAR: Record<Tone, string> = {
  ok: "[&_[data-slot=progress-indicator]]:bg-health-ok",
  warn: "[&_[data-slot=progress-indicator]]:bg-health-warn",
  bad: "[&_[data-slot=progress-indicator]]:bg-health-bad",
  off: "[&_[data-slot=progress-indicator]]:bg-health-off",
};

function LastError({ error, tone }: { error: string; tone: Tone }) {
  return (
    <HoverCard openDelay={200} closeDelay={80}>
      <HoverCardTrigger asChild>
        <button
          type="button"
          className={cn(
            "inline-flex h-5 w-fit items-center gap-1 rounded-md px-1.5 text-xs ring-1 ring-inset transition-colors duration-150 hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:outline-none",
            tone === "bad" ? "text-health-bad ring-health-bad/25" : "text-fg-2 ring-hairline-strong",
          )}
        >
          <TriangleAlert className={cn("size-3", tone === "bad" ? "" : "text-health-warn")} aria-hidden="true" />
          Last error
        </button>
      </HoverCardTrigger>
      <HoverCardContent align="start" className="w-[min(32rem,calc(100vw-2rem))] p-0">
        <div className="border-b border-hairline px-3 py-2 text-xs text-muted-foreground">
          Last error reported by the collector · shown as text
        </div>
        <div className="max-h-72 overflow-y-auto px-3 py-2.5 font-mono text-xs leading-relaxed text-fg-2">
          <UntrustedText value={error} multiline limit={4000} />
        </div>
      </HoverCardContent>
    </HoverCard>
  );
}

function Sources({ sources }: { sources: string[] }) {
  if (sources.length === 0) return <span className="text-muted-foreground">{DASH}</span>;
  const [first, ...rest] = sources;
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span className="inline-flex h-5 min-w-0 items-center rounded-md px-1.5 font-mono text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset">
        <UntrustedText value={first ?? ""} oneLine plain limit={48} />
      </span>
      {rest.length > 0 ? (
        <HoverCard openDelay={200} closeDelay={80}>
          <HoverCardTrigger asChild>
            <button
              type="button"
              aria-label={`${formatCount(sources.length)} source types`}
              className="inline-flex h-5 flex-none items-center rounded-md px-1.5 text-xs text-muted-foreground ring-1 ring-hairline ring-inset transition-colors duration-150 hover:bg-hover hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:outline-none"
            >
              +{formatCount(rest.length)}
            </button>
          </HoverCardTrigger>
          <HoverCardContent align="start" className="w-72 p-0">
            <div className="border-b border-hairline px-3 py-2 text-xs text-muted-foreground">
              {formatCount(sources.length)} source types
            </div>
            <ul className="grid gap-1 px-3 py-2.5">
              {sources.map((source) => (
                <li key={source} className="font-mono text-xs text-fg-2">
                  <UntrustedText value={source} limit={80} />
                </li>
              ))}
            </ul>
          </HoverCardContent>
        </HoverCard>
      ) : null}
    </span>
  );
}

function columns(now: string): ColumnDef<CollectorStatus, unknown>[] {
  return [
    {
      id: "health",
      accessorFn: (c) => healthKey(c),
      header: "Status",
      sortingFn: (a, b) => HEALTH_RANK[healthKey(a.original)] - HEALTH_RANK[healthKey(b.original)],
      sortDescFirst: true,
      meta: { className: "hidden w-[132px] @md:table-cell", label: "Status" },
      cell: ({ row }) => {
        const c = row.original;
        const fresh = collectorFreshness(c, now);
        return (
          <div className="grid justify-items-start gap-1.5">
            <span className="flex items-center gap-2">
              <HealthBadge status={c.status} className="text-sm" />
              {c.stale ? <StaleBadge reason={c.stale_reason} /> : null}
            </span>
            {c.last_error ? <LastError error={c.last_error} tone={fresh.tone === "bad" ? "bad" : "warn"} /> : null}
          </div>
        );
      },
    },
    {
      id: "collector",
      accessorFn: (c) => c.collector_id,
      header: "Collector",
      enableHiding: false,
      meta: { className: "min-w-[160px] @max-md:pl-(--table-edge)" },
      cell: ({ row }) => {
        const c = row.original;
        return (
          <div className="grid min-w-0 gap-1">
            <span className="flex items-center gap-2 @md:hidden">
              <HealthBadge status={c.status} className="text-xs" />
              {c.stale ? <StaleBadge reason={c.stale_reason} /> : null}
            </span>
            <span className="flex min-w-0 items-center gap-2">
              <span className="min-w-0 font-mono text-sm text-foreground">
                <UntrustedText value={c.collector_id} oneLine />
              </span>
              {/* Stale is already the status column's word; only retirement is added here. */}
              {c.lifecycle_state === "retired" ? <LifecycleBadge state={c.lifecycle_state} /> : null}
            </span>
            <span className="flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
              <span className="min-w-0 truncate">
                <UntrustedText value={c.collector_type} plain limit={32} /> ·{" "}
                <UntrustedText value={formatVersion(c.collector_version)} plain limit={40} /> · {formatInterval(c.interval_seconds)}
              </span>
              {c.self_test ? (
                <Hint content="SDK heartbeat self-test: it shows the collector pipeline works and is never counted as asset coverage.">
                  <span className="inline-flex h-5 flex-none items-center rounded-md px-1.5 text-xs text-muted-foreground ring-1 ring-hairline-strong ring-inset">
                    Self-test
                  </span>
                </Hint>
              ) : null}
            </span>
          </div>
        );
      },
    },
    {
      id: "asset",
      accessorFn: (c) => c.asset_id,
      header: "Asset",
      meta: { className: "hidden w-[216px] @3xl:table-cell", label: "Asset" },
      cell: ({ row }) => {
        const id = row.original.asset_id;
        return isAssetId(id) ? (
          <Link
            href={assetHref(id)}
            className="block min-w-0 truncate font-mono text-sm text-fg-2 transition-colors duration-150 hover:text-foreground hover:underline"
          >
            <UntrustedText value={id} plain limit={120} />
          </Link>
        ) : (
          <UntrustedText value={id} oneLine mono />
        );
      },
    },
    {
      id: "sources",
      accessorFn: (c) => c.source_types.join(" "),
      header: "Sources",
      enableSorting: false,
      meta: { className: "hidden w-[184px] @5xl:table-cell", label: "Source types" },
      cell: ({ row }) => <Sources sources={row.original.source_types} />,
    },
    {
      id: "lastSuccess",
      accessorFn: (c) => collectorFreshness(c, now).ratio ?? 2,
      header: "Last success",
      sortDescFirst: true,
      meta: { className: "w-[128px] @md:w-[168px] @max-2xl:pr-(--table-edge)", label: "Last success and freshness" },
      cell: ({ row }) => {
        const c = row.original;
        const fresh = collectorFreshness(c, now);
        const label =
          fresh.ageSeconds === null || fresh.budgetSeconds === null
            ? "Freshness unknown"
            : `${formatDuration(fresh.ageSeconds)} since the last success; stale after ${formatDuration(fresh.budgetSeconds)} (${STALE_INTERVALS} intervals)`;
        return (
          <div className="grid gap-1">
            <span className="text-sm">
              {c.last_success_at ? (
                <RelativeTime value={c.last_success_at} now={now} className="text-fg-2" />
              ) : (
                <span className="text-muted-foreground">Never succeeded</span>
              )}
            </span>
            <Hint content={label} className="w-full py-1">
              <Progress
                value={fresh.ratio === null ? 0 : Math.round(fresh.ratio * 100)}
                aria-label={label}
                className={cn("h-1 bg-white/[0.06]", BAR[fresh.tone])}
              />
            </Hint>
          </div>
        );
      },
    },
    {
      id: "lag",
      accessorFn: (c) => c.lag_seconds ?? -1,
      header: "Lag",
      sortDescFirst: true,
      meta: { align: "right", className: "hidden w-[80px] @2xl:table-cell", label: "Lag" },
      cell: ({ row }) => (
        <span className={cn("text-sm tabular-nums", row.original.lag_seconds ? "text-fg-2" : "text-muted-foreground")}>
          {formatDuration(row.original.lag_seconds)}
        </span>
      ),
    },
    {
      id: "buffered",
      accessorFn: (c) => c.records_buffered,
      header: "Buffered",
      sortDescFirst: true,
      meta: { align: "right", className: "hidden w-[96px] @2xl:table-cell", label: "Records buffered" },
      cell: ({ row }) => {
        const n = row.original.records_buffered;
        return (
          <span className={cn("text-sm tabular-nums", n > 0 ? "font-medium text-health-warn" : "text-muted-foreground")}>
            {formatCount(n)}
          </span>
        );
      },
    },
    {
      // Search target only.
      id: "search",
      accessorFn: (c) => `${c.collector_id} ${c.collector_type} ${c.asset_id} ${c.source_types.join(" ")}`,
      header: "Search",
      enableHiding: false,
      enableSorting: false,
      cell: () => null,
    },
    {
      // Facet only.
      id: "type",
      accessorFn: (c) => c.collector_type,
      header: "Type",
      enableHiding: false,
      enableSorting: false,
      cell: () => null,
    },
  ];
}

/**
 * Collectors: the latest report per collector, problems first. Freshness is the time since the
 * last successful collection against the staleness budget (3 collection intervals); the bar's
 * colour is the API's verdict (healthy green, stale amber, failed red).
 */
export function CollectorsTable({ collectors, now }: { collectors: CollectorStatus[]; now: string }) {
  const cols = useMemo(() => columns(now), [now]);
  const healthOptions = useMemo<FacetOption[]>(
    () =>
      (Object.keys(HEALTH_RANK) as HealthKey[])
        .filter((key) => collectors.some((c) => healthKey(c) === key))
        .map((key) => ({
          value: key,
          label: HEALTH_LABEL[key],
          icon: <span aria-hidden="true" className={cn("size-1.5 rounded-full", HEALTH_DOT[key])} />,
        })),
    [collectors],
  );
  const assetOptions = useMemo<FacetOption[]>(
    () => [...new Set(collectors.map((c) => c.asset_id))].sort().map((id) => ({ value: id, label: id })),
    [collectors],
  );
  const typeOptions = useMemo<FacetOption[]>(
    () => [...new Set(collectors.map((c) => c.collector_type))].sort().map((t) => ({ value: t, label: t })),
    [collectors],
  );
  return (
    <div className="@container">
      <DataTable
        data={collectors}
        columns={cols}
        label="Collectors and telemetry sources"
        getRowId={(c) => `${c.collector_id}|${c.asset_id}`}
        initialSort={[{ id: "health", desc: true }]}
        initialColumnVisibility={{ search: false, type: false }}
        search={{ placeholder: "Search collectors, assets, sources", columnIds: ["search"] }}
        facets={[
          { columnId: "health", title: "Status", options: healthOptions },
          { columnId: "asset", title: "Asset", options: assetOptions },
          { columnId: "type", title: "Type", options: typeOptions },
        ]}
        emptyMessage="No collector matches these filters."
        pageSize={25}
      />
    </div>
  );
}

import { cn } from "cn";
import { Radio } from "lucide-react";

import { Hint } from "@/components/console/hint";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState } from "@/components/console/states";
import { HealthBadge } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CollectorStatus } from "@/lib/api/schemas";
import { formatCount, formatDuration, formatInterval, formatVersion } from "@/lib/format";

import { collectorFreshness, STALE_FACTOR, type Tone } from "./model";

const SEGMENT_FILL: Record<Tone, string> = {
  ok: "bg-health-ok",
  warn: "bg-health-warn",
  bad: "bg-health-bad",
  off: "bg-health-off",
};

const LABEL_TEXT: Record<Tone, string> = {
  ok: "text-fg-2",
  warn: "text-health-warn",
  bad: "text-health-bad",
  off: "text-muted-foreground",
};

/**
 * Freshness of one collector as three segments, one per collection interval of the API's
 * staleness rule (stale after 3 intervals without a successful collection): three lit segments
 * = on schedule, fewer = runs overdue, none = stale. The API's own `stale` verdict decides.
 */
export function FreshnessMeter({
  collector,
  now,
  className,
}: {
  collector: Pick<
    CollectorStatus,
    "stale" | "status" | "interval_seconds" | "seconds_since_success" | "last_success_at" | "stale_reason"
  >;
  now: string;
  className?: string;
}) {
  const f = collectorFreshness(collector);
  const elapsed = f.ratio === null ? STALE_FACTOR : Math.min(STALE_FACTOR, Math.floor(f.ratio * STALE_FACTOR));
  const lit = collector.stale || !collector.last_success_at ? 0 : STALE_FACTOR - elapsed;
  // Two intervals without a success while the API does not call it stale yet: overdue.
  const overdue = f.tone === "ok" && lit === 1;
  const tone: Tone = overdue ? "warn" : f.tone;
  const label = overdue ? "Overdue" : f.label;
  // On schedule: the health column already says OK, so only the recency is shown. The interval
  // segments appear once a collector is late, overdue or stale.
  if (tone === "ok" && collector.last_success_at && lit === STALE_FACTOR) {
    return <RelativeTime value={collector.last_success_at} now={now} className={cn("text-xs", className)} />;
  }
  const explanation = [
    collector.last_success_at ? null : "No successful collection has been reported.",
    collector.stale_reason ? `${collector.stale_reason.charAt(0).toUpperCase()}${collector.stale_reason.slice(1)}.` : null,
    f.threshold
      ? `Each segment is one collection interval (${formatInterval(collector.interval_seconds)}); the API marks the source stale ${f.threshold.replace("stale after", "after")} without a successful collection.`
      : "The collector reported no valid interval.",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <Hint content={explanation} className={cn("items-center gap-2.5", className)}>
      <span aria-hidden="true" className="flex gap-0.5">
        {Array.from({ length: STALE_FACTOR }, (_, i) => (
          <span
            key={i}
            className={cn(
              "h-1.5 w-4 rounded-full",
              i < lit ? SEGMENT_FILL[tone] : tone === "warn" || tone === "bad" ? "bg-hairline-strong" : "bg-hairline",
            )}
          />
        ))}
      </span>
      <span className={cn("text-xs whitespace-nowrap", LABEL_TEXT[tone])}>
        {label}
        {collector.last_success_at ? (
          <span className="text-muted-foreground">
            {" · "}
            <RelativeTime value={collector.last_success_at} now={now} className="text-muted-foreground" />
          </span>
        ) : null}
      </span>
    </Hint>
  );
}

/**
 * Telemetry source coverage of an asset: every collector reporting for it (its own, or an
 * ancestor's for a Kubernetes node), the source types it collects, its health, a freshness
 * meter, lag, records waiting in its outbox and its last error (attacker-influenced text).
 */
export function TelemetrySourcesCard({
  collectors,
  assetId,
  assetType,
  inherited,
  now,
  className,
}: {
  collectors: CollectorStatus[];
  assetId: string;
  assetType: string;
  inherited: number;
  now: string;
  className?: string;
}) {
  const stale = collectors.filter((c) => c.stale).length;
  return (
    <SectionCard
      title="Telemetry sources"
      titleId="collectors-title"
      icon={Radio}
      description={
        inherited > 0
          ? `Collector health as last reported · ${formatCount(inherited)} reporting for ${
              assetType === "kubernetes_node" ? "the cluster, which covers its nodes" : "a parent asset"
            }`
          : "Collector health as last reported"
      }
      meta={
        collectors.length > 0 ? (
          <span className="tabular-nums">
            {formatCount(collectors.length - stale)} of {formatCount(collectors.length)} fresh
          </span>
        ) : null
      }
      flush
      className={className}
    >
      {collectors.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No collector has reported health for this asset, so its telemetry coverage is unknown.</EmptyState>
        </div>
      ) : (
        <Table aria-label="Collectors and telemetry sources">
          <TableHeader>
            <TableRow>
              <TableHead>Collector and sources</TableHead>
              <TableHead>Health</TableHead>
              <TableHead className="hidden sm:table-cell">Last success</TableHead>
              <TableHead className="hidden text-right lg:table-cell">Lag</TableHead>
              <TableHead className="hidden text-right md:table-cell">Buffered</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {collectors.map((c) => {
              const viaAncestor = c.asset_id !== assetId;
              return (
                <TableRow key={`${c.collector_id}|${c.asset_id}`} className="align-top">
                  <TableCell className="w-full max-w-0 min-w-64 py-3 whitespace-normal">
                    <div className="font-mono text-xs text-foreground">
                      <UntrustedText value={c.collector_id} oneLine mono />
                    </div>
                    <div className="mt-1 truncate text-xs text-muted-foreground">
                      <UntrustedText value={`${c.collector_type} ${formatVersion(c.collector_version)}`} plain limit={48} /> ·{" "}
                      {formatInterval(c.interval_seconds)}
                      {viaAncestor ? (
                        <>
                          {" · via "}
                          <span className="font-mono">
                            <UntrustedText value={c.asset_id} plain limit={48} />
                          </span>
                        </>
                      ) : null}
                    </div>
                    {c.source_types.length > 0 ? (
                      <ul className="mt-2 flex flex-wrap gap-1" aria-label="Source types">
                        {c.source_types.map((source) => (
                          <li
                            key={source}
                            className="inline-flex h-5 items-center rounded-md bg-white/[0.03] px-1.5 font-mono text-xs text-fg-2 ring-1 ring-hairline ring-inset"
                          >
                            <UntrustedText value={source} plain limit={40} />
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-2 text-xs text-muted-foreground">No source type declared</p>
                    )}
                    {c.last_error ? (
                      <div className="mt-2 flex min-w-0 items-center gap-1.5 text-xs">
                        <span className="flex-none text-health-bad">Last error</span>
                        <span className="min-w-0 flex-1 text-muted-foreground">
                          <UntrustedText value={c.last_error} oneLine />
                        </span>
                      </div>
                    ) : null}
                  </TableCell>
                  <TableCell className="py-3">
                    <HealthBadge status={c.status} className="text-xs" />
                  </TableCell>
                  <TableCell className="hidden py-3 sm:table-cell">
                    <FreshnessMeter collector={c} now={now} />
                  </TableCell>
                  <TableCell className="hidden py-3 text-right text-sm tabular-nums lg:table-cell">
                    <span className={c.lag_seconds ? "text-fg-2" : "text-muted-foreground"}>{formatDuration(c.lag_seconds)}</span>
                  </TableCell>
                  <TableCell className="hidden py-3 text-right text-sm tabular-nums md:table-cell">
                    <span className={c.records_buffered > 0 ? "text-fg-2" : "text-muted-foreground"}>{formatCount(c.records_buffered)}</span>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  );
}

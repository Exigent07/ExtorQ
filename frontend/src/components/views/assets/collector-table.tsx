import { HealthStatusDot, StaleBadge } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { CollectorStatus } from "@/lib/api/schemas";
import { DASH, formatCount, formatDuration, formatInterval, formatVersion } from "@/lib/format";

/**
 * Telemetry source coverage: one row per collector reporting for an asset (or for all
 * assets on the health view). Freshness is the API's own staleness verdict, shown as a badge
 * so old data never passes as current.
 */
export function CollectorTable({
  collectors,
  now,
  showAsset = false,
}: {
  collectors: CollectorStatus[];
  now: string;
  showAsset?: boolean;
}) {
  return (
    <Table aria-label="Collectors and telemetry sources">
      <TableHeader>
        <TableRow>
          <TableHead>Collector</TableHead>
          {showAsset ? <TableHead className="hidden lg:table-cell">Asset</TableHead> : null}
          <TableHead className="hidden md:table-cell">Sources</TableHead>
          <TableHead>Status</TableHead>
          <TableHead className="text-right">Last success</TableHead>
          <TableHead className="text-right">Lag</TableHead>
          <TableHead className="hidden text-right sm:table-cell">Buffered</TableHead>
          <TableHead className="hidden xl:table-cell">Last error</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {collectors.map((c) => (
          <TableRow key={`${c.collector_id}|${c.asset_id}`}>
            <TableCell className="py-2 whitespace-normal">
              <div className="font-mono text-xs text-ink">
                <UntrustedText value={c.collector_id} limit={60} />
              </div>
              <div className="mt-0.5 text-xs text-muted-foreground">
                <UntrustedText value={`${c.collector_type} · ${formatVersion(c.collector_version)}`} limit={72} /> ·{" "}
                {formatInterval(c.interval_seconds)}
              </div>
            </TableCell>
            {showAsset ? (
              <TableCell className="hidden font-mono text-xs text-ink-2 lg:table-cell">
                <UntrustedText value={c.asset_id} limit={60} />
              </TableCell>
            ) : null}
            <TableCell className="hidden max-w-64 whitespace-normal md:table-cell">
              <span className="font-mono text-xs text-ink-2">
                {c.source_types.length === 0 ? DASH : <UntrustedText value={c.source_types.join(", ")} limit={120} />}
              </span>
            </TableCell>
            <TableCell>
              <div className="flex flex-wrap items-center gap-2">
                <HealthStatusDot status={c.status} />
                {c.stale ? <StaleBadge reason={c.stale_reason} /> : null}
              </div>
            </TableCell>
            <TableCell className="text-right">
              <RelativeTime value={c.last_success_at} now={now} className="text-xs" />
            </TableCell>
            <TableCell className="text-right font-mono text-xs text-ink-2">{formatDuration(c.lag_seconds)}</TableCell>
            <TableCell className="hidden text-right font-mono text-xs sm:table-cell">
              <span className={c.records_buffered > 0 ? "text-warn" : "text-muted-foreground"}>
                {formatCount(c.records_buffered)}
              </span>
            </TableCell>
            <TableCell className="hidden max-w-80 text-xs whitespace-normal text-muted-foreground xl:table-cell">
              <UntrustedText value={c.last_error} limit={120} />
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

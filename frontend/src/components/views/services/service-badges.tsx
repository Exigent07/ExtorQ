import { Hint } from "@/components/console/hint";
import { StatusPill } from "@/components/console/status-badge";
import { formatDuration } from "@/lib/format";
import { serviceCoverage } from "@/lib/services";

type CoverageInput = Parameters<typeof serviceCoverage>[0];

/** Header form of the coverage state, with its meaning and the API's reasons on hover. */
export function ServiceCoveragePill({ service }: { service: CoverageInput }) {
  const badge = serviceCoverage(service);
  return (
    <Hint content={badge.detail}>
      <StatusPill tone={badge.tone} label={badge.label} />
    </Hint>
  );
}

/** Marks a service that is no longer observed (tombstone), never hidden. */
export function RemovedTag() {
  return (
    <Hint content="No longer observed by discovery. Kept for history; its telemetry and findings stay attached.">
      <span className="inline-flex h-5 flex-none items-center rounded-md px-1.5 text-xs whitespace-nowrap text-muted-foreground ring-1 ring-hairline-strong ring-inset">
        Removed
      </span>
    </Hint>
  );
}

/** Discovery has not refreshed this record recently: its current state cannot be confirmed. */
export function ReportStaleTag({ ageSeconds }: { ageSeconds: number }) {
  return (
    <Hint
      content={`Service discovery last refreshed this record ${formatDuration(ageSeconds)} ago, beyond its staleness threshold; its current state cannot be confirmed.`}
    >
      <StatusPill tone="warn" label="Report stale" />
    </Hint>
  );
}

import Link from "next/link";

import { BrandMark } from "@/components/console/brand-mark";
import { COVERAGE } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import type { AssetClassCoverage } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount } from "@/lib/format";
import { cn } from "cn";

const TONE_TEXT = { ok: "text-ok", warn: "text-warn", bad: "text-bad", off: "text-ink-2" } as const;
const TONE_LINE = { ok: "bg-ok", warn: "bg-warn", bad: "bg-bad", off: "bg-off" } as const;

/** Order of the four monitored classes; matches the four arcs of the ExtorQ mark. */
const CLASS_ORDER = ["macos_host", "linux_host", "kubernetes_cluster", "github_repository"];

function sortCoverage(items: AssetClassCoverage[]): AssetClassCoverage[] {
  return [...items].sort((a, b) => {
    const ia = CLASS_ORDER.indexOf(a.asset_type);
    const ib = CLASS_ORDER.indexOf(b.asset_type);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });
}

/**
 * Coverage of the four monitored asset classes: one lane each, a 2px status line on top,
 * the status in words, then the counts that justify it.
 */
export function CoverageLanes({ coverage, now }: { coverage: AssetClassCoverage[]; now: string }) {
  const lanes = sortCoverage(coverage.filter((c) => c.expected || c.assets_total > 0));
  return (
    <section aria-labelledby="coverage-title" className="rounded-md border border-border bg-surface">
      <header className="flex items-center justify-between gap-4 px-5 pt-4 pb-1">
        <h2 id="coverage-title" className="flex items-center gap-2 text-lg font-semibold text-ink">
          <BrandMark className="size-4 text-ink-2" />
          Telemetry coverage
        </h2>
        <Link href="/assets" className="text-xs text-muted-foreground hover:text-ink">
          View assets
        </Link>
      </header>
      <ol className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4">
        {lanes.map((lane, index) => {
          const { tone, label } = COVERAGE[lane.status];
          const reporting = lane.assets_ok + lane.assets_degraded;
          return (
            <li
              key={lane.asset_type}
              className={cn(
                "relative px-5 pt-4 pb-5",
                index > 0 && "border-t border-border sm:border-t-0",
                index % 2 === 1 && "sm:border-l sm:border-border",
                index >= 2 && "sm:border-t xl:border-t-0",
                index > 0 && "xl:border-l xl:border-border",
              )}
            >
              <span aria-hidden="true" className={cn("absolute top-0 left-5 h-0.5 w-10", TONE_LINE[tone])} />
              <p className="text-sm text-ink-2">{assetTypeLabel(lane.asset_type)}</p>
              <p className={cn("mt-1 text-xl font-medium", TONE_TEXT[tone])}>{label}</p>
              <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
                <dt className="text-muted-foreground">Assets</dt>
                <dd className="text-right font-mono text-ink-2">
                  {lane.assets_total === 0 ? (
                    "none reporting"
                  ) : (
                    <>
                      {formatCount(reporting)}
                      <span className="text-muted-foreground"> of {formatCount(lane.assets_total)} healthy or degraded</span>
                    </>
                  )}
                </dd>
                {lane.assets_stale > 0 ? (
                  <>
                    <dt className="text-muted-foreground">Stale</dt>
                    <dd className="text-right font-mono text-warn">{formatCount(lane.assets_stale)}</dd>
                  </>
                ) : null}
                {lane.assets_without_collector > 0 ? (
                  <>
                    <dt className="text-muted-foreground">No collector</dt>
                    <dd className="text-right font-mono text-warn">
                      {formatCount(lane.assets_without_collector)}
                    </dd>
                  </>
                ) : null}
                <dt className="text-muted-foreground">Last event</dt>
                <dd className="text-right">
                  <RelativeTime value={lane.last_event_at} now={now} className="text-xs" />
                </dd>
              </dl>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

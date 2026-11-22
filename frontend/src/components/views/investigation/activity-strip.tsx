import { cn } from "cn";

import { formatCount, formatUtc, formatUtcTime } from "@/lib/format";

import { relationshipLabel } from "./labels";
import { axisBounds, axisPercent, axisTicks, type TimelineRow } from "./model";

const LANES = [
  { kind: "evidence", tick: "bg-brand" },
  { kind: "direct", tick: "bg-foreground" },
  { kind: "candidate", tick: "bg-fg-2/70" },
  { kind: "unestablished", tick: "bg-fg-faint" },
] as const;

/**
 * Every entry of the investigation context on one UTC time axis, one lane per relationship
 * (evidence, direct, candidate, unestablished), with the alert's first-to-last-seen span
 * shaded. Positions come from the real event times; nothing is binned or interpolated.
 */
export function ActivityStrip({
  rows,
  windowStart,
  windowEnd,
  firstSeen,
  lastSeen,
}: {
  rows: readonly TimelineRow[];
  windowStart: string;
  windowEnd: string;
  firstSeen: string;
  lastSeen: string;
}) {
  const bounds = axisBounds(windowStart, windowEnd, rows.map((r) => r.time));
  const { ticks, stepSeconds } = axisTicks(bounds, 6);
  const spanStart = axisPercent(firstSeen, bounds);
  const spanEnd = axisPercent(lastSeen, bounds);
  const counts = LANES.map((lane) => rows.filter((r) => r.kind === lane.kind).length);
  const label = `Context timeline from ${formatUtc(new Date(bounds.start).toISOString())} to ${formatUtc(
    new Date(bounds.end).toISOString(),
  )}: ${LANES.map((lane, i) => `${formatCount(counts[i] ?? 0)} ${relationshipLabel(lane.kind).toLowerCase()}`).join(", ")}.`;
  const tickLabel = (ms: number) => {
    const time = formatUtcTime(new Date(ms).toISOString());
    return stepSeconds < 60 ? time : time.slice(0, 5);
  };

  return (
    <figure className="grid gap-2" role="img" aria-label={label}>
      <div className="grid grid-cols-[6.5rem_minmax(0,1fr)_2.5rem] items-center gap-x-3 gap-y-1.5">
        {LANES.map((lane, index) => (
          <div key={lane.kind} className="contents">
            <span className="text-xs text-muted-foreground">{relationshipLabel(lane.kind)}</span>
            <span className="relative h-4">
              <span aria-hidden="true" className="absolute inset-x-0 top-1/2 h-px bg-hairline-strong" />
              <span
                aria-hidden="true"
                className="absolute inset-y-[-3px] rounded-sm bg-brand/[0.08]"
                style={{ left: `${spanStart}%`, width: `${Math.max(0.4, spanEnd - spanStart)}%` }}
              />
              {rows
                .filter((r) => r.kind === lane.kind)
                .map((r) => (
                  <span
                    key={r.key}
                    aria-hidden="true"
                    className={cn("absolute top-0.5 h-3 w-[2px] -translate-x-1/2 rounded-full", lane.tick)}
                    style={{ left: `${axisPercent(r.time, bounds)}%` }}
                  />
                ))}
            </span>
            <span className={cn("text-right font-mono text-xs tabular-nums", (counts[index] ?? 0) > 0 ? "text-fg-2" : "text-muted-foreground")}>
              {formatCount(counts[index] ?? 0)}
            </span>
          </div>
        ))}
        <span />
        <span aria-hidden="true" className="relative h-4">
          {ticks.map((t) => (
            <span
              key={t}
              className="absolute top-0 -translate-x-1/2 font-mono text-xs whitespace-nowrap text-muted-foreground tabular-nums"
              style={{ left: `${axisPercent(new Date(t).toISOString(), bounds)}%` }}
            >
              {tickLabel(t)}
            </span>
          ))}
        </span>
        <span />
      </div>
      <figcaption className="flex flex-wrap items-center gap-x-4 gap-y-1 pl-[7.25rem] text-xs text-muted-foreground">
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="h-2.5 w-4 rounded-sm bg-brand/[0.16]" />
          Alert first to last seen
        </span>
        <span>Times in UTC · context window as built by the correlation layer</span>
      </figcaption>
    </figure>
  );
}

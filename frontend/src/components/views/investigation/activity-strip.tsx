import { cn } from "cn";

import { formatCount, formatUtc, formatUtcTime } from "@/lib/format";

/** A bucket width in words ("15 s", "1.5 s", "2 min"). */
function formatSpan(seconds: number): string {
  if (seconds < 10) return `${(Math.round(seconds * 10) / 10).toString()} s`;
  if (seconds < 120) return `${Math.round(seconds)} s`;
  return `${Math.round(seconds / 60)} min`;
}

import { relationshipLabel } from "./labels";
import { axisPercent, axisTicks, histogram, observedBounds, type TimelineRow } from "./model";

const LANES = [
  { kind: "evidence", tick: "bg-brand" },
  { kind: "direct", tick: "bg-foreground" },
  { kind: "candidate", tick: "bg-fg-2/70" },
  { kind: "unestablished", tick: "bg-fg-faint" },
] as const;

const BUCKETS = 60;
/** Bar height in px for a lane's busiest bucket; a single observation stays visible at 3 px. */
const MAX_BAR = 14;

/**
 * Every entry of the investigation context on one UTC time axis, one lane per relationship
 * (evidence, direct, candidate, unestablished): a histogram of real event times in 60 equal
 * buckets (bar height = observations in the bucket, relative to the lane's busiest), with the alert's
 * first-to-last-seen span shaded. The axis spans the observations, padded 5 %.
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
  const bounds = observedBounds(windowStart, windowEnd, [...rows.map((r) => r.time), firstSeen, lastSeen]);
  const lanes = LANES.map((lane) => histogram(rows.filter((r) => r.kind === lane.kind).map((r) => r.time), bounds, BUCKETS));
  // Each lane on its own scale (its busiest bucket is full height): the strip shows when each kind
  // of observation happened; the totals on the right give the sizes.
  const peaks = lanes.map((lane) => Math.max(1, ...lane));
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
            <span className="relative h-5">
              <span aria-hidden="true" className="absolute inset-x-0 bottom-0 h-px bg-hairline-strong" />
              <span
                aria-hidden="true"
                className="absolute -inset-y-0.5 rounded-sm bg-brand/[0.1]"
                style={{ left: `${spanStart}%`, width: `${Math.max(0, spanEnd - spanStart)}%`, minWidth: "2px" }}
              />
              {(lanes[index] ?? []).map((n, bucket) =>
                n > 0 ? (
                  <span
                    key={bucket}
                    aria-hidden="true"
                    className={cn("absolute bottom-0 rounded-t-[1px]", lane.tick)}
                    style={{
                      left: `${(bucket / BUCKETS) * 100}%`,
                      width: `max(3px, calc(${100 / BUCKETS}% - 2px))`,
                      height: `${Math.max(3, Math.round((n / (peaks[index] ?? 1)) * MAX_BAR))}px`,
                    }}
                  />
                ) : null,
              )}
            </span>
            <span className={cn("text-right text-xs tabular-nums", (counts[index] ?? 0) > 0 ? "text-fg-2" : "text-muted-foreground")}>
              {formatCount(counts[index] ?? 0)}
            </span>
          </div>
        ))}
        <span />
        <span aria-hidden="true" className="relative h-4">
          {ticks.map((t) => (
            <span
              key={t}
              className="absolute top-0 -translate-x-1/2 text-xs whitespace-nowrap text-muted-foreground tabular-nums"
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
        <span>
          Bars count observations per {formatSpan((bounds.end - bounds.start) / BUCKETS / 1000)}, each lane on its own scale · times
          in UTC
        </span>
      </figcaption>
    </figure>
  );
}

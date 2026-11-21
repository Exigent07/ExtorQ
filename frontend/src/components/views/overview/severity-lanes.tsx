"use client";

import { cn } from "cn";
import { Bar, BarChart, Cell, YAxis } from "recharts";

import { SEVERITY_COLOR_VAR, SEVERITY_LABEL } from "@/components/console/severity";
import { ChartContainer, ChartTooltip, type ChartConfig } from "@/components/ui/chart";
import { formatCount, formatUtcShort } from "@/lib/format";
import { axisTickIndices, type LaneData, type SeverityLane } from "@/lib/series";

function laneLabel(lane: SeverityLane): string {
  return lane.severity === "all" ? "All alerts" : SEVERITY_LABEL[lane.severity];
}

function laneColor(lane: SeverityLane): string {
  return lane.severity === "all" ? "var(--xq-text)" : SEVERITY_COLOR_VAR[lane.severity];
}

function axisLabel(iso: string, bucketSeconds: number): string {
  const short = formatUtcShort(iso);
  // Daily or coarser buckets: date only; finer: time only ("14:00").
  if (bucketSeconds >= 6 * 3600) return short.split(" ").slice(0, 2).join(" ");
  return short.split(" ").slice(2).join(" ");
}

/**
 * Detection alerts over time as one lane per severity on a shared time axis and a shared
 * scale. Identity comes from the lane's position and label (never colour alone); the
 * severity hue is the same status colour used by severity tags everywhere.
 */
export function SeverityLanes({ data, rangeLabel }: { data: LaneData; rangeLabel: string }) {
  const { buckets, lanes, max, bucketSeconds } = data;
  const ticks = axisTickIndices(buckets.length);
  const domainMax = Math.max(1, max);

  return (
    <figure className="m-0">
      <div className="grid grid-cols-[76px_minmax(0,1fr)_44px] items-center gap-x-3 text-xs">
        <span className="text-muted-foreground">Severity</span>
        <span className="sr-only">Alerts per bucket</span>
        <span aria-hidden="true" />
        <span className="text-right text-muted-foreground">{rangeLabel}</span>
        {lanes.map((lane) => {
          const config = { count: { label: laneLabel(lane), color: laneColor(lane) } } satisfies ChartConfig;
          const rows = buckets.map((bucket, i) => ({ start: bucket.start, end: bucket.end, count: lane.counts[i] ?? 0 }));
          return (
            <div key={lane.severity} className="contents">
              <span className={cn("py-1.5", lane.total > 0 ? "text-ink-2" : "text-muted-foreground")}>
                {laneLabel(lane)}
              </span>
              <div className="relative h-9 border-b border-grid">
                <ChartContainer config={config} className="aspect-auto h-9 w-full" initialDimension={{ width: 600, height: 36 }}>
                  <BarChart data={rows} margin={{ top: 2, right: 0, bottom: 0, left: 0 }} barCategoryGap={1}>
                    <YAxis hide domain={[0, domainMax]} allowDecimals={false} />
                    <ChartTooltip
                      cursor={{ fill: "var(--xq-raised)" }}
                      isAnimationActive={false}
                      content={({ active, payload }) => {
                        const row = payload?.[0]?.payload as (typeof rows)[number] | undefined;
                        if (!active || !row) return null;
                        return (
                          <div className="rounded-md border border-border bg-overlay px-2.5 py-1.5 text-xs text-ink shadow-md">
                            <span className="text-muted-foreground">
                              {formatUtcShort(row.start)}–{formatUtcShort(row.end).split(" ").slice(2).join(" ")} UTC
                            </span>
                            <span className="ml-2">
                              {laneLabel(lane)} · {formatCount(row.count)} alert{row.count === 1 ? "" : "s"}
                            </span>
                          </div>
                        );
                      }}
                    />
                    <Bar dataKey="count" fill="var(--color-count)" radius={[2, 2, 0, 0]} isAnimationActive={false} minPointSize={0}>
                      {rows.map((row) => (
                        <Cell key={row.start} fill={row.count > 0 ? "var(--color-count)" : "transparent"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ChartContainer>
              </div>
              <span className={cn("text-right font-mono", lane.total > 0 ? "text-ink" : "text-muted-foreground")}>
                {formatCount(lane.total)}
              </span>
            </div>
          );
        })}
        <span aria-hidden="true" />
        <div aria-hidden="true" className="relative mt-1 h-4">
          {ticks.map((i) => {
            const bucket = buckets[i];
            if (!bucket) return null;
            const left = ((i + 0.5) / buckets.length) * 100;
            return (
              <span
                key={bucket.start}
                className="absolute top-0 -translate-x-1/2 text-2xs whitespace-nowrap text-muted-foreground first:translate-x-0"
                style={{ left: `${left}%` }}
              >
                {axisLabel(bucket.start, bucketSeconds)}
              </span>
            );
          })}
        </div>
        <span aria-hidden="true" />
      </div>
      <figcaption className="mt-3 text-xs text-muted-foreground">
        Bars share one scale: the tallest is {formatCount(max)} alert{max === 1 ? "" : "s"} per{" "}
        {bucketSeconds >= 86400 ? "day" : bucketSeconds >= 3600 ? `${bucketSeconds / 3600} h` : `${bucketSeconds / 60} min`}.
        Times in UTC. An empty bucket means no alert was stored for it.
      </figcaption>
      <table className="sr-only">
        <caption>Detection alerts per time bucket and severity</caption>
        <thead>
          <tr>
            <th scope="col">Bucket start (UTC)</th>
            {lanes.map((lane) => (
              <th key={lane.severity} scope="col">
                {laneLabel(lane)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {buckets.map((bucket, i) =>
            lanes.some((lane) => (lane.counts[i] ?? 0) > 0) ? (
              <tr key={bucket.start}>
                <th scope="row">{formatUtcShort(bucket.start)}</th>
                {lanes.map((lane) => (
                  <td key={lane.severity}>{lane.counts[i] ?? 0}</td>
                ))}
              </tr>
            ) : null,
          )}
        </tbody>
      </table>
    </figure>
  );
}

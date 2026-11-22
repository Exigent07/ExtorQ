"use client";

import { ChartColumnStacked } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts";

import { CardLink, SectionCard } from "@/components/console/section-card";
import { SEVERITY_COLOR_VAR, SEVERITY_LABEL, SeverityDot } from "@/components/console/severity";
import { ChartContainer, ChartTooltip, type ChartConfig } from "@/components/ui/chart";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import type { Severity } from "@/lib/api/schemas";
import { formatCount, formatUtcShort } from "@/lib/format";
import { type ActivityRow, type ActivitySeries, niceTicks } from "@/lib/overview";

/** Stack order, bottom to top: the most severe segment sits on top of each column. */
const STACK: Severity[] = ["info", "low", "medium", "high", "critical"];
const LEGEND: Severity[] = ["critical", "high", "medium", "low", "info"];

const CONFIG = Object.fromEntries(
  STACK.map((severity) => [severity, { label: SEVERITY_LABEL[severity], color: SEVERITY_COLOR_VAR[severity] }]),
) satisfies ChartConfig;

type RangeKey = "24h" | "7d";
const RANGE_LABEL: Record<RangeKey, string> = { "24h": "last 24 hours", "7d": "last 7 days" };

function pad(n: number) {
  return String(n).padStart(2, "0");
}

function bucketName(bucketSeconds: number): string {
  if (bucketSeconds === 3600) return "Hourly";
  if (bucketSeconds === 86400) return "Daily";
  if (bucketSeconds % 3600 === 0) return `${bucketSeconds / 3600}-hour`;
  return `${Math.round(bucketSeconds / 60)}-minute`;
}

function tickLabel(iso: string, bucketSeconds: number): string {
  const d = new Date(iso);
  if (bucketSeconds >= 6 * 3600) return d.toLocaleString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
  return `${pad(d.getUTCHours())}:00`;
}

/** Ticks on whole steps: every 4 h for hourly buckets, every day at 00:00 for coarser ones. */
function tickStarts(rows: ActivityRow[], bucketSeconds: number): string[] {
  return rows
    .filter((row) => {
      const d = new Date(row.start);
      return bucketSeconds >= 6 * 3600 ? d.getUTCHours() === 0 : d.getUTCHours() % 4 === 0;
    })
    .map((row) => row.start);
}

/** Rounded top only on the topmost non-empty segment of a column (4px radius). */
function SegmentShape(props: {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  fill?: string;
  payload?: ActivityRow;
  severity: Severity;
}) {
  const { x = 0, y = 0, width = 0, height = 0, fill, payload, severity } = props;
  if (!payload || height <= 0 || width <= 0) return null;
  const above = STACK.slice(STACK.indexOf(severity) + 1);
  const isTop = above.every((s) => payload[s] === 0);
  const r = isTop ? Math.min(4, width / 2, height) : 0;
  const path = r
    ? `M${x},${y + height}V${y + r}Q${x},${y} ${x + r},${y}H${x + width - r}Q${x + width},${y} ${x + width},${y + r}V${y + height}Z`
    : `M${x},${y + height}V${y}H${x + width}V${y + height}Z`;
  return <path d={path} fill={fill} stroke="var(--card)" strokeWidth={1} />;
}

function TooltipBody({ row, bucketSeconds }: { row: ActivityRow; bucketSeconds: number }) {
  const end = new Date(row.end);
  const endLabel = bucketSeconds >= 86400 ? formatUtcShort(row.end) : `${pad(end.getUTCHours())}:${pad(end.getUTCMinutes())}`;
  return (
    <div className="grid min-w-44 gap-1.5 rounded-lg bg-popover px-3 py-2 text-xs shadow-float">
      <span className="text-muted-foreground">
        {formatUtcShort(row.start)}–{endLabel} UTC
      </span>
      {row.total === 0 ? (
        <span className="text-fg-2">No alert stored</span>
      ) : (
        LEGEND.filter((s) => row[s] > 0).map((s) => (
          <span key={s} className="flex items-center gap-2">
            <SeverityDot severity={s} />
            <span className="text-fg-2">{SEVERITY_LABEL[s]}</span>
            <span className="ml-auto font-medium text-foreground tabular-nums">{formatCount(row[s])}</span>
          </span>
        ))
      )}
      {row.total > 0 ? (
        <span className="flex items-center justify-between border-t border-hairline pt-1.5 text-fg-2">
          Total <span className="font-medium text-foreground tabular-nums">{formatCount(row.total)}</span>
        </span>
      ) : null}
    </div>
  );
}

/**
 * Alerts created per bucket, stacked by severity, for the last 24 hours (hourly, from the
 * overview response) or the last 7 days (6-hour buckets, from the time-series endpoint).
 * Empty buckets are drawn as nothing: no alert was stored for them.
 */
export function AlertActivityCard({
  day,
  week,
  className,
}: {
  day: ActivitySeries;
  /** null when the 7-day series could not be loaded (the toggle says so). */
  week: ActivitySeries | null;
  className?: string;
}) {
  const [range, setRange] = useState<RangeKey>("24h");
  const series = range === "7d" && week ? week : day;
  const max = Math.max(0, ...series.rows.map((r) => r.total));
  const ticks = tickStarts(series.rows, series.bucketSeconds);
  const yAxisTicks = niceTicks(max);
  const present = LEGEND.filter((s) => series.totals[s] > 0);

  return (
    <SectionCard
      title="Alert activity"
      titleId="alerts-time-title"
      icon={ChartColumnStacked}
      className={className}
      description={
        <>
          <span className="text-fg-2 tabular-nums">{formatCount(series.total)}</span> alerts created in the {RANGE_LABEL[range]}, by
          severity
        </>
      }
      action={
        <div className="flex items-center gap-3">
          <ToggleGroup
            type="single"
            size="sm"
            variant="outline"
            value={range}
            onValueChange={(value) => {
              if (value === "24h" || value === "7d") setRange(value);
            }}
            aria-label="Time range"
          >
            <ToggleGroupItem value="24h" className="h-7 px-2.5 text-xs data-[state=on]:bg-active data-[state=on]:text-foreground">
              24 h
            </ToggleGroupItem>
            <ToggleGroupItem
              value="7d"
              disabled={!week}
              title={week ? undefined : "The 7-day series could not be loaded"}
              className="h-7 px-2.5 text-xs data-[state=on]:bg-active data-[state=on]:text-foreground"
            >
              7 d
            </ToggleGroupItem>
          </ToggleGroup>
          <Link href="/detections" className="group/link">
            <CardLink>Alert history</CardLink>
          </Link>
        </div>
      }
    >
      <ul className="mb-4 flex flex-wrap gap-x-5 gap-y-1.5 text-sm" aria-label="Alerts in range by severity">
        {present.length === 0 ? (
          <li className="text-muted-foreground">No alert was stored in the {RANGE_LABEL[range]}.</li>
        ) : (
          present.map((s) => (
            <li key={s} className="flex items-center gap-1.5">
              <SeverityDot severity={s} className="size-2" />
              <span className="text-muted-foreground">{SEVERITY_LABEL[s]}</span>
              <span className="font-medium text-foreground tabular-nums">{formatCount(series.totals[s])}</span>
            </li>
          ))
        )}
      </ul>

      <figure className="relative m-0 flex min-h-[220px] flex-1 flex-col">
        <ChartContainer config={CONFIG} className="aspect-auto min-h-[220px] w-full flex-1" initialDimension={{ width: 720, height: 260 }}>
          <BarChart data={series.rows} margin={{ top: 6, right: 4, bottom: 0, left: -8 }} barCategoryGap="16%" maxBarSize={28}>
            <defs>
              {STACK.map((s) => (
                <linearGradient key={s} id={`activity-fill-${s}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={`var(--color-${s})`} stopOpacity={0.95} />
                  <stop offset="100%" stopColor={`var(--color-${s})`} stopOpacity={0.55} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid vertical={false} stroke="var(--xq-grid)" strokeDasharray="3 4" />
            <YAxis
              allowDecimals={false}
              axisLine={false}
              tickLine={false}
              width={36}
              tickMargin={6}
              domain={[0, yAxisTicks[yAxisTicks.length - 1] ?? 3]}
              ticks={yAxisTicks}
              tick={{ fill: "var(--xq-axis)", fontSize: 12 }}
            />
            <XAxis
              dataKey="start"
              ticks={ticks}
              tickFormatter={(value: string) => tickLabel(value, series.bucketSeconds)}
              axisLine={{ stroke: "var(--xq-hairline-strong)" }}
              tickLine={false}
              tickMargin={8}
              interval={0}
              tick={{ fill: "var(--xq-axis)", fontSize: 12 }}
            />
            <ChartTooltip
              cursor={{ fill: "var(--xq-hover)" }}
              isAnimationActive={false}
              content={({ active, payload }) => {
                const row = payload?.[0]?.payload as ActivityRow | undefined;
                return active && row ? <TooltipBody row={row} bucketSeconds={series.bucketSeconds} /> : null;
              }}
            />
            {STACK.map((s) => (
              <Bar
                key={s}
                dataKey={s}
                stackId="alerts"
                fill={`url(#activity-fill-${s})`}
                isAnimationActive={false}
                shape={(props: object) => <SegmentShape {...props} severity={s} />}
              />
            ))}
          </BarChart>
        </ChartContainer>
        {series.total === 0 ? (
          <p className="pointer-events-none absolute inset-x-0 top-1/2 -translate-y-1/2 text-center text-sm text-muted-foreground">
            No alerts were created in the {RANGE_LABEL[range]}.
          </p>
        ) : null}
        <figcaption className="mt-3 text-xs text-muted-foreground">
          {bucketName(series.bucketSeconds)} buckets in UTC; an empty bucket means no alert was stored for it.
          {series.truncated ? " The series was truncated by the API." : ""}
          {series.ungrouped > 0 ? ` ${formatCount(series.ungrouped)} alerts without a severity group are not drawn.` : ""}
        </figcaption>
      </figure>

      <table className="sr-only">
        <caption>Alerts created per bucket and severity, {RANGE_LABEL[range]}</caption>
        <thead>
          <tr>
            <th scope="col">Bucket start (UTC)</th>
            {LEGEND.map((s) => (
              <th key={s} scope="col" className="text-right">
                {SEVERITY_LABEL[s]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {series.rows
            .filter((row) => row.total > 0)
            .map((row) => (
              <tr key={row.start}>
                <th scope="row">{formatUtcShort(row.start)}</th>
                {LEGEND.map((s) => (
                  <td key={s} className="text-right">
                    {row[s]}
                  </td>
                ))}
              </tr>
            ))}
        </tbody>
      </table>
    </SectionCard>
  );
}

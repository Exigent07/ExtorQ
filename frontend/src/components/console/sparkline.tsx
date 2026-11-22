"use client";

import { useId } from "react";
import { Area, AreaChart, YAxis } from "recharts";

import { ChartContainer, type ChartConfig } from "@/components/ui/chart";

/**
 * A small trend line for a KpiCard's `visual` slot: straight segments, a faint fade under
 * the line (the only gradient a sparkline gets), no axes. Use it only with a real series
 * from the API and name the series and its window in the card's sub-label.
 */
export function Sparkline({
  values,
  label,
  color = "var(--xq-brand)",
  width = 104,
  height = 36,
}: {
  values: number[];
  /** Accessible description, e.g. "Alerts created per hour, last 24 hours". */
  label: string;
  /** CSS variable reference (validated by ChartContainer). */
  color?: string;
  width?: number;
  height?: number;
}) {
  const id = useId().replace(/:/g, "");
  const config = { value: { label, color } } satisfies ChartConfig;
  const data = values.map((value, index) => ({ index, value }));
  const max = Math.max(1, ...values);
  return (
    <figure role="img" aria-label={label} className="m-0" style={{ width, height }}>
      <ChartContainer config={config} className="aspect-auto size-full" initialDimension={{ width, height }}>
        <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
          <defs>
            <linearGradient id={`spark-${id}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--color-value)" stopOpacity={0.28} />
              <stop offset="100%" stopColor="var(--color-value)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <YAxis hide domain={[0, max]} />
          <Area
            type="linear"
            dataKey="value"
            stroke="var(--color-value)"
            strokeWidth={1.5}
            fill={`url(#spark-${id})`}
            isAnimationActive={false}
            dot={false}
            activeDot={false}
          />
        </AreaChart>
      </ChartContainer>
    </figure>
  );
}

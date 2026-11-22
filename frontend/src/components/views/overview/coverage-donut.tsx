"use client";

import type { ReactNode } from "react";
import { Cell, Pie, PieChart } from "recharts";

import { ChartContainer, ChartTooltip, type ChartConfig } from "@/components/ui/chart";
import { formatCount } from "@/lib/format";

export interface DonutPart {
  key: string;
  label: string;
  value: number;
  /** CSS variable reference, e.g. var(--xq-cov-monitored). */
  color: string;
}

/**
 * A thin donut of parts of one whole (service coverage): no labels on slices, the total and
 * the leading share in the centre, the parts listed beside it by the caller. Zero parts are
 * not drawn; an all-zero whole draws the empty ring.
 */
export function CoverageDonut({
  parts,
  centerValue,
  centerLabel,
  label,
}: {
  parts: DonutPart[];
  centerValue: ReactNode;
  centerLabel: string;
  /** Accessible summary of the parts. */
  label: string;
}) {
  const config = Object.fromEntries(parts.map((p) => [p.key, { label: p.label, color: p.color }])) satisfies ChartConfig;
  const drawn = parts.filter((p) => p.value > 0);
  const total = parts.reduce((sum, p) => sum + p.value, 0);
  return (
    <figure className="relative m-0 size-[156px] flex-none" role="img" aria-label={label}>
      <ChartContainer config={config} className="aspect-square size-[156px]" initialDimension={{ width: 156, height: 156 }}>
        <PieChart>
          <ChartTooltip
            isAnimationActive={false}
            content={({ active, payload }) => {
              const part = payload?.[0]?.payload as DonutPart | undefined;
              if (!active || !part) return null;
              return (
                <div className="rounded-lg bg-popover px-2.5 py-1.5 text-xs shadow-float">
                  <span className="text-fg-2">{part.label}</span>{" "}
                  <span className="font-medium text-foreground tabular-nums">{formatCount(part.value)}</span>
                  <span className="text-muted-foreground"> of {formatCount(total)}</span>
                </div>
              );
            }}
          />
          <Pie
            data={total > 0 ? drawn : [{ key: "empty", label: "None", value: 1, color: "var(--xq-hairline)" }]}
            dataKey="value"
            nameKey="label"
            innerRadius={58}
            outerRadius={74}
            paddingAngle={drawn.length > 1 ? 2 : 0}
            cornerRadius={3}
            startAngle={90}
            endAngle={-270}
            stroke="none"
            isAnimationActive={false}
          >
            {(total > 0 ? drawn : [{ key: "empty", color: "var(--xq-hairline)" }]).map((p) => (
              <Cell key={p.key} fill={p.color} />
            ))}
          </Pie>
        </PieChart>
      </ChartContainer>
      <figcaption className="absolute inset-[26px] flex flex-col items-center justify-center rounded-full text-center">
        <span className="text-xl leading-none font-semibold tracking-tight text-foreground tabular-nums">{centerValue}</span>
        <span className="mt-1 max-w-[96px] text-xs leading-tight text-muted-foreground">{centerLabel}</span>
      </figcaption>
    </figure>
  );
}

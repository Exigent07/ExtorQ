import { cn } from "cn";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Card } from "@/components/ui/card";
import { formatCount } from "@/lib/format";

import { StatusDot, type Tone } from "./status-badge";

/**
 * A headline figure on a shadcn Card: label, a 30px semibold value (proportional figures), an optional unit or denominator
 * in grey, one sub-label that states what the number is made of, an optional visual on the
 * right (coverage mark, split bar) and an optional status dot with its word.
 *
 * Values come from the API as they are: pass the DASH for unknown, a real 0 for zero. No
 * delta unless the API gives a comparable earlier value. With `href` the whole card is a link.
 */
export function KpiCard({
  label,
  value,
  unit,
  sub,
  status,
  visual,
  footer,
  icon: Icon,
  href,
  className,
}: {
  label: string;
  value: ReactNode;
  unit?: ReactNode;
  sub?: ReactNode;
  status?: { tone: Tone; label: string };
  visual?: ReactNode;
  /** Full-width element under the figure (e.g. a severity split bar). */
  footer?: ReactNode;
  icon?: LucideIcon;
  href?: string;
  className?: string;
}) {
  return (
    <Card
      className={cn(
        // Phones: a compact two-column grid (label and figure; status, bar and sub-label from sm).
        "group/kpi relative min-w-0 gap-3 overflow-visible px-4 text-base transition-colors duration-150 max-sm:[--card-spacing:--spacing(4)] sm:px-5",
        href && "hover:bg-[color-mix(in_oklab,var(--card),white_2%)] focus-within:ring-ring/60",
        className,
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <p className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground">
          {Icon ? <Icon className="size-4 flex-none" strokeWidth={1.75} aria-hidden="true" /> : null}
          <span className="truncate">{label}</span>
        </p>
        {status ? <StatusDot tone={status.tone} label={status.label} className="text-xs max-sm:hidden" /> : null}
      </div>
      <div className="flex min-h-8 items-center justify-between gap-4">
        <p className="flex min-w-0 flex-wrap items-baseline gap-x-1.5">
          <span className="text-2xl leading-none font-semibold tracking-tight text-foreground proportional-nums sm:text-3xl">{value}</span>
          {unit ? <span className="text-sm text-muted-foreground tabular-nums sm:text-base">{unit}</span> : null}
        </p>
        {visual ? <div className="flex-none max-sm:hidden">{visual}</div> : null}
      </div>
      {/* The footer slot is reserved, so bars and sub-labels line up across a KPI row. */}
      <div className="flex h-1.5 items-center max-sm:hidden">{footer ?? null}</div>
      {sub ? <div className="min-w-0 truncate text-sm leading-relaxed text-muted-foreground max-sm:hidden">{sub}</div> : null}
      {href ? (
        <Link
          href={href}
          aria-label={`${label}: details`}
          className="absolute inset-0 rounded-xl outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
        />
      ) : null}
    </Card>
  );
}

/**
 * The parts of a KPI figure on one line ("45 critical · 795 high · 5 unverified"): the KPI
 * sub-label truncates, it never wraps. `strong` lifts a non-zero count to the foreground;
 * `tone` colours a non-zero count that is a problem; `hideZero` leaves zero parts out.
 */
export function KpiFigures({
  items,
  hideZero = false,
}: {
  items: { label: string; value: number; strong?: boolean; tone?: "warn" | "bad" }[];
  hideZero?: boolean;
}) {
  const shown = hideZero ? items.filter((item) => item.value > 0) : items;
  return (
    <>
      {shown.map((item, index) => (
        <span key={item.label}>
          {index > 0 ? <span className="text-fg-faint"> · </span> : null}
          <span
            className={cn(
              "tabular-nums",
              item.value > 0 && item.tone === "bad"
                ? "font-medium text-health-bad"
                : item.value > 0 && item.tone === "warn"
                  ? "font-medium text-health-warn"
                  : item.value > 0 && item.strong
                    ? "text-foreground"
                    : "text-fg-2",
            )}
          >
            {formatCount(item.value)}
          </span>{" "}
          {item.label}
        </span>
      ))}
    </>
  );
}

/**
 * "15 / 84": the one way the console writes a part of a whole (KPI units, donut centres, class
 * rows); the denominator is muted. Numbers are formatted here, so pass raw counts.
 */
export function Fraction({ value, total, className }: { value: number; total: number; className?: string }) {
  return (
    <span className={cn("whitespace-nowrap tabular-nums", className)}>
      {formatCount(value)}
      <span className="text-muted-foreground"> / {formatCount(total)}</span>
    </span>
  );
}

/**
 * A proportional split bar (parts of one total), 6px tall with 2px seams. Zero parts are
 * omitted; an all-zero total draws the empty track. Pair it with the parts in words.
 */
export function SplitBar({
  parts,
  label,
  className,
}: {
  parts: { key: string; value: number; className: string }[];
  /** Accessible description, e.g. "4 high, 8 medium, 2 low". */
  label: string;
  className?: string;
}) {
  const total = parts.reduce((sum, part) => sum + Math.max(0, part.value), 0);
  return (
    <div role="img" aria-label={label} className={cn("flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full bg-hairline", className)}>
      {total > 0
        ? parts
            .filter((part) => part.value > 0)
            .map((part) => (
              <span
                key={part.key}
                className={cn("h-full first:rounded-l-full last:rounded-r-full", part.className)}
                style={{ width: `${(part.value / total) * 100}%` }}
              />
            ))
        : null}
    </div>
  );
}

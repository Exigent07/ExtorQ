import { cn } from "cn";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Card } from "@/components/ui/card";

import { StatusDot, type Tone } from "./status-badge";

/**
 * A headline figure on a shadcn Card: label, a 30px semibold value (tabular), an optional unit or denominator
 * in grey, one sub-label that states what the number is made of, an optional visual on the
 * right (sparkline, coverage mark, split bar) and an optional status dot with its word.
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
        "group/kpi relative min-w-0 gap-3 overflow-visible px-5 text-base transition-colors duration-150",
        href && "hover:bg-[color-mix(in_oklab,var(--card),white_2%)] focus-within:ring-ring/60",
        className,
      )}
    >
      <div className="flex items-center justify-between gap-3">
        <p className="flex min-w-0 items-center gap-2 text-sm text-muted-foreground">
          {Icon ? <Icon className="size-4 flex-none" strokeWidth={1.75} aria-hidden="true" /> : null}
          <span className="truncate">{label}</span>
        </p>
        {status ? <StatusDot tone={status.tone} label={status.label} className="text-xs" /> : null}
      </div>
      <div className="flex items-end justify-between gap-4">
        <p className="flex min-w-0 items-baseline gap-1.5">
          <span className="text-3xl leading-none font-semibold tracking-tight text-foreground tabular-nums">{value}</span>
          {unit ? <span className="text-base text-muted-foreground tabular-nums">{unit}</span> : null}
        </p>
        {visual ? <div className="flex-none">{visual}</div> : null}
      </div>
      {footer ? <div>{footer}</div> : null}
      {sub ? <div className="mt-auto text-sm leading-relaxed text-muted-foreground">{sub}</div> : null}
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

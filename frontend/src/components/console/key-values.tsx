import { cn } from "cn";
import type { ReactNode } from "react";

/**
 * Key/value rows (detail rails, sheets, cards): label left in grey, value right-aligned in
 * secondary ink, 1px rules between rows. Missing values are the caller's DASH, never "".
 */
export function KeyValueList({
  rows,
  className,
  layout = "split",
}: {
  rows: { label: string; value: ReactNode }[];
  className?: string;
  /** "split": label left, value right; "stacked": label above value (narrow rails, long values). */
  layout?: "split" | "stacked";
}) {
  return (
    <dl className={cn("divide-y divide-hairline-soft", className)}>
      {rows.map((row) =>
        layout === "stacked" ? (
          <div key={row.label} className="grid gap-1 py-2.5">
            <dt className="text-xs text-muted-foreground">{row.label}</dt>
            <dd className="min-w-0 text-sm break-words text-fg-2">{row.value}</dd>
          </div>
        ) : (
          <div key={row.label} className="flex min-h-9 items-start justify-between gap-4 py-2">
            <dt className="flex-none pt-px text-sm text-muted-foreground">{row.label}</dt>
            <dd className="min-w-0 text-right text-sm break-words text-fg-2">{row.value}</dd>
          </div>
        ),
      )}
    </dl>
  );
}

/**
 * A strip of headline figures inside one card, split by hairlines (label over value). Used by
 * detail pages; the Overview uses KpiCard.
 */
export function MetricStrip({
  items,
  className,
}: {
  items: { label: string; value: ReactNode; sub?: ReactNode }[];
  className?: string;
}) {
  return (
    <dl
      className={cn(
        "grid grid-cols-2 gap-y-5 rounded-xl bg-card py-5 shadow-card ring-1 ring-hairline sm:flex sm:flex-wrap sm:gap-y-4",
        className,
      )}
    >
      {items.map((item, index) => (
        <div key={item.label} className={cn("min-w-0 px-5 sm:flex-1", index > 0 && "sm:border-l sm:border-hairline-soft")}>
          <dt className="text-sm text-muted-foreground">{item.label}</dt>
          <dd className="mt-1.5 text-xl font-semibold tracking-tight text-foreground tabular-nums">{item.value}</dd>
          {item.sub ? <dd className="mt-1 text-xs text-muted-foreground">{item.sub}</dd> : null}
        </div>
      ))}
    </dl>
  );
}

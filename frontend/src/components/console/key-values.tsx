import { cn } from "cn";
import type { ReactNode } from "react";

/** Label-over-value strip split by 1px dividers (KPIs as type, not tiles). */
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
        "grid grid-cols-2 gap-y-4 rounded-md border border-border bg-surface py-4 sm:flex sm:flex-wrap sm:gap-y-3",
        className,
      )}
    >
      {items.map((item, index) => (
        <div
          key={item.label}
          className={cn(
            "min-w-0 px-5 sm:flex-1",
            index > 0 && "sm:border-l sm:border-border",
          )}
        >
          <dt className="text-xs text-muted-foreground">{item.label}</dt>
          <dd className="mt-1 text-lg text-ink">{item.value}</dd>
          {item.sub ? <dd className="mt-0.5 text-xs text-muted-foreground">{item.sub}</dd> : null}
        </div>
      ))}
    </dl>
  );
}

/** Key/value rows inside a panel (28px pitch, label left, value right). */
export function KeyValueList({
  rows,
  className,
}: {
  rows: { label: string; value: ReactNode }[];
  className?: string;
}) {
  return (
    <dl className={cn("divide-y divide-rule", className)}>
      {rows.map((row) => (
        <div key={row.label} className="flex min-h-8 items-start justify-between gap-4 py-1.5">
          <dt className="flex-none text-xs text-muted-foreground">{row.label}</dt>
          <dd className="min-w-0 text-right text-sm text-ink-2">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

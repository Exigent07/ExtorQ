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


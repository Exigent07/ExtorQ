import { cn } from "cn";

/**
 * Loading states: the final layout with each value replaced by a flat grey bar at its real
 * size. No shimmer, no layout shift when the data lands; labels are not invented.
 */
export function Bar({ className }: { className?: string }) {
  return <span aria-hidden="true" className={cn("block rounded-sm bg-raised", className)} />;
}

export function PanelSkeleton({
  rows = 4,
  className,
  tall = false,
}: {
  rows?: number;
  className?: string;
  tall?: boolean;
}) {
  return (
    <div aria-hidden="true" className={cn("rounded-md border border-border bg-surface px-5 pt-4 pb-5", className)}>
      <Bar className="h-5 w-40" />
      <div className={cn("mt-4 flex flex-col", tall ? "gap-4" : "gap-3")}>
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex items-center gap-4">
            <Bar className="h-4 w-16" />
            <Bar className={cn("h-4 flex-1", i % 2 ? "max-w-[60%]" : "max-w-[80%]")} />
            <Bar className="h-4 w-14" />
          </div>
        ))}
      </div>
    </div>
  );
}

/** Page-level skeleton: the title row, an optional strip and a set of panels. */
export function PageSkeleton({
  label,
  strip = false,
  panels = 2,
  columns = 1,
}: {
  label: string;
  strip?: boolean;
  panels?: number;
  columns?: 1 | 2 | 3;
}) {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading {label}</span>
      <div aria-hidden="true" className="pt-6 pb-6 lg:pt-8">
        <Bar className="h-3 w-32" />
        <Bar className="mt-3 h-7 w-56" />
        <Bar className="mt-3 h-4 w-96 max-w-full" />
      </div>
      {strip ? (
        <div aria-hidden="true" className="mb-6 grid grid-cols-2 gap-4 rounded-md border border-border bg-surface p-5 sm:grid-cols-4">
          {Array.from({ length: 4 }, (_, i) => (
            <div key={i}>
              <Bar className="h-3 w-20" />
              <Bar className="mt-2 h-6 w-24" />
            </div>
          ))}
        </div>
      ) : null}
      <div
        className={cn(
          "grid gap-6",
          columns === 2 && "xl:grid-cols-2",
          columns === 3 && "xl:grid-cols-3",
        )}
      >
        {Array.from({ length: panels }, (_, i) => (
          <PanelSkeleton key={i} rows={i === 0 ? 6 : 4} />
        ))}
      </div>
    </div>
  );
}

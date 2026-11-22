import { cn } from "cn";

/**
 * Loading states: the final layout with each value replaced by a flat bar at its real size.
 * No shimmer and no pulse; no layout shift when the data lands; labels are not invented.
 */
export function Bar({ className }: { className?: string }) {
  return <span aria-hidden="true" className={cn("block rounded-md bg-white/[0.05]", className)} />;
}

function CardFrame({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div aria-hidden="true" className={cn("rounded-xl bg-card shadow-card ring-1 ring-hairline", className)}>
      {children}
    </div>
  );
}

/** Title row placeholder (24px title + subtitle). */
export function HeaderSkeleton() {
  return (
    <div aria-hidden="true" className="pt-7 pb-6">
      <Bar className="h-7 w-48" />
      <Bar className="mt-3 h-4 w-[28rem] max-w-full" />
    </div>
  );
}

/** A row of KPI cards. */
export function KpiRowSkeleton({ count = 4 }: { count?: number }) {
  return (
    <div className={cn("grid gap-4 sm:grid-cols-2", count === 4 && "xl:grid-cols-4", count === 3 && "xl:grid-cols-3")}>
      {Array.from({ length: count }, (_, i) => (
        <CardFrame key={i} className="p-5">
          <Bar className="h-4 w-28" />
          <Bar className="mt-4 h-8 w-20" />
          <Bar className="mt-4 h-3 w-40" />
        </CardFrame>
      ))}
    </div>
  );
}

/** A card with a chart area of the given height. */
export function ChartSkeleton({ height = 240, className }: { height?: number; className?: string }) {
  return (
    <CardFrame className={cn("p-5", className)}>
      <Bar className="h-4 w-40" />
      <Bar className="mt-2 h-3 w-56" />
      <Bar className="mt-5 w-full" />
      <span aria-hidden="true" className="mt-5 block rounded-lg bg-white/[0.03]" style={{ height }} />
    </CardFrame>
  );
}

/** A card with table rows at the real 44px pitch. */
export function TableSkeleton({ rows = 6, className }: { rows?: number; className?: string }) {
  return (
    <CardFrame className={cn("px-5 pt-4 pb-3", className)}>
      <Bar className="h-4 w-44" />
      <div className="mt-4 divide-y divide-hairline-soft">
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex h-11 items-center gap-4">
            <Bar className="h-5 w-16" />
            <Bar className={cn("h-3.5 flex-1", i % 2 ? "max-w-[55%]" : "max-w-[70%]")} />
            <Bar className="h-3.5 w-16" />
          </div>
        ))}
      </div>
    </CardFrame>
  );
}

/** Generic card with label/value rows. */
export function PanelSkeleton({ rows = 4, className, tall = false }: { rows?: number; className?: string; tall?: boolean }) {
  return (
    <CardFrame className={cn("px-5 pt-4 pb-5", className)}>
      <Bar className="h-4 w-40" />
      <div className={cn("mt-4 flex flex-col", tall ? "gap-4" : "gap-3")}>
        {Array.from({ length: rows }, (_, i) => (
          <div key={i} className="flex items-center gap-4">
            <Bar className="h-4 w-16" />
            <Bar className={cn("h-4 flex-1", i % 2 ? "max-w-[60%]" : "max-w-[80%]")} />
            <Bar className="h-4 w-14" />
          </div>
        ))}
      </div>
    </CardFrame>
  );
}

/** Page-level skeleton: the title row, an optional KPI strip and a set of cards. */
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
      <HeaderSkeleton />
      {strip ? (
        <div className="mb-6">
          <KpiRowSkeleton />
        </div>
      ) : null}
      <div className={cn("grid gap-6", columns === 2 && "xl:grid-cols-2", columns === 3 && "xl:grid-cols-3")}>
        {Array.from({ length: panels }, (_, i) => (
          <PanelSkeleton key={i} rows={i === 0 ? 6 : 4} />
        ))}
      </div>
    </div>
  );
}

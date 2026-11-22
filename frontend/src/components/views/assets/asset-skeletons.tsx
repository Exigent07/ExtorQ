import { cn } from "cn";

import { Bar, HeaderSkeleton, KpiRowSkeleton, PanelSkeleton, TableSkeleton } from "@/components/console/skeletons";

/** One asset card at its real size: header, metric well, two bar rows, footer. */
export function AssetCardSkeleton({ className }: { className?: string }) {
  return (
    <div aria-hidden="true" className={cn("flex flex-col rounded-xl bg-card shadow-card ring-1 ring-hairline", className)}>
      <div className="flex items-start gap-3 px-5 pt-5">
        <Bar className="size-9 rounded-lg" />
        <div className="flex-1">
          <Bar className="h-4 w-44" />
          <Bar className="mt-2 h-3 w-56" />
        </div>
        <Bar className="h-3 w-16" />
      </div>
      <Bar className="mx-5 mt-4 h-[62px] rounded-lg bg-white/[0.03]" />
      <div className="grid gap-4 px-5 pt-4 pb-5">
        {[0, 1].map((i) => (
          <div key={i} className="grid gap-1.5">
            <div className="flex justify-between">
              <Bar className="h-3 w-24" />
              <Bar className="h-3 w-16" />
            </div>
            <Bar className="h-1.5 w-full rounded-full" />
            <Bar className="h-3 w-48" />
          </div>
        ))}
      </div>
      <div className="mt-auto flex h-11 items-center justify-between border-t border-hairline-soft px-5">
        <Bar className="h-3 w-40" />
        <Bar className="h-3 w-10" />
      </div>
    </div>
  );
}

/**
 * A detail page (asset or service) while it loads: title with its icon tile, the identity
 * card, the tab rule, then a KPI row (asset) and a main column with a rail of cards.
 */
export function DetailPageSkeleton({ label, figures = 0, kpis = false }: { label: string; figures?: number; kpis?: boolean }) {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading {label}</span>
      <div aria-hidden="true" className="flex items-center gap-3 pt-7">
        <Bar className="size-10 rounded-[10px]" />
        <Bar className="h-7 w-72" />
      </div>
      <Bar className="mt-3 mb-6 h-4 w-[30rem] max-w-full" />
      <div aria-hidden="true" className="mb-6 rounded-xl bg-card shadow-card ring-1 ring-hairline">
        <div className="grid grid-cols-2 gap-x-6 gap-y-4 px-5 py-4 lg:grid-cols-5">
          {Array.from({ length: 10 }, (_, i) => (
            <div key={i}>
              <Bar className="h-3 w-16" />
              <Bar className="mt-2 h-4 w-28" />
            </div>
          ))}
        </div>
        {figures > 0 ? (
          <div className="flex border-t border-hairline-soft">
            {Array.from({ length: figures }, (_, i) => (
              <div key={i} className="flex-1 px-5 py-3.5">
                <Bar className="h-3 w-16" />
                <Bar className="mt-2 h-6 w-12" />
              </div>
            ))}
          </div>
        ) : null}
      </div>
      <div aria-hidden="true" className="mb-6 flex h-10 items-center gap-6 border-b border-hairline">
        {[64, 80, 64, 56].map((width, i) => (
          <span key={i} className="block" style={{ width }}>
            <Bar className="h-3.5" />
          </span>
        ))}
      </div>
      {kpis ? (
        <div className="mb-6">
          <KpiRowSkeleton />
        </div>
      ) : null}
      <div className="grid gap-6 xl:grid-cols-12">
        <div className="grid content-start gap-6 xl:col-span-8">
          <TableSkeleton rows={4} />
          <TableSkeleton rows={5} />
        </div>
        <div className="grid content-start gap-6 xl:col-span-4">
          <PanelSkeleton rows={5} />
          <PanelSkeleton rows={4} />
        </div>
      </div>
    </div>
  );
}

/** The Assets page while it loads: title, then the class groups with their cards. */
export function AssetsPageSkeleton() {
  const groups = [1, 1, 2, 4];
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading the asset inventory</span>
      <HeaderSkeleton />
      <div className="grid gap-x-6 gap-y-10 lg:grid-cols-2">
        {groups.map((cards, i) => (
          <div key={i} className={cn("grid content-start gap-3", cards > 1 && "lg:col-span-2")}>
            <Bar className="h-5 w-48" />
            <div className={cn("grid gap-4", cards > 1 && "lg:grid-cols-2")}>
              {Array.from({ length: cards }, (_, j) => (
                <AssetCardSkeleton key={j} />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

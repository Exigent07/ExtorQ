import { cn } from "cn";

import { Bar, HeaderSkeleton, PanelSkeleton, TableSkeleton } from "@/components/console/skeletons";

/** System health loading state: the final layout (KPI row, collectors, pipeline, rules + side cards). */
export default function Loading() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading system health</span>
      <HeaderSkeleton />
      <div className="grid gap-6">
        <div aria-hidden="true" className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6 xl:grid-cols-5">
          {Array.from({ length: 5 }, (_, i) => (
            <div
              key={i}
              className={cn(
                "rounded-xl bg-card p-5 shadow-card ring-1 ring-hairline xl:col-span-1",
                i < 3 ? "lg:col-span-2" : "lg:col-span-3",
                i === 4 && "sm:col-span-2",
              )}
            >
              <Bar className="h-4 w-24" />
              <Bar className="mt-4 h-8 w-16" />
              <Bar className="mt-4 h-1.5 w-full" />
              <Bar className="mt-4 h-3 w-32" />
            </div>
          ))}
        </div>
        <TableSkeleton rows={8} />
        <TableSkeleton rows={4} />
        <div className="grid gap-6 xl:grid-cols-12">
          <TableSkeleton rows={6} className="xl:col-span-8" />
          <div className="grid content-start gap-6 xl:col-span-4">
            <PanelSkeleton rows={3} />
            <PanelSkeleton rows={4} />
          </div>
        </div>
      </div>
    </div>
  );
}

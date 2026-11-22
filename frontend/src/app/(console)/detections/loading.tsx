import { Bar, HeaderSkeleton, KpiRowSkeleton, TableSkeleton } from "@/components/console/skeletons";

/** Detections loading state: the final layout (header, KPI row, tabs, alert table) at real sizes. */
export default function Loading() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading detections</span>
      <HeaderSkeleton />
      <div className="grid gap-6">
        <KpiRowSkeleton count={4} />
        <div aria-hidden="true" className="flex h-10 items-center gap-6 border-b border-hairline px-3">
          <Bar className="h-4 w-20" />
          <Bar className="h-4 w-16" />
        </div>
        <TableSkeleton rows={8} />
      </div>
    </div>
  );
}

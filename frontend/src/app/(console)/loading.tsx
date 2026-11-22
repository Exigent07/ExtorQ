import { ChartSkeleton, HeaderSkeleton, KpiRowSkeleton, PanelSkeleton, TableSkeleton } from "@/components/console/skeletons";

/** Overview loading state: the final layout with flat bars (no shimmer, no layout shift). */
export default function Loading() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading the overview</span>
      <HeaderSkeleton />
      <div className="grid gap-6">
        <KpiRowSkeleton />
        <div className="grid gap-6 xl:grid-cols-12">
          <ChartSkeleton height={208} className="xl:col-span-8" />
          <PanelSkeleton rows={4} tall className="xl:col-span-4" />
        </div>
        <div className="grid gap-6 xl:grid-cols-12">
          <TableSkeleton rows={6} className="xl:col-span-8" />
          <PanelSkeleton rows={6} className="xl:col-span-4" />
        </div>
      </div>
    </div>
  );
}

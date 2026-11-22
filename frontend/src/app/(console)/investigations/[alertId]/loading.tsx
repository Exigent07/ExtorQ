import { cn } from "cn";
import type { ReactNode } from "react";

import { Bar } from "@/components/console/skeletons";

function Frame({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("rounded-xl bg-card shadow-card ring-1 ring-hairline", className)}>{children}</div>;
}

/**
 * The investigation's final layout with flat bars at real sizes (no shimmer, no invented
 * labels): header card with its facts strip, the tab bar, the first panel and the right rail.
 */
export default function Loading() {
  return (
    <div role="status" aria-live="polite" aria-busy="true">
      <span className="sr-only">Loading the investigation</span>
      <Frame className="mt-7">
        <div className="flex gap-4 px-6 pt-5 pb-6">
          <Bar className="hidden size-10 flex-none rounded-lg sm:block" />
          <div className="min-w-0 flex-1">
            <Bar className="h-3.5 w-64 max-w-full" />
            <Bar className="mt-3 h-7 w-[28rem] max-w-full" />
            <div className="mt-3.5 flex gap-2">
              <Bar className="h-6 w-20" />
              <Bar className="h-6 w-24" />
              <Bar className="h-6 w-16" />
            </div>
          </div>
          <Bar className="hidden h-9 w-28 lg:block" />
        </div>
        <div className="grid grid-cols-2 border-t border-hairline-soft lg:grid-cols-5 lg:divide-x lg:divide-hairline-soft">
          {Array.from({ length: 5 }, (_, i) => (
            <div key={i} className={cn("px-6 py-4", i > 1 && "hidden lg:block")}>
              <Bar className="h-3 w-24" />
              <Bar className="mt-2.5 h-5 w-32 max-w-full" />
              <Bar className="mt-2 h-3 w-20" />
            </div>
          ))}
        </div>
      </Frame>
      <div className="mt-6 grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_19rem] 2xl:grid-cols-[minmax(0,1fr)_21rem]">
        <div className="min-w-0">
          <div className="flex h-10 items-center gap-6 border-b border-hairline px-3">
            {["w-16", "w-20", "w-20", "w-24", "w-8", "w-16"].map((width, i) => (
              <Bar key={i} className={cn("h-3.5", width)} />
            ))}
          </div>
          <Frame className="mt-6 px-5 pt-4 pb-5">
            <Bar className="h-4 w-44" />
            <Bar className="mt-2 h-3 w-80 max-w-full" />
            <div className="mt-5 grid gap-2.5">
              <Bar className="h-4 w-full" />
              <Bar className="h-4 w-[92%]" />
              <Bar className="h-4 w-[70%]" />
            </div>
            <Bar className="mt-5 h-20 w-full rounded-lg" />
          </Frame>
          <Frame className="mt-6 px-5 pt-4 pb-5">
            <Bar className="h-4 w-40" />
            <div className="mt-5 grid gap-x-10 gap-y-3 sm:grid-cols-2">
              {Array.from({ length: 8 }, (_, i) => (
                <div key={i} className="flex items-center justify-between gap-4">
                  <Bar className="h-3.5 w-32" />
                  <Bar className="h-3.5 w-10" />
                </div>
              ))}
            </div>
          </Frame>
        </div>
        <div className="grid gap-6">
          <Frame className="px-5 pt-4 pb-5">
            <Bar className="h-4 w-32" />
            <Bar className="mt-5 h-3.5 w-full" />
            <Bar className="mt-3 h-3.5 w-3/4" />
            <Bar className="mt-6 h-8 w-full rounded-lg" />
            <Bar className="mt-3 h-20 w-full rounded-lg" />
            <Bar className="mt-3 h-8 w-28 rounded-lg" />
          </Frame>
          <Frame className="px-5 pt-4 pb-5">
            <Bar className="h-4 w-24" />
            <div className="mt-5 grid gap-3.5">
              {Array.from({ length: 6 }, (_, i) => (
                <div key={i} className="flex items-center justify-between gap-4">
                  <Bar className="h-3.5 w-20" />
                  <Bar className="h-3.5 w-24" />
                </div>
              ))}
            </div>
          </Frame>
        </div>
      </div>
    </div>
  );
}

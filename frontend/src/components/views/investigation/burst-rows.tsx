"use client";

import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { formatCount } from "@/lib/format";

/**
 * A folded burst (same kind, event type and source within short gaps): its one-line summary
 * with the expander at the right end ("9 ›"), closed by default; opening lists every
 * observation of the burst below. Rows are server-rendered children.
 */
export function BurstRows({ summary, count, children }: { summary: ReactNode; count: number; children: ReactNode }) {
  return (
    <Collapsible className="group/burst">
      <div className="flex min-w-0 items-baseline gap-3">
        <div className="min-w-0 flex-1">{summary}</div>
        <CollapsibleTrigger
          aria-label={`Show the ${formatCount(count)} observations`}
          className="inline-flex flex-none items-center gap-0.5 rounded-sm text-xs text-muted-foreground tabular-nums transition-colors duration-150 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          {formatCount(count)}
          <ChevronRight className="size-3.5 transition-transform duration-150 group-data-[state=open]/burst:rotate-90" aria-hidden="true" />
        </CollapsibleTrigger>
      </div>
      <CollapsibleContent>
        <ol className="mt-2 divide-y divide-hairline-soft rounded-lg bg-white/[0.015] ring-1 ring-hairline ring-inset">{children}</ol>
      </CollapsibleContent>
    </Collapsible>
  );
}

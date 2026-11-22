"use client";

import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { formatCount } from "@/lib/format";

/**
 * The rows of a folded burst (same kind, event type and source within short gaps): closed by
 * default, one click lists every observation of the burst. Rows are server-rendered children.
 */
export function BurstRows({ count, children }: { count: number; children: ReactNode }) {
  return (
    <Collapsible className="group/burst mt-1.5">
      <CollapsibleTrigger className="inline-flex items-center gap-1 rounded-sm text-xs text-muted-foreground transition-colors duration-150 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none">
        <ChevronRight className="size-3.5 transition-transform duration-150 group-data-[state=open]/burst:rotate-90" aria-hidden="true" />
        <span className="group-data-[state=open]/burst:hidden">Show the {formatCount(count)} observations</span>
        <span className="hidden group-data-[state=open]/burst:inline">Hide the observations</span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <ol className="mt-2 divide-y divide-hairline-soft rounded-lg bg-white/[0.015] ring-1 ring-hairline ring-inset">{children}</ol>
      </CollapsibleContent>
    </Collapsible>
  );
}

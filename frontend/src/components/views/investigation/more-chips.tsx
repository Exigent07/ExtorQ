"use client";

import type { ReactNode } from "react";

import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { formatCount } from "@/lib/format";

/**
 * The "+N more" chip of a capped chip list: the remaining items appear in a hover card on
 * hover or keyboard focus, so nothing is hidden. `children` are the remaining chips (already
 * rendered through UntrustedText by the caller).
 */
export function MoreChips({ count, title, children }: { count: number; title: string; children: ReactNode }) {
  return (
    <HoverCard openDelay={200} closeDelay={80}>
      <HoverCardTrigger asChild>
        <span
          tabIndex={0}
          className="inline-flex min-h-6 items-center rounded-md px-1.5 text-xs text-muted-foreground ring-1 ring-hairline-strong ring-inset outline-none transition-colors duration-150 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          +{formatCount(count)} more
        </span>
      </HoverCardTrigger>
      <HoverCardContent align="end" className="w-[min(28rem,calc(100vw-2rem))] p-0">
        <p className="border-b border-hairline px-3 py-2 text-xs text-muted-foreground">{title}</p>
        <div className="flex max-h-72 flex-wrap gap-1 overflow-y-auto p-3">{children}</div>
      </HoverCardContent>
    </HoverCard>
  );
}

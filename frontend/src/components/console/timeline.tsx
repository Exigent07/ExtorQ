import { cn } from "cn";
import type { ReactNode } from "react";

import { formatUtc } from "@/lib/format";

import { Hint } from "./hint";

/**
 * How an observation relates to the alert (contracts/context.py) plus "evidence" for events
 * the rule cited. Told by the marker's fill and outline AND by a word: never colour alone.
 */
export const TIMELINE_MARK: Record<string, { label: string; marker: string; hint: string }> = {
  evidence: {
    label: "Evidence",
    marker: "bg-brand ring-brand/30",
    hint: "Cited by the detection rule as evidence for this alert.",
  },
  direct: {
    label: "Direct",
    marker: "bg-foreground ring-white/20",
    hint: "A verified shared identifier links this event to the alert.",
  },
  candidate: {
    label: "Candidate",
    marker: "bg-canvas ring-fg-2 [outline:1px_dashed_var(--xq-fg-2)] outline-offset-1",
    hint: "Plausible but inferred: same asset and time window plus a shared non-identifying attribute.",
  },
  unestablished: {
    label: "Unestablished",
    marker: "bg-canvas ring-fg-faint",
    hint: "Considered for completeness; no supported link exists. Temporal proximity is not causation.",
  },
};

export interface TimelineItem {
  id: string;
  /** ISO time; shown in UTC. */
  time: string | null;
  /** evidence | direct | candidate | unestablished (unknown tokens shown as themselves). */
  kind: string;
  title: ReactNode;
  description?: ReactNode;
  meta?: ReactNode;
  /** Optional anchor id (e.g. `evidence-<event_id>`) so chips can jump to the row. */
  anchorId?: string;
}

/**
 * Vertical timeline with relationship-coded markers (filled brand = evidence, filled white =
 * direct, dashed outline = candidate, faint outline = unestablished) on a 1px rail. Times in
 * UTC in the figure face. Server-renderable.
 */
export function Timeline({ items, className }: { items: TimelineItem[]; className?: string }) {
  return (
    <ol className={cn("relative grid gap-0", className)}>
      {items.map((item, index) => {
        const mark = TIMELINE_MARK[item.kind];
        return (
          <li key={item.id} id={item.anchorId} className="evidence-row relative grid grid-cols-[20px_minmax(0,1fr)] gap-x-3 rounded-md pb-5 last:pb-0">
            {index < items.length - 1 ? (
              <span aria-hidden="true" className="absolute top-4 bottom-0 left-[9.5px] w-px bg-hairline-strong" />
            ) : null}
            <span className="relative flex h-5 items-center justify-center">
              <span
                aria-hidden="true"
                className={cn("size-2.5 rounded-full ring-2", mark?.marker ?? "bg-canvas ring-fg-faint")}
              />
            </span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                <time dateTime={item.time ?? undefined} className="font-mono text-xs text-muted-foreground tabular-nums">
                  {formatUtc(item.time)}
                </time>
                <Hint content={mark?.hint ?? "Relationship type reported by the correlation layer."}>
                  <span className="text-xs text-fg-2">{mark?.label ?? item.kind}</span>
                </Hint>
                {item.meta}
              </div>
              <div className="mt-1 text-sm text-foreground">{item.title}</div>
              {item.description ? <div className="mt-0.5 text-xs text-muted-foreground">{item.description}</div> : null}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

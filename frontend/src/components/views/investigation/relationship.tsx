"use client";

import { cn } from "cn";
import type { ReactNode } from "react";

import { TIMELINE_MARK } from "@/components/console/timeline";
import { UntrustedText } from "@/components/console/untrusted-text";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";

import { basisLabel, orderedBases, relationshipDetail, relationshipLabel, strengthLabel } from "./labels";
import { offsetLabel } from "./model";

/** The relationship marker (same marks as the timeline: brand, white, dashed, faint). */
export function RelationshipMarker({ type, className }: { type: string; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn("inline-block size-2 flex-none rounded-full ring-2", TIMELINE_MARK[type]?.marker ?? "bg-canvas ring-fg-faint", className)}
    />
  );
}

export interface RelationshipDetail {
  type: string;
  strength: string;
  bases: readonly string[];
  offsetSeconds: number;
  /** Written by the correlation layer from telemetry values (untrusted). */
  explanation: string;
}

/**
 * Relationship of an observation to the alert, with the correlation layer's own explanation
 * in a hover card (hover or keyboard focus). The type is told by marker and word; the
 * explanation is untrusted text, so it never goes into a tooltip or title attribute.
 */
export function RelationshipHover({
  rel,
  children,
  className,
}: {
  rel: RelationshipDetail;
  /** The trigger (defaults to marker + word). */
  children?: ReactNode;
  className?: string;
}) {
  return (
    <HoverCard openDelay={250} closeDelay={80}>
      <HoverCardTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            "inline-flex cursor-help items-center gap-1.5 rounded-md text-xs whitespace-nowrap text-fg-2 underline decoration-fg-faint decoration-dotted underline-offset-4 outline-none transition-colors duration-150 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50",
            className,
          )}
        >
          {children ?? (
            <>
              <RelationshipMarker type={rel.type} />
              {relationshipLabel(rel.type)}
            </>
          )}
        </span>
      </HoverCardTrigger>
      <HoverCardContent align="start" className="w-[min(26rem,calc(100vw-2rem))] p-0">
        <div className="flex items-center gap-2 border-b border-hairline px-3 py-2.5">
          <RelationshipMarker type={rel.type} />
          <span className="text-sm font-medium text-foreground">{relationshipLabel(rel.type)}</span>
          <span className="text-xs text-muted-foreground">
            {strengthLabel(rel.strength)} link · {offsetLabel(rel.offsetSeconds)} from the first evidence
          </span>
        </div>
        <div className="grid gap-2.5 px-3 py-2.5">
          <p className="text-xs leading-relaxed text-muted-foreground">{relationshipDetail(rel.type)}</p>
          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">Why this observation</p>
            <p className="text-sm leading-relaxed text-fg-2">
              <UntrustedText value={rel.explanation} limit={600} />
            </p>
          </div>
          {rel.bases.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {orderedBases(rel.bases).map((basis) => (
                <span
                  key={basis}
                  className={cn(
                    "inline-flex h-5 items-center rounded-md px-1.5 text-xs ring-1 ring-inset",
                    basis === "shared_nat_source_ip"
                      ? "bg-health-warn/[0.06] text-fg-2 ring-health-warn/25"
                      : "bg-white/[0.03] text-fg-2 ring-hairline-strong",
                  )}
                >
                  {basisLabel(basis)}
                </span>
              ))}
            </div>
          ) : null}
          <p className="text-xs text-muted-foreground">Correlation shows co-occurrence and shared attributes; it never establishes causation.</p>
        </div>
      </HoverCardContent>
    </HoverCard>
  );
}

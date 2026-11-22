"use client";

import { cn } from "cn";

import { coverageSwatchClass } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { serviceCoverage } from "@/lib/services";

type CoverageInput = Parameters<typeof serviceCoverage>[0] & {
  coverage_note?: string | null;
  adapter_id?: string | null;
};

/**
 * A service's coverage state as dot + word; on hover or keyboard focus a card says what the
 * state means, lists the API's qualifications and quotes the collector's note. The note is
 * collector-reported text, so it is rendered through UntrustedText inside a hover card (never
 * a tooltip or title). No click target: row links keep working.
 */
export function CoverageCell({ service, className }: { service: CoverageInput; className?: string }) {
  const badge = serviceCoverage(service);
  const meaning = serviceCoverage({ ...service, coverage_reasons: [] }).detail;
  const reasons = service.coverage_reasons ?? [];
  return (
    <HoverCard openDelay={200} closeDelay={80}>
      <HoverCardTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            "inline-flex max-w-full min-w-0 items-center gap-1.5 rounded-md text-xs whitespace-nowrap text-fg-2 decoration-fg-faint decoration-dotted underline-offset-4 outline-none transition-colors duration-150 hover:text-foreground hover:underline focus-visible:ring-2 focus-visible:ring-ring/50",
            className,
          )}
        >
          <span aria-hidden="true" className={cn("size-2 flex-none rounded-full", coverageSwatchClass(badge.kind))} />
          {badge.label}
        </span>
      </HoverCardTrigger>
      <HoverCardContent align="start" collisionPadding={16} className="w-[min(22rem,calc(100vw-2rem))] p-0">
        <div className="grid gap-1 px-3 pt-2.5 pb-2">
          <p className="flex items-center gap-2 text-sm font-medium text-foreground">
            <span aria-hidden="true" className={cn("size-2 flex-none rounded-full", coverageSwatchClass(badge.kind))} />
            {badge.label}
          </p>
          <p className="text-xs leading-relaxed text-muted-foreground">{meaning}</p>
        </div>
        {reasons.length > 0 ? (
          <div className="border-t border-hairline px-3 py-2">
            <p className="text-xs text-muted-foreground">From the API</p>
            <ul className="mt-1 grid gap-0.5 text-xs leading-relaxed text-fg-2">
              {reasons.map((reason) => (
                <li key={reason}>{`${reason.charAt(0).toUpperCase()}${reason.slice(1)}.`}</li>
              ))}
            </ul>
          </div>
        ) : null}
        {service.coverage_note ? (
          <div className="border-t border-hairline px-3 py-2">
            <p className="text-xs text-muted-foreground">Collector note</p>
            <p className="mt-1 text-xs leading-relaxed text-fg-2">
              <UntrustedText value={service.coverage_note} plain limit={400} />
            </p>
          </div>
        ) : null}
      </HoverCardContent>
    </HoverCard>
  );
}

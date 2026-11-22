"use client";

import { cn } from "cn";

import { UntrustedText } from "@/components/console/untrusted-text";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import type { ServiceEndpoint } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { attributionOf, exposureOf } from "@/lib/services";

import { sortEndpoints } from "./model";

/** "0.0.0.0:22/tcp": address as reported (telemetry, plain text), "*" when none was reported. */
function Address({ endpoint, className }: { endpoint: ServiceEndpoint; className?: string }) {
  return (
    <span className={cn("flex min-w-0 items-center font-mono text-xs whitespace-nowrap", className)}>
      {endpoint.address ? (
        <span className="min-w-0 truncate">
          {/* IPv6 in brackets ("[::]:22"), as in URLs; the address itself is shown as reported. */}
          {endpoint.address.includes(":") ? "[" : null}
          <UntrustedText value={endpoint.address} plain limit={48} />
          {endpoint.address.includes(":") ? "]" : null}
        </span>
      ) : (
        <span className="text-muted-foreground">*</span>
      )}
      <span className="flex-none">{`:${endpoint.port}/${endpoint.protocol}`}</span>
    </span>
  );
}

/**
 * Exposure and port attribution in words. "Owner unknown" is printed as such (in the brighter
 * tone, so it is not mistaken for a confirmed owner); all-interfaces exposure is amber.
 */
function ExposureAndOwner({ endpoint }: { endpoint: ServiceEndpoint }) {
  const exposure = exposureOf(endpoint.exposure);
  const attribution = attributionOf(endpoint.attribution);
  const unattributed = endpoint.attribution !== "confirmed" && endpoint.attribution !== "inferred";
  return (
    <span className="flex min-w-0 items-center gap-1.5 text-xs whitespace-nowrap">
      <span className={exposure.tone === "warn" ? "text-health-warn" : "text-muted-foreground"}>{exposure.label}</span>
      <span aria-hidden="true" className="text-fg-faint">
        ·
      </span>
      <span className={cn("truncate", unattributed ? "text-fg-2" : "text-muted-foreground")}>{attribution.label}</span>
    </span>
  );
}

/**
 * The ports of one service in a table cell: the most exposed endpoint on two lines (address,
 * then exposure and owner attribution) and a "+N" count; every endpoint, with what exposure
 * and attribution mean and the attribution basis, in a hover card on hover or keyboard focus.
 */
export function PortsCell({ endpoints }: { endpoints: ServiceEndpoint[] }) {
  if (endpoints.length === 0) return <span className="text-xs text-muted-foreground">None observed</span>;
  const sorted = sortEndpoints(endpoints);
  const first = sorted[0]!;
  return (
    <HoverCard openDelay={200} closeDelay={80}>
      <HoverCardTrigger asChild>
        <span
          tabIndex={0}
          className="grid max-w-full min-w-0 gap-0.5 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          <span className="flex min-w-0 items-center gap-1.5">
            <Address endpoint={first} className="text-fg-2" />
            {sorted.length > 1 ? (
              <span className="inline-flex h-4.5 flex-none items-center rounded px-1 text-xs leading-none text-muted-foreground tabular-nums ring-1 ring-hairline-strong ring-inset">
                +{formatCount(sorted.length - 1)}
                <span className="sr-only"> more endpoint{sorted.length === 2 ? "" : "s"}</span>
              </span>
            ) : null}
          </span>
          <ExposureAndOwner endpoint={first} />
        </span>
      </HoverCardTrigger>
      <HoverCardContent align="end" collisionPadding={16} className="w-[min(30rem,calc(100vw-2rem))] p-0">
        <p className="border-b border-hairline px-3 py-2 text-xs text-muted-foreground">
          {formatCount(sorted.length)} listening endpoint{sorted.length === 1 ? "" : "s"} · widest exposure first · an
          owner is attributed only with evidence
        </p>
        <ul className="max-h-80 divide-y divide-hairline-soft overflow-y-auto">
          {sorted.map((endpoint, i) => {
            const attribution = attributionOf(endpoint.attribution);
            return (
              <li key={`${endpoint.protocol}-${endpoint.address ?? "*"}-${endpoint.port}-${i}`} className="grid gap-1 px-3 py-2">
                <span className="flex min-w-0 items-center justify-between gap-3">
                  <Address endpoint={endpoint} className="text-foreground" />
                  <ExposureAndOwner endpoint={endpoint} />
                </span>
                <span className="text-xs leading-relaxed text-muted-foreground">
                  {attribution.detail}
                  {endpoint.attribution_basis ? (
                    <>
                      {" "}
                      Basis: <UntrustedText value={endpoint.attribution_basis} plain limit={200} />
                    </>
                  ) : null}
                </span>
              </li>
            );
          })}
        </ul>
      </HoverCardContent>
    </HoverCard>
  );
}

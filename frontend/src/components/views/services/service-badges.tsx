import { cn } from "cn";

import { Hint } from "@/components/console/hint";
import { StatusDot, StatusPill } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ServiceEndpoint } from "@/lib/api/schemas";
import { formatDuration } from "@/lib/format";
import { attributionOf, exposureOf, serviceCoverage } from "@/lib/services";

type CoverageInput = Parameters<typeof serviceCoverage>[0];

/**
 * Coverage of one service as a status dot + word, with the meaning in the tooltip. Kept for
 * the Investigation page (`views/investigation/context-sections.tsx` imports it); the asset
 * and service views use the console's CoverageBadge.
 */
export function ServiceCoverageDot({ service, className }: { service: CoverageInput; className?: string }) {
  const badge = serviceCoverage(service);
  return (
    <span title={badge.detail} className={className}>
      <StatusDot tone={badge.tone} label={badge.label} />
    </span>
  );
}

/** Header form of the coverage state, with its meaning and the API's reasons on hover. */
export function ServiceCoveragePill({ service }: { service: CoverageInput }) {
  const badge = serviceCoverage(service);
  return (
    <Hint content={badge.detail}>
      <StatusPill tone={badge.tone} label={badge.label} />
    </Hint>
  );
}

/** Marks a service that is no longer observed (tombstone), never hidden. */
export function RemovedTag() {
  return (
    <Hint content="No longer observed by discovery. Kept for history; its telemetry and findings stay attached.">
      <span className="inline-flex h-5 flex-none items-center rounded-md px-1.5 text-xs whitespace-nowrap text-muted-foreground ring-1 ring-hairline-strong ring-inset">
        Removed
      </span>
    </Hint>
  );
}

/** Discovery has not refreshed this record recently: its current state cannot be confirmed. */
export function ReportStaleTag({ ageSeconds }: { ageSeconds: number }) {
  return (
    <Hint
      content={`Service discovery last refreshed this record ${formatDuration(ageSeconds)} ago, beyond its staleness threshold; its current state cannot be confirmed.`}
    >
      <StatusPill tone="warn" label="Report stale" />
    </Hint>
  );
}

/**
 * One listening endpoint: address:port/protocol, its exposure and how confidently the port is
 * attributed to the service. "Owner unknown" is printed as such, never implied; the basis
 * (telemetry) is shown as text in the full form.
 */
export function EndpointLine({ endpoint, compact = false }: { endpoint: ServiceEndpoint; compact?: boolean }) {
  const exposure = exposureOf(endpoint.exposure);
  const attribution = attributionOf(endpoint.attribution);
  const unattributed = endpoint.attribution !== "confirmed" && endpoint.attribution !== "inferred";
  return (
    <span className={cn("flex min-w-0 flex-col gap-0.5", !compact && "gap-1")}>
      <span className="flex min-w-0 items-center font-mono text-xs whitespace-nowrap text-fg-2">
        {endpoint.address ? (
          <span className="min-w-0 truncate">
            <UntrustedText value={endpoint.address} plain limit={48} />
          </span>
        ) : (
          <span className="text-muted-foreground">*</span>
        )}
        <span className="flex-none">{`:${endpoint.port}/${endpoint.protocol}`}</span>
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-x-1.5 gap-y-0.5 text-xs">
        <Hint content={exposure.detail}>
          <span className={cn("whitespace-nowrap", exposure.tone === "warn" ? "text-health-warn" : "text-muted-foreground")}>
            {exposure.label}
          </span>
        </Hint>
        <span aria-hidden="true" className="text-fg-faint">
          ·
        </span>
        <Hint content={attribution.detail}>
          <span className={cn("whitespace-nowrap", unattributed ? "text-fg-2" : "text-muted-foreground")}>
            {attribution.label}
          </span>
        </Hint>
      </span>
      {!compact && endpoint.attribution_basis ? (
        <span className="min-w-0 text-xs text-muted-foreground">
          <UntrustedText value={endpoint.attribution_basis} oneLine />
        </span>
      ) : null}
    </span>
  );
}

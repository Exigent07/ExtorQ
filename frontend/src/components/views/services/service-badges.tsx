import { cn } from "cn";

import { StatusDot, StatusPill } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ServiceEndpoint } from "@/lib/api/schemas";
import { attributionOf, exposureOf, serviceCoverage } from "@/lib/services";

type CoverageInput = Parameters<typeof serviceCoverage>[0];

/** Coverage of one service as a status dot + word, with the meaning in the tooltip. */
export function ServiceCoverageDot({ service, className }: { service: CoverageInput; className?: string }) {
  const badge = serviceCoverage(service);
  return (
    <span title={badge.detail} className={className}>
      <StatusDot tone={badge.tone} label={badge.label} />
    </span>
  );
}

/** Header form of the coverage state. */
export function ServiceCoveragePill({ service }: { service: CoverageInput }) {
  const badge = serviceCoverage(service);
  return (
    <span title={badge.detail}>
      <StatusPill tone={badge.tone} label={badge.label} />
    </span>
  );
}

/** Marks a service that is no longer observed (tombstone), never hidden. */
export function RemovedTag() {
  return (
    <span
      title="No longer observed by discovery. Kept for history; telemetry and findings remain attached."
      className="inline-flex h-5 flex-none items-center rounded-sm border border-control px-1.5 text-xs whitespace-nowrap text-muted-foreground"
    >
      Removed
    </span>
  );
}

/** Discovery has not refreshed this record recently: its current state cannot be confirmed. */
export function ReportStaleTag({ ageSeconds }: { ageSeconds: number }) {
  const hours = Math.round(ageSeconds / 360) / 10;
  return (
    <span
      title={`Service discovery last refreshed this record ${hours} h ago; its current state cannot be confirmed.`}
      className="inline-flex h-5 flex-none items-center rounded-sm bg-warn-bg px-1.5 text-xs font-medium whitespace-nowrap text-warn"
    >
      Report stale
    </span>
  );
}

/**
 * One listening endpoint: protocol/port and bind address, its exposure and how confidently
 * the port is attributed. An "unknown" attribution is stated as such, never implied.
 */
export function EndpointLine({ endpoint, compact = false }: { endpoint: ServiceEndpoint; compact?: boolean }) {
  const exposure = exposureOf(endpoint.exposure);
  const attribution = attributionOf(endpoint.attribution);
  const unattributed = endpoint.attribution === "unknown";
  return (
    <span className={cn("inline-flex flex-wrap items-center gap-x-2 gap-y-0.5", unattributed && "text-muted-foreground")}>
      <span className="font-mono text-xs whitespace-nowrap text-ink-2">
        {endpoint.address ? <UntrustedText value={endpoint.address} limit={48} /> : <span className="text-muted-foreground">*</span>}
        :{endpoint.port}/{endpoint.protocol}
      </span>
      <span title={exposure.detail} className={cn("text-xs whitespace-nowrap", exposure.tone === "warn" ? "text-warn" : "text-muted-foreground")}>
        {exposure.label}
      </span>
      {compact ? (
        <span title={attribution.detail} className="text-xs whitespace-nowrap text-muted-foreground">
          {attribution.label}
        </span>
      ) : (
        <span className="text-xs text-muted-foreground">
          <span title={attribution.detail} className="whitespace-nowrap">
            {attribution.label}
          </span>
          {endpoint.attribution_basis ? (
            <>
              {" · "}
              <UntrustedText value={endpoint.attribution_basis} limit={80} />
            </>
          ) : null}
        </span>
      )}
    </span>
  );
}

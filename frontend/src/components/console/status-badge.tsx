import { cn } from "cn";

import { Badge } from "@/components/ui/badge";
import type { HealthStatus } from "@/lib/api/schemas";
import { lifecycleView } from "@/lib/lifecycle";
import { type CoverageKind, serviceCoverage } from "@/lib/services";

import { Hint } from "./hint";

export type Tone = "ok" | "warn" | "bad" | "off";

const DOT: Record<Tone, string> = {
  ok: "bg-health-ok",
  warn: "bg-health-warn",
  bad: "bg-health-bad",
  off: "bg-health-off",
};

const PILL: Record<Tone, string> = {
  ok: "bg-health-ok/10 text-health-ok ring-health-ok/25",
  warn: "bg-health-warn/10 text-health-warn ring-health-warn/25",
  bad: "bg-health-bad/10 text-health-bad ring-health-bad/25",
  off: "bg-sev-info/10 text-fg-2 ring-sev-info/20",
};

/** A 6px status dot with its word (health: ok emerald, degraded amber, failed red, unknown zinc). */
export function StatusDot({
  tone,
  label,
  className,
  pulse = false,
}: {
  tone: Tone;
  label: string;
  className?: string;
  /** A soft halo for a live problem (failed / degraded right now); never on "ok". */
  pulse?: boolean;
}) {
  return (
    <span className={cn("inline-flex flex-none items-center gap-1.5 whitespace-nowrap text-fg-2", className)}>
      <span aria-hidden="true" className="relative flex size-1.5">
        {pulse && tone !== "ok" ? (
          <span className={cn("absolute inset-0 rounded-full opacity-40 ring-4", tone === "bad" ? "ring-health-bad/30" : "ring-health-warn/30")} />
        ) : null}
        <span className={cn("relative size-1.5 rounded-full", DOT[tone])} />
      </span>
      {label}
    </span>
  );
}

/** Tinted pill form of a status (headers, one per object). */
export function StatusPill({ tone, label, className }: { tone: Tone; label: string; className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn("h-5 flex-none gap-1.5 rounded-md border-0 px-1.5 ring-1 ring-inset", PILL[tone], className)}
    >
      <span aria-hidden="true" className={cn("size-1.5 rounded-full", DOT[tone])} />
      {label}
    </Badge>
  );
}

const HEALTH: Record<HealthStatus, { tone: Tone; label: string }> = {
  ok: { tone: "ok", label: "OK" },
  degraded: { tone: "warn", label: "Degraded" },
  failed: { tone: "bad", label: "Failed" },
  disabled: { tone: "off", label: "Disabled" },
  unknown: { tone: "off", label: "Unknown" },
};

/** Health of a collector, pipeline component, rule or provider. */
export function HealthBadge({
  status,
  variant = "dot",
  className,
}: {
  status: HealthStatus;
  variant?: "dot" | "pill";
  className?: string;
}) {
  const { tone, label } = HEALTH[status];
  return variant === "pill" ? (
    <StatusPill tone={tone} label={label} className={className} />
  ) : (
    <StatusDot tone={tone} label={label} className={className} />
  );
}

const COVERAGE_KIND_DOT: Record<CoverageKind, string> = {
  monitored: "bg-cov-monitored",
  degraded: "bg-cov-degraded",
  unmonitored: "bg-cov-unmonitored",
  planned: "bg-transparent ring-1 ring-inset ring-cov-planned",
  unsupported: "bg-cov-unsupported",
  unknown: "bg-transparent ring-1 ring-inset ring-cov-planned",
};

/**
 * Service telemetry coverage (monitored, degraded, unmonitored, planned adapter,
 * unsupported) as dot + word, with the meaning (and the API's reasons) as a hint.
 */
export function CoverageBadge({
  service,
  className,
}: {
  service: Parameters<typeof serviceCoverage>[0];
  className?: string;
}) {
  const badge = serviceCoverage(service);
  return (
    <Hint content={badge.detail} className={className}>
      <span className="inline-flex flex-none items-center gap-1.5 text-fg-2 whitespace-nowrap">
        <span aria-hidden="true" className={cn("size-2 rounded-full", COVERAGE_KIND_DOT[badge.kind])} />
        {badge.label}
      </span>
    </Hint>
  );
}

/** The swatch class of a coverage kind (legends of stacked coverage visuals). */
export function coverageSwatchClass(kind: CoverageKind): string {
  return COVERAGE_KIND_DOT[kind];
}

/** Explicit staleness marker: never let old data pass as current. */
export function StaleBadge({ reason }: { reason?: string | null }) {
  return (
    <Hint content={reason ?? "No successful collection within 3 collection intervals."}>
      <StatusPill tone="warn" label="Stale" />
    </Hint>
  );
}

/**
 * Inventory lifecycle of an asset or collector: nothing for `active`, an amber "Stale" pill
 * (still counted) or a muted "Retired" pill (left out of rollups, never deleted). The hint says
 * what the state means and gives the API's reason (API-derived text, durations spelled out).
 */
export function LifecycleBadge({
  state,
  reason,
  className,
  plain = false,
}: {
  state: string | null | undefined;
  reason?: string | null;
  className?: string;
  /** Inside a link: the pill alone, without the focusable hint. */
  plain?: boolean;
}) {
  const view = lifecycleView(state, reason);
  if (!view) return null;
  if (plain) return <StatusPill tone={view.tone} label={view.label} className={className} />;
  return (
    <Hint
      content={
        <span className="grid gap-1">
          <span>
            <span className="font-medium text-foreground">{view.label}.</span> {view.meaning}
          </span>
          {view.reason ? <span className="text-muted-foreground">API: {view.reason}</span> : null}
        </span>
      }
    >
      <StatusPill tone={view.tone} label={view.label} className={className} />
    </Hint>
  );
}

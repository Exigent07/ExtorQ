import { cn } from "cn";

import type { CoverageStatus, HealthStatus } from "@/lib/api/schemas";

type Tone = "ok" | "warn" | "bad" | "off";

const DOT: Record<Tone, string> = {
  ok: "bg-ok",
  warn: "bg-warn",
  bad: "bg-bad",
  off: "bg-off",
};

const PILL: Record<Tone, string> = {
  ok: "bg-ok-bg text-ok",
  warn: "bg-warn-bg text-warn",
  bad: "bg-bad-bg text-bad",
  off: "bg-off-bg text-ink-2",
};

/** A 6px status dot with its word: one status mark per row. */
export function StatusDot({ tone, label, className }: { tone: Tone; label: string; className?: string }) {
  return (
    <span className={cn("inline-flex flex-none items-center gap-1.5 whitespace-nowrap text-ink-2", className)}>
      <span aria-hidden="true" className={cn("size-1.5 rounded-full", DOT[tone])} />
      {label}
    </span>
  );
}

export function StatusPill({ tone, label }: { tone: Tone; label: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 flex-none items-center rounded-sm px-1.5 text-xs font-medium whitespace-nowrap",
        PILL[tone],
      )}
    >
      {label}
    </span>
  );
}

export const COVERAGE: Record<CoverageStatus, { tone: Tone; label: string }> = {
  ok: { tone: "ok", label: "Healthy" },
  degraded: { tone: "warn", label: "Degraded" },
  stale: { tone: "warn", label: "Stale" },
  missing: { tone: "bad", label: "Missing" },
};

export function CoverageStatusDot({ status }: { status: CoverageStatus }) {
  const { tone, label } = COVERAGE[status];
  return <StatusDot tone={tone} label={label} />;
}

export const HEALTH: Record<HealthStatus, { tone: Tone; label: string }> = {
  ok: { tone: "ok", label: "OK" },
  degraded: { tone: "warn", label: "Degraded" },
  failed: { tone: "bad", label: "Failed" },
  disabled: { tone: "off", label: "Disabled" },
  unknown: { tone: "off", label: "Unknown" },
};

export function HealthStatusDot({ status }: { status: HealthStatus }) {
  const { tone, label } = HEALTH[status];
  return <StatusDot tone={tone} label={label} />;
}

/** Explicit staleness marker: never let old data pass as current. */
export function StaleBadge({ reason }: { reason?: string | null }) {
  return (
    <span title={reason ?? "No successful collection within 3 collection intervals"}>
      <StatusPill tone="warn" label="Stale" />
    </span>
  );
}

import { cn } from "cn";

import type { Severity } from "@/lib/api/schemas";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const MARK: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const PILL: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical",
  high: "bg-sev-high-bg text-sev-high",
  medium: "bg-sev-medium-bg text-sev-medium",
  low: "bg-sev-low-bg text-sev-low",
  info: "bg-sev-info-bg text-sev-info",
};

/** Dense-table form: a small square in the severity hue and the word in secondary ink. */
export function SeverityTag({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex flex-none items-center gap-1.5 whitespace-nowrap text-ink-2", className)}>
      <span aria-hidden="true" className={cn("size-2 rounded-[2px]", MARK[severity])} />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

/** Header form: the severity hue on its own dark tint. */
export function SeverityPill({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex h-6 flex-none items-center rounded-sm px-2 text-xs font-medium whitespace-nowrap",
        PILL[severity],
      )}
    >
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function severityMarkClass(severity: Severity): string {
  return MARK[severity];
}

/** Hue used by charts for each severity (CSS variable, validated by ChartContainer). */
export const SEVERITY_COLOR_VAR: Record<Severity, string> = {
  critical: "var(--xq-sev-critical)",
  high: "var(--xq-sev-high)",
  medium: "var(--xq-sev-medium)",
  low: "var(--xq-sev-low)",
  info: "var(--xq-sev-info)",
};

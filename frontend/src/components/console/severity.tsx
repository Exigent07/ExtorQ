import { cn } from "cn";

import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/lib/api/schemas";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Soft tinted pill: 400-shade ink, 10% tint, 25% inset ring. */
const PILL: Record<Severity, string> = {
  critical: "bg-sev-critical/10 text-sev-critical ring-sev-critical/25",
  high: "bg-sev-high/10 text-sev-high ring-sev-high/25",
  medium: "bg-sev-medium/10 text-sev-medium ring-sev-medium/25",
  low: "bg-sev-low/10 text-sev-low ring-sev-low/25",
  info: "bg-sev-info/10 text-sev-info ring-sev-info/20",
};

const DOT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

/**
 * Severity as a soft tinted pill (the one severity mark per row). `size="md"` for headers.
 * The word is always present: colour is never the only carrier.
 */
export function SeverityBadge({
  severity,
  size = "sm",
  className,
}: {
  severity: Severity;
  size?: "sm" | "md";
  className?: string;
}) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "flex-none gap-1.5 rounded-md border-0 ring-1 ring-inset",
        size === "md" ? "h-6 px-2" : "h-5 px-1.5",
        PILL[severity],
        className,
      )}
    >
      <span aria-hidden="true" className={cn("size-1.5 rounded-full", DOT[severity])} />
      {SEVERITY_LABEL[severity]}
    </Badge>
  );
}

/** A 6px severity dot (legends, palette rows); pair it with the word or a count. */
export function SeverityDot({ severity, className }: { severity: Severity; className?: string }) {
  return <span aria-hidden="true" className={cn("inline-block size-1.5 flex-none rounded-full", DOT[severity], className)} />;
}

/** Hue used by charts for each severity (CSS variable, validated by ChartContainer). */
export const SEVERITY_COLOR_VAR: Record<Severity, string> = {
  critical: "var(--xq-sev-critical)",
  high: "var(--xq-sev-high)",
  medium: "var(--xq-sev-medium)",
  low: "var(--xq-sev-low)",
  info: "var(--xq-sev-info)",
};

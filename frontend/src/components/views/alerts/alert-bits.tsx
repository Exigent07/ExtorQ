import { cn } from "cn";
import { FlaskConical } from "lucide-react";

import { analystStatusLabel, isClosedStatus } from "@/lib/format";

/** Marks alerts whose evidence carries an ExtorQ simulation marker (still genuine telemetry). */
export function SimulationTag({ runIds }: { runIds: string[] }) {
  if (runIds.length === 0) return null;
  return (
    <span
      title={`Evidence carries the simulation marker extorq-sim-${runIds.join(", extorq-sim-")}. The telemetry is genuine; the activity was a controlled lab scenario.`}
      className="inline-flex h-5 flex-none items-center gap-1 rounded-sm border border-control px-1.5 text-xs whitespace-nowrap text-ink-2"
    >
      <FlaskConical className="size-3" aria-hidden="true" />
      Simulation
    </span>
  );
}

/** Analyst workflow state in words; open states in ink, closed ones in grey. */
export function AnalystStatusText({ status, recorded }: { status: string; recorded?: boolean }) {
  const closed = isClosedStatus(status);
  return (
    <span
      className={cn("whitespace-nowrap", closed ? "text-muted-foreground" : "text-ink-2")}
      title={recorded === false ? "No analyst has acted on this alert yet" : undefined}
    >
      {analystStatusLabel(status)}
    </span>
  );
}

const CONFIDENCE_HINT: Record<string, string> = {
  high: "Independent sources agree (deterministic evidence completeness, not a maliciousness score)",
  medium: "Evidence from the primary source only",
  low: "Partial evidence; an expected source was missing",
};

export function ConfidenceText({ confidence }: { confidence: string }) {
  return (
    <span className="whitespace-nowrap text-ink-2" title={CONFIDENCE_HINT[confidence] ?? undefined}>
      {confidence.charAt(0).toUpperCase() + confidence.slice(1)}
    </span>
  );
}

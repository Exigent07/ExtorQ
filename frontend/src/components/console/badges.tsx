import { cn } from "cn";
import { FlaskConical } from "lucide-react";

import { Hint } from "./hint";

const CONFIDENCE: Record<string, { bars: number; label: string; hint: string }> = {
  high: {
    bars: 3,
    label: "High",
    hint: "Independent sources agree. This is deterministic evidence completeness, not a maliciousness score.",
  },
  medium: { bars: 2, label: "Medium", hint: "Evidence from the primary source only." },
  low: { bars: 1, label: "Low", hint: "Partial evidence: an expected source was missing." },
};

/**
 * Evidence confidence of an alert (deterministic completeness, never a verdict): three
 * signal bars in neutral ink plus the word. Unknown tokens are shown as reported.
 */
export function ConfidenceBadge({ confidence, className }: { confidence: string; className?: string }) {
  const known = CONFIDENCE[confidence];
  const label = known?.label ?? confidence;
  const body = (
    <span className={cn("inline-flex flex-none items-center gap-1.5 whitespace-nowrap text-fg-2", className)}>
      <span aria-hidden="true" className="flex h-2.5 items-end gap-[2px]">
        {[1, 2, 3].map((bar) => (
          <span
            key={bar}
            className={cn(
              "w-[3px] rounded-[1px]",
              bar === 1 ? "h-1" : bar === 2 ? "h-[7px]" : "h-2.5",
              known && bar <= known.bars ? "bg-fg-2" : "bg-hairline-strong",
            )}
          />
        ))}
      </span>
      {label}
    </span>
  );
  return known ? <Hint content={known.hint}>{body}</Hint> : body;
}

/**
 * Marks alerts whose evidence carries an ExtorQ simulation marker. The telemetry is genuine;
 * the activity was a controlled lab scenario. Neutral, never styled as a severity.
 */
export function SimulationBadge({ runIds, className }: { runIds: string[]; className?: string }) {
  if (runIds.length === 0) return null;
  return (
    <Hint
      content={`Evidence carries the simulation marker extorq-sim-${runIds.join(", extorq-sim-")}. The telemetry is genuine; the activity was a controlled lab scenario.`}
    >
      <span
        className={cn(
          "inline-flex h-5 flex-none items-center gap-1 rounded-md px-1.5 text-xs whitespace-nowrap text-fg-2 ring-1 ring-hairline-strong ring-inset",
          className,
        )}
      >
        <FlaskConical className="size-3" aria-hidden="true" />
        Simulation
      </span>
    </Hint>
  );
}

/** Role of the signed-in account. */
export function RoleBadge({ role, className }: { role: "analyst" | "viewer"; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 w-fit flex-none items-center rounded-md px-1.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        role === "analyst" ? "bg-brand-soft text-brand ring-brand/25" : "bg-sev-info/10 text-fg-2 ring-sev-info/20",
        className,
      )}
    >
      {role === "analyst" ? "Analyst" : "Viewer · read-only"}
    </span>
  );
}

/** The environment the console watches. Neutral: it states scope, not health. */
export function EnvironmentPill({ className }: { className?: string }) {
  return (
    <Hint
      side="bottom"
      content="Lab environment on one Mac: the macOS host, an Ubuntu 24.04 VM, the kind cluster extorq-lab, plus the GitHub lab repository. Not production."
    >
      <span
        className={cn(
          "inline-flex h-6 flex-none items-center gap-1.5 rounded-md px-2 text-xs font-medium tracking-wide text-fg-2 ring-1 ring-hairline-strong ring-inset",
          className,
        )}
      >
        <span aria-hidden="true" className="size-1.5 rounded-full bg-brand" />
        LAB
      </span>
    </Hint>
  );
}

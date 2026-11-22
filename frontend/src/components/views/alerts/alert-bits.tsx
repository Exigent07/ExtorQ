import { cn } from "cn";

import { SimulationBadge } from "@/components/console/badges";
import { Hint } from "@/components/console/hint";
import { analystStatusLabel, isClosedStatus } from "@/lib/format";

/** Marks alerts whose evidence carries an ExtorQ simulation marker (still genuine telemetry). */
export function SimulationTag({ runIds }: { runIds: string[] }) {
  return <SimulationBadge runIds={runIds} />;
}

const STATUS_DOT: Record<string, string> = {
  new: "bg-foreground",
  acknowledged: "bg-fg-2",
  investigating: "bg-sev-medium",
};

/**
 * Analyst workflow state: open states in ink with a small mark (new = white, investigating =
 * amber), closed ones in grey. Not a severity and not a health status.
 */
export function AnalystStatusText({ status, recorded }: { status: string; recorded?: boolean }) {
  const closed = isClosedStatus(status);
  const body = (
    <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap", closed ? "text-muted-foreground" : "text-fg-2")}>
      <span
        aria-hidden="true"
        className={cn("size-1.5 flex-none rounded-full", closed ? "bg-transparent ring-1 ring-fg-faint ring-inset" : STATUS_DOT[status] ?? "bg-fg-2")}
      />
      {analystStatusLabel(status)}
    </span>
  );
  return recorded === false ? <Hint content="No analyst has acted on this alert yet.">{body}</Hint> : body;
}


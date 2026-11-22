import { Info } from "lucide-react";

import { Notice } from "@/components/console/states";
import type { FindingsSummary } from "@/lib/api/schemas";

/** Notice shown whenever finding lifecycle (open / resolved) cannot be derived. */
export function LifecycleNotice({ summary }: { summary: Pick<FindingsSummary, "lifecycle_available" | "note"> }) {
  if (summary.lifecycle_available) return null;
  return (
    <Notice tone="warn" icon={Info} className="mt-3">
      Finding lifecycle is unavailable: counts are distinct findings observed within retention, not their open or
      resolved state.
      {summary.note ? <span className="mt-1 block text-muted-foreground">{summary.note}</span> : null}
    </Notice>
  );
}

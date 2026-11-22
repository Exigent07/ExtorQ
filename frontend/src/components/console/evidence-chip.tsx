import { cn } from "cn";
import { CircleCheck, TriangleAlert } from "lucide-react";

import { isHexId } from "@/lib/security/ids";
import { shortId } from "@/lib/security/display";

import { Hint } from "./hint";

/**
 * An evidence id cited by an AI statement (advisory). Verified ids (found among the alert's
 * evidence events) are links that jump to `#evidence-<event_id>`; unverified ids are flagged
 * with a warning and a dashed outline, are not links and are never styled as verified.
 */
export function EvidenceChip({ eventId, verified, className }: { eventId: string; verified: boolean; className?: string }) {
  const valid = isHexId(eventId);
  const label = valid ? shortId(eventId, 8) : shortId(eventId.replace(/[^\x20-\x7e]/g, "?"), 12);
  if (verified && valid) {
    return (
      <a
        href={`#evidence-${eventId}`}
        title={`Verified evidence ${eventId}: jump to the event`}
        className={cn(
          "inline-flex h-6 items-center gap-1 rounded-md px-1.5 font-mono text-xs text-fg-2 ring-1 ring-hairline-strong transition-colors duration-150 ring-inset hover:bg-hover hover:text-foreground",
          className,
        )}
      >
        <CircleCheck className="size-3 text-health-ok" aria-hidden="true" />
        {label}
        <span className="sr-only">(verified evidence)</span>
      </a>
    );
  }
  return (
    <Hint content="Not found among this alert's evidence events: unverified. The AI cited it; treat the statement with caution.">
      <span
        className={cn(
          "inline-flex h-6 items-center gap-1 rounded-md px-1.5 font-mono text-xs text-muted-foreground outline-1 outline-health-warn/40 outline-dashed",
          className,
        )}
      >
        <TriangleAlert className="size-3 text-health-warn" aria-hidden="true" />
        {label}
        <span className="sr-only">(unverified)</span>
      </span>
    </Hint>
  );
}

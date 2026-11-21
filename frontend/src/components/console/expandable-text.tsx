"use client";

import { useId, useState } from "react";

/**
 * Expand control for an already sanitised, truncated value (see UntrustedText). Only values
 * longer than their limit become a client component; everything else renders on the server.
 */
export function ExpandableText({ short, full, className }: { short: string; full: string; className?: string }) {
  const [expanded, setExpanded] = useState(false);
  const textId = useId();
  return (
    <>
      <span id={textId} className={className}>
        {expanded ? full : short}
      </span>
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={textId}
        onClick={() => setExpanded((v) => !v)}
        className="ml-1.5 inline text-xs whitespace-nowrap text-muted-foreground underline-offset-2 hover:text-ink hover:underline"
      >
        {expanded ? "Show less" : `Show all ${Array.from(full).length} characters`}
      </button>
    </>
  );
}

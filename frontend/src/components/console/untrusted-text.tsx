"use client";

import { cn } from "cn";
import { TriangleAlert } from "lucide-react";
import { useId, useState } from "react";

import { DASH } from "@/lib/format";
import { sanitizeForDisplay, truncateText } from "@/lib/security/display";

/**
 * Renders attacker-controlled telemetry as plain text only.
 *
 * - React text nodes (never HTML); URLs inside the text are not linkified.
 * - Bidi overrides, zero-width and control characters become visible ⟨U+XXXX⟩ markers.
 * - Long values are truncated with an accessible expand control.
 */
export function UntrustedText({
  value,
  limit = 160,
  multiline = false,
  mono = false,
  className,
}: {
  value: string | null | undefined;
  limit?: number;
  multiline?: boolean;
  mono?: boolean;
  className?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const textId = useId();
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">{DASH}</span>;
  }
  const { text, replaced } = sanitizeForDisplay(value, multiline);
  const { text: short, truncated } = truncateText(text, limit);
  const shown = expanded ? text : short;
  return (
    <span className={cn("min-w-0", className)}>
      <span
        id={textId}
        className={cn(
          multiline ? "whitespace-pre-wrap" : "",
          "break-words [overflow-wrap:anywhere]",
          mono && "font-mono text-xs",
        )}
      >
        {shown}
      </span>
      {truncated ? (
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={textId}
          onClick={() => setExpanded((v) => !v)}
          className="ml-1.5 inline whitespace-nowrap text-xs text-muted-foreground underline-offset-2 hover:text-ink hover:underline"
        >
          {expanded ? "Show less" : `Show all ${Array.from(text).length} characters`}
        </button>
      ) : null}
      {replaced > 0 ? (
        <span
          className="ml-1.5 inline-flex items-center gap-1 align-middle text-xs whitespace-nowrap text-warn"
          title="The source contained invisible, control or bidirectional characters; they are shown as ⟨U+XXXX⟩ markers."
        >
          <TriangleAlert className="size-3" aria-hidden="true" />
          {replaced} hidden character{replaced === 1 ? "" : "s"}
        </span>
      ) : null}
    </span>
  );
}

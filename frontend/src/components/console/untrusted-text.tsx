import { cn } from "cn";
import { TriangleAlert } from "lucide-react";

import { DASH } from "@/lib/format";
import { sanitizeForDisplay, truncateText } from "@/lib/security/display";

import { ExpandableText } from "./expandable-text";

/**
 * Renders attacker-controlled telemetry as plain text only.
 *
 * - React text nodes (never HTML); URLs inside the text are not linkified.
 * - Bidi overrides, zero-width, tag and control characters become visible ⟨U+XXXX⟩ markers.
 * - Long values are truncated, with an accessible expand control.
 *
 * Isomorphic on purpose (no "use client"): in server components it renders on the server,
 * and only values that need the expand control ship a small client component.
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
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">{DASH}</span>;
  }
  const { text, replaced } = sanitizeForDisplay(value, multiline);
  const { text: short, truncated } = truncateText(text, limit);
  const textClass = cn(
    multiline ? "whitespace-pre-wrap" : "",
    "break-words [overflow-wrap:anywhere]",
    mono && "font-mono text-xs",
  );
  return (
    <span className={cn("min-w-0", className)}>
      {truncated ? <ExpandableText short={short} full={text} className={textClass} /> : <span className={textClass}>{text}</span>}
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

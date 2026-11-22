import { cn } from "cn";
import { TriangleAlert } from "lucide-react";

import { DASH } from "@/lib/format";
import { sanitizeForDisplay, truncateText } from "@/lib/security/display";

import { OneLineValue, TruncatedValue } from "./full-value";
import { Hint } from "./hint";

/** One-line values longer than this get the hover card (shorter ones fit any column). */
const ONE_LINE_HOVER_MIN = 32;

/**
 * Renders attacker-controlled telemetry as plain text only.
 *
 * - React text nodes (never HTML); URLs inside the text are never turned into links.
 * - Bidi overrides, zero-width, tag and control characters become visible ⟨U+XXXX⟩ markers,
 *   with a "hidden characters" warning beside the value.
 * - Long values never become walls: the default form cuts at `limit` characters and offers the
 *   full value in a popover (button, keyboard accessible); `oneLine` ellipsises to the column
 *   width and shows the full value in a hover card on hover or focus.
 *
 * Isomorphic (no "use client"): short values render on the server as text; only values that
 * need the popover or hover card ship a small client component.
 */
export function UntrustedText({
  value,
  limit = 160,
  multiline = false,
  mono = false,
  oneLine = false,
  plain = false,
  className,
}: {
  value: string | null | undefined;
  limit?: number;
  multiline?: boolean;
  mono?: boolean;
  /** Single line with an ellipsis at the column width (tables, lists). */
  oneLine?: boolean;
  /**
   * No popover, hover card or focusable hint: for text inside a link or button (nested
   * interactive elements are not allowed). The destination shows the full value.
   */
  plain?: boolean;
  className?: string;
}) {
  if (value === null || value === undefined || value === "") {
    return <span className="text-muted-foreground">{DASH}</span>;
  }
  const { text, replaced } = sanitizeForDisplay(value, multiline && !oneLine);
  const markerBody =
    replaced > 0 ? (
      <span className="inline-flex flex-none items-center gap-1 text-xs whitespace-nowrap text-health-warn">
        <TriangleAlert className="size-3" aria-hidden="true" />
        {replaced} hidden character{replaced === 1 ? "" : "s"}
      </span>
    ) : null;
  const marker =
    markerBody && !plain ? (
      <Hint content="The source contained invisible, control or bidirectional characters; they are shown as ⟨U+XXXX⟩ markers.">
        {markerBody}
      </Hint>
    ) : (
      markerBody
    );

  if (oneLine) {
    const { text: shown } = truncateText(text, Math.max(limit, 240));
    const body =
      !plain && Array.from(text).length > ONE_LINE_HOVER_MIN ? (
        <OneLineValue text={shown} full={text} mono={mono} />
      ) : (
        <span className={cn("block min-w-0 truncate", mono && "font-mono text-xs")}>{text}</span>
      );
    return (
      <span className={cn("flex min-w-0 items-center gap-2", className)}>
        <span className="min-w-0 flex-1">{plain ? <span className={cn("block min-w-0 truncate", mono && "font-mono text-xs")}>{shown}</span> : body}</span>
        {marker}
      </span>
    );
  }

  const { text: short, truncated } = truncateText(text, limit);
  const textClass = cn(
    multiline ? "whitespace-pre-wrap" : "",
    "wrap-anywhere",
    mono && "font-mono text-xs",
  );
  return (
    <span className={cn("min-w-0", className)}>
      {truncated && plain ? (
        <span className={textClass}>{short}</span>
      ) : truncated ? (
        <TruncatedValue short={short} full={text} className={textClass} mono={mono} multiline={multiline} />
      ) : (
        <span className={textClass}>{text}</span>
      )}
      {marker ? <span className="ml-1.5 inline-flex align-middle">{marker}</span> : null}
    </span>
  );
}

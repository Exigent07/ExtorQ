import { cn } from "cn";

import { DASH, formatRelative, formatUtc } from "@/lib/format";

import { Hint } from "./hint";

/** "2026-11-21 14:32:05 UTC" (the console's UTC form, spelled out for tooltips and sheets). */
export function utcLabel(iso: string): string {
  return `${formatUtc(iso).replace(/Z$/, "")} UTC`;
}

/** Absolute UTC time in the figure face; missing values are a grey dash. */
export function Timestamp({ value, className }: { value: string | null | undefined; className?: string }) {
  if (!value) return <span className="text-muted-foreground">{DASH}</span>;
  return (
    <time dateTime={value} className={cn("font-mono text-xs whitespace-nowrap text-fg-2", className)}>
      {formatUtc(value)}
    </time>
  );
}

/**
 * Recency in words ("15 h ago") with the exact UTC time in a tooltip on hover and keyboard focus.
 * Pass the fetch time as `now` so server and client render the same words. `plain` drops the
 * tooltip (and its tab stop) inside links and stretched-link cards, where a nested focusable
 * element is invalid; the UTC time is then a native title. Missing values are a grey dash.
 */
export function RelativeTime({
  value,
  now,
  className,
  side = "top",
  plain = false,
}: {
  value: string | null | undefined;
  now: string;
  className?: string;
  side?: "top" | "right" | "bottom" | "left";
  plain?: boolean;
}) {
  if (!value) return <span className="text-muted-foreground">{DASH}</span>;
  const time = (
    <time
      dateTime={value}
      title={plain ? utcLabel(value) : undefined}
      className={cn("whitespace-nowrap text-fg-2 tabular-nums", className)}
    >
      {formatRelative(value, now)}
    </time>
  );
  if (plain) return time;
  return (
    <Hint side={side} content={<span className="font-mono text-xs tabular-nums">{utcLabel(value)}</span>}>
      {time}
    </Hint>
  );
}

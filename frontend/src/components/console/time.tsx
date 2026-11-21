import { cn } from "cn";

import { DASH, formatRelative, formatUtc } from "@/lib/format";

/** Absolute UTC time in the figure face; missing values are a grey dash. */
export function Timestamp({ value, className }: { value: string | null | undefined; className?: string }) {
  if (!value) return <span className="text-muted-foreground">{DASH}</span>;
  return (
    <time dateTime={value} className={cn("font-mono text-xs whitespace-nowrap text-ink-2", className)}>
      {formatUtc(value)}
    </time>
  );
}

/** Recency in words ("4 min ago") with the exact UTC time as its title. */
export function RelativeTime({
  value,
  now,
  className,
}: {
  value: string | null | undefined;
  now: string;
  className?: string;
}) {
  if (!value) return <span className="text-muted-foreground">{DASH}</span>;
  return (
    <time
      dateTime={value}
      title={formatUtc(value)}
      className={cn("whitespace-nowrap text-ink-2 tabular-nums", className)}
    >
      {formatRelative(value, now)}
    </time>
  );
}

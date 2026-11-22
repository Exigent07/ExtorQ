import { cn } from "cn";

/**
 * ExtorQ mark: a ring of four arcs, one per monitored asset class (macOS host, Linux VM,
 * Kubernetes cluster, GitHub repository), with the Q's tail leaving through the gap between them.
 */
const ARCS = {
  top: "M6.6 5.56A7 7 0 0 1 15.4 5.56",
  right: "M16.44 6.6A7 7 0 0 1 16.44 15.4",
  bottom: "M15.4 16.44A7 7 0 0 1 6.6 16.44",
  left: "M5.56 15.4A7 7 0 0 1 5.56 6.6",
} as const;
const TAIL = "M14.2 14.2L20 20";

export function BrandMark({ className, strokeWidth = 2 }: { className?: string; strokeWidth?: number }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="butt"
      aria-hidden="true"
      className={cn("size-6", className)}
    >
      <path d={ARCS.right} />
      <path d={ARCS.bottom} />
      <path d={ARCS.left} />
      <path d={ARCS.top} />
      <path d={TAIL} />
    </svg>
  );
}

/** The mark on a solid brand tile (sidebar header, login). */
export function BrandTile({ className }: { className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        "flex size-7 flex-none items-center justify-center rounded-lg bg-primary text-white shadow-[inset_0_1px_0_0_rgb(255_255_255/0.18)]",
        className,
      )}
    >
      <BrandMark className="size-[70%]" strokeWidth={2.4} />
    </span>
  );
}

/** Brand lockup: tile + wordmark + scope line. */
export function BrandLockup({ scope, className }: { scope?: string; className?: string }) {
  return (
    <span className={cn("flex min-w-0 items-center gap-2.5", className)}>
      <BrandTile />
      <span className="grid min-w-0 leading-tight">
        <span className="truncate text-sm font-semibold tracking-tight text-foreground">ExtorQ</span>
        {scope ? <span className="truncate text-xs text-muted-foreground">{scope}</span> : null}
      </span>
    </span>
  );
}

export type ArcTone = "ok" | "warn" | "bad" | "off";

const ARC_STROKE: Record<ArcTone, string> = {
  ok: "stroke-health-ok",
  warn: "stroke-health-warn",
  bad: "stroke-health-bad",
  off: "stroke-health-off",
};

/**
 * The coverage mark: the brand mark's four arcs, each in the health colour of its asset
 * class (clockwise from the top: macOS host, Linux VM, Kubernetes cluster, GitHub repository).
 * A class the API did not report is drawn in the neutral "unknown" tone, never as healthy.
 */
export function CoverageMark({
  tones,
  label,
  className,
}: {
  tones: { top: ArcTone; right: ArcTone; bottom: ArcTone; left: ArcTone };
  /** Accessible summary, e.g. "macOS host degraded, Linux VM healthy, ...". */
  label: string;
  className?: string;
}) {
  return (
    <svg viewBox="0 0 24 24" fill="none" strokeLinecap="butt" role="img" aria-label={label} className={cn("size-10", className)}>
      <title>{label}</title>
      {(Object.keys(ARCS) as (keyof typeof ARCS)[]).map((side) => (
        <path key={side} d={ARCS[side]} strokeWidth={2.4} className={ARC_STROKE[tones[side]]} />
      ))}
      <path d={TAIL} strokeWidth={2} className="stroke-fg-faint" />
    </svg>
  );
}

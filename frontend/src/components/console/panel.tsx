import { cn } from "cn";
import type { ReactNode } from "react";

/**
 * A panel: one step darker than the ground, 1px edge, 6px radius, no resting shadow.
 * The header carries the title (16/600), an optional grey meta line on the right
 * (period, count, freshness) and at most one action.
 */
export function Panel({
  title,
  titleId,
  meta,
  action,
  children,
  className,
  bodyClassName,
  flush = false,
}: {
  title: ReactNode;
  titleId: string;
  meta?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  /** Body without horizontal padding (tables that bleed to the panel edge use their own). */
  flush?: boolean;
}) {
  return (
    <section
      aria-labelledby={titleId}
      className={cn("min-w-0 rounded-md border border-border bg-surface", className)}
    >
      <header className="flex min-h-12 flex-wrap items-center justify-between gap-x-4 gap-y-1 px-5 pt-4 pb-2">
        <h2 id={titleId} className="text-lg font-semibold text-ink">
          {title}
        </h2>
        {meta || action ? (
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            {meta}
            {action}
          </div>
        ) : null}
      </header>
      <div className={cn(flush ? "pb-2" : "px-5 pb-5", bodyClassName)}>{children}</div>
    </section>
  );
}

/** Section heading between groups of panels (20/400, muted). */
export function SectionHeading({ id, children }: { id?: string; children: ReactNode }) {
  return (
    <h2 id={id} className="mt-2 text-xl font-normal text-muted-foreground">
      {children}
    </h2>
  );
}

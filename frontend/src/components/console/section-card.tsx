import { cn } from "cn";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardAction, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * The console card, composed from the shadcn Card primitives: #111113 surface, 1px hairline,
 * faint top highlight, 12px radius (ui/card.tsx carries the ExtorQ elevation tokens).
 *
 * Header: optional 16px icon, the title (an h2 with `titleId`: sections are found by it, and the
 * card is a labelled region), an optional one-line description, and on the right a grey meta
 * (period, count) and at most one action. `flush` removes the body's side padding for tables
 * that bleed to the card edge (their first and last cells then align with the title through
 * `--table-edge`). `footer` pins a quiet line or an action to the bottom of a stretched card.
 */
export function SectionCard({
  title,
  titleId,
  icon: Icon,
  description,
  meta,
  action,
  children,
  footer,
  className,
  bodyClassName,
  flush = false,
}: {
  title: ReactNode;
  titleId: string;
  icon?: LucideIcon;
  description?: ReactNode;
  meta?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  className?: string;
  bodyClassName?: string;
  flush?: boolean;
}) {
  return (
    <Card
      role="region"
      aria-labelledby={titleId}
      className={cn("min-w-0 gap-0 overflow-visible py-0 text-base has-data-[slot=card-footer]:pb-0", className)}
    >
      <CardHeader className="gap-0.5 px-5 pt-4 pb-3">
        <CardTitle className="min-w-0">
          <h2 id={titleId} className="flex items-center gap-2 text-base font-semibold tracking-tight text-foreground">
            {Icon ? <Icon className="size-4 flex-none text-muted-foreground" strokeWidth={1.75} aria-hidden="true" /> : null}
            {title}
          </h2>
        </CardTitle>
        {description ? <CardDescription className="text-sm">{description}</CardDescription> : null}
        {meta || action ? (
          <CardAction className="flex min-h-6 flex-wrap items-center justify-end gap-x-3 gap-y-1 pl-4 text-xs text-muted-foreground">
            {meta}
            {action}
          </CardAction>
        ) : null}
      </CardHeader>
      <CardContent className={cn("flex min-w-0 flex-1 flex-col", flush ? "px-0 pb-2 [--table-edge:1.25rem]" : "px-5 pb-5", bodyClassName)}>
        {children}
      </CardContent>
      {footer ? (
        <CardFooter className="block rounded-b-xl border-hairline-soft bg-transparent px-5 py-3 text-xs text-muted-foreground">
          {footer}
        </CardFooter>
      ) : null}
    </Card>
  );
}

/** A quiet link for card headers ("View all", "Details"), with an arrow on hover. */
export function CardLink({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 text-xs font-medium text-muted-foreground transition-colors duration-150 group-hover/link:text-foreground",
        className,
      )}
    >
      {children}
      <span aria-hidden="true" className="transition-transform duration-150 group-hover/link:translate-x-0.5">
        →
      </span>
    </span>
  );
}

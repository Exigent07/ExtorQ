"use client";

import { cn } from "cn";
import { type ReactNode, useRef } from "react";

import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet";

/**
 * Right-hand drawer for the details of one row (an event, an evidence record, a finding)
 * instead of inline expanders. The trigger is any button-like element (`asChild`); the body
 * is server-renderable children: KeyValueList for fields, DetailSection for groups and
 * RawBlock for a raw excerpt (rendered through UntrustedText, never as HTML).
 *
 * - Width: 576 px (`md`) or 672 px (`lg`), full width on phones. The widths use the base
 *   sheet's own `data-[side=right]:` variant so they replace its 384 px default.
 * - The Radix ScrollArea viewport wraps children in a `display: table` box that one-line values
 *   (UntrustedText `oneLine`, nowrap times) would widen past the sheet: forced to block.
 * - On open, focus lands on the drawer itself, not on its first control (often a hint whose
 *   tooltip would open on arrival and swallow the first Escape).
 *
 * Children are part of the page payload even while the sheet is closed: keep each sheet's
 * content bounded (raw excerpts are already capped by the API and by RawBlock's limit).
 */
export function DetailSheet({
  trigger,
  title,
  description,
  badges,
  children,
  footer,
  size = "md",
  titleClassName,
}: {
  trigger: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  /** Severity / status badges under the title. */
  badges?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
  size?: "md" | "lg";
  titleClassName?: string;
}) {
  const contentRef = useRef<HTMLDivElement>(null);
  return (
    <Sheet>
      <SheetTrigger asChild>{trigger}</SheetTrigger>
      <SheetContent
        ref={contentRef}
        side="right"
        className={cn(
          "gap-0 p-0 outline-none data-[side=right]:w-full",
          size === "lg" ? "data-[side=right]:sm:max-w-2xl" : "data-[side=right]:sm:max-w-xl",
        )}
        onOpenAutoFocus={(event) => {
          event.preventDefault();
          contentRef.current?.focus();
        }}
      >
        <SheetHeader className="gap-1.5 border-b border-hairline px-6 pt-5 pb-4">
          <SheetTitle className={cn("pr-8 text-lg leading-snug font-semibold tracking-tight", titleClassName)}>{title}</SheetTitle>
          {description ? <SheetDescription className="text-sm leading-relaxed">{description}</SheetDescription> : null}
          {badges ? <div className="mt-1.5 flex flex-wrap items-center gap-2">{badges}</div> : null}
        </SheetHeader>
        <ScrollArea className="min-h-0 flex-1 [&_[data-radix-scroll-area-viewport]>div]:block!">
          {/* One track no wider than the sheet: long unbroken values wrap or scroll inside their block. */}
          <div className="grid min-w-0 grid-cols-[minmax(0,1fr)] gap-6 px-6 py-5">{children}</div>
        </ScrollArea>
        {footer ? <SheetFooter className="border-t border-hairline px-6 py-3">{footer}</SheetFooter> : null}
      </SheetContent>
    </Sheet>
  );
}

/** A titled group inside a DetailSheet (or a detail page's right rail). */
export function DetailSection({ title, children, className }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section className={cn("grid gap-2", className)}>
      <h3 className="text-xs font-medium text-muted-foreground">{title}</h3>
      {children}
    </section>
  );
}

/**
 * Frame for a raw excerpt: mono, scrollable, max 20rem tall. Pass the excerpt through
 * UntrustedText with `multiline mono` and a generous limit as its child.
 */
export function RawBlock({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "max-h-80 overflow-auto rounded-lg bg-canvas px-3.5 py-3 font-mono text-xs leading-relaxed text-fg-2 ring-1 ring-hairline ring-inset",
        className,
      )}
    >
      {children}
    </div>
  );
}

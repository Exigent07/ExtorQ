"use client";

import { cn } from "cn";
import { ChevronRight } from "lucide-react";
import { type ReactNode, useState } from "react";

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

/**
 * A secondary block folded behind one quiet line ("Show 9 zero counters", "Timeline as
 * summarised (14)"): a real button with `aria-expanded`, a chevron that turns, the content
 * rendered only when open. For secondary detail that would otherwise push the decisive
 * content down; never for evidence rows (those open in a DetailSheet) and never to hide a
 * warning.
 */
export function Disclosure({
  label,
  openLabel,
  meta,
  children,
  defaultOpen = false,
  className,
  triggerClassName,
}: {
  /** Trigger text while closed (console text). */
  label: ReactNode;
  /** Trigger text while open (defaults to `label`). */
  openLabel?: ReactNode;
  /** Muted text after the label (a count). */
  meta?: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
  className?: string;
  triggerClassName?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <Collapsible open={open} onOpenChange={setOpen} className={className}>
      <CollapsibleTrigger
        className={cn(
          "group/disclosure inline-flex items-center gap-1.5 rounded-md text-sm text-fg-2 outline-none transition-colors duration-150 hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50",
          triggerClassName,
        )}
      >
        <ChevronRight
          className="size-3.5 flex-none text-muted-foreground transition-transform duration-150 group-data-[state=open]/disclosure:rotate-90"
          aria-hidden="true"
        />
        <span>{open && openLabel ? openLabel : label}</span>
        {meta !== undefined && meta !== null ? <span className="text-muted-foreground tabular-nums">{meta}</span> : null}
      </CollapsibleTrigger>
      <CollapsibleContent>{children}</CollapsibleContent>
    </Collapsible>
  );
}

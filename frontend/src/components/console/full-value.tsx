"use client";

import { cn } from "cn";
import { Check, Copy, Maximize2 } from "lucide-react";
import { useRef, useState } from "react";

import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";

/**
 * Client halves of UntrustedText. Both receive text that was already sanitised (visible
 * markers for invisible/bidi/control characters) and render it as React text only.
 */

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          setCopied(false);
        }
      }}
      className="inline-flex h-6 items-center gap-1 rounded-md px-1.5 text-xs text-muted-foreground transition-colors duration-150 hover:bg-hover hover:text-foreground"
    >
      {copied ? <Check className="size-3" aria-hidden="true" /> : <Copy className="size-3" aria-hidden="true" />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function FullValueBody({ full, mono, multiline }: { full: string; mono: boolean; multiline: boolean }) {
  const length = Array.from(full).length;
  return (
    <>
      <div className="flex items-center justify-between gap-3 border-b border-hairline px-3 py-2">
        <span className="text-xs text-muted-foreground">
          Full value · {length.toLocaleString("en-US")} characters · shown as text
        </span>
        <CopyButton text={full} />
      </div>
      <div className="max-h-[min(24rem,60vh)] overflow-y-auto px-3 py-2.5">
        <p
          className={cn(
            "text-sm leading-relaxed wrap-anywhere text-fg-2",
            multiline && "whitespace-pre-wrap",
            mono && "font-mono text-xs leading-relaxed",
          )}
        >
          {full}
        </p>
      </div>
    </>
  );
}

/** A value cut at its character limit: the short form plus a button that opens the full value. */
export function TruncatedValue({
  short,
  full,
  className,
  mono = false,
  multiline = false,
}: {
  short: string;
  full: string;
  className?: string;
  mono?: boolean;
  multiline?: boolean;
}) {
  const length = Array.from(full).length;
  return (
    <>
      <span className={className}>{short}</span>
      <Popover>
        <PopoverTrigger asChild>
          <button
            type="button"
            aria-label={`Show the full value (${length} characters)`}
            className="ml-1 inline-flex size-5 translate-y-[3px] items-center justify-center rounded-md align-baseline text-muted-foreground transition-colors duration-150 hover:bg-hover hover:text-foreground"
          >
            <Maximize2 className="size-3" aria-hidden="true" />
          </button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-[min(36rem,calc(100vw-2rem))] gap-0 p-0">
          <FullValueBody full={full} mono={mono} multiline={multiline} />
        </PopoverContent>
      </Popover>
    </>
  );
}

/**
 * True while a modal surface (a sheet, a dialog, the palette, a popover) is open that does not
 * contain `element`: a hover card opened then would sit above it and take its first Escape.
 */
function coveredByOverlay(element: Element | null): boolean {
  if (!element) return false;
  const open = document.querySelectorAll('[role="dialog"][data-state="open"], [role="alertdialog"][data-state="open"]');
  return Array.from(open).some((surface) => !surface.contains(element));
}

/**
 * One-line form for dense rows: CSS ellipsis, the full value in a hover card on hover or
 * keyboard focus (no click, so row links keep working). The full text stays in the DOM, so
 * screen readers read all of it.
 *
 * Inside clickable rows the hover card must never outlive the click: a press closes it and
 * keeps it closed until the pointer leaves (the row may be opening a sheet), and it does not
 * open while a sheet or dialog that does not contain it is open (it would cover the sheet and
 * swallow its first Escape).
 */
export function OneLineValue({
  text,
  full,
  className,
  mono = false,
}: {
  /** What the row shows (may be cut at the one-line limit). */
  text: string;
  /** The whole sanitised value. */
  full: string;
  className?: string;
  mono?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const pressed = useRef(false);
  const triggerRef = useRef<HTMLSpanElement>(null);
  return (
    <HoverCard
      open={open}
      onOpenChange={(next) => {
        if (next && (pressed.current || coveredByOverlay(triggerRef.current))) return;
        setOpen(next);
      }}
      openDelay={350}
      closeDelay={80}
    >
      <HoverCardTrigger asChild>
        <span
          ref={triggerRef}
          onPointerDown={() => {
            pressed.current = true;
            setOpen(false);
          }}
          onPointerLeave={() => {
            pressed.current = false;
          }}
          tabIndex={0}
          className={cn(
            "block min-w-0 truncate rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/50",
            mono && "font-mono text-xs",
            className,
          )}
        >
          {text}
        </span>
      </HoverCardTrigger>
      <HoverCardContent align="start" className="w-[min(32rem,calc(100vw-2rem))] p-0">
        <FullValueBody full={full} mono={mono} multiline={false} />
      </HoverCardContent>
    </HoverCard>
  );
}

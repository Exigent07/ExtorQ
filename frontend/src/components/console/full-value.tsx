"use client";

import { cn } from "cn";
import { Check, Copy, Maximize2 } from "lucide-react";
import { useState } from "react";

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
 * One-line form for dense rows: CSS ellipsis, the full value in a hover card on hover or
 * keyboard focus (no click, so row links keep working). The full text stays in the DOM, so
 * screen readers read all of it.
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
  return (
    <HoverCard openDelay={350} closeDelay={80}>
      <HoverCardTrigger asChild>
        <span
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

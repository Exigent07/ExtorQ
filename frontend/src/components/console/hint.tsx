"use client";

import { cn } from "cn";
import type { ReactNode } from "react";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/**
 * A short explanation on hover and keyboard focus (Radix Tooltip). The trigger is a focusable
 * inline span, so keyboard users reach the hint too. Content is console text (labels,
 * definitions), never raw telemetry: long attacker-controlled values use UntrustedText.
 */
export function Hint({
  content,
  children,
  side = "top",
  className,
}: {
  content: ReactNode;
  children: ReactNode;
  side?: "top" | "right" | "bottom" | "left";
  className?: string;
}) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          tabIndex={0}
          className={cn(
            "inline-flex rounded-md outline-none focus-visible:ring-2 focus-visible:ring-ring/50",
            className,
          )}
        >
          {children}
        </span>
      </TooltipTrigger>
      <TooltipContent side={side} className="max-w-80 leading-relaxed">
        {content}
      </TooltipContent>
    </Tooltip>
  );
}

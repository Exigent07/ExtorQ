"use client";

import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { Spinner } from "@/components/ui/spinner";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";

export interface RangeOption {
  key: string;
  /** Short label on the toggle ("24 h"). */
  short: string;
  /** Accessible name ("Last 24 hours"). */
  label: string;
  /** Console URL of the view with this range (built on the server from validated ids). */
  href: string;
}

/**
 * Time-range toggle of a server-rendered view: choosing a range navigates to its URL (the server
 * reads the API for that window; nothing is fetched in the browser). A spinner shows while the
 * new page renders.
 */
export function RangeToggle({ options, value, label }: { options: RangeOption[]; value: string; label: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <span className="inline-flex items-center gap-2">
      {pending ? <Spinner className="size-3.5 text-muted-foreground" aria-label="Loading" /> : null}
      <ToggleGroup
        type="single"
        size="sm"
        variant="outline"
        spacing={0}
        value={value}
        onValueChange={(next) => {
          const option = options.find((o) => o.key === next);
          if (!option || next === value) return;
          startTransition(() => router.push(option.href, { scroll: false }));
        }}
        aria-label={label}
      >
        {options.map((option) => (
          <ToggleGroupItem
            key={option.key}
            value={option.key}
            aria-label={option.label}
            className="h-7 px-2.5 text-xs tabular-nums data-[state=on]:bg-active data-[state=on]:text-foreground"
          >
            {option.short}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
    </span>
  );
}

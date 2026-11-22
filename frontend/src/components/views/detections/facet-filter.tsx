"use client";

import { cn } from "cn";
import { Check, CirclePlus } from "lucide-react";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { formatCount } from "@/lib/format";

export interface FacetOption {
  value: string;
  label: string;
  /** Secondary text in the list (e.g. a rule's title); console data only, shown as text. */
  description?: string;
  /** Leading mark (severity dot, status dot). */
  icon?: ReactNode;
}

/**
 * One faceted filter (shadcn "data table" pattern): a dashed button that names the facet and
 * the current selection, and a searchable checkbox list with the number of rows each value
 * would keep given the other filters. Controlled: the Detections state owns the selection
 * (it mirrors the URL).
 */
export function FacetFilter({
  title,
  options,
  selected,
  counts,
  onChange,
}: {
  title: string;
  options: FacetOption[];
  selected: readonly string[];
  /** Rows per value under the other active filters (TanStack faceted unique values). */
  counts: Map<unknown, number>;
  onChange: (next: string[]) => void;
}) {
  const chosen = new Set(selected);
  const chosenLabels = options.filter((o) => chosen.has(o.value)).map((o) => o.label);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className={cn("border-dashed", chosen.size > 0 && "border-solid")}>
          <CirclePlus aria-hidden="true" />
          {title}
          {chosen.size > 0 ? (
            <>
              <Separator orientation="vertical" className="mx-0.5 data-vertical:h-3.5" />
              <span className="max-w-40 truncate rounded-sm bg-active px-1.5 text-xs font-normal text-foreground tabular-nums">
                {chosen.size > 2 ? `${chosen.size} selected` : chosenLabels.join(", ") || `${chosen.size} selected`}
              </span>
            </>
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-72 p-0">
        <Command>
          <CommandInput placeholder={`Filter ${title.toLowerCase()}`} />
          <CommandList>
            <CommandEmpty>No value matches.</CommandEmpty>
            <CommandGroup>
              {options.map((option) => {
                const isSelected = chosen.has(option.value);
                const count = counts.get(option.value) ?? 0;
                return (
                  <CommandItem
                    key={option.value}
                    value={`${option.label} ${option.description ?? ""}`}
                    onSelect={() => {
                      const next = new Set(chosen);
                      if (isSelected) next.delete(option.value);
                      else next.add(option.value);
                      onChange([...next]);
                    }}
                    className="gap-2.5"
                  >
                    <span
                      aria-hidden="true"
                      className={cn(
                        "flex size-4 flex-none items-center justify-center rounded-[4px] ring-1 ring-hairline-strong ring-inset transition-colors duration-150",
                        isSelected && "bg-primary ring-primary",
                      )}
                    >
                      {isSelected ? <Check className="size-3 text-white" strokeWidth={3} /> : null}
                    </span>
                    {option.icon}
                    <span className="grid min-w-0 flex-1">
                      <span className="truncate">{option.label}</span>
                      {option.description ? (
                        <span className="truncate text-xs text-muted-foreground">{option.description}</span>
                      ) : null}
                    </span>
                    <span className={cn("ml-auto pl-2 font-mono text-xs tabular-nums", count > 0 ? "text-fg-2" : "text-muted-foreground")}>
                      {formatCount(count)}
                    </span>
                  </CommandItem>
                );
              })}
            </CommandGroup>
            {chosen.size > 0 ? (
              <>
                <CommandSeparator />
                <CommandGroup>
                  <CommandItem onSelect={() => onChange([])} className="justify-center text-center">
                    Clear filter
                  </CommandItem>
                </CommandGroup>
              </>
            ) : null}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

"use client";

import { cn } from "cn";
import type { ReactNode } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatCount } from "@/lib/format";

export interface ServiceTab {
  key: string;
  label: string;
  /** Count after the label (only when the API reported it). */
  count?: number | null;
  /** Text in place of the count (e.g. "50+" for a capped list). */
  countLabel?: string;
  content: ReactNode;
}

/**
 * In-page tabs of the service view. Every panel is rendered on the server and kept mounted
 * (inactive ones are hidden), so the page works as a document and each tab is a deep link:
 * the active tab is mirrored into `?tab=` with history.replaceState (no server round trip,
 * no API call). The active tab's underline is the brand accent, as on the asset tabs.
 */
export function ServiceTabs({ tabs, initial, label }: { tabs: ServiceTab[]; initial: string; label: string }) {
  const first = tabs[0]?.key ?? "";
  const value = tabs.some((t) => t.key === initial) ? initial : first;
  return (
    <Tabs
      defaultValue={value}
      onValueChange={(next) => {
        try {
          const url = new URL(window.location.href);
          if (next === first) url.searchParams.delete("tab");
          else url.searchParams.set("tab", next);
          window.history.replaceState(window.history.state, "", url);
        } catch {
          // URL sync is a convenience only.
        }
      }}
      className="gap-6"
    >
      <div className="border-b border-hairline">
        <TabsList
          variant="line"
          aria-label={label}
          className="no-scrollbar -mb-px h-10 w-full justify-start gap-1 overflow-x-auto rounded-none p-0 group-data-horizontal/tabs:h-10"
        >
          {tabs.map((tab) => (
            <TabsTrigger
              key={tab.key}
              value={tab.key}
              className={cn(
                "h-10 flex-none rounded-none border-0 px-3 text-sm font-normal text-muted-foreground transition-colors duration-150 hover:text-foreground",
                "data-active:font-medium data-active:text-foreground",
                "after:absolute after:inset-x-3 after:bottom-0 after:h-0.5 after:rounded-full after:bg-brand after:opacity-0 data-active:after:opacity-100",
                "group-data-horizontal/tabs:after:inset-x-3 group-data-horizontal/tabs:after:bottom-0",
              )}
            >
              {tab.label}
              {tab.count !== undefined && tab.count !== null ? (
                <span className="rounded-md bg-white/[0.05] px-1.5 text-xs font-normal text-muted-foreground tabular-nums">
                  {tab.countLabel ?? formatCount(tab.count)}
                </span>
              ) : null}
            </TabsTrigger>
          ))}
        </TabsList>
      </div>
      {tabs.map((tab) => (
        <TabsContent key={tab.key} value={tab.key} forceMount className="data-[state=inactive]:hidden">
          {tab.content}
        </TabsContent>
      ))}
    </Tabs>
  );
}

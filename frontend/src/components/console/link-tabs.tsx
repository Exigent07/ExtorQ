import { cn } from "cn";
import Link from "next/link";

import { formatCount } from "@/lib/format";

export interface LinkTab {
  key: string;
  label: string;
  href: string;
  /** Count shown after the label (only when the API returned it; null is omitted). */
  count?: number | null;
}

/**
 * Underline tabs on a full-width 1px rule. Each tab is a real link (server-rendered view per
 * tab, shareable URL, works without JavaScript); the current one carries aria-current.
 */
export function LinkTabs({ tabs, active, label }: { tabs: LinkTab[]; active: string; label: string }) {
  return (
    <nav aria-label={label} className="mb-6 border-b border-hairline">
      <ul className="no-scrollbar -mb-px flex gap-1 overflow-x-auto">
        {tabs.map((tab) => {
          const current = tab.key === active;
          return (
            <li key={tab.key} className="flex-none">
              <Link
                href={tab.href}
                aria-current={current ? "page" : undefined}
                className={cn(
                  "relative inline-flex h-10 items-center gap-2 px-3 text-sm whitespace-nowrap transition-colors duration-150",
                  "after:absolute after:inset-x-3 after:-bottom-px after:h-0.5 after:rounded-full",
                  current
                    ? "font-medium text-foreground after:bg-brand"
                    : "text-muted-foreground after:bg-transparent hover:text-foreground",
                )}
              >
                {tab.label}
                {tab.count !== undefined && tab.count !== null ? (
                  <span className="rounded-md bg-white/[0.05] px-1.5 text-xs text-muted-foreground tabular-nums">
                    {formatCount(tab.count)}
                  </span>
                ) : null}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

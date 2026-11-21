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
    <nav aria-label={label} className="mb-6 border-b border-border">
      <ul className="no-scrollbar -mb-px flex gap-6 overflow-x-auto">
        {tabs.map((tab) => {
          const current = tab.key === active;
          return (
            <li key={tab.key} className="flex-none">
              <Link
                href={tab.href}
                aria-current={current ? "page" : undefined}
                className={cn(
                  "inline-flex h-10 items-center gap-2 border-b-2 text-sm whitespace-nowrap transition-colors",
                  current ? "border-line text-ink" : "border-transparent text-muted-foreground hover:text-ink",
                )}
              >
                {tab.label}
                {tab.count !== undefined && tab.count !== null ? (
                  <span className="font-mono text-xs text-muted-foreground">{formatCount(tab.count)}</span>
                ) : null}
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

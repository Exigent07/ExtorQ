"use client";

import { cn } from "cn";
import { useSearchParams } from "next/navigation";
import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { formatCount } from "@/lib/format";

import { evidenceIdFromHash, parseTab, TABS, type TabKey } from "./model";

/**
 * Navigation inside the investigation: the active tab, and the evidence-row reveal used by
 * AI evidence chips and timeline links (`#evidence-<event_id>`). The evidence table registers
 * a reveal function that clears its filters, turns to the row's page and returns true when the
 * row exists.
 */
interface InvestigationNav {
  tab: TabKey;
  showTab: (tab: TabKey) => void;
  registerEvidenceReveal: (reveal: ((eventId: string) => boolean) | null) => void;
}

const NavContext = createContext<InvestigationNav | null>(null);

export function useInvestigationNav(): InvestigationNav | null {
  return useContext(NavContext);
}

export interface TabSpec {
  key: TabKey;
  label: string;
  /** Count after the label (only real API counts; null/undefined shows none). */
  count?: number | null;
  /** A small amber dot: something in the tab needs attention (stale source, gap, outdated AI). */
  attention?: string | null;
}

/** Keep `?tab=` (and the evidence anchor) in the address without a server round trip. */
function writeAddress(tab: TabKey, hash: string | null) {
  const url = new URL(window.location.href);
  if (tab === "overview") url.searchParams.delete("tab");
  else url.searchParams.set("tab", tab);
  url.hash = hash ?? "";
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

/**
 * The investigation tabs (shadcn Tabs, underline style with the brand indicator). Every panel
 * is rendered on the server and kept mounted (`forceMount`), hidden while inactive: anchors
 * exist for evidence jumps, the page works as one document for search and print, and
 * switching tabs never calls the API.
 */
export function InvestigationTabs({ tabs, panels }: { tabs: TabSpec[]; panels: Record<TabKey, ReactNode> }) {
  // The address is the source of truth (shareable, and right after back/forward navigation);
  // local state answers clicks immediately and follows the address when it changes.
  const urlTab = parseTab(useSearchParams().get("tab"));
  const [tab, setTab] = useState<TabKey>(urlTab);
  const [seenUrlTab, setSeenUrlTab] = useState<TabKey>(urlTab);
  if (urlTab !== seenUrlTab) {
    setSeenUrlTab(urlTab);
    setTab(urlTab);
  }
  const rootRef = useRef<HTMLDivElement>(null);
  const evidenceReveal = useRef<((eventId: string) => boolean) | null>(null);

  const bringIntoView = useCallback(() => {
    const root = rootRef.current;
    if (root && root.getBoundingClientRect().top < 0) root.scrollIntoView({ block: "start" });
  }, []);

  const showTab = useCallback(
    (next: TabKey) => {
      setTab(next);
      writeAddress(next, null);
      requestAnimationFrame(bringIntoView);
    },
    [bringIntoView],
  );

  const revealEvidence = useCallback((eventId: string) => {
    flushSync(() => setTab("evidence"));
    writeAddress("evidence", `#evidence-${eventId}`);
    const found = evidenceReveal.current?.(eventId) ?? false;
    if (!found) rootRef.current?.scrollIntoView({ block: "start" });
  }, []);

  // Evidence links anywhere on the page (AI chips, timeline rows) open the Evidence tab.
  useEffect(() => {
    function onClick(event: MouseEvent) {
      if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      const target = event.target instanceof Element ? event.target : null;
      const anchor = target?.closest("a[href^='#evidence-']");
      const eventId = anchor ? evidenceIdFromHash(anchor.getAttribute("href") ?? "") : null;
      if (!eventId) return;
      event.preventDefault();
      revealEvidence(eventId);
    }
    function fromAddress() {
      const eventId = evidenceIdFromHash(window.location.hash);
      if (eventId) revealEvidence(eventId);
    }
    document.addEventListener("click", onClick);
    window.addEventListener("hashchange", fromAddress);
    // A shared link with #evidence-<id>: reveal once the table has registered.
    const timer = window.setTimeout(fromAddress, 0);
    return () => {
      document.removeEventListener("click", onClick);
      window.removeEventListener("hashchange", fromAddress);
      window.clearTimeout(timer);
    };
  }, [revealEvidence]);

  const nav = useMemo<InvestigationNav>(
    () => ({
      tab,
      showTab,
      registerEvidenceReveal: (reveal) => {
        evidenceReveal.current = reveal;
      },
    }),
    [tab, showTab],
  );

  return (
    <NavContext.Provider value={nav}>
      <Tabs
        ref={rootRef}
        value={tab}
        onValueChange={(value) => showTab(value as TabKey)}
        className="min-w-0 scroll-mt-20 gap-0"
      >
        <div className="no-scrollbar -mx-1 overflow-x-auto px-1">
          <TabsList
            variant="line"
            aria-label="Investigation sections"
            className="h-auto w-full min-w-max justify-start gap-1 rounded-none border-b border-hairline p-0 group-data-horizontal/tabs:h-auto"
          >
            {tabs.map((spec) => (
              <TabsTrigger
                key={spec.key}
                value={spec.key}
                className={cn(
                  "h-10 flex-none rounded-none border-0 px-3 text-sm font-normal text-muted-foreground transition-colors duration-150 hover:text-foreground data-active:font-medium data-active:text-foreground",
                  "after:rounded-full after:bg-brand group-data-horizontal/tabs:after:inset-x-3 group-data-horizontal/tabs:after:bottom-[-1px]",
                )}
              >
                {spec.label}
                {spec.count !== undefined && spec.count !== null ? (
                  <span className="rounded-md bg-white/[0.05] px-1.5 text-xs font-normal text-muted-foreground tabular-nums">
                    {formatCount(spec.count)}
                  </span>
                ) : null}
                {spec.attention ? (
                  <span aria-label={spec.attention} role="img" className="size-1.5 rounded-full bg-health-warn" />
                ) : null}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        {TABS.map((key) => (
          <TabsContent key={key} value={key} forceMount className="mt-6 min-w-0 outline-none data-[state=inactive]:hidden">
            {panels[key]}
          </TabsContent>
        ))}
      </Tabs>
    </NavContext.Provider>
  );
}

/** A button that opens another tab of the investigation (inside server-rendered panels). */
export function TabLink({ tab, children, className }: { tab: TabKey; children: ReactNode; className?: string }) {
  const nav = useInvestigationNav();
  return (
    <button
      type="button"
      onClick={() => nav?.showTab(tab)}
      className={cn(
        "inline-flex items-center gap-1 rounded-sm font-medium text-fg-2 underline-offset-4 transition-colors duration-150 hover:text-foreground hover:underline",
        className,
      )}
    >
      {children}
    </button>
  );
}

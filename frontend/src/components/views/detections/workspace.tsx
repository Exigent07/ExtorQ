"use client";

import { cn } from "cn";
import { ListChecks, ShieldAlert } from "lucide-react";
import { useRouter } from "next/navigation";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useMemo,
  useOptimistic,
  useState,
  useTransition,
} from "react";

import { Spinner } from "@/components/ui/spinner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { TIME_RANGES, type TimeRangeKey } from "@/lib/filters";
import { formatCount } from "@/lib/format";

import {
  type DetectionsTab,
  detectionsSearch,
  emptySelection,
  type FacetSelection,
  RANGE_KEYS,
  sanitizeSelection,
} from "./model";

/**
 * Client state of the Detections page, mirrored in the URL so every view is shareable and a
 * refresh keeps it: the tab (`tab=rules`), the facet selection (the allow-listed alert
 * filters `severity`, `rule`, `asset`, `status`) and the time range (`range`).
 *
 * - Tab and facet changes rewrite the URL in place (history.replaceState, which Next.js
 *   integrates with its router) without a server round trip when the table holds every alert
 *   of the range (`complete`); facets then filter the loaded rows instantly.
 * - When the API holds more alerts than one request returns, a facet change navigates so the
 *   server can ask the API for the filtered set instead.
 * - A range change always navigates: it needs new data from the API.
 *
 * The URL is the source of truth: when the server renders new props (refresh, back/forward,
 * navigation), the state follows them.
 */

interface DetectionsState {
  tab: DetectionsTab;
  setTab: (tab: DetectionsTab) => void;
  selection: FacetSelection;
  setSelection: (selection: FacetSelection) => void;
  /** The range being shown (optimistically the requested one while it loads). */
  range: TimeRangeKey;
  setRange: (range: TimeRangeKey) => void;
  /** A navigation (range change, server-side filter) is in flight. */
  pending: boolean;
  /** The table holds every alert of the range: facets filter locally. */
  complete: boolean;
  /** Switch to the Alerts tab filtered to one rule. */
  showRuleAlerts: (ruleId: string) => void;
}

const DetectionsContext = createContext<DetectionsState | null>(null);

export function useDetections(): DetectionsState {
  const context = useContext(DetectionsContext);
  if (!context) throw new Error("useDetections outside DetectionsProvider");
  return context;
}

function selectionKey(selection: FacetSelection): string {
  return detectionsSearch(selection);
}

export function DetectionsProvider({
  initialTab,
  initialSelection,
  range,
  offset,
  complete,
  children,
}: {
  initialTab: DetectionsTab;
  initialSelection: FacetSelection;
  range: TimeRangeKey;
  /** Server-side page offset (only meaningful when the range is not complete). */
  offset: number;
  complete: boolean;
  children: ReactNode;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [optimisticRange, setOptimisticRange] = useOptimistic(range);
  const [tab, setTabState] = useState<DetectionsTab>(initialTab);
  const [selection, setSelectionState] = useState<FacetSelection>(initialSelection);

  // Follow the URL when the server renders new props (adjusting state during render).
  const propKey = `${initialTab}|${selectionKey(initialSelection)}`;
  const [syncedKey, setSyncedKey] = useState(propKey);
  if (propKey !== syncedKey) {
    setSyncedKey(propKey);
    setTabState(initialTab);
    setSelectionState(initialSelection);
  }

  const urlFor = useCallback(
    (next: { tab: DetectionsTab; selection: FacetSelection; range: TimeRangeKey; offset: number }) =>
      `/detections${detectionsSearch({ ...next.selection, range: next.range, tab: next.tab, offset: complete ? 0 : next.offset })}`,
    [complete],
  );

  const setTab = useCallback(
    (next: DetectionsTab) => {
      setTabState(next);
      window.history.replaceState(null, "", urlFor({ tab: next, selection, range, offset }));
    },
    [urlFor, selection, range, offset],
  );

  const setSelection = useCallback(
    (raw: FacetSelection) => {
      const next = sanitizeSelection(raw);
      setSelectionState(next);
      const url = urlFor({ tab, selection: next, range, offset: 0 });
      if (complete) {
        window.history.replaceState(null, "", url);
      } else {
        startTransition(() => router.push(url, { scroll: false }));
      }
    },
    [urlFor, tab, range, complete, router],
  );

  const setRange = useCallback(
    (next: TimeRangeKey) => {
      if (next === range) return;
      startTransition(() => {
        setOptimisticRange(next);
        router.push(urlFor({ tab, selection, range: next, offset: 0 }), { scroll: false });
      });
    },
    [range, setOptimisticRange, router, urlFor, tab, selection],
  );

  const showRuleAlerts = useCallback(
    (ruleId: string) => {
      const next = sanitizeSelection({ ...emptySelection(), rule: [ruleId] });
      setTabState("alerts");
      setSelectionState(next);
      const url = urlFor({ tab: "alerts", selection: next, range, offset: 0 });
      if (complete) window.history.replaceState(null, "", url);
      else startTransition(() => router.push(url, { scroll: false }));
      document.getElementById("detections-tabs")?.scrollIntoView({ block: "start", behavior: "smooth" });
    },
    [urlFor, range, complete, router],
  );

  const value = useMemo<DetectionsState>(
    () => ({ tab, setTab, selection, setSelection, range: optimisticRange, setRange, pending, complete, showRuleAlerts }),
    [tab, setTab, selection, setSelection, optimisticRange, setRange, pending, complete, showRuleAlerts],
  );
  return <DetectionsContext.Provider value={value}>{children}</DetectionsContext.Provider>;
}

const TRIGGER =
  "h-10 flex-none gap-2 px-3 text-sm group-data-horizontal/tabs:after:inset-x-3 group-data-horizontal/tabs:after:bottom-[-1px] after:bg-brand";

function TabCount({ value }: { value: number | null }) {
  if (value === null) return null;
  return (
    <span className="rounded-md bg-white/[0.05] px-1.5 text-xs font-normal text-muted-foreground tabular-nums group-data-active/trigger:text-fg-2">
      {formatCount(value)}
    </span>
  );
}

/**
 * The Alerts | Rules tabs (shadcn Tabs, underline variant with the brand indicator). Both
 * panels are rendered on the server (`forceMount`) and the inactive one is hidden, so a
 * deep link to either tab paints at once and the page works before hydration.
 */
export function DetectionsTabs({
  alerts,
  rules,
  alertCount,
  ruleCount,
}: {
  alerts: ReactNode;
  rules: ReactNode;
  /** Alerts in the range (null when unknown). */
  alertCount: number | null;
  ruleCount: number | null;
}) {
  const { tab, setTab } = useDetections();
  return (
    <Tabs
      id="detections-tabs"
      value={tab}
      onValueChange={(value) => setTab(value === "rules" ? "rules" : "alerts")}
      className="scroll-mt-20 gap-6"
    >
      <TabsList
        variant="line"
        aria-label="Detections views"
        className="w-full justify-start gap-1 rounded-none border-b border-hairline p-0 group-data-horizontal/tabs:h-10"
      >
        <TabsTrigger value="alerts" className={cn(TRIGGER, "group/trigger")}>
          <ShieldAlert aria-hidden="true" strokeWidth={1.75} />
          Alerts
          <TabCount value={alertCount} />
        </TabsTrigger>
        <TabsTrigger value="rules" className={cn(TRIGGER, "group/trigger")}>
          <ListChecks aria-hidden="true" strokeWidth={1.75} />
          Rules
          <TabCount value={ruleCount} />
        </TabsTrigger>
      </TabsList>
      <TabsContent value="alerts" forceMount className="min-w-0 data-[state=inactive]:hidden">
        {alerts}
      </TabsContent>
      <TabsContent value="rules" forceMount className="min-w-0 data-[state=inactive]:hidden">
        {rules}
      </TabsContent>
    </Tabs>
  );
}

const RANGE_SHORT: Record<TimeRangeKey, string> = { "1h": "1 h", "24h": "24 h", "7d": "7 d", "30d": "30 d" };

/** Time range of the alert history (URL `range`): 1 h, 24 h, 7 d, 30 d. */
export function TimeRangeToggle() {
  const { range, setRange, pending } = useDetections();
  return (
    <div className="flex items-center gap-2">
      {pending ? <Spinner className="size-3.5 text-muted-foreground" aria-label="Loading" /> : null}
      <ToggleGroup
        type="single"
        size="sm"
        variant="outline"
        spacing={0}
        value={range}
        onValueChange={(value) => {
          if ((RANGE_KEYS as string[]).includes(value)) setRange(value as TimeRangeKey);
        }}
        aria-label="Time range"
      >
        {RANGE_KEYS.map((key) => (
          <ToggleGroupItem
            key={key}
            value={key}
            aria-label={TIME_RANGES[key].label}
            className="h-7 px-2.5 text-xs tabular-nums data-[state=on]:bg-active data-[state=on]:text-foreground"
          >
            {RANGE_SHORT[key]}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
    </div>
  );
}

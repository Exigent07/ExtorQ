"use client";

import { cn } from "cn";
import { RotateCw } from "lucide-react";
import { useRouter } from "next/navigation";
import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useState,
  useSyncExternalStore,
  useTransition,
} from "react";

import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { formatUtc, formatUtcTime } from "@/lib/format";

/**
 * Data freshness for the top bar.
 *
 * The shell renders the indicator; the page reports when *its* data was received from the
 * API (the API client's `receivedAt`) by rendering `<Freshness at=... />` (or passing
 * `freshness` to PageHeader). Until a page reports, the indicator shows when the server
 * rendered the view. Refresh re-runs the server components of the route (fresh API reads);
 * old values stay on screen while it runs.
 */

type FreshnessState = { at: string; setAt: (at: string) => void };

const FreshnessContext = createContext<FreshnessState | null>(null);

export function FreshnessProvider({ initial, children }: { initial: string; children: ReactNode }) {
  const [at, setAt] = useState(initial);
  return <FreshnessContext.Provider value={{ at, setAt }}>{children}</FreshnessContext.Provider>;
}

/** Reports the time the page's data was received; renders nothing itself. */
export function Freshness({ at }: { at: string }) {
  const context = useContext(FreshnessContext);
  const setAt = context?.setAt;
  useEffect(() => {
    setAt?.(at);
  }, [at, setAt]);
  return null;
}

/** A view older than this is marked as possibly stale (the data is not live-updating). */
const STALE_VIEW_MS = 5 * 60_000;
const TICK_MS = 15_000;

function subscribeClock(onTick: () => void): () => void {
  const timer = setInterval(onTick, TICK_MS);
  return () => clearInterval(timer);
}
const clockSnapshot = () => Math.floor(Date.now() / TICK_MS) * TICK_MS;
const serverClockSnapshot = () => null;

export function FreshnessIndicator({ className }: { className?: string }) {
  const context = useContext(FreshnessContext);
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const at = context?.at ?? null;
  // Client clock, sampled every 15 s; null during server rendering and hydration.
  const now = useSyncExternalStore(subscribeClock, clockSnapshot, serverClockSnapshot);
  const ageMs = at && now !== null ? now - Date.parse(at) : null;
  const stale = ageMs !== null && ageMs > STALE_VIEW_MS;
  return (
    <div className={cn("flex items-center gap-1", className)}>
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            tabIndex={0}
            aria-live="polite"
            className="hidden h-8 items-center gap-2 rounded-lg px-2 text-xs text-muted-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring/50 lg:inline-flex"
          >
            <span
              aria-hidden="true"
              className={cn(
                "size-1.5 rounded-full",
                pending ? "animate-pulse bg-brand" : stale ? "bg-health-warn" : ageMs === null ? "bg-fg-faint" : "bg-health-ok",
              )}
            />
            {pending ? (
              "Refreshing…"
            ) : at ? (
              <span>
                Updated <time dateTime={at} className="font-mono text-fg-2 tabular-nums">{formatUtcTime(at)}</time> UTC
              </span>
            ) : (
              "Not loaded"
            )}
          </span>
        </TooltipTrigger>
        <TooltipContent side="bottom">
          {at
            ? `Data received from the analyst API at ${formatUtc(at)}.${stale ? " The view is not live: refresh for current data." : ""}`
            : "No data received yet"}
        </TooltipContent>
      </Tooltip>
      <button
        type="button"
        onClick={() => startTransition(() => router.refresh())}
        disabled={pending}
        aria-label="Refresh data"
        className="flex size-8 items-center justify-center rounded-lg text-muted-foreground transition-colors duration-150 hover:bg-hover hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none disabled:opacity-60"
      >
        <RotateCw className={cn("size-3.5", pending && "animate-spin")} aria-hidden="true" />
      </button>
    </div>
  );
}

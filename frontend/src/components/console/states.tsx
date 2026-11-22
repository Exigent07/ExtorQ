import { cn } from "cn";
import { ArrowLeft, CircleAlert, type LucideIcon, SearchX } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Alert, AlertAction, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { ApiFailure } from "@/lib/api/result";

import { RetryButton } from "./retry-button";

/**
 * An honest empty block: it keeps its frame and says, in one sentence, what is absent (and,
 * when useful, what would make it appear). `compact` for empty rows inside a card.
 */
export function EmptyState({
  children,
  icon: Icon,
  action,
  className,
  compact = true,
}: {
  children: ReactNode;
  icon?: LucideIcon;
  action?: ReactNode;
  className?: string;
  compact?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex rounded-lg border border-dashed border-hairline-strong text-sm text-muted-foreground",
        compact ? "items-center gap-2.5 px-4 py-3" : "flex-col items-center justify-center gap-2 px-6 py-10 text-center",
        className,
      )}
    >
      {Icon ? <Icon className={cn("flex-none", compact ? "size-4" : "size-5")} strokeWidth={1.75} aria-hidden="true" /> : null}
      <div className="min-w-0">{children}</div>
      {action ? <div className={compact ? "ml-auto flex-none" : "mt-1"}>{action}</div> : null}
    </div>
  );
}

/**
 * Errors stay inside the block that failed: what failed, the API's safe message and request
 * id, and a retry (re-runs the server components). Wording "Couldn't load …" is relied on by
 * scripts/smoke.mjs to detect error states.
 */
export function ErrorState({
  what,
  error,
  className,
}: {
  what: string;
  error: Pick<ApiFailure, "message" | "requestId" | "kind">;
  className?: string;
}) {
  const retry = error.kind !== "config" && error.kind !== "not_found";
  return (
    <Alert
      className={cn(
        "gap-x-2.5 rounded-lg border-0 bg-health-bad/[0.06] px-4 py-3 ring-1 ring-health-bad/20 ring-inset *:[svg]:text-health-bad",
        retry && "has-data-[slot=alert-action]:pr-24",
        className,
      )}
    >
      <CircleAlert aria-hidden="true" />
      <AlertTitle className="text-sm font-medium text-foreground">Couldn&apos;t load {what}.</AlertTitle>
      <AlertDescription className="text-xs break-words text-muted-foreground">
        {error.message}
        {error.requestId && error.requestId !== "-" ? (
          <>
            {" · request "}
            <span className="font-mono">{error.requestId.slice(0, 8)}</span>
          </>
        ) : null}
      </AlertDescription>
      {retry ? (
        <AlertAction className="top-1/2 right-3 -translate-y-1/2">
          <RetryButton />
        </AlertAction>
      ) : null}
    </Alert>
  );
}

/**
 * A missing object (the API answered 404, or the address holds no valid id): a calm empty
 * state with one sentence and a way back, never a red failure. Errors (5xx, timeouts) keep
 * using ErrorState.
 */
export function NotFoundState({
  children,
  backHref,
  backLabel,
  requestId,
}: {
  children: ReactNode;
  backHref: string;
  backLabel: string;
  /** The API's request id of the 404, for support (omitted for invalid addresses). */
  requestId?: string | null;
}) {
  return (
    <div className="mt-6 flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-hairline-strong px-6 py-14 text-center">
      <span className="flex size-10 items-center justify-center rounded-lg bg-white/[0.04] text-fg-2 ring-1 ring-hairline ring-inset">
        <SearchX className="size-5" strokeWidth={1.75} aria-hidden="true" />
      </span>
      <p className="max-w-[60ch] text-sm leading-relaxed text-fg-2">{children}</p>
      {requestId && requestId !== "-" ? (
        <p className="text-xs text-muted-foreground">
          Not found · request <span className="font-mono">{requestId.slice(0, 8)}</span>
        </p>
      ) : null}
      <Link
        href={backHref}
        className="mt-1 inline-flex h-8 items-center gap-1.5 rounded-lg px-3 text-sm text-foreground ring-1 ring-hairline-strong ring-inset transition-colors duration-150 hover:bg-hover focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:outline-none"
      >
        <ArrowLeft className="size-3.5" aria-hidden="true" />
        {backLabel}
      </Link>
    </div>
  );
}

/** A quiet notice inside a card (capped list, lifecycle unavailable, stale source). */
export function Notice({
  children,
  tone = "neutral",
  icon: Icon,
  className,
}: {
  children: ReactNode;
  tone?: "neutral" | "warn";
  icon?: LucideIcon;
  className?: string;
}) {
  return (
    <p
      className={cn(
        "flex items-start gap-2 rounded-lg px-3 py-2 text-xs leading-relaxed ring-1 ring-inset",
        tone === "warn"
          ? "bg-health-warn/[0.06] text-fg-2 ring-health-warn/20"
          : "bg-white/[0.02] text-muted-foreground ring-hairline",
        className,
      )}
    >
      {Icon ? (
        <Icon className={cn("mt-px size-3.5 flex-none", tone === "warn" ? "text-health-warn" : "")} aria-hidden="true" />
      ) : null}
      <span className="min-w-0">{children}</span>
    </p>
  );
}

import { cn } from "cn";
import { CircleAlert, type LucideIcon } from "lucide-react";
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

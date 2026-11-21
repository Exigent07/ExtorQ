import { cn } from "cn";
import { CircleAlert } from "lucide-react";
import type { ReactNode } from "react";

import type { ApiFailure } from "@/lib/api/result";

import { RetryButton } from "./retry-button";

/** An empty block keeps its frame and says, in one sentence, what is absent. */
export function EmptyState({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "rounded-md border border-dashed border-border px-4 py-3 text-sm text-muted-foreground",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Errors stay inside the block that failed, with what failed and a retry. */
export function ErrorState({
  what,
  error,
  className,
}: {
  what: string;
  error: Pick<ApiFailure, "message" | "requestId" | "kind">;
  className?: string;
}) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-wrap items-start justify-between gap-3 rounded-md border border-border bg-ground/40 px-4 py-3",
        className,
      )}
    >
      <div className="flex min-w-0 items-start gap-2">
        <CircleAlert className="mt-0.5 size-4 flex-none text-bad" aria-hidden="true" />
        <div className="min-w-0">
          <p className="text-sm text-ink">Couldn&apos;t load {what}.</p>
          <p className="mt-0.5 text-xs break-words text-muted-foreground">
            {error.message}
            {error.requestId && error.requestId !== "-" ? (
              <>
                {" · request "}
                <span className="font-mono">{error.requestId.slice(0, 8)}</span>
              </>
            ) : null}
          </p>
        </div>
      </div>
      {error.kind !== "config" && error.kind !== "not_found" ? <RetryButton /> : null}
    </div>
  );
}

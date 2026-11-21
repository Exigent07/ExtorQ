"use client";

import { CircleAlert, RotateCw } from "lucide-react";

/**
 * Unexpected rendering failure inside a console view (not an API error: those are shown in
 * the block that failed). The message stays generic; the digest correlates with server logs.
 */
export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="pt-8">
      <h1 className="text-2xl font-semibold text-ink">Something went wrong</h1>
      <div role="alert" className="mt-4 flex max-w-2xl items-start gap-3 rounded-md border border-border bg-surface px-4 py-3">
        <CircleAlert className="mt-0.5 size-4 flex-none text-bad" aria-hidden="true" />
        <div className="min-w-0 text-sm">
          <p className="text-ink">This view could not be rendered. The data was not changed.</p>
          {error.digest ? (
            <p className="mt-1 text-xs text-muted-foreground">
              Reference <span className="font-mono">{error.digest}</span> (search the console server log for it).
            </p>
          ) : null}
          <button
            type="button"
            onClick={reset}
            className="mt-3 inline-flex h-7 items-center gap-1.5 rounded-full border border-control px-3 text-xs text-ink hover:bg-raised"
          >
            <RotateCw className="size-3.5" aria-hidden="true" />
            Try again
          </button>
        </div>
      </div>
    </div>
  );
}

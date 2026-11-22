"use client";

import { CircleAlert, RotateCw } from "lucide-react";

import { Button } from "@/components/ui/button";

/**
 * Unexpected rendering failure inside a console view (not an API error: those are shown in
 * the block that failed). The message stays generic; the digest correlates with server logs.
 */
export default function ConsoleError({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="pt-8">
      <h1 className="text-2xl font-semibold tracking-tight text-foreground">Something went wrong</h1>
      <div
        role="alert"
        className="mt-4 flex max-w-2xl items-start gap-3 rounded-xl bg-card px-5 py-4 shadow-card ring-1 ring-hairline"
      >
        <CircleAlert className="mt-0.5 size-4 flex-none text-health-bad" aria-hidden="true" />
        <div className="min-w-0 text-sm">
          <p className="text-foreground">This view could not be rendered. The data was not changed.</p>
          {error.digest ? (
            <p className="mt-1 text-xs text-muted-foreground">
              Reference <span className="font-mono">{error.digest}</span> (search the console server log for it).
            </p>
          ) : null}
          <Button type="button" variant="outline" size="sm" onClick={reset} className="mt-3">
            <RotateCw aria-hidden="true" />
            Try again
          </Button>
        </div>
      </div>
    </div>
  );
}

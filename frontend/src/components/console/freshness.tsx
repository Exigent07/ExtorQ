"use client";

import { RotateCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { formatUtcTime } from "@/lib/format";

/** "Updated 14:32:05 UTC" with a refresh control; old values stay visible while reloading. */
export function Freshness({ at }: { at: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <div className="flex items-center gap-2 text-xs text-muted-foreground">
      <span aria-live="polite">
        {pending ? "Refreshing…" : (
          <>
            Updated <time dateTime={at} className="font-mono text-ink-2">{formatUtcTime(at)}</time> UTC
          </>
        )}
      </span>
      <button
        type="button"
        onClick={() => startTransition(() => router.refresh())}
        disabled={pending}
        aria-label="Refresh data"
        className="flex size-8 items-center justify-center rounded-full border border-control text-ink-2 transition-colors hover:bg-raised hover:text-ink disabled:opacity-60"
      >
        <RotateCw className={pending ? "size-3.5 animate-spin" : "size-3.5"} aria-hidden="true" />
      </button>
    </div>
  );
}

"use client";

import { RotateCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";

/** Re-runs the server components of the current route (fresh API reads). */
export function RetryButton({ label = "Retry" }: { label?: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <button
      type="button"
      onClick={() => startTransition(() => router.refresh())}
      disabled={pending}
      className="inline-flex h-7 flex-none items-center gap-1.5 rounded-full border border-control px-3 text-xs text-ink transition-colors hover:bg-raised disabled:opacity-60"
    >
      <RotateCw className={pending ? "size-3.5 animate-spin" : "size-3.5"} aria-hidden="true" />
      {pending ? "Retrying" : label}
    </button>
  );
}

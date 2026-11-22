"use client";

import { RotateCw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { Button } from "@/components/ui/button";

/** Re-runs the server components of the current route (fresh API reads). */
export function RetryButton({ label = "Retry" }: { label?: string }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={() => startTransition(() => router.refresh())}
      disabled={pending}
      className="flex-none"
    >
      <RotateCw className={pending ? "animate-spin" : undefined} aria-hidden="true" />
      {pending ? "Retrying" : label}
    </Button>
  );
}

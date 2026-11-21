"use client";

import { Sparkles } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useTransition } from "react";

import { requestSummaryAction } from "@/app/(console)/actions";
import { Spinner } from "@/components/ui/spinner";

import { aiStatusText } from "./ai-labels";

/**
 * On-demand Gemini overview. Analysts only (the server action and the API both re-check the
 * role). Spends AI budget, so it is never triggered automatically; failures are shown
 * inline and leave the deterministic investigation untouched.
 */
export function SummaryRequestButton({
  alertId,
  canRequest,
  hasSummary,
}: {
  alertId: string;
  canRequest: boolean;
  hasSummary: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string } | null>(null);

  if (!canRequest) {
    return <p className="text-xs text-muted-foreground">Viewer accounts cannot request AI overviews.</p>;
  }

  function request() {
    setMessage(null);
    startTransition(async () => {
      const result = await requestSummaryAction(alertId);
      if (!result.ok) {
        setMessage({ tone: "error", text: result.message });
        return;
      }
      if (result.status !== "ok") {
        setMessage({ tone: "error", text: `${aiStatusText(result.status)}. No overview was produced.` });
      }
      router.refresh();
    });
  }

  return (
    <div className="flex flex-col items-start gap-2">
      <button
        type="button"
        onClick={request}
        disabled={pending}
        aria-describedby={`summary-note-${alertId}`}
        className="inline-flex h-8 items-center gap-2 rounded-full border border-control px-4 text-sm text-ink transition-colors hover:bg-raised disabled:opacity-60"
      >
        {pending ? <Spinner className="size-3.5" /> : <Sparkles className="size-3.5" aria-hidden="true" />}
        {pending ? "Generating overview" : hasSummary ? "Generate a new overview" : "Generate overview"}
      </button>
      <p id={`summary-note-${alertId}`} aria-live="polite" className="text-xs text-muted-foreground">
        {pending
          ? "Waiting for Gemini; this can take up to a minute and a half."
          : message
            ? <span className={message.tone === "error" ? "text-bad" : undefined}>{message.text}</span>
            : "Uses the daily AI budget. The overview is advisory and cites evidence ids that are checked against this alert."}
      </p>
    </div>
  );
}

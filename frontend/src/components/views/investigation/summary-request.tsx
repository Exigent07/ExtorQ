"use client";

import { Sparkles } from "lucide-react";
import { useState, useTransition } from "react";

import { requestSummaryAction } from "@/app/(console)/actions";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

import { refusalDetail, SUMMARY_OUTCOME } from "./ai-labels";

/**
 * On-demand Gemini overview. Analysts only (the server action and the API both re-check the
 * role). It spends AI budget, so it is never triggered automatically. The server action
 * revalidates the page on success, so a new overview appears without another request.
 */
export function SummaryRequestButton({
  alertId,
  canRequest,
  hasSummary,
  unavailable = null,
}: {
  alertId: string;
  canRequest: boolean;
  hasSummary: boolean;
  /** Why the API would refuse a request right now (provider disabled); the button is then off. */
  unavailable?: string | null;
}) {
  const [pending, startTransition] = useTransition();
  const [message, setMessage] = useState<{ tone: "info" | "error"; text: string } | null>(null);

  if (!canRequest) {
    return <p className="text-xs text-muted-foreground">Viewer accounts cannot request AI overviews.</p>;
  }

  if (unavailable) {
    return (
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <Button type="button" variant="outline" disabled aria-describedby={`summary-note-${alertId}`} className="h-8">
          <Sparkles aria-hidden="true" />
          {hasSummary ? "Generate a new overview" : "Generate overview"}
        </Button>
        <p id={`summary-note-${alertId}`} className="min-w-0 flex-1 text-xs text-muted-foreground">
          {unavailable} System health lists the AI providers.
        </p>
      </div>
    );
  }

  function request() {
    setMessage(null);
    startTransition(async () => {
      const result = await requestSummaryAction(alertId);
      if (!result.ok) {
        setMessage({ tone: "error", text: result.message });
      } else if (result.status !== "ok") {
        const detail = result.status === "budget_exceeded" ? refusalDetail(result.error) : null;
        setMessage({
          tone: "error",
          text: detail ?? SUMMARY_OUTCOME[result.status] ?? `No overview was produced (${result.status}).`,
        });
      } else {
        setMessage({ tone: "info", text: "Overview generated. Its evidence ids were checked against this alert." });
      }
    });
  }

  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
      <Button type="button" variant="outline" onClick={request} disabled={pending} aria-describedby={`summary-note-${alertId}`} className="h-8">
        {pending ? <Spinner className="size-3.5" /> : <Sparkles aria-hidden="true" />}
        {pending ? "Generating overview" : hasSummary ? "Generate a new overview" : "Generate overview"}
      </Button>
      <p id={`summary-note-${alertId}`} aria-live="polite" className="min-w-0 flex-1 text-xs text-muted-foreground">
        {pending ? (
          "Waiting for Gemini; this can take up to a minute and a half."
        ) : message ? (
          <span className={message.tone === "error" ? "text-health-warn" : "text-fg-2"}>{message.text}</span>
        ) : (
          "Spends the daily AI budget (one request per alert per cooldown). Advisory; cited evidence ids are checked against this alert."
        )}
      </p>
    </div>
  );
}

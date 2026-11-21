"use client";

import { ChevronRight } from "lucide-react";
import { useId, useState, useTransition } from "react";

import { loadRawExcerptAction, type RawExcerpt } from "@/app/(console)/actions";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Spinner } from "@/components/ui/spinner";

/**
 * On-demand raw excerpt of one stored event (sanitised at ingestion: secrets redacted,
 * controls stripped, size-bounded). Loaded through a server action so the API token never
 * reaches the browser; rendered as plain text with invisible characters made visible.
 */
export function RawExcerptToggle({ eventId }: { eventId: string }) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<{ excerpt: RawExcerpt } | { error: string } | null>(null);
  const [pending, startTransition] = useTransition();
  const panelId = useId();

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && state === null) {
      startTransition(async () => {
        const result = await loadRawExcerptAction(eventId);
        setState(result.ok ? { excerpt: result.excerpt } : { error: result.message });
      });
    }
  }

  return (
    <div className="min-w-0">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={toggle}
        className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-ink"
      >
        <ChevronRight className={open ? "size-3 rotate-90 transition-transform" : "size-3 transition-transform"} aria-hidden="true" />
        Raw excerpt
      </button>
      {open ? (
        <div id={panelId} className="mt-2 rounded-md border border-border bg-ground px-3 py-2">
          {pending || state === null ? (
            <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
              <Spinner className="size-3" /> Loading the stored record
            </span>
          ) : "error" in state ? (
            <p className="text-xs text-bad">{state.error}</p>
          ) : (
            <ExcerptBody excerpt={state.excerpt} />
          )}
        </div>
      ) : null}
    </div>
  );
}

function ExcerptBody({ excerpt }: { excerpt: RawExcerpt }) {
  return (
    <div className="flex flex-col gap-2">
      {excerpt.raw ? (
        <pre className="max-h-64 overflow-auto font-mono text-xs leading-5 whitespace-pre-wrap text-ink-2">
          <UntrustedText value={excerpt.raw} limit={4000} multiline />
        </pre>
      ) : (
        <p className="text-xs text-muted-foreground">No raw text was stored for this event (structured source).</p>
      )}
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
        <dt className="text-muted-foreground">Parser</dt>
        <dd className="font-mono text-ink-2">
          <UntrustedText value={`${excerpt.parser} ${excerpt.parserVersion}`} limit={80} />
        </dd>
        <dt className="text-muted-foreground">Collector</dt>
        <dd className="font-mono text-ink-2">
          <UntrustedText value={excerpt.collectorId} limit={80} />
        </dd>
        <dt className="text-muted-foreground">Ingested</dt>
        <dd>
          <Timestamp value={excerpt.ingestedTime} />
        </dd>
        {excerpt.sourceNativeId ? (
          <>
            <dt className="text-muted-foreground">Source id</dt>
            <dd className="font-mono text-ink-2">
              <UntrustedText value={excerpt.sourceNativeId} limit={120} />
            </dd>
          </>
        ) : null}
        {excerpt.rawSha256 ? (
          <>
            <dt className="text-muted-foreground">Raw SHA-256</dt>
            <dd className="font-mono break-all text-ink-2">{excerpt.rawSha256}</dd>
          </>
        ) : null}
        <dt className="text-muted-foreground">Handling</dt>
        <dd className="text-ink-2">
          {excerpt.redactionCount > 0
            ? `${excerpt.redactionCount} value${excerpt.redactionCount === 1 ? "" : "s"} redacted at ingestion`
            : "no redactions"}
          {excerpt.truncated ? " · truncated at ingestion" : ""}
        </dd>
      </dl>
    </div>
  );
}

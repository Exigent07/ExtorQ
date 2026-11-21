"use client";

import { ChevronRight } from "lucide-react";
import Link from "next/link";
import { useId, useState, useTransition } from "react";

import { type EvidenceActionResult, loadEvidenceAction } from "@/app/(console)/actions";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Spinner } from "@/components/ui/spinner";
import { formatCount } from "@/lib/format";
import { investigationHref } from "@/lib/security/ids";

/**
 * Source-evidence drill-down for one alert in the history table: the stored events the
 * detector cited, fetched on demand through a server action.
 */
export function EvidenceDrilldown({ alertId, eventCount }: { alertId: string; eventCount: number }) {
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<EvidenceActionResult | null>(null);
  const [pending, startTransition] = useTransition();
  const panelId = useId();
  const href = investigationHref(alertId);

  function toggle() {
    const next = !open;
    setOpen(next);
    if (next && result === null) {
      startTransition(async () => setResult(await loadEvidenceAction(alertId)));
    }
  }

  return (
    <div className="mt-1">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={toggle}
        className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-ink"
      >
        <ChevronRight className={open ? "size-3 rotate-90 transition-transform" : "size-3 transition-transform"} aria-hidden="true" />
        Evidence ({formatCount(eventCount)} event{eventCount === 1 ? "" : "s"})
      </button>
      {open ? (
        <div id={panelId} className="mt-2 rounded-md border border-border bg-ground px-3 py-2">
          {pending || result === null ? (
            <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
              <Spinner className="size-3" /> Loading evidence
            </span>
          ) : !result.ok ? (
            <p className="text-xs text-bad">{result.message}</p>
          ) : result.rows.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No evidence event could be resolved from storage
              {result.unresolved > 0 ? ` (${formatCount(result.unresolved)} cited ids not found; retention may have removed them)` : ""}.
            </p>
          ) : (
            <div>
              <ul className="divide-y divide-rule">
                {result.rows.map((row) => (
                  <li key={row.eventId} className="grid gap-x-3 gap-y-0.5 py-1.5 text-xs sm:grid-cols-[11rem_minmax(0,1fr)]">
                    <Timestamp value={row.eventTime} />
                    <div className="min-w-0">
                      <span className="font-mono text-ink">
                        <UntrustedText value={row.eventType} limit={64} />
                      </span>
                      <span className="text-muted-foreground">
                        {" · "}
                        <UntrustedText value={row.sourceType} limit={32} />
                        {row.actor ? (
                          <>
                            {" · "}
                            <UntrustedText value={row.actor} limit={48} />
                          </>
                        ) : null}
                        {row.srcIp ? (
                          <>
                            {" · "}
                            <UntrustedText value={row.srcIp} limit={48} mono />
                          </>
                        ) : null}
                      </span>
                      {row.message ? (
                        <div className="text-muted-foreground">
                          <UntrustedText value={row.message} limit={160} />
                        </div>
                      ) : null}
                    </div>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-xs text-muted-foreground">
                {formatCount(result.rows.length)} of {formatCount(result.total)} evidence events shown
                {result.capped ? " (the detector capped the evidence list)" : ""}
                {result.unresolved > 0 ? ` · ${formatCount(result.unresolved)} cited ids not found in storage` : ""}.{" "}
                {href ? (
                  <Link href={href} className="text-ink-2 hover:text-ink hover:underline">
                    Open the investigation
                  </Link>
                ) : null}
              </p>
            </div>
          )}
        </div>
      ) : null}
    </div>
  );
}

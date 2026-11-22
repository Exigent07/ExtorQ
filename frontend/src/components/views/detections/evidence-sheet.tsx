"use client";

import { ArrowRight, CircleAlert, Layers } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { type EvidenceActionResult, loadEvidenceAction } from "@/app/(console)/actions";
import { ConfidenceBadge, SimulationBadge } from "@/components/console/badges";
import { DetailSection, DetailSheet } from "@/components/console/detail-sheet";
import { KeyValueList } from "@/components/console/key-values";
import { SeverityBadge } from "@/components/console/severity";
import { Bar } from "@/components/console/skeletons";
import { EmptyState } from "@/components/console/states";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Button } from "@/components/ui/button";
import { AnalystStatusText } from "@/components/views/alerts/alert-bits";
import { DASH, formatCount, humanize } from "@/lib/format";
import { assetHref, investigationHref, isAssetId } from "@/lib/security/ids";

import type { AlertRow } from "./model";
import { utcLabel } from "@/components/console/time";

/** Evidence fetched in this browser tab, reused for a minute (each fetch costs API reads). */
const CACHE_MS = 60_000;
const cache = new Map<string, { at: number; result: EvidenceActionResult }>();

function cached(alertId: string): EvidenceActionResult | null {
  const hit = cache.get(alertId);
  return hit && Date.now() - hit.at < CACHE_MS ? hit.result : null;
}

/**
 * The evidence count of an alert as a chip; it opens a right-hand sheet with the alert's
 * facts and the stored events the detector cited (loaded on open through a read-only server
 * action, never from the browser). Replaces the first console's inline "Evidence (n events)"
 * disclosure.
 */
export function EvidenceSheet({ row }: { row: AlertRow }) {
  const href = investigationHref(row.id);
  return (
    <DetailSheet
      trigger={
        <button
          type="button"
          aria-label={`Evidence: ${formatCount(row.events)} event${row.events === 1 ? "" : "s"} of ${row.ruleId}. Open details`}
          className="inline-flex h-6 items-center gap-1.5 rounded-md px-2 font-mono text-xs text-fg-2 ring-1 ring-hairline-strong transition-colors duration-150 ring-inset hover:bg-hover hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/60 focus-visible:outline-none"
        >
          <Layers className="size-3 text-muted-foreground" aria-hidden="true" />
          {formatCount(row.events)}
        </button>
      }
      title={<UntrustedText value={row.ruleTitle} plain limit={200} />}
      description={
        <span className="font-mono text-xs">
          {row.ruleId} · v<UntrustedText value={row.ruleVersion} plain limit={24} />
        </span>
      }
      badges={
        <>
          <SeverityBadge severity={row.severity} size="md" />
          <span className="inline-flex h-6 items-center gap-2 rounded-md px-2 text-xs text-muted-foreground ring-1 ring-hairline-strong ring-inset">
            Evidence confidence
            <ConfidenceBadge confidence={row.confidence} className="text-xs" />
          </span>
          <SimulationBadge runIds={row.simulationRunIds} />
        </>
      }
      footer={
        href ? (
          <div className="flex w-full items-center justify-between gap-3">
            <span className="text-xs text-muted-foreground">Full timeline, correlation and AI context</span>
            <Button asChild>
              <Link href={href}>
                Open investigation
                <ArrowRight data-icon="inline-end" aria-hidden="true" />
              </Link>
            </Button>
          </div>
        ) : null
      }
    >
      <DetailSection title="What fired">
        <p className="text-sm leading-relaxed text-fg-2">
          <UntrustedText value={row.summary} limit={600} />
        </p>
      </DetailSection>
      <DetailSection title="Alert">
        <KeyValueList
          rows={[
            {
              label: "Asset",
              value: isAssetId(row.assetId) ? (
                <Link href={assetHref(row.assetId)} className="font-mono text-xs text-fg-2 hover:text-foreground hover:underline">
                  <UntrustedText value={row.assetId} plain limit={80} />
                </Link>
              ) : (
                <UntrustedText value={row.assetId} limit={80} mono />
              ),
            },
            { label: "First seen", value: <span className="font-mono text-xs">{utcLabel(row.firstSeen)}</span> },
            { label: "Last seen", value: <span className="font-mono text-xs">{utcLabel(row.lastSeen)}</span> },
            { label: "Evidence events", value: <span className="tabular-nums">{formatCount(row.events)}</span> },
            {
              label: "Services",
              value: row.services > 0 ? <span className="tabular-nums">{formatCount(row.services)}</span> : "None linked",
            },
            { label: "Analyst status", value: <AnalystStatusText status={row.status} recorded={row.statusRecorded} /> },
          ]}
        />
      </DetailSection>
      <EvidenceEvents alertId={row.id} />
    </DetailSheet>
  );
}

function EvidenceEvents({ alertId }: { alertId: string }) {
  const [result, setResult] = useState<EvidenceActionResult | null>(() => cached(alertId));

  useEffect(() => {
    if (result) return;
    let cancelled = false;
    loadEvidenceAction(alertId)
      .then((loaded) => {
        if (cancelled) return;
        if (loaded.ok) cache.set(alertId, { at: Date.now(), result: loaded });
        setResult(loaded);
      })
      .catch(() => {
        if (!cancelled) setResult({ ok: false, message: "The evidence could not be loaded. Try again." });
      });
    return () => {
      cancelled = true;
    };
  }, [alertId, result]);

  if (result === null) {
    return (
      <DetailSection title="Evidence events">
        <div role="status" aria-live="polite" className="grid gap-3 rounded-lg px-3.5 py-3 ring-1 ring-hairline ring-inset">
          <span className="sr-only">Loading evidence</span>
          {[0, 1, 2].map((i) => (
            <div key={i} className="grid gap-2">
              <Bar className="h-3.5 w-2/3" />
              <Bar className="h-3 w-1/2" />
            </div>
          ))}
        </div>
      </DetailSection>
    );
  }
  if (!result.ok) {
    return (
      <DetailSection title="Evidence events">
        <p role="alert" className="flex items-start gap-2 rounded-lg bg-health-bad/[0.06] px-3.5 py-3 text-sm text-fg-2 ring-1 ring-health-bad/20 ring-inset">
          <CircleAlert className="mt-0.5 size-4 flex-none text-health-bad" aria-hidden="true" />
          <span>
            Couldn&apos;t load the evidence. <span className="text-muted-foreground">{result.message}</span>
          </span>
        </p>
      </DetailSection>
    );
  }
  if (result.rows.length === 0) {
    return (
      <DetailSection title="Evidence events">
        <EmptyState>
          No evidence event could be resolved from storage
          {result.unresolved > 0
            ? ` (${formatCount(result.unresolved)} cited id${result.unresolved === 1 ? "" : "s"} not found; retention may have removed them)`
            : ""}
          .
        </EmptyState>
      </DetailSection>
    );
  }
  return (
    <DetailSection title={`Evidence events · ${formatCount(result.rows.length)} of ${formatCount(result.total)}`}>
      <ol className="divide-y divide-hairline-soft overflow-hidden rounded-lg ring-1 ring-hairline ring-inset">
        {result.rows.map((event) => (
          <li key={event.eventId} className="grid gap-1.5 px-3.5 py-3">
            <div className="flex min-w-0 items-center justify-between gap-3">
              <span className="min-w-0 flex-1 text-sm font-medium text-foreground">
                <UntrustedText value={event.eventType} oneLine mono />
              </span>
              <time dateTime={event.eventTime} className="flex-none font-mono text-xs text-muted-foreground tabular-nums">
                {utcLabel(event.eventTime)}
              </time>
            </div>
            <dl className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
              <Field label="Source" value={event.sourceType} mono />
              {event.role ? <Field label="Role" value={humanize(event.role)} /> : null}
              {event.actor ? <Field label="Actor" value={event.actor} /> : null}
              {event.srcIp ? <Field label="From" value={event.srcIp} mono /> : null}
            </dl>
            {event.message ? (
              <p className="text-xs leading-relaxed text-fg-2">
                <UntrustedText value={event.message} limit={240} />
              </p>
            ) : null}
          </li>
        ))}
      </ol>
      <p className="text-xs leading-relaxed text-muted-foreground">
        {formatCount(result.rows.length)} of {formatCount(result.total)} cited events shown
        {result.capped ? " (the detector capped the evidence list)" : ""}
        {result.unresolved > 0
          ? ` · ${formatCount(result.unresolved)} cited id${result.unresolved === 1 ? "" : "s"} not found in storage`
          : ""}
        . Raw excerpts and the full timeline are in the investigation.
      </p>
    </DetailSection>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string | null; mono?: boolean }) {
  return (
    <div className="flex min-w-0 max-w-full items-baseline gap-1.5">
      <dt className="flex-none text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-fg-2">{value ? <UntrustedText value={value} limit={80} mono={mono} /> : DASH}</dd>
    </div>
  );
}

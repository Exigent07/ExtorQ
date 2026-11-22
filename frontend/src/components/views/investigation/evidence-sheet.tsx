"use client";

import { ArrowUpRight } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";

import { loadRawExcerptAction, type RawExcerptResult } from "@/app/(console)/actions";
import { DetailSection, RawBlock } from "@/components/console/detail-sheet";
import { IdText } from "@/components/console/id-text";
import { KeyValueList } from "@/components/console/key-values";
import { Bar } from "@/components/console/skeletons";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { EvidenceEvent } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { assetHref, isHexId, serviceHref } from "@/lib/security/ids";

import { FeatureTable } from "./feature-value";
import { evidenceFieldGroups, type FieldRow, orderFeatures } from "./model";

function FieldValue({ row }: { row: FieldRow }) {
  if (row.value === null || row.value === undefined || row.value === "") return <span className="text-muted-foreground">—</span>;
  if (row.time && typeof row.value === "string") return <Timestamp value={row.value} />;
  return <UntrustedText value={String(row.value)} limit={120} mono={row.mono} className={row.mono ? "text-fg-2" : undefined} />;
}

/**
 * The stored record behind an evidence row, loaded when the sheet opens (one read through the
 * server action; the API token never reaches the browser). Sanitised at ingestion: secrets
 * redacted, controls stripped, size-bounded; shown as text with invisible characters marked.
 */
function RawExcerpt({ eventId }: { eventId: string }) {
  const [state, setState] = useState<RawExcerptResult | null>(null);
  useEffect(() => {
    let live = true;
    loadRawExcerptAction(eventId).then(
      (result) => {
        if (live) setState(result);
      },
      () => {
        if (live) setState({ ok: false, message: "The request for the stored record failed." });
      },
    );
    return () => {
      live = false;
    };
  }, [eventId]);

  if (state === null) {
    return (
      <div role="status" aria-label="Loading the stored record" className="grid gap-2">
        <Bar className="h-24 w-full" />
        <Bar className="h-4 w-2/3" />
      </div>
    );
  }
  if (!state.ok) {
    return <p className="text-sm text-health-bad">Couldn&apos;t load the stored record. {state.message}</p>;
  }
  const excerpt = state.excerpt;
  return (
    <div className="grid gap-3">
      {excerpt.raw ? (
        <RawBlock>
          <UntrustedText value={excerpt.raw} limit={8000} multiline mono />
        </RawBlock>
      ) : (
        <p className="rounded-lg px-3 py-2.5 text-sm text-muted-foreground ring-1 ring-hairline ring-inset">
          No raw text was stored for this event (structured source).
        </p>
      )}
      <KeyValueList
        rows={[
          { label: "Parser", value: <UntrustedText value={`${excerpt.parser} ${excerpt.parserVersion}`} limit={80} mono /> },
          { label: "Collector", value: <UntrustedText value={excerpt.collectorId} limit={80} mono /> },
          { label: "Ingested", value: <Timestamp value={excerpt.ingestedTime} /> },
          ...(excerpt.sourceNativeId
            ? [{ label: "Source record id", value: <UntrustedText value={excerpt.sourceNativeId} limit={120} mono /> }]
            : []),
          ...(excerpt.rawSha256 ? [{ label: "Raw SHA-256", value: <IdText id={excerpt.rawSha256} head={16} /> }] : []),
          {
            label: "Handling",
            value: (
              <span>
                {excerpt.redactionCount > 0
                  ? `${formatCount(excerpt.redactionCount)} value${excerpt.redactionCount === 1 ? "" : "s"} redacted at ingestion`
                  : "No redactions"}
                {excerpt.truncated ? " · truncated at ingestion" : ""}
              </span>
            ),
          },
        ]}
      />
    </div>
  );
}

/** Body of an evidence row's detail sheet: every normalised field, attributes, raw excerpt. */
export function EvidenceDetails({ event }: { event: EvidenceEvent }) {
  const groups = evidenceFieldGroups(event);
  const attributes = orderFeatures(event.attributes);
  return (
    <>
      {groups.map((group) => (
        <DetailSection key={group.title} title={group.title}>
          <KeyValueList rows={group.rows.map((row) => ({ label: row.label, value: <FieldValue row={row} /> }))} />
        </DetailSection>
      ))}
      {attributes.length > 0 ? (
        <DetailSection title={`Source attributes (${formatCount(attributes.length)})`}>
          <FeatureTable features={event.attributes} empty="No source attributes were stored." columns={1} />
        </DetailSection>
      ) : null}
      <DetailSection title="Raw excerpt (sanitised at ingestion)">
        <RawExcerpt eventId={event.event_id} />
      </DetailSection>
    </>
  );
}

/** Sheet footer: links built from validated ids only. */
export function EvidenceFooter({ event }: { event: EvidenceEvent }) {
  const service = event.service_id && isHexId(event.service_id) ? serviceHref(event.service_id) : null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
      <span className="inline-flex items-center gap-1">
        Event <IdText id={event.event_id} />
      </span>
      <span className="flex items-center gap-4">
        <Link href={assetHref(event.asset_id)} className="inline-flex items-center gap-0.5 hover:text-foreground">
          Asset <ArrowUpRight className="size-3" aria-hidden="true" />
        </Link>
        {service ? (
          <Link href={service} className="inline-flex items-center gap-0.5 hover:text-foreground">
            Service <ArrowUpRight className="size-3" aria-hidden="true" />
          </Link>
        ) : null}
      </span>
    </div>
  );
}

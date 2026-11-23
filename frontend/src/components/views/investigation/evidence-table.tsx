"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { PanelRightOpen } from "lucide-react";
import { useEffect, useMemo, useRef } from "react";

import { clickRowOpener, DataTable, type DataTableHandle, type Facet, type FacetOption } from "@/components/console/data-table";
import { DetailSheet } from "@/components/console/detail-sheet";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { EvidenceEvent } from "@/lib/api/schemas";
import { DASH, humanize } from "@/lib/format";
import { shortId } from "@/lib/security/display";

import { EvidenceDetails, EvidenceFooter } from "./evidence-sheet";
import { useInvestigationNav } from "./investigation-tabs";
import { evidenceRoleLabel } from "./labels";
import { actorOf, identifiers } from "./model";

function timeValue(e: EvidenceEvent): number {
  const ms = Date.parse(e.event_time);
  return Number.isNaN(ms) ? Number.POSITIVE_INFINITY : ms;
}

function searchText(e: EvidenceEvent): string {
  return [e.event_type, e.message, actorOf(e), e.src_ip, e.source_type, ...identifiers(e)].filter(Boolean).join(" ").toLowerCase();
}

/** The detail sheet of one evidence row (right drawer; the row click delegates to its trigger). */
function OpenButton({ event }: { event: EvidenceEvent }) {
  const role = evidenceRoleLabel(event.role);
  return (
    <DetailSheet
      size="lg"
      titleClassName="font-mono text-base"
      trigger={
        <button
          type="button"
          data-row-open=""
          className="inline-flex max-w-full min-w-0 items-center gap-1.5 rounded-sm text-left font-mono text-xs font-medium text-foreground underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <span className="min-w-0 truncate">
            <UntrustedText value={event.event_type} limit={64} plain />
          </span>
          <span className="sr-only">: open all fields and the raw excerpt</span>
        </button>
      }
      title={<UntrustedText value={event.event_type} limit={80} />}
      description={event.message ? <UntrustedText value={event.message} limit={400} /> : "No message was stored for this event."}
      badges={
        <>
          <span className="inline-flex h-5 items-center rounded-md px-1.5 text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset">
            Outcome: <UntrustedText value={event.outcome} limit={24} className="ml-1" />
          </span>
          {role ? (
            <span className="inline-flex h-5 items-center rounded-md px-1.5 text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset">
              {role} evidence
            </span>
          ) : null}
          <Timestamp value={event.event_time} className="text-xs" />
        </>
      }
      footer={<EvidenceFooter event={event} />}
    >
      <EvidenceDetails event={event} />
    </DetailSheet>
  );
}

const columns: ColumnDef<EvidenceEvent, unknown>[] = [
  {
    id: "time",
    accessorFn: timeValue,
    header: "Time (UTC)",
    enableHiding: false,
    cell: ({ row }) => (
      <div className="grid gap-0.5">
        <Timestamp value={row.original.event_time} />
        <span className="font-mono text-xs text-muted-foreground">{shortId(row.original.event_id, 12)}</span>
      </div>
    ),
    meta: { className: "hidden w-40 @xl:table-cell" },
  },
  {
    id: "event",
    accessorFn: (e) => e.event_type,
    header: "Event",
    enableHiding: false,
    cell: ({ row }) => {
      const e = row.original;
      const ids = identifiers(e);
      return (
        <div className="grid min-w-0 gap-1">
          <span className="@xl:hidden">
            <Timestamp value={e.event_time} />
          </span>
          <div className="flex min-w-0 items-center gap-2">
            <OpenButton event={e} />
            <span className="flex-none text-xs text-muted-foreground">
              <UntrustedText value={e.outcome} limit={24} />
            </span>
            <PanelRightOpen
              className="ml-auto size-3.5 flex-none text-muted-foreground opacity-0 transition-opacity duration-150 group-hover/row:opacity-100 group-focus-within/row:opacity-100"
              aria-hidden="true"
            />
          </div>
          {e.message ? (
            <span className="min-w-0 text-sm text-fg-2">
              <UntrustedText value={e.message} limit={400} oneLine />
            </span>
          ) : null}
          {ids.length > 0 ? (
            <span className="min-w-0 text-xs text-muted-foreground">
              <UntrustedText value={ids.join(" · ")} limit={400} oneLine plain mono />
            </span>
          ) : null}
        </div>
      );
    },
    meta: { className: "w-full max-w-0 min-w-48 whitespace-normal @max-xl:pl-(--table-edge) @max-2xl:pr-(--table-edge)" },
  },
  {
    id: "actor",
    accessorFn: (e) => actorOf(e) ?? "",
    header: "Actor",
    enableHiding: false,
    cell: ({ row }) => {
      const actor = actorOf(row.original);
      return actor ? (
        <div className="max-w-56 min-w-0 text-sm text-fg-2">
          <UntrustedText value={actor} limit={120} oneLine />
        </div>
      ) : (
        <span className="text-muted-foreground">{DASH}</span>
      );
    },
    meta: { className: "hidden min-w-[200px] @3xl:table-cell" },
  },
  {
    id: "src",
    accessorFn: (e) => e.src_ip ?? "",
    header: "Source IP",
    enableHiding: false,
    cell: ({ row }) =>
      row.original.src_ip ? (
        <div className="w-[112px] max-w-32 min-w-0 font-mono text-xs text-fg-2">
          <UntrustedText value={row.original.src_ip} limit={64} oneLine plain />
        </div>
      ) : (
        <span className="text-muted-foreground">{DASH}</span>
      ),
    meta: { className: "hidden @2xl:table-cell @max-4xl:pr-(--table-edge)" },
  },
  {
    id: "role",
    accessorFn: (e) => e.role ?? "",
    header: "Role",
    enableSorting: false,
    enableHiding: false,
    cell: ({ row }) => <span className="text-xs text-fg-2">{evidenceRoleLabel(row.original.role) ?? DASH}</span>,
    meta: { className: "hidden @4xl:table-cell" },
  },
  {
    id: "source",
    accessorFn: (e) => e.source_type,
    header: "Source",
    enableSorting: false,
    enableHiding: false,
  },
];

function options(values: readonly string[], label: (value: string) => string = (v) => v): FacetOption[] {
  return [...new Set(values.filter(Boolean))].sort().map((value) => ({ value, label: label(value) }));
}

/**
 * Supporting evidence as a data table (the shared DataTable): oldest first, sortable,
 * filterable by event type, source and role, searchable, paginated. Every row is the anchor
 * `#evidence-<event_id>`; clicking a row opens its detail sheet, which holds every full value.
 * AI evidence chips and timeline links reveal a row through the investigation navigation: the
 * table clears its filters, turns to the row's page and highlights it.
 */
export function EvidenceTable({ evidence }: { evidence: EvidenceEvent[] }) {
  const nav = useInvestigationNav();
  const handle = useRef<DataTableHandle>(null);
  const haystack = useMemo(() => new Map(evidence.map((e) => [e.event_id, searchText(e)])), [evidence]);
  const facets = useMemo<Facet[]>(
    () => [
      { columnId: "event", title: "Event type", options: options(evidence.map((e) => e.event_type)) },
      { columnId: "source", title: "Source", options: options(evidence.map((e) => e.source_type)) },
      {
        columnId: "role",
        title: "Role",
        options: options(
          evidence.map((e) => e.role ?? ""),
          (v) => evidenceRoleLabel(v) ?? humanize(v),
        ),
      },
    ],
    [evidence],
  );

  useEffect(() => {
    nav?.registerEvidenceReveal((eventId) => handle.current?.reveal(eventId) ?? false);
    return () => nav?.registerEvidenceReveal(null);
  }, [nav]);

  return (
    <div className="@container">
      <DataTable
        data={evidence}
        columns={columns}
        getRowId={(e) => e.event_id}
        label="Supporting evidence"
        initialSort={[{ id: "time", desc: false }]}
        facets={facets}
        search={{
          placeholder: "Search events, actors, IPs, ids",
          label: "Search the evidence",
          match: (e, needle) => (haystack.get(e.event_id) ?? "").includes(needle),
        }}
        initialColumnVisibility={{ source: false }}
        rowAnchorId={(e) => `evidence-${e.event_id}`}
        onRowClick={clickRowOpener}
        handleRef={handle}
        emptyMessage="No evidence event matches the search and filters."
        cellClassName="py-3 align-top"
      />
    </div>
  );
}

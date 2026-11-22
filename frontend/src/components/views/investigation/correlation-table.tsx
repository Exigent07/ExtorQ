"use client";

import type { ColumnDef } from "@tanstack/react-table";

import { DataTable, type Facet } from "@/components/console/data-table";
import { UntrustedText } from "@/components/console/untrusted-text";
import { formatCount } from "@/lib/format";

import { basisLabel, orderedBases, relationshipLabel, strengthLabel } from "./labels";
import { offsetLabel, type RelatedRow } from "./model";
import { RelationshipHover, RelationshipMarker } from "./relationship";

const columns: ColumnDef<RelatedRow, unknown>[] = [
  {
    id: "relationship",
    accessorFn: (r) => r.type,
    header: "Relationship",
    enableSorting: false,
    cell: ({ row }) => (
      <RelationshipHover
        rel={{
          type: row.original.type,
          strength: row.original.strength,
          bases: row.original.bases,
          offsetSeconds: row.original.offsetSeconds,
          explanation: row.original.explanation,
        }}
      />
    ),
    meta: { className: "w-32", label: "Relationship" },
  },
  {
    id: "strength",
    accessorFn: (r) => r.strength,
    header: "Strength",
    enableSorting: false,
    cell: ({ row }) => <span className="text-xs text-fg-2">{strengthLabel(row.original.strength)}</span>,
    meta: { className: "hidden w-24 @2xl:table-cell", label: "Strength" },
  },
  {
    id: "observation",
    accessorFn: (r) => r.summary ?? "",
    header: "Observation",
    enableSorting: false,
    cell: ({ row }) => {
      const r = row.original;
      return (
        <div className="grid min-w-0 gap-0.5">
          <span className="font-mono text-xs text-foreground">
            {r.eventType ? <UntrustedText value={r.eventType} limit={64} oneLine /> : "Event not in the context timeline"}
          </span>
          {r.summary && r.summary !== r.eventType ? (
            <span className="min-w-0 text-sm text-fg-2">
              <UntrustedText value={r.summary} limit={300} oneLine />
            </span>
          ) : null}
        </div>
      );
    },
    meta: { className: "w-full max-w-0 min-w-56 whitespace-normal", label: "Observation" },
  },
  {
    id: "basis",
    accessorFn: (r) => r.bases.join(" "),
    header: "Basis",
    enableSorting: false,
    cell: ({ row }) => {
      const bases = orderedBases(row.original.bases);
      return (
        <span className="flex max-w-56 flex-wrap gap-1">
          {bases.slice(0, 2).map((basis) => (
            <span
              key={basis}
              className={
                basis === "shared_nat_source_ip"
                  ? "inline-flex h-5 items-center rounded-md bg-health-warn/[0.06] px-1.5 text-xs text-fg-2 ring-1 ring-health-warn/25 ring-inset"
                  : "inline-flex h-5 items-center rounded-md bg-white/[0.03] px-1.5 text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset"
              }
            >
              {basisLabel(basis)}
            </span>
          ))}
          {bases.length > 2 ? <span className="inline-flex h-5 items-center text-xs text-muted-foreground">+{bases.length - 2}</span> : null}
        </span>
      );
    },
    meta: { className: "hidden @4xl:table-cell", label: "Basis" },
  },
  {
    id: "offset",
    accessorFn: (r) => r.offsetSeconds,
    header: "From first evidence",
    cell: ({ row }) => <span className="font-mono text-xs text-fg-2">{offsetLabel(row.original.offsetSeconds)}</span>,
    meta: { align: "right", className: "w-32", label: "From first evidence" },
  },
  { id: "eventType", accessorFn: (r) => r.eventType ?? "", enableHiding: false, enableSorting: false },
  { id: "explanation", accessorFn: (r) => r.explanation, enableHiding: false, enableSorting: false },
];

function facetOptions(values: readonly string[], label: (v: string) => string, withMarker = false) {
  return [...new Set(values.filter(Boolean))].map((value) => ({
    value,
    label: label(value),
    icon: withMarker ? <RelationshipMarker type={value} /> : undefined,
  }));
}

/**
 * Every related observation of the investigation context (the shared DataTable: facets by
 * relationship, strength and event type, search over summaries and explanations, paging).
 * The explanation of each link is in the relationship's hover card.
 */
export function CorrelationTable({ rows }: { rows: RelatedRow[] }) {
  const order = ["direct", "candidate", "unestablished"];
  const facets: Facet[] = [
    {
      columnId: "relationship",
      title: "Relationship",
      options: facetOptions(rows.map((r) => r.type), relationshipLabel, true).sort(
        (a, b) => order.indexOf(a.value) - order.indexOf(b.value),
      ),
    },
    {
      columnId: "strength",
      title: "Strength",
      options: facetOptions(rows.map((r) => r.strength), strengthLabel).sort(
        (a, b) => ["strong", "moderate", "weak"].indexOf(a.value) - ["strong", "moderate", "weak"].indexOf(b.value),
      ),
    },
    {
      columnId: "eventType",
      title: "Event type",
      options: facetOptions(rows.map((r) => r.eventType ?? ""), (v) => v).sort((a, b) => a.label.localeCompare(b.label)),
    },
  ].filter((facet) => facet.options.length > 1);

  return (
    <div className="@container">
      <DataTable
        data={rows}
        columns={columns}
        getRowId={(r) => r.eventId}
        label="Correlated observations"
        facets={facets}
        search={{ placeholder: "Search observations and reasons", columnIds: ["observation", "eventType", "explanation"] }}
        pageSize={25}
        initialColumnVisibility={{ eventType: false, explanation: false }}
        emptyMessage={`No related observation matches the filters (${formatCount(rows.length)} in total).`}
      />
    </div>
  );
}

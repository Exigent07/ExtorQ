"use client";

import type { ColumnDef, ColumnFiltersState } from "@tanstack/react-table";
import { cn } from "cn";
import { PanelRightOpen } from "lucide-react";
import { useMemo, useState } from "react";

import { clickRowOpener, DataTable, type Facet } from "@/components/console/data-table";
import { DetailSection, DetailSheet } from "@/components/console/detail-sheet";
import { UntrustedText } from "@/components/console/untrusted-text";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { formatCount } from "@/lib/format";

import { basisLabel, orderedBases, relationshipDetail, relationshipLabel, strengthLabel } from "./labels";
import { groupRelated, offsetLabel, type RelatedGroup, type RelatedRow, type RelationshipGroup } from "./model";
import { RelationshipHover, RelationshipMarker } from "./relationship";

const ORDER = ["direct", "candidate", "unestablished"];
const STRENGTHS = ["strong", "moderate", "weak"];

/** Link strength as a 3-dot meter and its word (strong ●●●, moderate ●●○, weak ●○○). */
export function StrengthMeter({ strength }: { strength: string }) {
  const filled = strength === "strong" ? 3 : strength === "moderate" ? 2 : strength === "weak" ? 1 : 0;
  return (
    <span className="inline-flex items-center gap-1.5 text-xs whitespace-nowrap text-fg-2">
      <span aria-hidden="true" className="inline-flex gap-0.5">
        {[0, 1, 2].map((i) => (
          <span key={i} className={cn("size-1.5 rounded-full", i < filled ? "bg-fg-2" : "bg-transparent ring-1 ring-fg-faint ring-inset")} />
        ))}
      </span>
      {strengthLabel(strength)}
    </span>
  );
}

function BasisChips({ bases, max = 2 }: { bases: readonly string[]; max?: number }) {
  const ordered = orderedBases(bases);
  return (
    <span className="flex max-w-56 flex-wrap gap-1">
      {ordered.slice(0, max).map((basis) => (
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
      {ordered.length > max ? <span className="inline-flex h-5 items-center text-xs text-muted-foreground">+{ordered.length - max}</span> : null}
    </span>
  );
}

function offsetRange(group: RelatedGroup): string {
  const from = offsetLabel(group.minOffset);
  const to = offsetLabel(group.maxOffset);
  return from === to ? from : `${from} to ${to}`;
}

/** Every member of a group in a sheet: time offset, summary, bases and the layer's explanation. */
function GroupSheet({ group }: { group: RelatedGroup }) {
  const count = group.rows.length;
  return (
    <DetailSheet
      size="lg"
      title={
        <span className="flex items-center gap-2">
          <RelationshipMarker type={group.type} />
          {relationshipLabel(group.type)} · {strengthLabel(group.strength)} ·{" "}
          <span className="font-mono text-base">{group.eventType ? <UntrustedText value={group.eventType} limit={64} plain /> : "not in the timeline"}</span>
        </span>
      }
      description={`${formatCount(count)} related observation${count === 1 ? "" : "s"}, ${offsetRange(group)} from the first evidence. ${relationshipDetail(group.type)}`}
      trigger={
        <button
          type="button"
          data-row-open=""
          aria-label={`${formatCount(count)} ${relationshipLabel(group.type).toLowerCase()} observations: open the list`}
          className="flex-none rounded-md p-1 text-muted-foreground opacity-0 transition-opacity duration-150 group-hover/row:opacity-100 hover:bg-hover hover:text-foreground focus-visible:opacity-100 focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <PanelRightOpen className="size-3.5" aria-hidden="true" />
        </button>
      }
    >
      <DetailSection title="Shared by every observation">
        {group.bases.length > 0 ? <BasisChips bases={group.bases} max={6} /> : <p className="text-sm text-muted-foreground">No basis common to all.</p>}
      </DetailSection>
      <DetailSection title="Observations">
        <ol className="divide-y divide-hairline-soft rounded-lg ring-1 ring-hairline ring-inset">
          {group.rows.map((row) => (
            <li key={row.eventId} className="grid gap-1 px-3 py-2.5">
              <div className="flex items-baseline justify-between gap-3">
                <span className="min-w-0 text-sm text-fg-2">
                  {row.summary ? <UntrustedText value={row.summary} limit={300} /> : <span className="text-muted-foreground">No summary stored</span>}
                </span>
                <span className="flex-none text-xs text-muted-foreground tabular-nums">{offsetLabel(row.offsetSeconds)}</span>
              </div>
              <p className="text-xs leading-relaxed text-muted-foreground">
                <UntrustedText value={row.explanation} limit={400} />
              </p>
            </li>
          ))}
        </ol>
      </DetailSection>
    </DetailSheet>
  );
}

function groupColumns(showStrength: boolean): ColumnDef<RelatedGroup, unknown>[] {
  return [
    {
      id: "relationship",
      accessorFn: (g) => g.type,
      header: "Relationship",
      enableSorting: false,
      cell: ({ row }) => (
        <span className="inline-flex items-center gap-1.5 text-xs whitespace-nowrap text-fg-2">
          <RelationshipMarker type={row.original.type} />
          {relationshipLabel(row.original.type)}
        </span>
      ),
      meta: { className: "w-32", label: "Relationship" },
    },
    ...(showStrength
      ? [
          {
            id: "strength",
            accessorFn: (g: RelatedGroup) => g.strength,
            header: "Strength",
            enableSorting: false,
            cell: ({ row }: { row: { original: RelatedGroup } }) => <StrengthMeter strength={row.original.strength} />,
            meta: { className: "hidden w-28 @2xl:table-cell", label: "Strength" },
          } satisfies ColumnDef<RelatedGroup, unknown>,
        ]
      : []),
    {
      id: "observation",
      accessorFn: (g) => `${g.eventType ?? ""} ${g.rows.map((r) => r.summary ?? "").join(" ")}`,
      header: "Observations",
      enableSorting: false,
      cell: ({ row }) => {
        const g = row.original;
        const example = g.rows[0]?.summary ?? null;
        return (
          <div className="grid min-w-0 gap-0.5">
            <span className="flex min-w-0 items-center gap-2">
              <span className="min-w-0 font-mono text-xs text-foreground">
                {g.eventType ? <UntrustedText value={g.eventType} limit={64} oneLine /> : "Event not in the context timeline"}
              </span>
              <span className="flex-none text-xs text-muted-foreground tabular-nums">× {formatCount(g.rows.length)}</span>
              <GroupSheet group={g} />
            </span>
            {example ? (
              <span className="min-w-0 text-sm text-fg-2">
                <UntrustedText value={example} limit={300} oneLine />
              </span>
            ) : null}
          </div>
        );
      },
      meta: { className: "w-full max-w-0 min-w-56 whitespace-normal", label: "Observations" },
    },
    {
      id: "basis",
      accessorFn: (g) => g.bases.join(" "),
      header: "Shared basis",
      enableSorting: false,
      cell: ({ row }) => <BasisChips bases={row.original.bases} />,
      meta: { className: "hidden @4xl:table-cell", label: "Shared basis" },
    },
    {
      id: "offset",
      accessorFn: (g) => Math.abs(g.minOffset),
      header: "From first evidence",
      cell: ({ row }) => <span className="text-xs whitespace-nowrap text-fg-2 tabular-nums">{offsetRange(row.original)}</span>,
      meta: { align: "right", className: "w-40", label: "From first evidence" },
    },
  ];
}

function rowColumns(showStrength: boolean): ColumnDef<RelatedRow, unknown>[] {
  return [
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
    ...(showStrength
      ? [
          {
            id: "strength",
            accessorFn: (r: RelatedRow) => r.strength,
            header: "Strength",
            enableSorting: false,
            cell: ({ row }: { row: { original: RelatedRow } }) => <StrengthMeter strength={row.original.strength} />,
            meta: { className: "hidden w-28 @2xl:table-cell", label: "Strength" },
          } satisfies ColumnDef<RelatedRow, unknown>,
        ]
      : []),
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
      cell: ({ row }) => <BasisChips bases={row.original.bases} />,
      meta: { className: "hidden @4xl:table-cell", label: "Basis" },
    },
    {
      id: "offset",
      accessorFn: (r) => r.offsetSeconds,
      header: "From first evidence",
      cell: ({ row }) => <span className="text-xs text-fg-2 tabular-nums">{offsetLabel(row.original.offsetSeconds)}</span>,
      meta: { align: "right", className: "w-32", label: "From first evidence" },
    },
    { id: "eventType", accessorFn: (r) => r.eventType ?? "", enableHiding: false, enableSorting: false },
    { id: "explanation", accessorFn: (r) => r.explanation, enableHiding: false, enableSorting: false },
  ];
}

function facetOptions(values: readonly string[], label: (v: string) => string, withMarker = false) {
  return [...new Set(values.filter(Boolean))].map((value) => ({
    value,
    label: label(value),
    icon: withMarker ? <RelationshipMarker type={value} /> : undefined,
  }));
}

/** One relationship type as a toggle: marker, word (definition on hover), count, strength mix. */
function GroupTile({ group, pressed, onToggle }: { group: RelationshipGroup; pressed: boolean; onToggle: () => void }) {
  const words = STRENGTHS.filter((k) => group[k as "strong"] > 0).map((k) => `${formatCount(group[k as "strong"])} ${k}`);
  const empty = group.count === 0;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-pressed={pressed}
          aria-disabled={empty || undefined}
          onClick={empty ? undefined : onToggle}
          className={cn(
            "group/tile flex min-w-0 items-center gap-3 rounded-lg px-4 text-left ring-1 ring-inset transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-ring/60",
            empty ? "h-14 cursor-default ring-hairline" : "h-14 bg-white/[0.02] ring-hairline hover:bg-hover",
            pressed && "bg-active ring-hairline-strong",
          )}
        >
          <RelationshipMarker type={group.type} />
          <span className="grid min-w-0 flex-1">
            <span className={cn("text-sm", empty ? "text-muted-foreground" : "font-medium text-foreground")}>{relationshipLabel(group.type)}</span>
            {!empty ? <span className="truncate text-xs text-muted-foreground tabular-nums">{words.join(" · ")}</span> : null}
          </span>
          <span className={cn("tabular-nums", empty ? "text-sm text-muted-foreground" : "text-2xl leading-none font-semibold tracking-tight text-foreground")}>
            {formatCount(group.count)}
          </span>
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-80 leading-relaxed">
        {relationshipDetail(group.type)}
        {empty ? null : pressed ? " Press again to show every relationship." : " Press to list only these."}
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * The Correlation tab's body: one toggle per relationship type (counts and strength mix; a
 * press filters the list below), then the related observations folded into groups of the same
 * relationship, strength and event type (each group opens its members in a sheet), or every
 * observation when ungrouped. Explanations stay untrusted text in hover cards and sheets.
 */
export function CorrelationView({ rows, groups }: { rows: RelatedRow[]; groups: RelationshipGroup[] }) {
  const [filters, setFilters] = useState<ColumnFiltersState>([]);
  const [mode, setMode] = useState<"grouped" | "all">("grouped");
  const grouped = useMemo(() => groupRelated(rows), [rows]);
  const selected = (filters.find((f) => f.id === "relationship")?.value as string[] | undefined) ?? [];
  const showStrength = new Set(rows.map((r) => r.strength)).size > 1;
  const toggle = (type: string) => {
    const next = selected.includes(type) ? selected.filter((t) => t !== type) : [...selected, type];
    setFilters([...filters.filter((f) => f.id !== "relationship"), ...(next.length > 0 ? [{ id: "relationship", value: next }] : [])]);
  };
  const facets: Facet[] = [
    {
      columnId: "relationship",
      title: "Relationship",
      options: facetOptions(rows.map((r) => r.type), relationshipLabel, true).sort((a, b) => ORDER.indexOf(a.value) - ORDER.indexOf(b.value)),
    },
    {
      columnId: "strength",
      title: "Strength",
      options: facetOptions(rows.map((r) => r.strength), strengthLabel).sort((a, b) => STRENGTHS.indexOf(a.value) - STRENGTHS.indexOf(b.value)),
    },
  ].filter((facet) => facet.options.length > 1);
  const modeToggle = (
    <ToggleGroup
      type="single"
      size="sm"
      variant="outline"
      spacing={0}
      value={mode}
      onValueChange={(value) => {
        if (value === "grouped" || value === "all") setMode(value);
      }}
      aria-label="List mode"
    >
      <ToggleGroupItem value="grouped" className="px-2.5">
        Grouped
      </ToggleGroupItem>
      <ToggleGroupItem value="all" className="px-2.5">
        Every observation
      </ToggleGroupItem>
    </ToggleGroup>
  );

  return (
    <div className="grid gap-4">
      <div className="grid gap-2 px-5 sm:grid-cols-3">
        {groups.map((group) => (
          <GroupTile key={group.type} group={group} pressed={selected.includes(group.type)} onToggle={() => toggle(group.type)} />
        ))}
      </div>
      <div className="@container">
        {mode === "grouped" ? (
          <DataTable
            data={grouped}
            columns={groupColumns(showStrength)}
            getRowId={(g) => g.id}
            label="Correlated observations, grouped"
            facets={facets}
            columnFilters={filters}
            onColumnFiltersChange={setFilters}
            search={{ placeholder: "Search observations", columnIds: ["observation"] }}
            pageSize={25}
            onRowClick={clickRowOpener}
            toolbar={modeToggle}
            summary={(c) => (
              <>
                {formatCount(c.filtered)} group{c.filtered === 1 ? "" : "s"} of {formatCount(rows.length)} observations
                {c.isFiltered ? " (filtered)" : ""}
              </>
            )}
            emptyMessage={`No group matches the filters (${formatCount(rows.length)} observations in total).`}
          />
        ) : (
          <DataTable
            data={rows}
            columns={rowColumns(showStrength)}
            getRowId={(r) => r.eventId}
            label="Correlated observations"
            facets={facets}
            columnFilters={filters}
            onColumnFiltersChange={setFilters}
            search={{ placeholder: "Search observations and reasons", columnIds: ["observation", "eventType", "explanation"] }}
            pageSize={25}
            toolbar={modeToggle}
            initialColumnVisibility={{ eventType: false, explanation: false }}
            emptyMessage={`No related observation matches the filters (${formatCount(rows.length)} in total).`}
          />
        )}
      </div>
    </div>
  );
}

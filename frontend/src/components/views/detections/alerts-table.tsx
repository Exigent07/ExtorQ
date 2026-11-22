"use client";

import type { ColumnDef, ColumnFiltersState } from "@tanstack/react-table";
import Link from "next/link";
import { useMemo } from "react";

import { ConfidenceBadge, SimulationBadge } from "@/components/console/badges";
import { DataTable, type Facet, type FacetOption, type TableCounts } from "@/components/console/data-table";
import { SEVERITY_LABEL, SEVERITY_ORDER, SeverityBadge, SeverityDot } from "@/components/console/severity";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { AnalystStatusText } from "@/components/views/alerts/alert-bits";
import { ANALYST_STATUSES } from "@/lib/api/schemas";
import { analystStatusLabel, formatCount } from "@/lib/format";
import { assetHref, investigationHref, isAssetId } from "@/lib/security/ids";

import { EvidenceSheet } from "./evidence-sheet";
import { type AlertRow, emptySelection, FACET_KEYS, type FacetKey, type FacetSelection, plural, SEVERITY_RANK } from "./model";
import { useDetections } from "./workspace";

/** The search box: rule id, rule title, asset, summary and alert id (needle is lower-cased). */
function matchesSearch(row: AlertRow, needle: string): boolean {
  return [row.ruleId, row.ruleTitle, row.assetId, row.summary, row.id].some((value) => value.toLowerCase().includes(needle));
}

/*
 * Column visibility follows the width of the card (container queries on the table wrapper),
 * not the viewport, so it adapts when the sidebar collapses. Card width W:
 *   always: Alert · W >= 28rem: Severity, Last seen · >= 42rem: Evidence · >= 56rem: Status
 *   · >= 1080px: Asset (below that the asset id leads the alert's second line).
 * The edge padding moves with the first and last visible column.
 */
function columns(now: string): ColumnDef<AlertRow, unknown>[] {
  return [
    {
      id: "severity",
      accessorFn: (r) => r.severity,
      header: "Severity",
      sortingFn: (a, b) => SEVERITY_RANK[a.original.severity] - SEVERITY_RANK[b.original.severity],
      sortDescFirst: true,
      meta: { className: "hidden w-[108px] @md:table-cell", label: "Severity" },
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: "rule",
      accessorFn: (r) => r.ruleId,
      header: "Alert",
      enableHiding: false,
      meta: { className: "@max-md:px-(--table-edge)" },
      cell: ({ row }) => <AlertCell row={row.original} />,
    },
    {
      id: "asset",
      accessorFn: (r) => r.assetId,
      header: "Asset",
      meta: { className: "hidden w-[200px] @min-[1080px]:table-cell", label: "Asset" },
      cell: ({ row }) => <AssetCell row={row.original} />,
    },
    {
      id: "events",
      accessorFn: (r) => r.events,
      header: "Evidence",
      sortDescFirst: true,
      meta: { className: "hidden w-[128px] @2xl:table-cell", label: "Evidence and confidence" },
      cell: ({ row }) => (
        <div className="grid justify-items-start gap-1.5">
          <EvidenceSheet row={row.original} />
          <ConfidenceBadge confidence={row.original.confidence} className="text-xs text-muted-foreground" />
        </div>
      ),
    },
    {
      id: "lastSeen",
      accessorFn: (r) => Date.parse(r.lastSeen),
      header: "Last seen",
      sortDescFirst: true,
      meta: {
        align: "right",
        className: "hidden w-[116px] @md:table-cell @max-4xl:pr-(--table-edge)",
        label: "First and last seen",
      },
      cell: ({ row }) => (
        <div className="grid justify-items-end gap-1.5">
          <RelativeTime value={row.original.lastSeen} now={now} side="left" className="text-sm text-fg-2" />
          {/* The first-seen line only when it says something the last-seen time does not. */}
          {Math.abs(Date.parse(row.original.lastSeen) - Date.parse(row.original.firstSeen)) >= 60_000 ? (
            <span className="flex items-center gap-1 text-xs text-muted-foreground">
              first
              <RelativeTime value={row.original.firstSeen} now={now} side="left" className="text-inherit" />
            </span>
          ) : null}
        </div>
      ),
    },
    {
      id: "status",
      accessorFn: (r) => r.status,
      header: "Status",
      meta: { className: "hidden w-[164px] @4xl:table-cell", label: "Analyst status" },
      cell: ({ row }) => <AnalystStatusText status={row.original.status} recorded={row.original.statusRecorded} />,
    },
    {
      // Facet only (the simulation badge sits in the alert cell): never displayed.
      id: "sim",
      accessorFn: (r) => r.sim,
      header: "Simulation",
      enableHiding: false,
      enableSorting: false,
      cell: () => null,
    },
  ];
}

function AlertCell({ row }: { row: AlertRow }) {
  const href = investigationHref(row.id);
  return (
    <div className="grid min-w-0 gap-1.5">
      <div className="flex min-w-0 items-baseline gap-2">
        <SeverityDot severity={row.severity} className="translate-y-[-1px] @md:hidden" />
        <span className="sr-only @md:hidden">{SEVERITY_LABEL[row.severity]}</span>
        <span className="flex-none font-mono text-xs text-muted-foreground">{row.ruleId}</span>
        {href ? (
          <Link
            href={href}
            className="block min-w-0 truncate font-medium text-foreground underline-offset-4 transition-colors duration-150 hover:text-brand hover:underline"
          >
            <UntrustedText value={row.ruleTitle} plain limit={160} />
          </Link>
        ) : (
          <span className="block min-w-0 truncate font-medium text-foreground">
            <UntrustedText value={row.ruleTitle} plain limit={160} />
          </span>
        )}
      </div>
      <div className="flex min-h-5 min-w-0 items-center gap-2 overflow-hidden text-sm text-muted-foreground">
        <span className="max-w-[55%] min-w-0 shrink truncate font-mono text-xs text-fg-2 @min-[1080px]:hidden">
          <UntrustedText value={row.assetId} plain limit={48} />
        </span>
        <SimulationBadge runIds={row.simulationRunIds} />
        <span className="min-w-0 flex-1">
          <UntrustedText value={row.summary} oneLine />
        </span>
      </div>
    </div>
  );
}

function AssetCell({ row }: { row: AlertRow }) {
  return (
    <div className="grid min-w-0 gap-1">
      {isAssetId(row.assetId) ? (
        <Link
          href={assetHref(row.assetId)}
          className="block min-w-0 truncate font-mono text-xs text-fg-2 transition-colors duration-150 hover:text-foreground hover:underline"
        >
          <UntrustedText value={row.assetId} plain limit={120} />
        </Link>
      ) : (
        <UntrustedText value={row.assetId} oneLine mono />
      )}
      <span className="truncate text-xs text-muted-foreground">
        {row.services > 0 ? `${plural(row.services, "service")} linked` : "No service linked"}
      </span>
    </div>
  );
}

const SIM_OPTIONS: FacetOption[] = [
  { value: "yes", label: "Simulation", description: "Evidence carries an extorq-sim marker" },
  { value: "no", label: "Not simulation", description: "No simulation marker in the evidence" },
];

const STATUS_OPTIONS: FacetOption[] = ANALYST_STATUSES.map((status) => ({ value: status, label: analystStatusLabel(status) }));

const SEVERITY_OPTIONS: FacetOption[] = SEVERITY_ORDER.map((severity) => ({
  value: severity,
  label: SEVERITY_LABEL[severity],
  icon: <SeverityDot severity={severity} className="size-2" />,
}));

const FACET_TITLES: Record<FacetKey, string> = {
  severity: "Severity",
  rule: "Rule",
  asset: "Asset",
  status: "Status",
  sim: "Simulation",
};

function summary({ first, last, filtered, total, pageSize, isFiltered }: TableCounts) {
  return isFiltered ? (
    <>
      Alerts that match the filters: <span className="text-fg-2">{formatCount(filtered)}</span> of {formatCount(total)}
      {filtered > pageSize ? ` · showing ${formatCount(first)}–${formatCount(last)}` : ""}
    </>
  ) : (
    <>
      {formatCount(first)}–{formatCount(last)} of {plural(total, "alert")}
    </>
  );
}

/**
 * Alert history table (the shared DataTable): one row per alert (deduplicated by the
 * detector). Facets mirror the URL filters (OR within a facet, AND across facets) with live
 * counts, through the table's controlled filters; the search runs on the loaded rows. A row
 * opens its investigation; the evidence chip opens the evidence sheet; the rule title and the
 * asset are real links for keyboard and screen readers.
 */
export function AlertsTable({
  rows,
  now,
  ruleOptions,
  loadedNote,
}: {
  rows: AlertRow[];
  now: string;
  /** Rule facet options (every registered rule, with its title). */
  ruleOptions: FacetOption[];
  /** Says what the counts cover when the range holds more alerts than were loaded. */
  loadedNote: string | null;
}) {
  const { selection, setSelection, pending } = useDetections();
  const cols = useMemo(() => columns(now), [now]);

  const columnFilters = useMemo<ColumnFiltersState>(
    () => FACET_KEYS.filter((key) => selection[key].length > 0).map((key) => ({ id: key, value: selection[key] })),
    [selection],
  );

  // Asset options: every asset in the loaded rows plus a selected one that has no rows here.
  const assetOptions = useMemo<FacetOption[]>(() => {
    const ids = new Set(rows.map((r) => r.assetId));
    for (const id of selection.asset) ids.add(id);
    return [...ids].sort().map((id) => ({ value: id, label: id }));
  }, [rows, selection.asset]);

  const rulesWithSelection = useMemo<FacetOption[]>(() => {
    const known = new Set(ruleOptions.map((o) => o.value));
    const extra = [...new Set([...rows.map((r) => r.ruleId), ...selection.rule])]
      .filter((id) => !known.has(id))
      .map((id) => ({ value: id, label: id }));
    return [...ruleOptions, ...extra];
  }, [ruleOptions, rows, selection.rule]);

  const facets = useMemo<Facet[]>(() => {
    const options: Record<FacetKey, FacetOption[]> = {
      severity: SEVERITY_OPTIONS,
      rule: rulesWithSelection,
      asset: assetOptions,
      status: STATUS_OPTIONS,
      sim: SIM_OPTIONS,
    };
    return FACET_KEYS.map((key) => ({ columnId: key, title: FACET_TITLES[key], options: options[key] }));
  }, [rulesWithSelection, assetOptions]);

  function onFiltersChange(next: ColumnFiltersState) {
    const out: FacetSelection = emptySelection();
    for (const filter of next) {
      if ((FACET_KEYS as readonly string[]).includes(filter.id) && Array.isArray(filter.value)) {
        out[filter.id as FacetKey] = filter.value.map(String);
      }
    }
    setSelection(out);
  }

  return (
    <div className="@container">
      <DataTable
        data={rows}
        columns={cols}
        getRowId={(row) => row.id}
        label="Alert history"
        initialSort={[{ id: "lastSeen", desc: true }]}
        facets={facets}
        columnFilters={columnFilters}
        onColumnFiltersChange={onFiltersChange}
        search={{ placeholder: "Search rule, title, asset, summary", label: "Search alerts", match: matchesSearch }}
        initialColumnVisibility={{ sim: false }}
        rowHref={(row) => investigationHref(row.id)}
        busy={pending}
        summary={summary}
        footerNote={loadedNote}
        emptyMessage="No alert in this range matches these filters."
        tableClassName="table-fixed"
        cellClassName="py-3"
      />
    </div>
  );
}

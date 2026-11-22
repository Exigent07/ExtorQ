"use client";

import {
  type ColumnDef,
  type ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFacetedRowModel,
  getFacetedUniqueValues,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  type Row,
  type SortingState,
  useReactTable,
  type VisibilityState,
} from "@tanstack/react-table";
import { cn } from "cn";
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  Search,
  Settings2,
  X,
} from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { type MouseEvent, useMemo, useState } from "react";

import { ConfidenceBadge, SimulationBadge } from "@/components/console/badges";
import { SEVERITY_LABEL, SEVERITY_ORDER, SeverityBadge, SeverityDot } from "@/components/console/severity";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AnalystStatusText } from "@/components/views/alerts/alert-bits";
import { ANALYST_STATUSES } from "@/lib/api/schemas";
import { analystStatusLabel, formatCount } from "@/lib/format";
import { assetHref, investigationHref, isAssetId } from "@/lib/security/ids";

import { EvidenceSheet } from "./evidence-sheet";
import { FacetFilter, type FacetOption } from "./facet-filter";
import { type AlertRow, emptySelection, FACET_KEYS, type FacetKey, type FacetSelection, plural, SEVERITY_RANK } from "./model";
import { RelativeTime } from "@/components/console/time";
import { useDetections } from "./workspace";

function facetFilter(row: Row<AlertRow>, columnId: string, selected: unknown): boolean {
  if (!Array.isArray(selected) || selected.length === 0) return true;
  return selected.includes(String(row.getValue(columnId)));
}

function matchesSearch(row: AlertRow, raw: string): boolean {
  const needle = raw.trim().toLowerCase();
  if (!needle) return true;
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
      filterFn: facetFilter,
      sortingFn: (a, b) => SEVERITY_RANK[a.original.severity] - SEVERITY_RANK[b.original.severity],
      sortDescFirst: true,
      meta: { className: "hidden w-[108px] @md:table-cell", label: "Severity" },
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: "rule",
      accessorFn: (r) => r.ruleId,
      header: "Alert",
      filterFn: facetFilter,
      enableHiding: false,
      meta: { className: "@max-md:px-(--table-edge)" },
      cell: ({ row }) => <AlertCell row={row.original} />,
    },
    {
      id: "asset",
      accessorFn: (r) => r.assetId,
      header: "Asset",
      filterFn: facetFilter,
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
          <span className="flex items-center gap-1 text-xs text-muted-foreground">
            first
            <RelativeTime value={row.original.firstSeen} now={now} side="left" className="text-inherit" />
          </span>
        </div>
      ),
    },
    {
      id: "status",
      accessorFn: (r) => r.status,
      header: "Status",
      filterFn: facetFilter,
      meta: { className: "hidden w-[164px] @4xl:table-cell", label: "Analyst status" },
      cell: ({ row }) => <AnalystStatusText status={row.original.status} recorded={row.original.statusRecorded} />,
    },
    {
      // Facet only (the simulation badge sits in the alert cell): never displayed.
      id: "sim",
      accessorFn: (r) => r.sim,
      header: "Simulation",
      filterFn: facetFilter,
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

/**
 * Alert history table: one row per alert (deduplicated by the detector). Facets mirror the
 * URL filters (OR within a facet, AND across facets) with live counts; the search runs on
 * the loaded rows. A row opens its investigation; the evidence chip opens the evidence
 * sheet; the rule title and the asset are real links for keyboard and screen readers.
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
  const router = useRouter();
  const { selection, setSelection, pending } = useDetections();
  const [sorting, setSorting] = useState<SortingState>([{ id: "lastSeen", desc: true }]);
  const [search, setSearch] = useState("");
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({ sim: false });
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

  // TanStack Table returns non-memoisable functions; the React Compiler lint knows this.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: rows,
    columns: cols,
    state: { sorting, columnFilters, columnVisibility, globalFilter: search },
    onSortingChange: setSorting,
    onColumnFiltersChange: (updater) => {
      const next = typeof updater === "function" ? updater(columnFilters) : updater;
      const out: FacetSelection = emptySelection();
      for (const filter of next) {
        if ((FACET_KEYS as readonly string[]).includes(filter.id) && Array.isArray(filter.value)) {
          out[filter.id as FacetKey] = filter.value.map(String);
        }
      }
      setSelection(out);
    },
    onColumnVisibilityChange: setColumnVisibility,
    onGlobalFilterChange: setSearch,
    globalFilterFn: (row, _columnId, value: string) => matchesSearch(row.original, value),
    getRowId: (row) => row.id,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  });

  const facetOptions: Record<FacetKey, FacetOption[]> = {
    severity: SEVERITY_OPTIONS,
    rule: rulesWithSelection,
    asset: assetOptions,
    status: STATUS_OPTIONS,
    sim: SIM_OPTIONS,
  };

  const filtered = table.getFilteredRowModel().rows.length;
  const { pageIndex, pageSize } = table.getState().pagination;
  const first = filtered === 0 ? 0 : pageIndex * pageSize + 1;
  const last = Math.min(filtered, (pageIndex + 1) * pageSize);
  const facetsActive = columnFilters.length > 0;
  const searching = search.trim() !== "";
  const hideable = table.getAllLeafColumns().filter((c) => c.getCanHide());

  function onRowClick(event: MouseEvent<HTMLTableRowElement>, href: string | null) {
    if (!href) return;
    const target = event.target as HTMLElement;
    // Clicks from portalled content (sheets, hover cards) bubble through the React tree: only
    // react to clicks on the row itself, and let links, buttons and text selection win.
    if (!event.currentTarget.contains(target)) return;
    if (target.closest("a,button,input,[role=button]") || window.getSelection()?.toString()) return;
    router.push(href);
  }

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2 px-(--table-edge)">
        <div className="relative w-full sm:w-60">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search rule, title, asset, summary"
            aria-label="Search alerts"
            className="h-8 pl-8"
          />
        </div>
        {FACET_KEYS.map((key) => {
          const column = table.getColumn(key);
          if (!column) return null;
          return (
            <FacetFilter
              key={key}
              title={FACET_TITLES[key]}
              options={facetOptions[key]}
              selected={selection[key]}
              counts={column.getFacetedUniqueValues()}
              onChange={(values) => setSelection({ ...selection, [key]: values })}
            />
          );
        })}
        {facetsActive || searching ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSearch("");
              if (facetsActive) setSelection(emptySelection());
            }}
          >
            Reset
            <X data-icon="inline-end" aria-hidden="true" />
          </Button>
        ) : null}
        <div className="ml-auto flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" aria-label="Choose columns">
                <Settings2 aria-hidden="true" />
                <span className="hidden sm:inline">Columns</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-52">
              <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">Visible columns</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {hideable.map((column) => (
                <DropdownMenuCheckboxItem
                  key={column.id}
                  checked={column.getIsVisible()}
                  onCheckedChange={(value) => column.toggleVisibility(Boolean(value))}
                  onSelect={(event) => event.preventDefault()}
                >
                  {column.columnDef.meta?.label ?? column.id}
                </DropdownMenuCheckboxItem>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      <div aria-busy={pending} className={cn("@container transition-opacity duration-150", pending && "opacity-60")}>
        <Table aria-label="Alert history" className="table-fixed">
          <TableHeader>
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id}>
                {group.headers.map((header) => {
                  const meta = header.column.columnDef.meta;
                  const sorted = header.column.getIsSorted();
                  if (!header.column.getIsVisible()) return null;
                  return (
                    <TableHead
                      key={header.id}
                      aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                      className={cn(meta?.align === "right" && "text-right", meta?.className)}
                    >
                      {header.isPlaceholder ? null : header.column.getCanSort() ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          className={cn(
                            "inline-flex items-center gap-1 rounded-sm transition-colors duration-150 hover:text-foreground",
                            meta?.align === "right" && "flex-row-reverse",
                            sorted && "text-fg-2",
                          )}
                        >
                          {flexRender(header.column.columnDef.header, header.getContext())}
                          {sorted === "asc" ? (
                            <ArrowUp className="size-3" aria-hidden="true" />
                          ) : sorted === "desc" ? (
                            <ArrowDown className="size-3" aria-hidden="true" />
                          ) : null}
                        </button>
                      ) : (
                        flexRender(header.column.columnDef.header, header.getContext())
                      )}
                    </TableHead>
                  );
                })}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={table.getVisibleLeafColumns().length} className="h-28 text-center whitespace-normal">
                  <p className="text-sm text-muted-foreground">No alert in this range matches these filters.</p>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="mt-2"
                    onClick={() => {
                      setSearch("");
                      setSelection(emptySelection());
                    }}
                  >
                    Clear filters
                  </Button>
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => {
                const href = investigationHref(row.original.id);
                return (
                  <TableRow
                    key={row.id}
                    onClick={(event) => onRowClick(event, href)}
                    className={cn(href && "cursor-pointer")}
                  >
                    {row.getVisibleCells().map((cell) => {
                      const meta = cell.column.columnDef.meta;
                      return (
                        <TableCell
                          key={cell.id}
                          className={cn("py-3", meta?.align === "right" && "text-right tabular-nums", meta?.className)}
                        >
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </TableCell>
                      );
                    })}
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 px-(--table-edge) text-xs text-muted-foreground">
        <p className="tabular-nums" aria-live="polite">
          {facetsActive || searching ? (
            <>
              Alerts that match the filters: <span className="text-fg-2">{formatCount(filtered)}</span> of{" "}
              {formatCount(rows.length)}
              {filtered > pageSize ? ` · showing ${formatCount(first)}–${formatCount(last)}` : ""}
            </>
          ) : (
            <>
              {formatCount(first)}–{formatCount(last)} of {plural(rows.length, "alert")}
            </>
          )}
          {loadedNote ? <span> · {loadedNote}</span> : null}
        </p>
        <div className="flex items-center gap-2">
          <span className="hidden sm:inline">Rows per page</span>
          <Select value={String(pageSize)} onValueChange={(value) => table.setPageSize(Number(value))}>
            <SelectTrigger size="sm" className="h-7 w-[72px]" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent align="end">
              {[10, 25, 50, 100].map((option) => (
                <SelectItem key={option} value={String(option)}>
                  {option}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Separator orientation="vertical" className="mx-1 data-vertical:h-4" />
          <Button variant="ghost" size="icon-sm" onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()} aria-label="First page">
            <ChevronsLeft aria-hidden="true" />
          </Button>
          <Button variant="ghost" size="icon-sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()} aria-label="Previous page">
            <ChevronLeft aria-hidden="true" />
          </Button>
          <span className="tabular-nums">
            {formatCount(pageIndex + 1)} / {formatCount(Math.max(1, table.getPageCount()))}
          </span>
          <Button variant="ghost" size="icon-sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()} aria-label="Next page">
            <ChevronRight aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={() => table.setPageIndex(table.getPageCount() - 1)}
            disabled={!table.getCanNextPage()}
            aria-label="Last page"
          >
            <ChevronsRight aria-hidden="true" />
          </Button>
        </div>
      </div>
    </div>
  );
}

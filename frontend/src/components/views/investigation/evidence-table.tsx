"use client";

import {
  type Column,
  type ColumnDef,
  type ColumnFiltersState,
  flexRender,
  getCoreRowModel,
  getFacetedRowModel,
  getFacetedUniqueValues,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  type PaginationState,
  type Row,
  type SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { cn } from "cn";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, CirclePlus, PanelRightOpen, Search, X } from "lucide-react";
import { type MouseEvent, useCallback, useEffect, useMemo, useState } from "react";
import { flushSync } from "react-dom";

import { SimulationBadge } from "@/components/console/badges";
import { DetailSheet } from "@/components/console/detail-sheet";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { EvidenceEvent } from "@/lib/api/schemas";
import { DASH, formatCount, humanize } from "@/lib/format";
import { shortId } from "@/lib/security/display";

import { EvidenceDetails, EvidenceFooter } from "./evidence-sheet";
import { useInvestigationNav } from "./investigation-tabs";
import { evidenceRoleLabel } from "./labels";
import { actorOf, identifiers } from "./model";

const PAGE_SIZES = [10, 25, 50, 100];

function timeValue(e: EvidenceEvent): number {
  const ms = Date.parse(e.event_time);
  return Number.isNaN(ms) ? Number.POSITIVE_INFINITY : ms;
}

function facetFilter(row: Row<EvidenceEvent>, columnId: string, selected: unknown): boolean {
  if (!Array.isArray(selected) || selected.length === 0) return true;
  return selected.includes(String(row.getValue(columnId)));
}

function searchText(e: EvidenceEvent): string {
  return [e.event_type, e.message, actorOf(e), e.src_ip, e.source_type, ...identifiers(e)].filter(Boolean).join(" ").toLowerCase();
}

function SortHeader({ column, label, align }: { column: Column<EvidenceEvent, unknown>; label: string; align?: "right" }) {
  const sorted = column.getIsSorted();
  return (
    <button
      type="button"
      onClick={column.getToggleSortingHandler()}
      className={cn(
        "inline-flex items-center gap-1 rounded-sm transition-colors duration-150 hover:text-foreground",
        align === "right" && "flex-row-reverse",
        sorted && "text-fg-2",
      )}
    >
      {label}
      {sorted === "asc" ? <ArrowUp className="size-3" aria-hidden="true" /> : sorted === "desc" ? <ArrowDown className="size-3" aria-hidden="true" /> : null}
    </button>
  );
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
          data-evidence-open=""
          className="inline-flex max-w-full min-w-0 items-center gap-1.5 rounded-sm text-left font-mono text-xs font-medium text-foreground underline-offset-4 hover:underline focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
        >
          <span className="min-w-0 truncate">
            <UntrustedText value={event.event_type} limit={64} plain />
          </span>
          <PanelRightOpen className="size-3.5 flex-none text-muted-foreground" aria-hidden="true" />
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
            <span className="inline-flex h-5 items-center rounded-md bg-brand-soft px-1.5 text-xs text-fg-2 ring-1 ring-brand/25 ring-inset">
              {role} evidence
            </span>
          ) : null}
          {event.simulation_run_id ? <SimulationBadge runIds={[event.simulation_run_id]} /> : null}
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
    header: ({ column }) => <SortHeader column={column} label="Time (UTC)" />,
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
    header: ({ column }) => <SortHeader column={column} label="Event" />,
    filterFn: facetFilter,
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
          </div>
          {e.message ? (
            <span className="min-w-0 text-sm text-fg-2">
              <UntrustedText value={e.message} limit={400} oneLine plain />
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
    meta: { className: "w-full max-w-0 min-w-48 whitespace-normal" },
  },
  {
    id: "actor",
    accessorFn: (e) => actorOf(e) ?? "",
    header: ({ column }) => <SortHeader column={column} label="Actor" />,
    cell: ({ row }) => {
      const actor = actorOf(row.original);
      return actor ? (
        <div className="max-w-40 min-w-0 text-sm text-fg-2">
          <UntrustedText value={actor} limit={120} oneLine plain />
        </div>
      ) : (
        <span className="text-muted-foreground">{DASH}</span>
      );
    },
    meta: { className: "hidden @3xl:table-cell" },
  },
  {
    id: "src",
    accessorFn: (e) => e.src_ip ?? "",
    header: ({ column }) => <SortHeader column={column} label="Source IP" />,
    cell: ({ row }) =>
      row.original.src_ip ? (
        <div className="max-w-32 min-w-0 font-mono text-xs text-fg-2">
          <UntrustedText value={row.original.src_ip} limit={64} oneLine plain />
        </div>
      ) : (
        <span className="text-muted-foreground">{DASH}</span>
      ),
    meta: { className: "hidden @2xl:table-cell" },
  },
  {
    id: "role",
    accessorFn: (e) => e.role ?? "",
    header: "Role",
    enableSorting: false,
    filterFn: facetFilter,
    cell: ({ row }) => <span className="text-xs text-fg-2">{evidenceRoleLabel(row.original.role) ?? DASH}</span>,
    meta: { className: "hidden @4xl:table-cell" },
  },
  {
    id: "source",
    accessorFn: (e) => e.source_type,
    filterFn: facetFilter,
    enableSorting: false,
  },
];

/** One faceted filter: a dashed button, a searchable checkbox list with live counts. */
function FacetFilter({
  column,
  title,
  options,
}: {
  column: Column<EvidenceEvent, unknown> | undefined;
  title: string;
  options: { value: string; label: string }[];
}) {
  if (!column || options.length < 2) return null;
  const counts = column.getFacetedUniqueValues();
  const selected = new Set((column.getFilterValue() as string[] | undefined) ?? []);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="border-dashed">
          <CirclePlus aria-hidden="true" />
          {title}
          {selected.size > 0 ? (
            <>
              <Separator orientation="vertical" className="mx-0.5 data-vertical:h-3.5" />
              <span className="rounded-sm bg-active px-1.5 text-xs font-normal text-foreground tabular-nums">
                {selected.size > 1 ? `${selected.size} selected` : options.find((o) => selected.has(o.value))?.label}
              </span>
            </>
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 p-0">
        <Command>
          <CommandInput placeholder={title} />
          <CommandList>
            <CommandEmpty>No value matches.</CommandEmpty>
            <CommandGroup>
              {options.map((option) => {
                const isSelected = selected.has(option.value);
                return (
                  <CommandItem
                    key={option.value}
                    value={option.label}
                    onSelect={() => {
                      const next = new Set(selected);
                      if (isSelected) next.delete(option.value);
                      else next.add(option.value);
                      column.setFilterValue(next.size > 0 ? [...next] : undefined);
                    }}
                  >
                    <span
                      aria-hidden="true"
                      className={cn(
                        "flex size-4 flex-none items-center justify-center rounded-[4px] ring-1 ring-hairline-strong ring-inset",
                        isSelected && "bg-primary ring-primary",
                      )}
                    >
                      {isSelected ? <span className="size-1.5 rounded-[1px] bg-white" /> : null}
                    </span>
                    <span className="min-w-0 truncate font-mono text-xs">{option.label}</span>
                    <span className="ml-auto pr-1 font-mono text-xs text-muted-foreground">{counts.get(option.value) ?? 0}</span>
                  </CommandItem>
                );
              })}
            </CommandGroup>
            {selected.size > 0 ? (
              <>
                <CommandSeparator />
                <CommandGroup>
                  <CommandItem onSelect={() => column.setFilterValue(undefined)} className="justify-center text-center">
                    Clear filter
                  </CommandItem>
                </CommandGroup>
              </>
            ) : null}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}

function options(values: readonly string[], label: (value: string) => string = (v) => v) {
  return [...new Set(values.filter(Boolean))].sort().map((value) => ({ value, label: label(value) }));
}

/**
 * Supporting evidence as a data table: oldest first, sortable, filterable by event type,
 * source and role, searchable, paginated. Every row is the anchor `#evidence-<event_id>`;
 * clicking a row opens its detail sheet, which holds every full value (cells truncate to one
 * line without hover cards, so a hover card never opens over the sheet). AI evidence chips and timeline links reveal a row
 * through the investigation navigation: filters are cleared and the row's page is shown.
 */
export function EvidenceTable({ evidence }: { evidence: EvidenceEvent[] }) {
  const nav = useInvestigationNav();
  const [sorting, setSorting] = useState<SortingState>([{ id: "time", desc: false }]);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [globalFilter, setGlobalFilter] = useState("");
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: 25 });
  const [highlight, setHighlight] = useState<string | null>(null);
  const haystack = useMemo(() => new Map(evidence.map((e) => [e.event_id, searchText(e)])), [evidence]);

  // TanStack Table returns non-memoisable functions; the React Compiler lint knows this.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: evidence,
    columns,
    state: { sorting, columnFilters, globalFilter, pagination, columnVisibility: { source: false } },
    onSortingChange: setSorting,
    onColumnFiltersChange: (updater) => {
      setColumnFilters(updater);
      setPagination((p) => ({ ...p, pageIndex: 0 }));
    },
    onGlobalFilterChange: (value) => {
      setGlobalFilter(String(value ?? ""));
      setPagination((p) => ({ ...p, pageIndex: 0 }));
    },
    onPaginationChange: setPagination,
    globalFilterFn: (row, _columnId, value: string) => {
      const needle = value.trim().toLowerCase();
      return !needle || (haystack.get(row.original.event_id) ?? "").includes(needle);
    },
    getRowId: (e) => e.event_id,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getPaginationRowModel: getPaginationRowModel(),
    autoResetPageIndex: false,
  });

  const reveal = useCallback(
    (eventId: string) => {
      if (!evidence.some((e) => e.event_id === eventId)) return false;
      flushSync(() => {
        setColumnFilters([]);
        setGlobalFilter("");
      });
      const index = table.getPrePaginationRowModel().rows.findIndex((row) => row.id === eventId);
      if (index < 0) return false;
      flushSync(() => {
        setPagination((p) => ({ ...p, pageIndex: Math.floor(index / p.pageSize) }));
        setHighlight(eventId);
      });
      const target = document.getElementById(`evidence-${eventId}`);
      target?.scrollIntoView({ block: "center" });
      target?.focus({ preventScroll: true });
      return true;
    },
    [evidence, table],
  );

  useEffect(() => {
    nav?.registerEvidenceReveal(reveal);
    return () => nav?.registerEvidenceReveal(null);
  }, [nav, reveal]);

  const filtered = table.getFilteredRowModel().rows.length;
  const { pageIndex, pageSize } = pagination;
  const first = filtered === 0 ? 0 : pageIndex * pageSize + 1;
  const last = Math.min(filtered, (pageIndex + 1) * pageSize);
  const isFiltered = columnFilters.length > 0 || globalFilter.trim() !== "";

  function openRow(event: MouseEvent<HTMLTableRowElement>) {
    const row = event.currentTarget;
    const target = event.target as Node;
    // Portaled content (the open sheet, hover cards) bubbles through React: ignore it.
    if (!row.contains(target)) return;
    if (target instanceof Element && target.closest("a,button,input,[role=button]")) return;
    if (window.getSelection()?.toString()) return;
    row.querySelector<HTMLButtonElement>("[data-evidence-open]")?.click();
  }

  return (
    <div className="grid gap-3 @container">
      <div className="flex flex-wrap items-center gap-2 px-5">
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            value={globalFilter}
            onChange={(e) => table.setGlobalFilter(e.target.value)}
            placeholder="Search events, actors, IPs, ids"
            aria-label="Search the evidence"
            className="h-8 pl-8"
          />
        </div>
        <FacetFilter column={table.getColumn("event")} title="Event type" options={options(evidence.map((e) => e.event_type))} />
        <FacetFilter column={table.getColumn("source")} title="Source" options={options(evidence.map((e) => e.source_type))} />
        <FacetFilter
          column={table.getColumn("role")}
          title="Role"
          options={options(evidence.map((e) => e.role ?? ""), (v) => evidenceRoleLabel(v) ?? humanize(v))}
        />
        {isFiltered ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setColumnFilters([]);
              setGlobalFilter("");
              setPagination((p) => ({ ...p, pageIndex: 0 }));
            }}
          >
            Reset
            <X data-icon="inline-end" aria-hidden="true" />
          </Button>
        ) : null}
      </div>

      <Table aria-label="Supporting evidence">
        <TableHeader>
          {table.getHeaderGroups().map((group) => (
            <TableRow key={group.id}>
              {group.headers.map((header) => {
                const sorted = header.column.getIsSorted();
                return (
                  <TableHead
                    key={header.id}
                    aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                    className={header.column.columnDef.meta?.className}
                  >
                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                );
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {table.getRowModel().rows.length === 0 ? (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={table.getVisibleLeafColumns().length} className="h-24 text-center text-sm whitespace-normal text-muted-foreground">
                No evidence event matches the search and filters.
              </TableCell>
            </TableRow>
          ) : (
            table.getRowModel().rows.map((row) => (
              <TableRow
                key={row.id}
                id={`evidence-${row.id}`}
                tabIndex={-1}
                onClick={openRow}
                data-highlighted={highlight === row.id ? "" : undefined}
                className="evidence-row cursor-pointer scroll-mt-24 outline-none data-highlighted:bg-raised data-highlighted:shadow-[inset_2px_0_0_var(--xq-brand)]"
              >
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id} className={cn("py-3 align-top", cell.column.columnDef.meta?.className)}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>

      <div className="flex flex-wrap items-center justify-between gap-3 px-5 text-xs text-muted-foreground">
        <span className="tabular-nums">
          {formatCount(first)}–{formatCount(last)} of {formatCount(filtered)}
          {filtered !== evidence.length ? ` (filtered from ${formatCount(evidence.length)})` : ""}
        </span>
        {evidence.length > 10 ? (
          <div className="flex items-center gap-2">
            <span className="hidden sm:inline">Rows per page</span>
            <Select value={String(pageSize)} onValueChange={(value) => setPagination({ pageIndex: 0, pageSize: Number(value) })}>
              <SelectTrigger size="sm" className="h-7 w-[72px]" aria-label="Rows per page">
                <SelectValue />
              </SelectTrigger>
              <SelectContent align="end">
                {PAGE_SIZES.map((size) => (
                  <SelectItem key={size} value={String(size)}>
                    {size}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Separator orientation="vertical" className="mx-1 data-vertical:h-4" />
            <Button variant="ghost" size="icon-sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()} aria-label="Previous page">
              <ChevronLeft aria-hidden="true" />
            </Button>
            <span className="tabular-nums">
              {formatCount(pageIndex + 1)} / {formatCount(Math.max(1, table.getPageCount()))}
            </span>
            <Button variant="ghost" size="icon-sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()} aria-label="Next page">
              <ChevronRight aria-hidden="true" />
            </Button>
          </div>
        ) : null}
      </div>
    </div>
  );
}

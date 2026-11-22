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
  type PaginationState,
  type Row,
  type RowData,
  type SortingState,
  type Updater,
  useReactTable,
  type VisibilityState,
} from "@tanstack/react-table";
import { cn } from "cn";
import {
  ArrowDown,
  ArrowUp,
  Check,
  ChevronLeft,
  ChevronRight,
  ChevronsLeft,
  ChevronsRight,
  CirclePlus,
  Search,
  Settings2,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type MouseEvent, type ReactNode, type Ref, useCallback, useImperativeHandle, useMemo, useRef, useState } from "react";
import { flushSync } from "react-dom";

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
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatCount } from "@/lib/format";

declare module "@tanstack/react-table" {
  // Column presentation hints shared by every console table.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends RowData, TValue> {
    /** Numeric columns are right-aligned, header flush with the values. */
    align?: "right";
    /** Extra classes for the header and cells (responsive hiding, widths). */
    className?: string;
    /** Name in the column-visibility menu (defaults to the column id). */
    label?: string;
  }
}

export interface FacetOption {
  value: string;
  label: string;
  /** Secondary line in the list (e.g. a rule's title). Console data only, rendered as text. */
  description?: string;
  /** Optional leading mark (a severity dot, a status dot). */
  icon?: ReactNode;
}

export interface Facet {
  columnId: string;
  title: string;
  options: FacetOption[];
}

/** Imperative handle of a DataTable (`handleRef`). */
export interface DataTableHandle {
  /**
   * Shows one row: clears the search and the filters, turns to the row's page, highlights it,
   * scrolls it into view and focuses it. False when the row is not in the data.
   */
  reveal: (rowId: string) => boolean;
}

/** What the footer's count line is made of (for a custom `summary`). */
export interface TableCounts {
  /** 1-based index of the first row on the page (0 when nothing matches). */
  first: number;
  last: number;
  /** Rows that pass the search and the filters. */
  filtered: number;
  /** Rows loaded into the table. */
  total: number;
  pageSize: number;
  isFiltered: boolean;
}

/** Keeps rows whose column value is one of the selected facet values. */
function facetFilter<T>(row: Row<T>, columnId: string, selected: unknown): boolean {
  if (!Array.isArray(selected) || selected.length === 0) return true;
  return selected.includes(String(row.getValue(columnId)));
}

/**
 * True when a click on a row should act on the row: the click happened in the row's own DOM
 * (content portalled out of the row, such as an open sheet, a hover card or a popover, still
 * bubbles through the React tree), not on a control inside the row, and not at the end of a
 * text selection.
 */
export function isRowActivation(event: MouseEvent<HTMLElement>): boolean {
  const target = event.target;
  if (!(target instanceof Node) || !event.currentTarget.contains(target)) return false;
  const element = target instanceof Element ? target : target.parentElement;
  if (element?.closest("a,button,input,select,textarea,label,[role=button],[role=checkbox],[role=menuitem],[role=combobox]")) {
    return false;
  }
  return !window.getSelection()?.toString();
}

/**
 * `onRowClick` for tables whose rows open a detail sheet: clicks the row's own opener (the
 * identity cell's button marked `data-row-open`), so the row and the button behave the same
 * and focus returns to that button when the sheet closes.
 */
export function clickRowOpener(_row: unknown, element: HTMLTableRowElement): void {
  element.querySelector<HTMLElement>("[data-row-open]")?.click();
}

function resolve<S>(updater: Updater<S>, current: S): S {
  return typeof updater === "function" ? (updater as (old: S) => S)(current) : updater;
}

/**
 * The console data table (TanStack Table on the shadcn table).
 *
 * - Sorting on every column that allows it (aria-sort on headers, glyph on the active one).
 * - Faceted filters (`facets`): a popover per column with checkboxes and live counts; a facet
 *   with fewer than two values (and nothing selected) is not shown. Filters are uncontrolled
 *   (`initialColumnFilters`) or controlled (`columnFilters` + `onColumnFiltersChange`, e.g. to
 *   mirror the URL); the server render applies them, so filtered pages work without JavaScript.
 * - Text search (`search`) over the listed columns' values, or a custom `match`.
 * - Column visibility menu, pagination with page size, the visible range and the total
 *   (`summary` replaces the count line; `footerNote` adds to it).
 * - Row click: `rowHref` navigates, `onRowClick` runs a callback (open the row's sheet). Keep a
 *   real link or button in the identity cell so keyboard and screen-reader users have a native
 *   target (the row itself is not focusable). Clicks from portalled content, controls inside the
 *   row and text selections are ignored.
 * - Jump targets: `rowAnchorId` gives each row a DOM id (`#evidence-<id>`), and `handleRef`
 *   exposes `reveal(rowId)` for links that must show a row on another page or behind a filter.
 *
 * Rows are validated API data; cells render untrusted strings through UntrustedText (use
 * `oneLine` in dense columns). Filters run on the rows already loaded: say so when the API
 * capped the list.
 */
export function DataTable<T>({
  data,
  columns,
  getRowId,
  label,
  initialSort = [],
  facets = [],
  search,
  pageSize = 25,
  pageSizes = [10, 25, 50, 100],
  rowHref,
  onRowClick,
  rowAnchorId,
  handleRef,
  columnFilters: controlledFilters,
  onColumnFiltersChange,
  initialColumnFilters,
  emptyMessage = "No rows match the current filters.",
  toolbar,
  initialColumnVisibility,
  busy = false,
  summary,
  footerNote,
  className,
  tableClassName,
  cellClassName,
}: {
  data: T[];
  columns: ColumnDef<T, unknown>[];
  getRowId: (row: T) => string;
  /** Accessible name of the table. */
  label: string;
  initialSort?: SortingState;
  facets?: Facet[];
  search?: {
    placeholder: string;
    /** Columns whose values the search looks in (case-insensitive substring). */
    columnIds?: string[];
    /** Custom matcher (receives the trimmed, lower-cased needle); replaces `columnIds`. */
    match?: (row: T, needle: string) => boolean;
    /** Accessible name of the field (defaults to the placeholder). */
    label?: string;
  };
  pageSize?: number;
  pageSizes?: number[];
  rowHref?: (row: T) => string | null;
  onRowClick?: (row: T, element: HTMLTableRowElement) => void;
  /** DOM id of a row (a jump target); the row becomes programmatically focusable. */
  rowAnchorId?: (row: T) => string | null;
  handleRef?: Ref<DataTableHandle>;
  /** Controlled column filters (facet selections); pair with `onColumnFiltersChange`. */
  columnFilters?: ColumnFiltersState;
  onColumnFiltersChange?: (filters: ColumnFiltersState) => void;
  initialColumnFilters?: ColumnFiltersState;
  emptyMessage?: ReactNode;
  /** Extra controls on the toolbar's right (before the column menu). */
  toolbar?: ReactNode;
  initialColumnVisibility?: VisibilityState;
  /** New data is on its way (e.g. a server navigation): dims the rows and sets aria-busy. */
  busy?: boolean;
  /** Replaces the footer's count line. */
  summary?: (counts: TableCounts) => ReactNode;
  /** Appended to the count line (e.g. "the API returned the newest 200"). */
  footerNote?: ReactNode;
  className?: string;
  tableClassName?: string;
  /** Extra classes for every body cell (e.g. "py-3 align-top" for two-line rows). */
  cellClassName?: string;
}) {
  const router = useRouter();
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const [ownFilters, setOwnFilters] = useState<ColumnFiltersState>(initialColumnFilters ?? []);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(initialColumnVisibility ?? {});
  const [globalFilter, setGlobalFilter] = useState("");
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize });
  const [highlighted, setHighlighted] = useState<string | null>(null);
  const rowElements = useRef(new Map<string, HTMLTableRowElement>());

  const columnFilters = controlledFilters ?? ownFilters;
  // Controlled filters that change from outside (a link, back/forward) start at page one.
  const [seenFilters, setSeenFilters] = useState(columnFilters);
  if (seenFilters !== columnFilters) {
    setSeenFilters(columnFilters);
    if (pagination.pageIndex !== 0) setPagination((p) => ({ ...p, pageIndex: 0 }));
  }

  const applyFilters = useCallback(
    (next: ColumnFiltersState) => {
      if (controlledFilters === undefined) setOwnFilters(next);
      onColumnFiltersChange?.(next);
      setPagination((p) => ({ ...p, pageIndex: 0 }));
    },
    [controlledFilters, onColumnFiltersChange],
  );

  const facetIds = useMemo(() => new Set(facets.map((f) => f.columnId)), [facets]);
  const tableColumns = useMemo(
    () =>
      columns.map((column) =>
        column.id && facetIds.has(column.id) && !column.filterFn ? { ...column, filterFn: facetFilter<T> } : column,
      ),
    [columns, facetIds],
  );

  // TanStack Table returns non-memoisable functions; the React Compiler lint knows this.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data,
    columns: tableColumns,
    state: { sorting, columnFilters, columnVisibility, globalFilter, pagination },
    onSortingChange: (updater) => {
      setSorting(updater);
      setPagination((p) => ({ ...p, pageIndex: 0 }));
    },
    onColumnFiltersChange: (updater) => applyFilters(resolve(updater, columnFilters)),
    onColumnVisibilityChange: setColumnVisibility,
    onGlobalFilterChange: (updater) => {
      setGlobalFilter(String(resolve(updater, globalFilter) ?? ""));
      setPagination((p) => ({ ...p, pageIndex: 0 }));
    },
    onPaginationChange: setPagination,
    globalFilterFn: (row, _columnId, value: string) => {
      const needle = value.trim().toLowerCase();
      if (!needle || !search) return true;
      if (search.match) return search.match(row.original, needle);
      return (search.columnIds ?? []).some((id) => String(row.getValue(id) ?? "").toLowerCase().includes(needle));
    },
    getRowId: (row) => getRowId(row),
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getPaginationRowModel: getPaginationRowModel(),
    autoResetPageIndex: false,
  });

  const filtered = table.getFilteredRowModel().rows.length;
  const pageCount = Math.max(1, Math.ceil(filtered / pagination.pageSize));
  // New data with fewer rows (another range, a refresh) keeps the page index in range.
  if (pagination.pageIndex > pageCount - 1) setPagination((p) => ({ ...p, pageIndex: pageCount - 1 }));

  const reveal = useCallback(
    (rowId: string): boolean => {
      if (!data.some((row) => getRowId(row) === rowId)) return false;
      flushSync(() => {
        applyFilters([]);
        setGlobalFilter("");
      });
      const index = table.getPrePaginationRowModel().rows.findIndex((row) => row.id === rowId);
      if (index < 0) return false;
      flushSync(() => {
        setPagination((p) => ({ ...p, pageIndex: Math.floor(index / p.pageSize) }));
        setHighlighted(rowId);
      });
      const element = rowElements.current.get(rowId);
      element?.scrollIntoView({ block: "center" });
      element?.focus({ preventScroll: true });
      return true;
    },
    [applyFilters, data, getRowId, table],
  );
  useImperativeHandle(handleRef, () => ({ reveal }), [reveal]);

  const { pageIndex, pageSize: size } = pagination;
  const first = filtered === 0 ? 0 : pageIndex * size + 1;
  const last = Math.min(filtered, (pageIndex + 1) * size);
  const isFiltered = columnFilters.length > 0 || globalFilter.trim() !== "";
  const hideable = table.getAllLeafColumns().filter((c) => c.getCanHide());
  // Paging controls only when they can do something: the size menu once the rows outgrow the
  // default page, the arrows and "1 / N" only with more than one page.
  const showSizes = data.length > pageSize && data.length > Math.min(...pageSizes);
  const counts: TableCounts = { first, last, filtered, total: data.length, pageSize: size, isFiltered };
  const resetAll = () => {
    applyFilters([]);
    setGlobalFilter("");
  };

  return (
    <div className={cn("grid gap-3", className)}>
      <div className="flex flex-wrap items-center gap-2 px-(--table-edge)">
        {search ? (
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              value={globalFilter}
              onChange={(event) => table.setGlobalFilter(event.target.value)}
              placeholder={search.placeholder}
              aria-label={search.label ?? search.placeholder}
              className="h-8 pl-8"
            />
          </div>
        ) : null}
        {facets.map((facet) => {
          const column = table.getColumn(facet.columnId);
          if (!column) return null;
          const selected = (column.getFilterValue() as string[] | undefined) ?? [];
          if (facet.options.length < 2 && selected.length === 0) return null;
          return (
            <FacetFilter
              key={facet.columnId}
              title={facet.title}
              options={facet.options}
              selected={selected}
              counts={column.getFacetedUniqueValues()}
              onChange={(values) => column.setFilterValue(values.length > 0 ? values : undefined)}
            />
          );
        })}
        {isFiltered ? (
          <Button variant="ghost" size="sm" onClick={resetAll}>
            Reset
            <X data-icon="inline-end" aria-hidden="true" />
          </Button>
        ) : null}
        <div className="ml-auto flex items-center gap-2">
          {toolbar}
          {hideable.length > 0 ? (
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
          ) : null}
        </div>
      </div>

      <div aria-busy={busy || undefined} className={cn("transition-opacity duration-150", busy && "opacity-60")}>
        <Table aria-label={label} className={tableClassName}>
          <TableHeader>
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id}>
                {group.headers.map((header) => {
                  const meta = header.column.columnDef.meta;
                  const sorted = header.column.getIsSorted();
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
                  <p className="text-sm text-muted-foreground">{emptyMessage}</p>
                  {isFiltered ? (
                    <Button variant="ghost" size="sm" className="mt-2" onClick={resetAll}>
                      Clear filters
                    </Button>
                  ) : null}
                </TableCell>
              </TableRow>
            ) : (
              table.getRowModel().rows.map((row) => {
                const href = rowHref?.(row.original) ?? null;
                const anchor = rowAnchorId?.(row.original) ?? null;
                const clickable = href !== null || onRowClick !== undefined;
                return (
                  <TableRow
                    key={row.id}
                    ref={(element) => {
                      if (element) rowElements.current.set(row.id, element);
                      else rowElements.current.delete(row.id);
                    }}
                    id={anchor ?? undefined}
                    tabIndex={anchor ? -1 : undefined}
                    data-highlighted={highlighted === row.id ? "" : undefined}
                    onClick={
                      clickable
                        ? (event) => {
                            if (!isRowActivation(event)) return;
                            if (onRowClick) onRowClick(row.original, event.currentTarget);
                            else if (href) router.push(href);
                          }
                        : undefined
                    }
                    className={cn(
                      "group/row",
                      clickable && "cursor-pointer",
                      anchor && "anchor-row scroll-mt-24 outline-none",
                      "data-highlighted:bg-raised data-highlighted:shadow-[inset_2px_0_0_var(--xq-brand)]",
                    )}
                  >
                    {row.getVisibleCells().map((cell) => {
                      const meta = cell.column.columnDef.meta;
                      return (
                        <TableCell
                          key={cell.id}
                          className={cn(cellClassName, meta?.align === "right" && "text-right tabular-nums", meta?.className)}
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
          {summary ? (
            summary(counts)
          ) : (
            <>
              {formatCount(first)}–{formatCount(last)} of {formatCount(filtered)}
              {filtered !== data.length ? ` (filtered from ${formatCount(data.length)})` : ""}
            </>
          )}
          {footerNote ? <span> · {footerNote}</span> : null}
        </p>
        {showSizes || pageCount > 1 ? (
          <div className="flex items-center gap-2">
            {showSizes ? (
              <>
                <span className="hidden sm:inline">Rows per page</span>
                <Select value={String(size)} onValueChange={(value) => setPagination({ pageIndex: 0, pageSize: Number(value) })}>
                  <SelectTrigger size="sm" className="h-7 w-[72px]" aria-label="Rows per page">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent align="end">
                    {pageSizes.map((option) => (
                      <SelectItem key={option} value={String(option)}>
                        {option}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </>
            ) : null}
            {pageCount > 1 ? (
              <>
                {showSizes ? <Separator orientation="vertical" className="mx-1 data-vertical:h-4" /> : null}
                <Button variant="ghost" size="icon-sm" onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()} aria-label="First page">
                  <ChevronsLeft aria-hidden="true" />
                </Button>
                <Button variant="ghost" size="icon-sm" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()} aria-label="Previous page">
                  <ChevronLeft aria-hidden="true" />
                </Button>
                <span className="tabular-nums">
                  {formatCount(pageIndex + 1)} / {formatCount(pageCount)}
                </span>
                <Button variant="ghost" size="icon-sm" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()} aria-label="Next page">
                  <ChevronRight aria-hidden="true" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={() => table.setPageIndex(pageCount - 1)}
                  disabled={!table.getCanNextPage()}
                  aria-label="Last page"
                >
                  <ChevronsRight aria-hidden="true" />
                </Button>
              </>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

/**
 * One faceted filter (shadcn "data table" pattern): a dashed button that names the facet and
 * the current selection, and a searchable checkbox list with the number of rows each value would
 * keep under the other filters. Controlled: DataTable wires it to a column; a view that owns its
 * own state (URL filters) can use it directly.
 */
export function FacetFilter({
  title,
  options,
  selected,
  counts,
  onChange,
}: {
  title: string;
  options: FacetOption[];
  selected: readonly string[];
  /** Rows per value under the other active filters (TanStack faceted unique values). */
  counts?: Map<unknown, number>;
  onChange: (next: string[]) => void;
}) {
  const chosen = new Set(selected);
  const chosenLabels = options.filter((o) => chosen.has(o.value)).map((o) => o.label);
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className={cn("border-dashed", chosen.size > 0 && "border-solid")}>
          <CirclePlus aria-hidden="true" />
          {title}
          {chosen.size > 0 ? (
            <>
              <Separator orientation="vertical" className="mx-0.5 data-vertical:h-3.5" />
              <span className="max-w-40 truncate rounded-sm bg-active px-1.5 text-xs font-normal text-foreground tabular-nums">
                {chosen.size > 2 ? `${chosen.size} selected` : chosenLabels.join(", ") || `${chosen.size} selected`}
              </span>
            </>
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-[min(20rem,calc(100vw-2rem))] p-0">
        <Command>
          <CommandInput placeholder={`Filter ${title.toLowerCase()}`} />
          <CommandList>
            <CommandEmpty>No value matches.</CommandEmpty>
            <CommandGroup>
              {options.map((option) => {
                const isSelected = chosen.has(option.value);
                const count = counts?.get(option.value) ?? 0;
                return (
                  <CommandItem
                    key={option.value}
                    value={`${option.label} ${option.description ?? ""} ${option.value}`}
                    onSelect={() => {
                      const next = new Set(chosen);
                      if (isSelected) next.delete(option.value);
                      else next.add(option.value);
                      onChange([...next]);
                    }}
                    className="gap-2.5"
                  >
                    <span
                      aria-hidden="true"
                      className={cn(
                        "flex size-4 flex-none items-center justify-center rounded-[4px] ring-1 ring-hairline-strong ring-inset transition-colors duration-150",
                        isSelected && "bg-primary ring-primary",
                      )}
                    >
                      {isSelected ? <Check className="size-3 text-white" strokeWidth={3} /> : null}
                    </span>
                    {option.icon}
                    <span className="grid min-w-0 flex-1">
                      <span className="truncate">{option.label}</span>
                      {option.description ? <span className="truncate text-xs text-muted-foreground">{option.description}</span> : null}
                    </span>
                    {counts ? (
                      <span className={cn("ml-auto pl-2 text-xs tabular-nums", count > 0 ? "text-fg-2" : "text-muted-foreground")}>
                        {formatCount(count)}
                      </span>
                    ) : null}
                  </CommandItem>
                );
              })}
            </CommandGroup>
            {chosen.size > 0 ? (
              <>
                <CommandSeparator />
                <CommandGroup>
                  <CommandItem onSelect={() => onChange([])} className="justify-center text-center">
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

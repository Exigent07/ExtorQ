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
  type Row,
  type RowData,
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
  CirclePlus,
  Search,
  Settings2,
  X,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { type ReactNode, useMemo, useState } from "react";

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
  /** Optional leading mark (a severity dot, a status dot). */
  icon?: ReactNode;
}

export interface Facet {
  columnId: string;
  title: string;
  options: FacetOption[];
}

/** Keeps rows whose column value is one of the selected facet values. */
function facetFilter<T>(row: Row<T>, columnId: string, selected: unknown): boolean {
  if (!Array.isArray(selected) || selected.length === 0) return true;
  return selected.includes(String(row.getValue(columnId)));
}

/**
 * The console data table (TanStack Table on the shadcn table).
 *
 * - Sorting on every column that allows it (aria-sort on headers, glyph on the active one).
 * - Faceted filters (`facets`): a popover per column with checkboxes and live counts.
 * - Text search (`search`) over the listed columns' string values (case-insensitive).
 * - Column visibility menu, pagination with page size, the visible range and the total.
 * - Row click (`rowHref`): the whole row navigates; keep a real link in the identity cell so
 *   keyboard and screen-reader users have a native target (the row itself is not focusable).
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
  emptyMessage = "No rows match the current filters.",
  toolbar,
  initialColumnVisibility,
  className,
}: {
  data: T[];
  columns: ColumnDef<T, unknown>[];
  getRowId: (row: T) => string;
  /** Accessible name of the table. */
  label: string;
  initialSort?: SortingState;
  facets?: Facet[];
  search?: { placeholder: string; columnIds: string[] };
  pageSize?: number;
  pageSizes?: number[];
  rowHref?: (row: T) => string | null;
  emptyMessage?: string;
  /** Extra controls on the toolbar's right (before the column menu). */
  toolbar?: ReactNode;
  initialColumnVisibility?: VisibilityState;
  className?: string;
}) {
  const router = useRouter();
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([]);
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>(initialColumnVisibility ?? {});
  const [globalFilter, setGlobalFilter] = useState("");

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
    state: { sorting, columnFilters, columnVisibility, globalFilter },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onColumnVisibilityChange: setColumnVisibility,
    onGlobalFilterChange: setGlobalFilter,
    globalFilterFn: (row, _columnId, value: string) => {
      const needle = value.trim().toLowerCase();
      if (!needle || !search) return true;
      return search.columnIds.some((id) => String(row.getValue(id) ?? "").toLowerCase().includes(needle));
    },
    getRowId: (row) => getRowId(row),
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getFacetedRowModel: getFacetedRowModel(),
    getFacetedUniqueValues: getFacetedUniqueValues(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize } },
  });

  const filtered = table.getFilteredRowModel().rows.length;
  const { pageIndex, pageSize: size } = table.getState().pagination;
  const first = filtered === 0 ? 0 : pageIndex * size + 1;
  const last = Math.min(filtered, (pageIndex + 1) * size);
  const isFiltered = columnFilters.length > 0 || globalFilter.trim() !== "";
  const hideable = table.getAllLeafColumns().filter((c) => c.getCanHide());

  return (
    <div className={cn("grid gap-3", className)}>
      <div className="flex flex-wrap items-center gap-2 px-(--table-edge)">
        {search ? (
          <div className="relative w-full sm:w-64">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              value={globalFilter}
              onChange={(event) => setGlobalFilter(event.target.value)}
              placeholder={search.placeholder}
              aria-label={search.placeholder}
              className="h-8 pl-8"
            />
          </div>
        ) : null}
        {facets.map((facet) => {
          const column = table.getColumn(facet.columnId);
          return column ? <FacetFilter key={facet.columnId} column={column} title={facet.title} options={facet.options} /> : null;
        })}
        {isFiltered ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              table.resetColumnFilters();
              setGlobalFilter("");
            }}
          >
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
              <DropdownMenuContent align="end" className="w-48">
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

      <Table aria-label={label}>
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
              <TableCell colSpan={table.getVisibleLeafColumns().length} className="h-24 text-center text-sm whitespace-normal text-muted-foreground">
                {emptyMessage}
              </TableCell>
            </TableRow>
          ) : (
            table.getRowModel().rows.map((row) => {
              const href = rowHref?.(row.original) ?? null;
              return (
                <TableRow
                  key={row.id}
                  onClick={
                    href
                      ? (event) => {
                          // Clicks inside portalled content (a sheet, a hover card) bubble through the React
                          // tree to the row: only clicks on the row's own DOM navigate.
                          const target = event.target as HTMLElement;
                          if (!event.currentTarget.contains(target)) return;
                          // Let real links, buttons and text selection inside the row win.
                          if (target.closest("a,button,input,[role=button]") || window.getSelection()?.toString()) return;
                          router.push(href);
                        }
                      : undefined
                  }
                  className={cn(href && "cursor-pointer")}
                >
                  {row.getVisibleCells().map((cell) => {
                    const meta = cell.column.columnDef.meta;
                    return (
                      <TableCell key={cell.id} className={cn(meta?.align === "right" && "text-right tabular-nums", meta?.className)}>
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

      <div className="flex flex-wrap items-center justify-between gap-3 px-(--table-edge) text-xs text-muted-foreground">
        <span className="tabular-nums">
          {formatCount(first)}–{formatCount(last)} of {formatCount(filtered)}
          {filtered !== data.length ? ` (filtered from ${formatCount(data.length)})` : ""}
        </span>
        <div className="flex items-center gap-2">
          <span className="hidden sm:inline">Rows per page</span>
          <Select value={String(size)} onValueChange={(value) => table.setPageSize(Number(value))}>
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

/** One faceted filter: a dashed button, a searchable checkbox list with live counts. */
export function FacetFilter<T>({ column, title, options }: { column: Column<T, unknown>; title: string; options: FacetOption[] }) {
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
                {selected.size > 2 ? `${selected.size} selected` : options.filter((o) => selected.has(o.value)).map((o) => o.label).join(", ")}
              </span>
            </>
          ) : null}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-56 p-0">
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
                        "flex size-4 items-center justify-center rounded-[4px] ring-1 ring-hairline-strong ring-inset",
                        isSelected && "bg-primary ring-primary",
                      )}
                    >
                      {isSelected ? <span className="size-1.5 rounded-[1px] bg-white" /> : null}
                    </span>
                    {option.icon}
                    <span className="min-w-0 truncate">{option.label}</span>
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

"use client";

import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  type RowData,
  type SortingState,
  useReactTable,
} from "@tanstack/react-table";
import { cn } from "cn";
import { ArrowDown, ArrowUp } from "lucide-react";
import { useState } from "react";

import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

declare module "@tanstack/react-table" {
  // Column presentation hints shared by every console table.
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  interface ColumnMeta<TData extends RowData, TValue> {
    /** Numeric columns are right-aligned, header flush with the values. */
    align?: "right";
    /** Extra classes for the header and cells (responsive hiding, widths). */
    className?: string;
  }
}

/**
 * A data table with client-side sorting (TanStack Table). Rows are already validated API
 * data; cells render untrusted strings through UntrustedText. Only the active column shows a
 * sort glyph; headers are buttons, and the column state is exposed with aria-sort.
 */
export function SortableTable<T>({
  data,
  columns,
  initialSort = [],
  getRowId,
  label,
  rowClassName,
}: {
  data: T[];
  columns: ColumnDef<T, unknown>[];
  initialSort?: SortingState;
  getRowId: (row: T) => string;
  /** Accessible name of the table. */
  label: string;
  rowClassName?: (row: T) => string | undefined;
}) {
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  // TanStack Table returns non-memoisable functions; the React Compiler lint knows this.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (row) => getRowId(row),
  });

  return (
    <Table aria-label={label}>
      <TableHeader>
        {table.getHeaderGroups().map((group) => (
          <TableRow key={group.id}>
            {group.headers.map((header) => {
              const meta = header.column.columnDef.meta;
              const sorted = header.column.getIsSorted();
              const canSort = header.column.getCanSort();
              return (
                <TableHead
                  key={header.id}
                  aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                  className={cn(meta?.align === "right" && "text-right", meta?.className)}
                >
                  {header.isPlaceholder ? null : canSort ? (
                    <button
                      type="button"
                      onClick={header.column.getToggleSortingHandler()}
                      className={cn(
                        "inline-flex items-center gap-1 rounded-sm hover:text-ink",
                        meta?.align === "right" && "flex-row-reverse",
                        sorted && "text-ink-2",
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
        {table.getRowModel().rows.map((row) => (
          <TableRow key={row.id} className={rowClassName?.(row.original)}>
            {row.getVisibleCells().map((cell) => {
              const meta = cell.column.columnDef.meta;
              return (
                <TableCell key={cell.id} className={cn(meta?.align === "right" && "text-right", meta?.className)}>
                  {flexRender(cell.column.columnDef.cell, cell.getContext())}
                </TableCell>
              );
            })}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

/** A row of filter chips (radio semantics) for client-side table filters. */
export function FilterChips<K extends string>({
  label,
  options,
  value,
  onChange,
}: {
  label: string;
  options: { key: K; label: string; count?: number }[];
  value: K;
  onChange: (key: K) => void;
}) {
  return (
    <div role="radiogroup" aria-label={label} className="flex flex-wrap items-center gap-1.5">
      {options.map((option) => {
        const checked = option.key === value;
        return (
          <button
            key={option.key}
            type="button"
            role="radio"
            aria-checked={checked}
            onClick={() => onChange(option.key)}
            className={cn(
              "inline-flex h-7 items-center gap-1.5 rounded-full border px-3 text-xs transition-colors",
              checked ? "border-line text-ink" : "border-control text-muted-foreground hover:text-ink",
            )}
          >
            {option.label}
            {option.count !== undefined ? <span className="font-mono text-muted-foreground">{option.count}</span> : null}
          </button>
        );
      })}
    </div>
  );
}

"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "cn";
import Link from "next/link";
import { type ReactNode, useMemo } from "react";

import { DataTable, type Facet } from "@/components/console/data-table";
import { coverageSwatchClass } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ServiceItem } from "@/lib/api/schemas";
import { DASH, formatCount } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";
import { categoryLabel, type CoverageKind, serviceCoverage, serviceKindLabel } from "@/lib/services";

import { CoverageCell } from "./coverage-cell";
import { EXPOSURE_RANK, widestExposure } from "./model";
import { PortsCell } from "./ports-cell";

export type ServicesVariant = "host" | "k8s_workload" | "k8s_service";

const COVERAGE_ORDER: Record<CoverageKind, number> = {
  degraded: 0,
  unmonitored: 1,
  monitored: 2,
  planned: 3,
  unsupported: 4,
  unknown: 5,
};

const COVERAGE_LABEL: Record<CoverageKind, string> = {
  monitored: "Monitored",
  degraded: "Degraded",
  unmonitored: "Unmonitored",
  planned: "Planned adapter",
  unsupported: "Unsupported",
  unknown: "Unknown state",
};

const EXPOSURE_LABEL: Record<string, string> = {
  any: "All interfaces",
  private: "Private network",
  loopback: "Loopback only",
  unknown: "Exposure unknown",
  none: "No port observed",
};

function RemovedChip() {
  return (
    <span className="inline-flex h-5 flex-none items-center rounded-md px-1.5 text-xs text-muted-foreground ring-1 ring-hairline-strong ring-inset">
      Removed
    </span>
  );
}

function nameColumn(variant: ServicesVariant): ColumnDef<ServiceItem, unknown> {
  return {
    id: "name",
    header: variant === "k8s_workload" ? "Workload" : variant === "k8s_service" ? "Kubernetes Service" : "Service",
    accessorFn: (s) => [s.name, s.service_key, s.product, s.version].filter(Boolean).join(" "),
    sortingFn: (a, b) => a.original.name.localeCompare(b.original.name),
    meta: { className: "w-full max-w-0 min-w-60", label: "Name" },
    enableHiding: false,
    cell: ({ row }) => {
      const s = row.original;
      const href = serviceHref(s.service_id);
      const product = [s.product, s.version].filter(Boolean).join(" ");
      // The key repeats the name for most Kubernetes objects ("ns/name"): shown only when it adds.
      const key = s.service_key !== s.name ? s.service_key : null;
      return (
        <div className={cn("min-w-0", !s.present && "opacity-70")}>
          <div className="flex min-w-0 items-center gap-2">
            {href ? (
              <Link
                href={href}
                className="min-w-0 truncate font-medium text-foreground underline-offset-2 transition-colors duration-150 hover:text-brand hover:underline"
              >
                <UntrustedText value={s.name} plain limit={120} />
              </Link>
            ) : (
              <span className="min-w-0 truncate font-medium text-foreground">
                <UntrustedText value={s.name} plain limit={120} />
              </span>
            )}
            {!s.present ? <RemovedChip /> : null}
          </div>
          {key || product ? (
            <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
              {key ? (
                <span className="min-w-0 truncate font-mono">
                  <UntrustedText value={key} oneLine mono />
                </span>
              ) : null}
              {key && product ? (
                <span aria-hidden="true" className="text-fg-faint">
                  ·
                </span>
              ) : null}
              {product ? (
                <span className={cn("truncate", key ? "max-w-[45%] flex-none" : "min-w-0")}>
                  <UntrustedText value={product} plain limit={64} />
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
      );
    },
  };
}

const kindColumn: ColumnDef<ServiceItem, unknown> = {
  id: "kind",
  header: "Kind",
  accessorFn: (s) => s.service_kind,
  meta: { className: "hidden lg:table-cell", label: "Kind" },
  cell: ({ row }) => <span className="text-xs whitespace-nowrap text-fg-2">{serviceKindLabel(row.original.service_kind)}</span>,
};

const categoryColumn: ColumnDef<ServiceItem, unknown> = {
  id: "category",
  header: "Category",
  accessorFn: (s) => s.category,
  meta: { className: "hidden xl:table-cell", label: "Category" },
  cell: ({ row }) =>
    row.original.category === "unknown" ? (
      <span className="text-xs text-muted-foreground">Unknown</span>
    ) : (
      <span className="text-xs whitespace-nowrap text-fg-2">{categoryLabel(row.original.category)}</span>
    ),
};

const coverageColumn: ColumnDef<ServiceItem, unknown> = {
  id: "coverage",
  header: "Coverage",
  accessorFn: (s) => serviceCoverage(s).kind,
  sortingFn: (a, b) => COVERAGE_ORDER[serviceCoverage(a.original).kind] - COVERAGE_ORDER[serviceCoverage(b.original).kind],
  meta: { className: "w-36", label: "Coverage" },
  cell: ({ row }) => <CoverageCell service={row.original} />,
};

const portsColumn: ColumnDef<ServiceItem, unknown> = {
  id: "ports",
  header: "Ports",
  accessorFn: (s) => s.endpoints.length,
  meta: { className: "hidden w-56 min-w-56 md:table-cell", label: "Ports" },
  cell: ({ row }) => <PortsCell endpoints={row.original.endpoints} />,
};

/** Hidden column: the widest exposure of the service's endpoints (facet only). */
const exposureColumn: ColumnDef<ServiceItem, unknown> = {
  id: "exposure",
  header: "Exposure",
  accessorFn: (s) => widestExposure(s),
  enableHiding: false,
  enableSorting: false,
  cell: () => null,
};

/** Hidden column: whether discovery re-reported the record recently (facet only). */
const reportColumn: ColumnDef<ServiceItem, unknown> = {
  id: "report",
  header: "Discovery report",
  accessorFn: (s) => (s.report_stale ? "stale" : "current"),
  enableHiding: false,
  enableSorting: false,
  cell: () => null,
};

function instancesColumn(variant: ServicesVariant): ColumnDef<ServiceItem, unknown> {
  return {
    id: "instances",
    header: variant === "k8s_workload" ? "Pods" : "Instances",
    accessorFn: (s) => s.instance_count ?? -1,
    meta: { align: "right", className: "w-24", label: variant === "k8s_workload" ? "Pods" : "Instances" },
    cell: ({ row }) =>
      row.original.instance_count === null || row.original.instance_count === undefined ? (
        <span className="text-muted-foreground">{DASH}</span>
      ) : (
        <span className="font-mono text-xs text-fg-2">{formatCount(row.original.instance_count)}</span>
      ),
  };
}

/**
 * Telemetry sources of the service and, when the collector reported it, the time of its latest
 * telemetry. No source at all is said in words; an unreported time is left out, not guessed.
 */
function telemetryColumn(now: string): ColumnDef<ServiceItem, unknown> {
  return {
    id: "telemetry",
    header: "Telemetry",
    accessorFn: (s) => (s.last_telemetry_at ? Date.parse(s.last_telemetry_at) : s.telemetry_sources.length > 0 ? 0 : -1),
    meta: { align: "right", className: "hidden w-32 sm:table-cell", label: "Telemetry" },
    cell: ({ row }) => {
      const s = row.original;
      const sources = s.telemetry_sources.length;
      if (sources === 0 && !s.last_telemetry_at) return <span className="text-xs whitespace-nowrap text-muted-foreground">No sources</span>;
      return (
        <div className="text-right">
          <span className="text-xs whitespace-nowrap text-fg-2">
            {formatCount(sources)} source{sources === 1 ? "" : "s"}
          </span>
          {s.last_telemetry_at ? (
            <div className="mt-0.5 text-xs whitespace-nowrap text-muted-foreground">
              last <RelativeTime value={s.last_telemetry_at} now={now} className="text-muted-foreground" />
            </div>
          ) : null}
        </div>
      );
    },
  };
}

function columnsFor(variant: ServicesVariant, now: string, showKind: boolean): ColumnDef<ServiceItem, unknown>[] {
  const cols: ColumnDef<ServiceItem, unknown>[] = [nameColumn(variant)];
  if (showKind) cols.push(kindColumn);
  cols.push(categoryColumn, coverageColumn);
  if (variant !== "k8s_workload") cols.push(portsColumn);
  if (variant !== "k8s_service") cols.push(instancesColumn(variant));
  cols.push(telemetryColumn(now), exposureColumn, reportColumn);
  return cols;
}

/**
 * Services of one level of an asset as a data table: coverage, kind, category, exposure and
 * discovery-report facets (counts from these rows), search over name, key and product, sort on
 * every column, row click opening the service. Coverage carries its meaning, the API's reasons
 * and the collector's note in a hover card; ports show exposure and owner attribution as
 * reported ("Owner unknown" is never shown as an owner). The kind column appears only when the
 * rows mix kinds.
 */
export function ServicesDataTable({
  services,
  now,
  variant,
  label,
  toolbar,
}: {
  services: ServiceItem[];
  now: string;
  variant: ServicesVariant;
  label: string;
  toolbar?: ReactNode;
}) {
  const serviceKinds = useMemo(() => [...new Set(services.map((s) => s.service_kind))], [services]);
  const showKind = variant === "host" && serviceKinds.length > 1;
  const cols = useMemo(() => columnsFor(variant, now, showKind), [variant, now, showKind]);
  const facets = useMemo<Facet[]>(() => {
    const kinds = new Set(services.map((s) => serviceCoverage(s).kind));
    const list: Facet[] = [
      {
        columnId: "coverage",
        title: "Coverage",
        options: (Object.keys(COVERAGE_ORDER) as CoverageKind[])
          .filter((k) => kinds.has(k))
          .sort((a, b) => COVERAGE_ORDER[a] - COVERAGE_ORDER[b])
          .map((k) => ({
            value: k,
            label: COVERAGE_LABEL[k],
            icon: <span aria-hidden="true" className={cn("size-2 flex-none rounded-full", coverageSwatchClass(k))} />,
          })),
      },
    ];
    if (showKind) {
      list.push({ columnId: "kind", title: "Kind", options: serviceKinds.map((k) => ({ value: k, label: serviceKindLabel(k) })) });
    }
    const categories = [...new Set(services.map((s) => s.category))].sort((a, b) => categoryLabel(a).localeCompare(categoryLabel(b)));
    if (categories.length > 1) {
      list.push({ columnId: "category", title: "Category", options: categories.map((c) => ({ value: c, label: categoryLabel(c) })) });
    }
    const exposures = [...new Set(services.map(widestExposure))].sort((a, b) => (EXPOSURE_RANK[a] ?? 9) - (EXPOSURE_RANK[b] ?? 9));
    if (variant !== "k8s_workload" && exposures.length > 1) {
      list.push({
        columnId: "exposure",
        title: "Exposure",
        options: exposures.map((e) => ({ value: e, label: EXPOSURE_LABEL[e] ?? e })),
      });
    }
    if (services.some((s) => s.report_stale)) {
      list.push({
        columnId: "report",
        title: "Discovery report",
        options: [
          { value: "current", label: "Current" },
          { value: "stale", label: "Stale" },
        ],
      });
    }
    return list;
  }, [services, variant, showKind, serviceKinds]);

  return (
    <DataTable
      data={services}
      columns={cols}
      getRowId={(s) => s.service_id}
      label={label}
      facets={facets}
      search={{ placeholder: variant === "k8s_workload" ? "Search workloads" : "Search services", columnIds: ["name"] }}
      initialSort={[{ id: "coverage", desc: false }]}
      initialColumnVisibility={{ exposure: false, report: false }}
      rowHref={(s) => serviceHref(s.service_id)}
      pageSize={variant === "host" ? 25 : 50}
      toolbar={toolbar}
      emptyMessage="No service matches the current filters."
    />
  );
}

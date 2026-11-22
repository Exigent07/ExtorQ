"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "cn";
import Link from "next/link";
import { type ReactNode, useMemo } from "react";

import { DataTable, type Facet } from "@/components/console/data-table";
import { coverageSwatchClass, CoverageBadge } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import type { ServiceItem } from "@/lib/api/schemas";
import { DASH, formatCount } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";
import { categoryLabel, type CoverageKind, serviceCoverage, serviceKindLabel } from "@/lib/services";

import { EndpointLine } from "./service-badges";
import { EXPOSURE_RANK, widestExposure } from "./model";

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

/** Ports of a service: the first endpoint inline, every endpoint in a hover card. */
function Ports({ service }: { service: ServiceItem }) {
  const endpoints = service.endpoints;
  if (endpoints.length === 0) return <span className="text-xs text-muted-foreground">None observed</span>;
  const first = endpoints[0]!;
  const line = <EndpointLine endpoint={first} compact />;
  if (endpoints.length === 1) return <div className="min-w-0">{line}</div>;
  return (
    <div className="flex min-w-0 flex-col items-start gap-1">
      {line}
      <HoverCard openDelay={250} closeDelay={80}>
        <HoverCardTrigger asChild>
          <button
            type="button"
            className="rounded-sm text-xs text-muted-foreground underline decoration-dotted underline-offset-2 outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
          >
            +{formatCount(endpoints.length - 1)} more
          </button>
        </HoverCardTrigger>
        <HoverCardContent align="start" className="w-[min(30rem,calc(100vw-2rem))] p-0">
          <p className="border-b border-hairline px-3 py-2 text-xs text-muted-foreground">
            {formatCount(endpoints.length)} listening endpoints · attribution as reported
          </p>
          <ul className="max-h-72 divide-y divide-hairline-soft overflow-y-auto">
            {endpoints.map((endpoint, i) => (
              <li key={`${endpoint.protocol}-${endpoint.address ?? "*"}-${endpoint.port}-${i}`} className="px-3 py-2">
                <EndpointLine endpoint={endpoint} compact />
              </li>
            ))}
          </ul>
        </HoverCardContent>
      </HoverCard>
    </div>
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
            {!s.present ? (
              <span className="inline-flex h-5 flex-none items-center rounded-md px-1.5 text-xs text-muted-foreground ring-1 ring-hairline-strong ring-inset">
                Removed
              </span>
            ) : null}
          </div>
          <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
            <span className="min-w-0 truncate font-mono">
              <UntrustedText value={s.service_key} oneLine mono />
            </span>
            {product ? (
              <>
                <span aria-hidden="true" className="text-fg-faint">
                  ·
                </span>
                <span className="max-w-[45%] flex-none truncate">
                  <UntrustedText value={product} plain limit={64} />
                </span>
              </>
            ) : null}
          </div>
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

function coverageColumn(variant: ServicesVariant): ColumnDef<ServiceItem, unknown> {
  return {
  id: "coverage",
  header: "Coverage",
  accessorFn: (s) => serviceCoverage(s).kind,
  sortingFn: (a, b) => COVERAGE_ORDER[serviceCoverage(a.original).kind] - COVERAGE_ORDER[serviceCoverage(b.original).kind],
  meta: { label: "Coverage" },
  cell: ({ row }) => {
    const s = row.original;
    const kind = serviceCoverage(s).kind;
    // The collector's note explains a gap (and what a Kubernetes Service is); for monitored and
    // unsupported host services the state says it all.
    const showNote =
      s.coverage_note && (kind === "degraded" || kind === "unmonitored" || kind === "planned" || variant === "k8s_service");
    return (
      <div className="flex max-w-60 min-w-0 flex-col items-start gap-1">
        <CoverageBadge service={s} className="text-xs" />
        {showNote ? (
          <span className="block w-full min-w-0 text-xs text-muted-foreground">
            <UntrustedText value={s.coverage_note} oneLine />
          </span>
        ) : null}
      </div>
    );
  },
  };
}

const portsColumn: ColumnDef<ServiceItem, unknown> = {
  id: "ports",
  header: "Ports",
  accessorFn: (s) => s.endpoints.length,
  meta: { className: "hidden md:table-cell", label: "Ports" },
  cell: ({ row }) => <Ports service={row.original} />,
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

function telemetryColumn(now: string): ColumnDef<ServiceItem, unknown> {
  return {
    id: "telemetry",
    header: "Last telemetry",
    accessorFn: (s) => (s.last_telemetry_at ? Date.parse(s.last_telemetry_at) : -1),
    meta: { align: "right", className: "hidden w-32 sm:table-cell", label: "Last telemetry" },
    cell: ({ row }) => {
      const s = row.original;
      return (
        <div className="text-right">
          <RelativeTime value={s.last_telemetry_at} now={now} className="text-xs" />
          <div className="mt-0.5 text-xs text-muted-foreground">
            {s.telemetry_sources.length === 0
              ? "no sources"
              : `${formatCount(s.telemetry_sources.length)} source${s.telemetry_sources.length === 1 ? "" : "s"}`}
          </div>
        </div>
      );
    },
  };
}

function columnsFor(variant: ServicesVariant, now: string): ColumnDef<ServiceItem, unknown>[] {
  const cols: ColumnDef<ServiceItem, unknown>[] = [nameColumn(variant)];
  if (variant === "host") cols.push(kindColumn);
  cols.push(categoryColumn, coverageColumn(variant));
  if (variant !== "k8s_workload") cols.push(portsColumn);
  if (variant !== "k8s_service") cols.push(instancesColumn(variant));
  cols.push(telemetryColumn(now), exposureColumn, reportColumn);
  return cols;
}

/**
 * Services of one level of an asset as a data table: coverage, kind, category, exposure and
 * discovery-report facets (counts from these rows), search over name, key and product, sort on
 * every column, row click opening the service. Coverage carries the API's reasons in its hint;
 * an "unknown" port attribution is printed as such.
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
  const cols = useMemo(() => columnsFor(variant, now), [variant, now]);
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
    const serviceKinds = [...new Set(services.map((s) => s.service_kind))];
    if (variant === "host" && serviceKinds.length > 1) {
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
  }, [services, variant]);

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

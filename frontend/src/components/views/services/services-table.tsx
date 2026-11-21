"use client";

import type { ColumnDef } from "@tanstack/react-table";
import Link from "next/link";
import { useMemo, useState } from "react";

import { FilterChips, SortableTable } from "@/components/console/sortable-table";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ServiceItem } from "@/lib/api/schemas";
import { DASH, formatCount } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";
import { categoryLabel, type CoverageKind, serviceCoverage } from "@/lib/services";

import { EndpointLine, RemovedTag, ReportStaleTag, ServiceCoverageDot } from "./service-badges";

const COVERAGE_ORDER: Record<CoverageKind, number> = {
  degraded: 0,
  unmonitored: 1,
  monitored: 2,
  planned: 3,
  unsupported: 4,
  unknown: 5,
};

const FILTERS: { key: "all" | CoverageKind; label: string }[] = [
  { key: "all", label: "All" },
  { key: "monitored", label: "Monitored" },
  { key: "degraded", label: "Degraded" },
  { key: "unmonitored", label: "Unmonitored" },
  { key: "planned", label: "Planned adapter" },
  { key: "unsupported", label: "Unsupported" },
];

const MAX_ENDPOINTS = 3;

function columns(now: string): ColumnDef<ServiceItem, unknown>[] {
  return [
    {
      id: "name",
      header: "Service",
      accessorFn: (s) => s.name.toLowerCase(),
      meta: { className: "w-[32%] min-w-56 whitespace-normal" },
      cell: ({ row }) => {
        const s = row.original;
        const href = serviceHref(s.service_id);
        return (
          <div className="min-w-0 py-1">
            <div className="flex flex-wrap items-center gap-2">
              {href ? (
                <Link href={href} className="font-medium text-ink underline-offset-2 hover:underline">
                  <UntrustedText value={s.name} limit={80} />
                </Link>
              ) : (
                <UntrustedText value={s.name} limit={80} className="font-medium text-ink" />
              )}
              {!s.present ? <RemovedTag /> : null}
              {s.present && s.report_stale ? <ReportStaleTag ageSeconds={s.report_age_seconds} /> : null}
            </div>
            <div className="mt-1 sm:hidden">
              <ServiceCoverageDot service={s} />
            </div>
            <div className="mt-0.5 flex flex-wrap gap-x-2 text-xs text-muted-foreground">
              <UntrustedText value={s.service_key} limit={72} mono />
              {s.product ? (
                <span>
                  <UntrustedText value={s.product} limit={40} />
                  {s.version ? (
                    <>
                      {" "}
                      <UntrustedText value={s.version} limit={32} />
                    </>
                  ) : null}
                </span>
              ) : null}
            </div>
          </div>
        );
      },
    },
    {
      id: "category",
      header: "Category",
      accessorFn: (s) => categoryLabel(s.category),
      meta: { className: "hidden lg:table-cell" },
      cell: ({ getValue }) => <span className="text-ink-2">{String(getValue())}</span>,
    },
    {
      id: "coverage",
      header: "Coverage",
      accessorFn: (s) => COVERAGE_ORDER[serviceCoverage(s).kind],
      meta: { className: "hidden whitespace-normal sm:table-cell" },
      cell: ({ row }) => {
        const s = row.original;
        return (
          <div className="py-1">
            <ServiceCoverageDot service={s} />
            {s.coverage_reasons.length > 0 ? (
              <div className="mt-0.5 max-w-72 text-xs text-warn">
                <UntrustedText value={s.coverage_reasons.join("; ")} limit={110} />
              </div>
            ) : null}
            {s.coverage_note ? (
              <div className="mt-0.5 max-w-72 text-xs text-muted-foreground">
                <UntrustedText value={s.coverage_note} limit={80} />
              </div>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "endpoints",
      header: "Ports",
      enableSorting: false,
      meta: { className: "hidden whitespace-normal md:table-cell" },
      cell: ({ row }) => {
        const endpoints = row.original.endpoints;
        if (endpoints.length === 0) return <span className="text-xs text-muted-foreground">None observed</span>;
        return (
          <ul className="flex flex-col gap-1 py-1">
            {endpoints.slice(0, MAX_ENDPOINTS).map((endpoint, i) => (
              <li key={`${endpoint.protocol}-${endpoint.address ?? "*"}-${endpoint.port}-${i}`}>
                <EndpointLine endpoint={endpoint} compact />
              </li>
            ))}
            {endpoints.length > MAX_ENDPOINTS ? (
              <li className="text-xs text-muted-foreground">{endpoints.length - MAX_ENDPOINTS} more on the service page</li>
            ) : null}
          </ul>
        );
      },
    },
    {
      id: "telemetry",
      header: "Last telemetry",
      accessorFn: (s) => (s.last_telemetry_at ? Date.parse(s.last_telemetry_at) : -1),
      meta: { align: "right", className: "hidden sm:table-cell" },
      cell: ({ row }) => {
        const s = row.original;
        return (
          <div className="text-right">
            <RelativeTime value={s.last_telemetry_at} now={now} className="text-xs" />
            <div className="text-xs text-muted-foreground">
              {s.telemetry_sources.length === 0
                ? "no sources"
                : `${s.telemetry_sources.length} source${s.telemetry_sources.length === 1 ? "" : "s"}`}
            </div>
          </div>
        );
      },
    },
    {
      id: "instances",
      header: "Instances",
      accessorFn: (s) => s.instance_count ?? -1,
      meta: { align: "right", className: "hidden sm:table-cell" },
      cell: ({ row }) => (
        <span className="font-mono text-xs text-ink-2">
          {row.original.instance_count === null || row.original.instance_count === undefined
            ? DASH
            : formatCount(row.original.instance_count)}
        </span>
      ),
    },
  ];
}

/** Services of one kind on an asset, with coverage filter chips computed from these rows. */
export function ServicesTable({ services, now, label }: { services: ServiceItem[]; now: string; label: string }) {
  const [filter, setFilter] = useState<"all" | CoverageKind>("all");
  const cols = useMemo(() => columns(now), [now]);
  const counts = useMemo(() => {
    const map = new Map<string, number>();
    for (const s of services) {
      const kind = serviceCoverage(s).kind;
      map.set(kind, (map.get(kind) ?? 0) + 1);
    }
    return map;
  }, [services]);
  const options = FILTERS.filter((f) => f.key === "all" || (counts.get(f.key) ?? 0) > 0).map((f) => ({
    ...f,
    count: f.key === "all" ? services.length : (counts.get(f.key) ?? 0),
  }));
  const rows = filter === "all" ? services : services.filter((s) => serviceCoverage(s).kind === filter);

  return (
    <div>
      {options.length > 2 ? (
        <div className="mb-2">
          <FilterChips label={`Filter ${label} by coverage`} options={options} value={filter} onChange={setFilter} />
        </div>
      ) : null}
      <SortableTable
        data={rows}
        columns={cols}
        label={label}
        getRowId={(s) => s.service_id}
        initialSort={[{ id: "coverage", desc: false }]}
        rowClassName={(s) => (s.present ? undefined : "opacity-70")}
      />
    </div>
  );
}

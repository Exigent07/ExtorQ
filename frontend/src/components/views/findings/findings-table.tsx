"use client";

import type { ColumnDef } from "@tanstack/react-table";
import Link from "next/link";
import { useMemo, useState } from "react";

import { SEVERITY_ORDER, SeverityTag } from "@/components/console/severity";
import { EmptyState } from "@/components/console/states";
import { FilterChips, SortableTable } from "@/components/console/sortable-table";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { FindingItem } from "@/lib/api/schemas";
import { FINDING_STATE } from "@/lib/findings";
import { DASH, humanize } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";

function stateOf(finding: FindingItem): string {
  return finding.state ?? "lifecycle unavailable";
}

function resourceText(f: FindingItem): string | null {
  if (f.package_name) {
    const fixed = f.fixed_version ? ` (fixed in ${f.fixed_version})` : "";
    return `${f.package_name} ${f.installed_version ?? ""}${fixed}`.trim();
  }
  const parts = [f.resource_namespace, f.resource_name ?? f.resource_path].filter(Boolean);
  return parts.length > 0 ? parts.join("/") : null;
}

function columns(now: string, serviceNames: Record<string, string>): ColumnDef<FindingItem, unknown>[] {
  return [
    {
      id: "severity",
      header: "Severity",
      accessorFn: (f) => SEVERITY_ORDER.indexOf(f.severity),
      meta: { className: "w-24" },
      cell: ({ row }) => <SeverityTag severity={row.original.severity} />,
    },
    {
      id: "title",
      header: "Finding",
      accessorFn: (f) => f.title.toLowerCase(),
      meta: { className: "min-w-64 whitespace-normal" },
      cell: ({ row }) => {
        const f = row.original;
        const resource = resourceText(f);
        const serviceName = f.service_id ? serviceNames[f.service_id] : undefined;
        const href = f.service_id ? serviceHref(f.service_id) : null;
        return (
          <div className="min-w-0 py-1">
            <div className="text-ink">
              <UntrustedText value={f.title} limit={120} />
            </div>
            <div className="mt-0.5 flex flex-wrap gap-x-2 text-xs text-muted-foreground">
              <UntrustedText value={f.check_id} limit={64} mono />
              {f.cve_ids.length > 0 ? <UntrustedText value={f.cve_ids.join(", ")} limit={80} mono /> : null}
              {f.cvss_score !== null && f.cvss_score !== undefined ? <span>CVSS {f.cvss_score.toFixed(1)}</span> : null}
            </div>
            {resource ? (
              <div className="mt-0.5 text-xs text-ink-2">
                <UntrustedText value={resource} limit={120} />
              </div>
            ) : null}
            {f.service_id && href ? (
              <div className="mt-0.5 text-xs text-muted-foreground">
                Service{" "}
                <Link href={href} className="text-ink-2 hover:text-ink hover:underline">
                  {serviceName ? <UntrustedText value={serviceName} limit={48} /> : `${f.service_id.slice(0, 8)}…`}
                </Link>
              </div>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "category",
      header: "Category",
      accessorFn: (f) => f.category,
      meta: { className: "hidden md:table-cell" },
      cell: ({ row }) => <span className="text-ink-2 capitalize">{humanize(row.original.category)}</span>,
    },
    {
      id: "state",
      header: "State",
      accessorFn: (f) => stateOf(f),
      cell: ({ row }) => {
        const f = row.original;
        const state = f.state ? FINDING_STATE[f.state] : undefined;
        return (
          <div className="py-1">
            {state ? (
              <span title={state.detail} className={`whitespace-nowrap ${state.className}`}>
                {state.label}
              </span>
            ) : (
              <span className="text-muted-foreground" title="The findings lifecycle view is unavailable">
                {DASH}
              </span>
            )}
            {f.accepted_risk_reason ? (
              <div className="mt-0.5 max-w-56 text-xs whitespace-normal text-muted-foreground">
                <span className="text-ink-2">Accepted risk:</span> <UntrustedText value={f.accepted_risk_reason} limit={80} />
              </div>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "scanner",
      header: "Scanner",
      accessorFn: (f) => f.scanner,
      meta: { className: "hidden lg:table-cell" },
      cell: ({ row }) => (
        <span className="font-mono text-xs text-ink-2">
          <UntrustedText value={row.original.scanner} limit={32} />
        </span>
      ),
    },
    {
      id: "last",
      header: "Last observed",
      accessorFn: (f) => Date.parse(f.last_observed_at),
      meta: { align: "right" },
      cell: ({ row }) => <RelativeTime value={row.original.last_observed_at} now={now} className="text-xs" />,
    },
  ];
}

type CategoryKey = string;

/**
 * Vulnerabilities and misconfigurations of one asset or service, with category and state
 * filters whose counts are computed from these rows.
 */
export function FindingsTable({
  findings,
  now,
  serviceNames = {},
}: {
  findings: FindingItem[];
  now: string;
  serviceNames?: Record<string, string>;
}) {
  const [category, setCategory] = useState<CategoryKey>("all");
  const [state, setState] = useState<string>("all");
  const cols = useMemo(() => columns(now, serviceNames), [now, serviceNames]);

  const categories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const f of findings) counts.set(f.category, (counts.get(f.category) ?? 0) + 1);
    return [
      { key: "all", label: "All categories", count: findings.length },
      ...[...counts.entries()].sort((a, b) => b[1] - a[1]).map(([key, count]) => ({ key, label: humanize(key), count })),
    ];
  }, [findings]);

  const byCategory = category === "all" ? findings : findings.filter((f) => f.category === category);
  const states = useMemo(() => {
    const counts = new Map<string, number>();
    for (const f of byCategory) counts.set(stateOf(f), (counts.get(stateOf(f)) ?? 0) + 1);
    return [
      { key: "all", label: "Any state", count: byCategory.length },
      ...["open", "unverified", "resolved"]
        .filter((key) => counts.has(key))
        .map((key) => ({ key, label: FINDING_STATE[key]?.label ?? key, count: counts.get(key) ?? 0 })),
    ];
  }, [byCategory]);
  const rows = state === "all" ? byCategory : byCategory.filter((f) => stateOf(f) === state);

  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-2">
        {categories.length > 2 ? (
          <FilterChips label="Filter findings by category" options={categories} value={category} onChange={setCategory} />
        ) : null}
        {states.length > 2 ? <FilterChips label="Filter findings by state" options={states} value={state} onChange={setState} /> : null}
      </div>
      {rows.length === 0 ? (
        <EmptyState>No finding matches the selected category and state.</EmptyState>
      ) : (
        <SortableTable
          data={rows}
          columns={cols}
          label="Findings"
          getRowId={(f) => `${f.finding_id}|${f.asset_id}`}
          initialSort={[{ id: "severity", desc: false }]}
          rowClassName={(f) => (f.state === "resolved" ? "opacity-70" : undefined)}
        />
      )}
    </div>
  );
}

"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "cn";
import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { type ReactElement, useMemo } from "react";

import { DataTable, type Facet } from "@/components/console/data-table";
import { DetailSection, DetailSheet, RawBlock } from "@/components/console/detail-sheet";
import { Hint } from "@/components/console/hint";
import { KeyValueList } from "@/components/console/key-values";
import { SEVERITY_LABEL, SEVERITY_ORDER, SeverityBadge, SeverityDot } from "@/components/console/severity";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { FindingItem } from "@/lib/api/schemas";
import { FINDING_STATE } from "@/lib/findings";
import { DASH, humanize } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";

const STATE_TONE: Record<string, string> = {
  open: "bg-foreground",
  unverified: "bg-health-warn",
  resolved: "ring-1 ring-fg-faint ring-inset",
};

function stateKey(f: FindingItem): string {
  return f.state ?? "unavailable";
}

function resourceText(f: FindingItem): string | null {
  if (f.package_name) {
    const fixed = f.fixed_version ? ` → ${f.fixed_version}` : "";
    return `${f.package_name} ${f.installed_version ?? ""}${fixed}`.trim();
  }
  const parts = [f.resource_namespace, f.resource_name ?? f.resource_path].filter(Boolean);
  return parts.length > 0 ? parts.join("/") : null;
}

/** Lifecycle state (open / unverified / resolved) with its meaning on hover. */
function FindingState({ finding }: { finding: FindingItem }) {
  const state = finding.state ? FINDING_STATE[finding.state] : undefined;
  if (!state) {
    return (
      <Hint content="The findings lifecycle view is unavailable: only the observation is known.">
        <span className="text-muted-foreground">{DASH}</span>
      </Hint>
    );
  }
  return (
    <Hint content={state.detail}>
      <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap", finding.state === "resolved" ? "text-muted-foreground" : "text-fg-2")}>
        <span aria-hidden="true" className={cn("size-1.5 rounded-full", STATE_TONE[finding.state ?? ""] ?? "bg-fg-2")} />
        {state.label}
      </span>
    </Hint>
  );
}

function AcceptedRisk() {
  return (
    <span className="inline-flex h-5 flex-none items-center gap-1 rounded-md px-1.5 text-xs whitespace-nowrap text-fg-2 ring-1 ring-hairline-strong ring-inset">
      <ShieldCheck className="size-3" aria-hidden="true" />
      Accepted risk
    </span>
  );
}

/** Everything the API reported about one finding, in a right-hand sheet. */
function FindingSheet({
  finding: f,
  now,
  serviceName,
  children,
}: {
  finding: FindingItem;
  now: string;
  serviceName?: string;
  children: ReactElement;
}) {
  const href = f.service_id ? serviceHref(f.service_id) : null;
  const state = f.state ? FINDING_STATE[f.state] : undefined;
  return (
    <DetailSheet
      trigger={children}
      title={<UntrustedText value={f.title} limit={200} />}
      description={
        <span className="font-mono text-xs">
          <UntrustedText value={f.check_id} plain limit={120} />
        </span>
      }
      badges={
        <>
          <SeverityBadge severity={f.severity} size="md" />
          <FindingState finding={f} />
          {f.accepted_risk_reason ? <AcceptedRisk /> : null}
        </>
      }
    >
      <DetailSection title="Finding">
        <KeyValueList
          rows={[
            { label: "Scanner", value: <UntrustedText value={f.scanner} plain limit={48} /> },
            { label: "Category", value: <span className="capitalize">{humanize(f.category)}</span> },
            { label: "State", value: state ? `${state.label}: ${state.detail}` : "Lifecycle unavailable" },
            {
              label: "CVSS",
              value: f.cvss_score === null || f.cvss_score === undefined ? <span className="text-muted-foreground">{DASH}</span> : f.cvss_score.toFixed(1),
            },
            {
              label: "CVE",
              value: f.cve_ids.length > 0 ? <UntrustedText value={f.cve_ids.join(", ")} mono limit={160} /> : <span className="text-muted-foreground">{DASH}</span>,
            },
            { label: "First observed", value: <Timestamp value={f.first_observed_at} /> },
            {
              label: "Last observed",
              value: (
                <span className="inline-flex flex-wrap items-center justify-end gap-2">
                  <Timestamp value={f.last_observed_at} />
                  <RelativeTime value={f.last_observed_at} now={now} className="text-xs text-muted-foreground" />
                </span>
              ),
            },
            { label: "Last scan run", value: <UntrustedText value={f.last_scan_run_id} mono plain limit={64} /> },
          ]}
        />
      </DetailSection>
      <DetailSection title="Affected resource">
        <KeyValueList
          layout="stacked"
          rows={[
            ...(f.package_name
              ? [
                  { label: "Package", value: <UntrustedText value={f.package_name} mono limit={160} /> },
                  { label: "Installed version", value: <UntrustedText value={f.installed_version} mono limit={80} /> },
                  { label: "Fixed version", value: <UntrustedText value={f.fixed_version} mono limit={80} /> },
                ]
              : []),
            { label: "Resource type", value: <UntrustedText value={f.resource_type} limit={80} /> },
            {
              label: "Resource",
              value: <UntrustedText value={[f.resource_namespace, f.resource_name].filter(Boolean).join("/") || null} mono limit={200} />,
            },
            { label: "Path", value: <UntrustedText value={f.resource_path} mono limit={300} /> },
            {
              label: "Service",
              value:
                f.service_id && href ? (
                  <Link href={href} className="text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
                    {serviceName ? <UntrustedText value={serviceName} plain limit={80} /> : `Service ${f.service_id.slice(0, 8)}…`}
                  </Link>
                ) : (
                  <span className="text-muted-foreground">Not attributed to a service</span>
                ),
            },
          ]}
        />
      </DetailSection>
      {f.remediation ? (
        <DetailSection title="Remediation (from the scanner)">
          <RawBlock className="font-sans text-sm">
            <UntrustedText value={f.remediation} multiline limit={4000} />
          </RawBlock>
        </DetailSection>
      ) : null}
      {f.accepted_risk_reason ? (
        <DetailSection title="Accepted risk">
          <p className="text-sm text-fg-2">
            <UntrustedText value={f.accepted_risk_reason} multiline limit={2000} />
          </p>
        </DetailSection>
      ) : null}
    </DetailSheet>
  );
}

function columns(now: string, serviceNames: Record<string, string>): ColumnDef<FindingItem, unknown>[] {
  return [
    {
      id: "severity",
      header: "Severity",
      accessorFn: (f) => f.severity,
      sortingFn: (a, b) => SEVERITY_ORDER.indexOf(a.original.severity) - SEVERITY_ORDER.indexOf(b.original.severity),
      meta: { className: "w-28", label: "Severity" },
      enableHiding: false,
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: "title",
      header: "Finding",
      accessorFn: (f) => [f.title, f.check_id, f.package_name, f.cve_ids.join(" "), resourceText(f)].filter(Boolean).join(" "),
      sortingFn: (a, b) => a.original.title.localeCompare(b.original.title),
      meta: { className: "max-w-0 w-full min-w-64", label: "Finding" },
      enableHiding: false,
      cell: ({ row }) => {
        const f = row.original;
        const resource = resourceText(f);
        return (
          <div className="min-w-0">
            <FindingSheet finding={f} now={now} serviceName={f.service_id ? serviceNames[f.service_id] : undefined}>
              <button
                type="button"
                className="block w-full min-w-0 truncate rounded-sm text-left font-medium text-foreground underline-offset-2 outline-none hover:text-brand hover:underline focus-visible:ring-2 focus-visible:ring-ring/50"
              >
                <UntrustedText value={f.title} oneLine plain />
              </button>
            </FindingSheet>
            <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
              <span className="max-w-[45%] min-w-0 flex-none truncate font-mono">
                <UntrustedText value={f.check_id} oneLine plain mono />
              </span>
              {resource ? (
                <>
                  <span aria-hidden="true" className="text-fg-faint">
                    ·
                  </span>
                  <span className="min-w-0 flex-1 truncate">
                    <UntrustedText value={resource} oneLine plain />
                  </span>
                </>
              ) : null}
            </div>
          </div>
        );
      },
    },
    {
      id: "category",
      header: "Category",
      accessorFn: (f) => f.category,
      meta: { className: "hidden lg:table-cell", label: "Category" },
      cell: ({ row }) => <span className="text-fg-2 capitalize">{humanize(row.original.category)}</span>,
    },
    {
      id: "state",
      header: "State",
      accessorFn: (f) => stateKey(f),
      sortingFn: (a, b) =>
        ["open", "unverified", "resolved", "unavailable"].indexOf(stateKey(a.original)) -
        ["open", "unverified", "resolved", "unavailable"].indexOf(stateKey(b.original)),
      meta: { label: "State" },
      cell: ({ row }) => (
        <span className="flex flex-col items-start gap-1">
          <FindingState finding={row.original} />
          {row.original.accepted_risk_reason ? <AcceptedRisk /> : null}
        </span>
      ),
    },
    {
      id: "scanner",
      header: "Scanner",
      accessorFn: (f) => f.scanner,
      meta: { className: "hidden xl:table-cell", label: "Scanner" },
      cell: ({ row }) => (
        <span className="font-mono text-xs text-fg-2">
          <UntrustedText value={row.original.scanner} plain limit={32} />
        </span>
      ),
    },
    {
      id: "last",
      header: "Last observed",
      accessorFn: (f) => Date.parse(f.last_observed_at),
      meta: { align: "right", className: "w-32", label: "Last observed" },
      cell: ({ row }) => <RelativeTime value={row.original.last_observed_at} now={now} className="text-xs" />,
    },
  ];
}

/**
 * Findings of an asset or service as a data table: severity, state, category and scanner
 * facets (counts from these rows), search over title, check, package, CVE and resource, and a
 * details sheet per finding. Rows are the API's, in its order (open first, most severe first).
 */
export function FindingsDataTable({
  findings,
  now,
  serviceNames = {},
  label = "Findings",
}: {
  findings: FindingItem[];
  now: string;
  serviceNames?: Record<string, string>;
  label?: string;
}) {
  const cols = useMemo(() => columns(now, serviceNames), [now, serviceNames]);
  const facets = useMemo<Facet[]>(() => {
    const present = (values: string[]) => [...new Set(values)];
    const severities = present(findings.map((f) => f.severity));
    const states = present(findings.map(stateKey));
    const categories = present(findings.map((f) => f.category)).sort();
    const scanners = present(findings.map((f) => f.scanner)).sort();
    const list: Facet[] = [
      {
        columnId: "severity",
        title: "Severity",
        options: SEVERITY_ORDER.filter((s) => severities.includes(s)).map((s) => ({
          value: s,
          label: SEVERITY_LABEL[s],
          icon: <SeverityDot severity={s} />,
        })),
      },
      {
        columnId: "state",
        title: "State",
        options: ["open", "unverified", "resolved", "unavailable"]
          .filter((s) => states.includes(s))
          .map((s) => ({ value: s, label: FINDING_STATE[s]?.label ?? "Lifecycle unavailable" })),
      },
    ];
    if (categories.length > 1) {
      list.push({ columnId: "category", title: "Category", options: categories.map((c) => ({ value: c, label: humanize(c) })) });
    }
    if (scanners.length > 1) list.push({ columnId: "scanner", title: "Scanner", options: scanners.map((s) => ({ value: s, label: s })) });
    return list;
  }, [findings]);

  return (
    <DataTable
      data={findings}
      columns={cols}
      getRowId={(f) => `${f.finding_id}|${f.asset_id}`}
      label={label}
      facets={facets}
      search={{ placeholder: "Search findings", columnIds: ["title"] }}
      pageSize={25}
      emptyMessage="No finding matches the current filters."
    />
  );
}

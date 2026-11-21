"use client";

import type { ColumnDef } from "@tanstack/react-table";
import Link from "next/link";
import { useMemo } from "react";

import { SEVERITY_ORDER, SeverityTag } from "@/components/console/severity";
import { SortableTable } from "@/components/console/sortable-table";
import { StatusDot, StatusPill } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { RuleListItem } from "@/lib/api/schemas";
import { DASH, formatCount, formatInterval, formatMs } from "@/lib/format";

const RUN_TONE: Record<string, "ok" | "warn" | "bad" | "off"> = {
  succeeded: "ok",
  skipped: "warn",
  failed: "bad",
};

function columns(now: string): ColumnDef<RuleListItem, unknown>[] {
  return [
    {
      id: "rule",
      header: "Rule",
      accessorFn: (r) => r.rule_id,
      meta: { className: "min-w-64 whitespace-normal" },
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="py-1">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="font-mono text-xs text-muted-foreground">{r.rule_id}</span>
              <Link
                href={`/detections?rule=${encodeURIComponent(r.rule_id)}`}
                className="font-medium text-ink underline-offset-2 hover:underline"
                title="Show this rule's alerts"
              >
                <UntrustedText value={r.title} limit={96} />
              </Link>
            </div>
            <div className="mt-0.5 text-xs text-muted-foreground">
              v<UntrustedText value={r.version} limit={16} />
              {r.mitre_techniques.length > 0 ? <> · <UntrustedText value={r.mitre_techniques.join(", ")} limit={64} /></> : null}
              {r.interval_seconds ? ` · ${formatInterval(r.interval_seconds)}` : ""}
            </div>
          </div>
        );
      },
    },
    {
      id: "severity",
      header: "Severity",
      accessorFn: (r) => SEVERITY_ORDER.indexOf(r.severity),
      cell: ({ row }) => <SeverityTag severity={row.original.severity} />,
    },
    {
      id: "status",
      header: "Status",
      accessorFn: (r) => `${r.enabled ? 0 : 1}${r.status}`,
      meta: { className: "hidden md:table-cell" },
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="flex flex-wrap items-center gap-2 text-xs">
            {r.enabled ? <span className="text-ink-2">Enabled</span> : <StatusPill tone="off" label="Disabled" />}
            <span className="text-muted-foreground capitalize">{r.status}</span>
          </div>
        );
      },
    },
    {
      id: "lastRun",
      header: "Last run",
      accessorFn: (r) => (r.last_run ? Date.parse(r.last_run.last_run_at) : -1),
      meta: { className: "min-w-52 whitespace-normal" },
      cell: ({ row }) => {
        const r = row.original;
        if (!r.last_run) return <span className="text-xs text-muted-foreground">Never ran</span>;
        const run = r.last_run;
        return (
          <div className="py-1 text-xs">
            <div className="flex flex-wrap items-center gap-2">
              <StatusDot tone={RUN_TONE[run.last_status] ?? "off"} label={run.last_status} />
              <RelativeTime value={run.last_run_at} now={now} className="text-xs" />
              {r.run_stale ? <StatusPill tone="warn" label="Overdue" /> : null}
            </div>
            <div className="mt-0.5 text-muted-foreground">
              {formatMs(run.last_duration_ms)} · {formatCount(run.runs_24h)} runs in 24 h
            </div>
            {run.last_error ? (
              <div className="mt-0.5 max-w-80 text-bad">
                <UntrustedText value={run.last_error} limit={140} />
              </div>
            ) : null}
          </div>
        );
      },
    },
    {
      id: "failures",
      header: "Failures 24 h",
      accessorFn: (r) => r.last_run?.failures_24h ?? -1,
      meta: { align: "right" },
      cell: ({ row }) => {
        const n = row.original.last_run?.failures_24h;
        if (n === undefined) return <span className="text-muted-foreground">{DASH}</span>;
        return <span className={n > 0 ? "font-mono text-xs text-bad" : "font-mono text-xs text-muted-foreground"}>{formatCount(n)}</span>;
      },
    },
    {
      id: "missing",
      header: "Missing sources",
      accessorFn: (r) => r.last_run?.missing_sources.length ?? -1,
      meta: { className: "hidden whitespace-normal lg:table-cell" },
      cell: ({ row }) => {
        const missing = row.original.last_run?.missing_sources;
        if (!missing) return <span className="text-muted-foreground">{DASH}</span>;
        if (missing.length === 0) return <span className="text-xs text-muted-foreground">None</span>;
        return (
          <span className="font-mono text-xs text-warn">
            <UntrustedText value={missing.join(", ")} limit={120} />
          </span>
        );
      },
    },
    {
      id: "alerts",
      header: "Alerts open / total",
      accessorFn: (r) => r.alerts_open,
      meta: { align: "right" },
      cell: ({ row }) => (
        <span className="font-mono text-xs">
          <span className={row.original.alerts_open > 0 ? "text-ink" : "text-muted-foreground"}>
            {formatCount(row.original.alerts_open)}
          </span>
          <span className="text-muted-foreground"> / {formatCount(row.original.alerts_total)}</span>
        </span>
      ),
    },
  ];
}

/** Detection rules with their execution health; sortable by any column. */
export function RulesTable({ rules, now }: { rules: RuleListItem[]; now: string }) {
  const cols = useMemo(() => columns(now), [now]);
  return (
    <SortableTable
      data={rules}
      columns={cols}
      label="Detection rules"
      getRowId={(r) => r.rule_id}
      initialSort={[{ id: "rule", desc: false }]}
    />
  );
}

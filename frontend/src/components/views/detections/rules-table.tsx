"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "cn";
import Link from "next/link";
import type { MouseEvent, ReactNode } from "react";
import { useMemo } from "react";

import { DataTable, type FacetOption } from "@/components/console/data-table";
import { Hint } from "@/components/console/hint";
import { SEVERITY_LABEL, SEVERITY_ORDER, SeverityBadge, SeverityDot } from "@/components/console/severity";
import { StatusDot, StatusPill } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { RuleListItem } from "@/lib/api/schemas";
import { DASH, formatCount, formatInterval, formatMs, formatVersion } from "@/lib/format";

import { detectionsSearch, plural, ruleStatusLabel, runTone, SEVERITY_RANK } from "./model";
import { RelativeTime } from "@/components/console/time";
import { useDetections } from "./workspace";

const OUTCOME_LABEL: Record<string, string> = {
  succeeded: "Succeeded",
  failed: "Failed",
  skipped: "Skipped",
  never: "Never ran",
};

function outcomeOf(rule: RuleListItem): string {
  return rule.last_run?.last_status ?? "never";
}

/** A small neutral token badge (ATT&CK technique, source type). */
function Token({ children, muted = false, className }: { children: ReactNode; muted?: boolean; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 max-w-full items-center rounded-md px-1.5 font-mono text-xs whitespace-nowrap ring-1 ring-inset",
        muted ? "bg-white/[0.03] text-muted-foreground ring-hairline" : "text-fg-2 ring-hairline-strong",
        className,
      )}
    >
      {children}
    </span>
  );
}

function RuleLink({ rule, children, className }: { rule: RuleListItem; children: ReactNode; className?: string }) {
  const { range, showRuleAlerts } = useDetections();
  const href = `/detections${detectionsSearch({ rule: [rule.rule_id], range })}`;
  return (
    <Link
      href={href}
      className={className}
      onClick={(event: MouseEvent<HTMLAnchorElement>) => {
        // Plain clicks switch tabs in place; modified clicks open the link as usual.
        if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        event.preventDefault();
        showRuleAlerts(rule.rule_id);
      }}
    >
      {children}
    </Link>
  );
}

function columns(now: string): ColumnDef<RuleListItem, unknown>[] {
  return [
    {
      id: "rule",
      accessorFn: (r) => r.rule_id,
      header: "Rule",
      enableHiding: false,
      meta: { className: "min-w-[180px] whitespace-normal @5xl:min-w-[340px]" },
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="grid min-w-0 gap-1.5 py-0.5">
            <p className="min-w-0 leading-snug">
              <span className="mr-2 font-mono text-xs text-muted-foreground">{r.rule_id}</span>
              <RuleLink
                rule={r}
                className="font-medium text-foreground underline-offset-4 transition-colors duration-150 hover:text-brand hover:underline"
              >
                <UntrustedText value={r.title} plain limit={160} />
              </RuleLink>
            </p>
            {r.mitre_techniques.length > 0 ? (
              <ul aria-label="MITRE ATT&CK techniques" className="flex flex-wrap gap-1">
                {r.mitre_techniques.slice(0, 6).map((technique) => (
                  <li key={technique}>
                    <Token>
                      <UntrustedText value={technique} plain limit={24} />
                    </Token>
                  </li>
                ))}
                {r.mitre_techniques.length > 6 ? (
                  <li className="text-xs text-muted-foreground">+{formatCount(r.mitre_techniques.length - 6)}</li>
                ) : null}
              </ul>
            ) : (
              <span className="text-xs text-muted-foreground">No ATT&amp;CK mapping</span>
            )}
          </div>
        );
      },
    },
    {
      // Search target only.
      id: "title",
      accessorFn: (r) => `${r.rule_id} ${r.title} ${r.mitre_techniques.join(" ")}`,
      header: "Title",
      enableHiding: false,
      enableSorting: false,
      cell: () => null,
    },
    {
      id: "severity",
      accessorFn: (r) => r.severity,
      header: "Severity",
      sortingFn: (a, b) => SEVERITY_RANK[a.original.severity] - SEVERITY_RANK[b.original.severity],
      sortDescFirst: true,
      meta: { className: "hidden w-[108px] @md:table-cell", label: "Severity" },
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: "status",
      accessorFn: (r) => r.status,
      header: "Status",
      meta: { className: "hidden w-[120px] @4xl:table-cell", label: "Status and version" },
      cell: ({ row }) => {
        const r = row.original;
        return (
          <div className="grid justify-items-start gap-1">
            {r.enabled ? (
              r.status === "experimental" ? (
                <span className="inline-flex h-5 items-center rounded-md px-1.5 text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset">
                  {ruleStatusLabel(r.status)}
                </span>
              ) : (
                <span className="text-sm text-foreground">{ruleStatusLabel(r.status)}</span>
              )
            ) : (
              <StatusPill tone="off" label="Disabled" />
            )}
            <span className="font-mono text-xs text-muted-foreground">
              <UntrustedText value={formatVersion(r.version)} plain limit={24} />
            </span>
          </div>
        );
      },
    },
    {
      id: "lastRun",
      accessorFn: (r) => (r.last_run ? Date.parse(r.last_run.last_run_at) : -1),
      header: "Last run",
      sortDescFirst: true,
      meta: { className: "w-[200px] @max-3xl:pr-(--table-edge)", label: "Last run" },
      cell: ({ row }) => {
        const r = row.original;
        const run = r.last_run;
        if (!run) {
          return (
            <div className="grid gap-1">
              <StatusDot tone="off" label="Never ran" className="text-sm" />
              <span className="text-xs text-muted-foreground">{formatInterval(r.interval_seconds)}</span>
            </div>
          );
        }
        return (
          <div className="grid min-w-0 gap-1">
            <span className="flex min-w-0 items-center gap-2 text-sm">
              <StatusDot tone={runTone(run.last_status)} label={OUTCOME_LABEL[run.last_status] ?? run.last_status} />
              <RelativeTime value={run.last_run_at} now={now} className="text-muted-foreground" />
              {r.run_stale ? <StatusPill tone="warn" label="Overdue" /> : null}
            </span>
            {run.last_error ? (
              <span className="min-w-0 text-xs text-health-bad">
                <UntrustedText value={run.last_error} oneLine />
              </span>
            ) : (
              <span className="text-xs text-muted-foreground tabular-nums">
                {formatMs(run.last_duration_ms)} · {formatInterval(r.interval_seconds)}
              </span>
            )}
          </div>
        );
      },
    },
    {
      // Facet only.
      id: "outcome",
      accessorFn: (r) => outcomeOf(r),
      header: "Outcome",
      enableHiding: false,
      enableSorting: false,
      cell: () => null,
    },
    {
      id: "runs",
      // Sorted by failures, then by runs.
      accessorFn: (r) => (r.last_run ? r.last_run.failures_24h * 1_000_000 + r.last_run.runs_24h : -1),
      header: "Last 24 h",
      sortDescFirst: true,
      meta: { align: "right", className: "hidden w-[104px] @4xl:table-cell", label: "Runs and failures, 24 h" },
      cell: ({ row }) => {
        const run = row.original.last_run;
        if (!run) return <span className="text-muted-foreground">{DASH}</span>;
        return (
          <div className="grid justify-items-end gap-1 tabular-nums">
            <span className="text-sm text-fg-2">{plural(run.runs_24h, "run")}</span>
            <span className={cn("text-xs", run.failures_24h > 0 ? "font-medium text-health-bad" : "text-muted-foreground")}>
              {plural(run.failures_24h, "failure")}
            </span>
          </div>
        );
      },
    },
    {
      id: "missing",
      accessorFn: (r) => r.last_run?.missing_sources.length ?? -1,
      header: () => (
        <Hint content="Source types with no event in the rule's last evaluation window (required or optional inputs). A quiet source can hide detections: a blind spot, not a rule failure.">
          <span className="underline decoration-hairline-strong decoration-dotted underline-offset-4">Quiet sources</span>
        </Hint>
      ),
      // The header holds a focusable hint: no sort button around it.
      enableSorting: false,
      meta: { className: "hidden w-[168px] @min-[1080px]:table-cell", label: "Quiet sources" },
      cell: ({ row }) => {
        const missing = row.original.last_run?.missing_sources;
        if (!missing) return <span className="text-muted-foreground">{DASH}</span>;
        if (missing.length === 0) return <span className="text-sm text-muted-foreground">None</span>;
        return (
          <ul aria-label="Sources without events" className="flex flex-wrap gap-1">
            {missing.slice(0, 4).map((source) => (
              <li key={source}>
                <Token className="gap-1.5 text-fg-2 ring-hairline-strong">
                  <span aria-hidden="true" className="size-1.5 flex-none rounded-full bg-health-warn" />
                  <UntrustedText value={source} plain limit={40} />
                </Token>
              </li>
            ))}
            {missing.length > 4 ? <li className="text-xs text-muted-foreground">+{formatCount(missing.length - 4)}</li> : null}
          </ul>
        );
      },
    },
    {
      id: "alerts",
      accessorFn: (r) => r.alerts_open,
      header: "Alerts",
      sortDescFirst: true,
      meta: { align: "right", className: "hidden w-[96px] @3xl:table-cell", label: "Open and total alerts" },
      cell: ({ row }) => {
        const r = row.original;
        return (
          <RuleLink
            rule={r}
            className="group/alerts inline-grid justify-items-end gap-1 rounded-sm tabular-nums outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
          >
            <span
              className={cn(
                "text-sm underline-offset-4 group-hover/alerts:underline",
                r.alerts_open > 0 ? "font-medium text-foreground" : "text-muted-foreground",
              )}
            >
              {formatCount(r.alerts_open)} open
            </span>
            <span className="text-xs text-muted-foreground">{formatCount(r.alerts_total)} total</span>
          </RuleLink>
        );
      },
    },
  ];
}

const SEVERITY_FACET: FacetOption[] = SEVERITY_ORDER.map((severity) => ({
  value: severity,
  label: SEVERITY_LABEL[severity],
  icon: <SeverityDot severity={severity} className="size-2" />,
}));

/** Registered detection rules with their execution health; sortable, faceted, searchable. */
export function RulesTable({ rules, now }: { rules: RuleListItem[]; now: string }) {
  const cols = useMemo(() => columns(now), [now]);
  const statusOptions = useMemo<FacetOption[]>(
    () => [...new Set(rules.map((r) => r.status))].sort().map((status) => ({ value: status, label: ruleStatusLabel(status) })),
    [rules],
  );
  const outcomeOptions = useMemo<FacetOption[]>(
    () =>
      [...new Set(rules.map(outcomeOf))].sort().map((outcome) => ({
        value: outcome,
        label: OUTCOME_LABEL[outcome] ?? outcome,
        icon: (
          <span
            aria-hidden="true"
            className={cn(
              "size-1.5 rounded-full",
              { ok: "bg-health-ok", warn: "bg-health-warn", bad: "bg-health-bad", off: "bg-health-off" }[runTone(outcome)],
            )}
          />
        ),
      })),
    [rules],
  );
  return (
    <div className="@container">
      <DataTable
        data={rules}
        columns={cols}
        label="Detection rules"
        getRowId={(r) => r.rule_id}
        initialSort={[{ id: "rule", desc: false }]}
        initialColumnVisibility={{ title: false, outcome: false }}
        search={{ placeholder: "Search rules and techniques", columnIds: ["title"] }}
        facets={[
          { columnId: "severity", title: "Severity", options: SEVERITY_FACET },
          { columnId: "status", title: "Status", options: statusOptions },
          { columnId: "outcome", title: "Last run", options: outcomeOptions },
        ]}
        emptyMessage="No rule matches these filters."
        pageSize={25}
      />
    </div>
  );
}

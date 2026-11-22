"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "cn";
import { Box, Container, Cpu } from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";

import { DataTable, type Facet } from "@/components/console/data-table";
import { CoverageBadge } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ServiceInstance, ServiceItem } from "@/lib/api/schemas";
import { DASH } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";
import { INSTANCE_KIND_LABEL } from "@/lib/services";

import { instanceName } from "./model";

export interface InstanceTableRow {
  id: string;
  instance: ServiceInstance;
  /** Containers of a Pod (children by parent_instance_id). */
  children: ServiceInstance[];
  /** The workload the instance belongs to (node view), absent on a service's own page. */
  workload?: ServiceItem;
}

const STATE_TONE: Record<string, string> = {
  running: "bg-health-ok",
  pending: "bg-health-warn",
  failed: "bg-health-bad",
  stopped: "bg-health-off",
};

function KindIcon({ kind }: { kind: string }) {
  const Icon = kind === "pod" ? Box : kind === "container" ? Container : Cpu;
  return <Icon className="size-3.5 flex-none text-muted-foreground" strokeWidth={1.75} aria-hidden="true" />;
}

/** The state token as reported, with a neutral dot for known states (not a health verdict). */
function InstanceState({ state }: { state: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs whitespace-nowrap text-fg-2">
      <span aria-hidden="true" className={cn("size-1.5 rounded-full", STATE_TONE[state] ?? "bg-health-off")} />
      <UntrustedText value={state} plain limit={24} />
    </span>
  );
}

function ContainerList({ containers }: { containers: ServiceInstance[] }) {
  if (containers.length === 0) return null;
  return (
    <ul className="mt-1.5 grid gap-1" aria-label="Containers">
      {containers.map((c) => (
        <li key={c.instance_id} className="flex min-w-0 items-center gap-1.5 pl-1 text-xs text-muted-foreground">
          <Container className="size-3 flex-none text-fg-faint" strokeWidth={1.75} aria-hidden="true" />
          <span className="flex-none text-fg-2">
            <UntrustedText value={instanceName(c)} plain limit={48} />
          </span>
          {c.image ? (
            <span className="min-w-0 flex-1 truncate font-mono">
              <UntrustedText value={c.image} oneLine mono />
            </span>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

function columns(
  now: string,
  withWorkload: boolean,
  kubernetes: boolean,
  showNode: boolean,
): ColumnDef<InstanceTableRow, unknown>[] {
  const cols: ColumnDef<InstanceTableRow, unknown>[] = [
    {
      id: "instance",
      header: kubernetes ? "Pod and containers" : "Instance",
      accessorFn: (r) =>
        [instanceName(r.instance), r.instance.instance_key, ...r.children.map(instanceName), r.instance.image, ...r.children.map((c) => c.image)]
          .filter(Boolean)
          .join(" "),
      sortingFn: (a, b) => instanceName(a.original.instance).localeCompare(instanceName(b.original.instance)),
      meta: { className: "w-full max-w-0 min-w-64", label: "Instance" },
      enableHiding: false,
      cell: ({ row }) => {
        const { instance: i, children } = row.original;
        return (
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-2">
              <KindIcon kind={i.instance_kind} />
              <span className="flex-none text-xs text-muted-foreground">{INSTANCE_KIND_LABEL[i.instance_kind] ?? i.instance_kind}</span>
              <span className="min-w-0 truncate font-mono text-xs text-foreground">
                <UntrustedText value={instanceName(i)} oneLine mono />
              </span>
            </div>
            {i.instance_kind !== "pod" && i.image ? (
              <div className="mt-1 min-w-0 truncate pl-5.5 font-mono text-xs text-muted-foreground">
                <UntrustedText value={i.image} oneLine mono />
              </div>
            ) : null}
            <ContainerList containers={children} />
          </div>
        );
      },
    },
  ];
  if (withWorkload) {
    cols.push({
      id: "workload",
      header: "Workload",
      accessorFn: (r) => r.workload?.name ?? "",
      meta: { className: "max-w-64", label: "Workload" },
      cell: ({ row }) => {
        const w = row.original.workload;
        if (!w) return <span className="text-muted-foreground">{DASH}</span>;
        const href = serviceHref(w.service_id);
        return (
          <div className="flex min-w-0 flex-col items-start gap-1">
            {href ? (
              <Link
                href={href}
                className="block max-w-full min-w-0 truncate text-sm font-medium text-foreground underline-offset-2 hover:text-brand hover:underline"
              >
                <UntrustedText value={w.name} plain limit={80} />
              </Link>
            ) : (
              <span className="block max-w-full truncate text-sm text-foreground">
                <UntrustedText value={w.name} plain limit={80} />
              </span>
            )}
            <CoverageBadge service={w} className="text-xs" />
          </div>
        );
      },
    });
  }
  if (kubernetes) {
    cols.push({
      id: "namespace",
      header: "Namespace",
      accessorFn: (r) => r.instance.namespace ?? "",
      meta: { className: "hidden md:table-cell", label: "Namespace" },
      cell: ({ row }) => (
        <span className="text-xs text-fg-2">
          <UntrustedText value={row.original.instance.namespace} plain limit={48} />
        </span>
      ),
    });
    if (showNode) {
      cols.push({
        id: "node",
        header: "Node",
        accessorFn: (r) => r.instance.node_name ?? "",
        meta: { className: "hidden lg:table-cell", label: "Node" },
        cell: ({ row }) => (
          <span className="text-xs text-fg-2">
            <UntrustedText value={row.original.instance.node_name} plain limit={48} />
          </span>
        ),
      });
    }
    cols.push(
      {
        id: "ids",
        header: "Pod UID / container id",
        accessorFn: (r) => r.instance.pod_uid ?? r.instance.container_id ?? "",
        enableSorting: false,
        meta: { className: "hidden max-w-48 2xl:table-cell", label: "Pod UID / container id" },
        cell: ({ row }) => {
          const { instance: i, children } = row.original;
          const ids = [i.pod_uid, i.container_id, ...children.map((c) => c.container_id)].filter(Boolean) as string[];
          if (ids.length === 0) return <span className="text-muted-foreground">{DASH}</span>;
          return (
            <div className="grid min-w-0 gap-0.5">
              {ids.map((id) => (
                <span key={id} className="block min-w-0 font-mono text-xs text-muted-foreground">
                  <UntrustedText value={id} oneLine mono />
                </span>
              ))}
            </div>
          );
        },
      },
    );
  } else {
    cols.push(
      {
        id: "process",
        header: "Process",
        accessorFn: (r) => r.instance.process_name ?? "",
        meta: { className: "hidden md:table-cell", label: "Process" },
        cell: ({ row }) => {
          const i = row.original.instance;
          return (
            <span className="text-xs whitespace-nowrap text-fg-2">
              {i.process_name ? <UntrustedText value={i.process_name} plain limit={48} /> : <span className="text-muted-foreground">{DASH}</span>}
              {i.pid !== null && i.pid !== undefined ? <span className="ml-1.5 font-mono text-muted-foreground">pid {i.pid}</span> : null}
            </span>
          );
        },
      },
      {
        id: "user",
        header: "User",
        accessorFn: (r) => r.instance.user ?? "",
        meta: { className: "hidden lg:table-cell", label: "User" },
        cell: ({ row }) => (
          <span className="text-xs text-fg-2">
            <UntrustedText value={row.original.instance.user} plain limit={48} />
          </span>
        ),
      },
    );
  }
  cols.push(
    {
      id: "state",
      header: "State",
      accessorFn: (r) => r.instance.state,
      meta: { className: "w-28", label: "State" },
      cell: ({ row }) => <InstanceState state={row.original.instance.state} />,
    },
    {
      id: "observed",
      header: "Observed",
      accessorFn: (r) => Date.parse(r.instance.observed_at),
      meta: { align: "right", className: "w-28", label: "Observed" },
      cell: ({ row }) => {
        const i = row.original.instance;
        return (
          <div className="text-right">
            <RelativeTime value={i.observed_at} now={now} className="text-xs text-muted-foreground" />
            {i.started_at ? (
              <div className="mt-0.5 text-xs whitespace-nowrap text-muted-foreground">
                started <RelativeTime value={i.started_at} now={now} className="text-muted-foreground" />
              </div>
            ) : null}
          </div>
        );
      },
    },
  );
  return cols;
}

/**
 * Instances as a data table: Pods with their containers nested under them (Kubernetes) or
 * processes (hosts), with namespace / workload / state facets. Staleness is stated once by the
 * caller above the table, not repeated on every row; the observed time stays visible per row.
 */
export function InstancesDataTable({
  rows,
  now,
  kubernetes,
  label,
  showNode = true,
}: {
  rows: InstanceTableRow[];
  now: string;
  kubernetes: boolean;
  label: string;
  /** Node column (off on a node's own page, where every row is on that node). */
  showNode?: boolean;
}) {
  const withWorkload = rows.some((r) => r.workload);
  const cols = useMemo(() => columns(now, withWorkload, kubernetes, showNode), [now, withWorkload, kubernetes, showNode]);
  const facets = useMemo<Facet[]>(() => {
    const list: Facet[] = [];
    const namespaces = [...new Set(rows.map((r) => r.instance.namespace ?? "").filter(Boolean))].sort();
    if (kubernetes && namespaces.length > 1) {
      list.push({ columnId: "namespace", title: "Namespace", options: namespaces.map((n) => ({ value: n, label: n })) });
    }
    const states = [...new Set(rows.map((r) => r.instance.state))].sort();
    if (states.length > 1) list.push({ columnId: "state", title: "State", options: states.map((s) => ({ value: s, label: s })) });
    return list;
  }, [rows, kubernetes]);

  return (
    <DataTable
      data={rows}
      columns={cols}
      getRowId={(r) => r.id}
      label={label}
      facets={facets}
      search={{ placeholder: kubernetes ? "Search Pods, containers, images" : "Search instances", columnIds: ["instance", ...(withWorkload ? ["workload"] : [])] }}
      initialSort={withWorkload ? [{ id: "workload", desc: false }] : [{ id: "instance", desc: false }]}
      pageSize={25}
      emptyMessage="No instance matches the current filters."
    />
  );
}

"use client";

import type { ColumnDef } from "@tanstack/react-table";
import { cn } from "cn";
import Link from "next/link";
import { type ReactElement, type ReactNode, useEffect, useMemo, useState } from "react";

import { loadRawExcerptAction, type RawExcerpt } from "@/app/(console)/actions";
import { clickRowOpener, DataTable, type Facet } from "@/components/console/data-table";
import { DetailSection, DetailSheet, RawBlock } from "@/components/console/detail-sheet";
import { KeyValueList } from "@/components/console/key-values";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Spinner } from "@/components/ui/spinner";
import type { EventListItem } from "@/lib/api/schemas";
import { DASH, humanize } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";

import { emptyOptionalColumns } from "./model";

/** The acting principal as the source reported it (never inferred). */
function actorOf(e: EventListItem): string | null {
  return e.actor_name ?? e.k8s_user ?? e.gh_actor_login ?? null;
}

const OUTCOME_TONE: Record<string, string> = {
  failure: "text-health-warn",
  denied: "text-health-warn",
  success: "text-fg-2",
};

const OUTCOME_DOT: Record<string, string> = {
  failure: "bg-health-warn",
  denied: "bg-health-warn",
  success: "bg-fg-faint",
};

/** The outcome as reported, with a quiet dot (amber for failures and denials). */
function Outcome({ outcome }: { outcome: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs whitespace-nowrap", OUTCOME_TONE[outcome] ?? "text-muted-foreground")}>
      <span aria-hidden="true" className={cn("size-1.5 flex-none rounded-full", OUTCOME_DOT[outcome] ?? "ring-1 ring-fg-faint ring-inset")} />
      <UntrustedText value={outcome} plain limit={24} />
    </span>
  );
}

type Field = { label: string; value: string | number | null | undefined; mono?: boolean };

function hostPort(ip: string | null | undefined, port: number | null | undefined): string | null {
  if (!ip && (port === null || port === undefined)) return null;
  return `${ip ?? "?"}${port !== null && port !== undefined ? `:${port}` : ""}`;
}

/** The event's reported fields in groups; absent fields are left out, never filled in. */
function fieldGroups(e: EventListItem): { title: string; rows: Field[] }[] {
  const groups: { title: string; rows: Field[] }[] = [
    {
      title: "Event",
      rows: [
        { label: "Event id", value: e.event_id, mono: true },
        { label: "Type", value: e.event_type, mono: true },
        { label: "Category", value: e.category },
        { label: "Action", value: e.action },
        { label: "Outcome", value: e.outcome },
        { label: "Severity hint", value: e.severity_hint },
        { label: "Source type", value: e.source_type, mono: true },
        { label: "Collector", value: e.collector_id, mono: true },
      ],
    },
    {
      title: "Actor and network",
      rows: [
        { label: "Actor type", value: e.actor_type },
        { label: "Actor", value: actorOf(e) },
        { label: "Actor id", value: e.actor_id, mono: true },
        { label: "Source", value: hostPort(e.src_ip, e.src_port), mono: true },
        { label: "Destination", value: hostPort(e.dst_ip, e.dst_port), mono: true },
      ],
    },
    {
      title: "Resource and process",
      rows: [
        { label: "Resource type", value: e.resource_type },
        { label: "Namespace", value: e.resource_namespace },
        { label: "Resource", value: e.resource_name, mono: true },
        { label: "Path", value: e.resource_path, mono: true },
        { label: "Process", value: e.process_name, mono: true },
        { label: "PID", value: e.process_pid, mono: true },
      ],
    },
    {
      title: "HTTP",
      rows: [
        { label: "Method", value: e.http_method },
        { label: "Route", value: e.http_route, mono: true },
        { label: "Status", value: e.http_status, mono: true },
        { label: "Request id", value: e.http_request_id, mono: true },
      ],
    },
    {
      title: "Kubernetes",
      rows: [
        { label: "Cluster", value: e.k8s_cluster },
        { label: "Node", value: e.k8s_node },
        { label: "Namespace", value: e.k8s_namespace },
        { label: "Pod", value: e.k8s_pod_name, mono: true },
        { label: "Pod UID", value: e.k8s_pod_uid, mono: true },
        { label: "Container", value: e.k8s_container, mono: true },
        { label: "Container id", value: e.k8s_container_id, mono: true },
        { label: "Verb", value: e.k8s_verb },
        { label: "Resource", value: e.k8s_resource },
        { label: "Object", value: e.k8s_object_name, mono: true },
        { label: "Response code", value: e.k8s_response_code, mono: true },
        { label: "User", value: e.k8s_user, mono: true },
        { label: "Audit id", value: e.k8s_audit_id, mono: true },
      ],
    },
    {
      title: "GitHub",
      rows: [
        { label: "Repository", value: e.gh_repository, mono: true },
        { label: "Commit", value: e.gh_commit_sha, mono: true },
        { label: "Workflow", value: e.gh_workflow_path, mono: true },
        { label: "Workflow run", value: e.gh_workflow_run_id, mono: true },
        { label: "Actor", value: e.gh_actor_login },
      ],
    },
    {
      title: "Attribution",
      rows: [
        { label: "Service instance", value: e.service_instance_id, mono: true },
        { label: "Adapter", value: e.adapter_id, mono: true },
      ],
    },
  ];
  return groups
    .map((g) => ({ ...g, rows: g.rows.filter((r) => r.value !== null && r.value !== undefined && r.value !== "") }))
    .filter((g) => g.rows.length > 0);
}

/** The stored raw excerpt, read through a server action when the sheet opens (API token stays server-side). */
function RawExcerptSection({ eventId }: { eventId: string }) {
  const [state, setState] = useState<{ excerpt: RawExcerpt } | { error: string } | null>(null);
  useEffect(() => {
    let cancelled = false;
    loadRawExcerptAction(eventId).then(
      (result) => {
        if (!cancelled) setState(result.ok ? { excerpt: result.excerpt } : { error: result.message });
      },
      () => {
        if (!cancelled) setState({ error: "The stored record could not be loaded." });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [eventId]);

  return (
    <DetailSection title="Raw excerpt (sanitised at ingestion)">
      {state === null ? (
        <p className="inline-flex items-center gap-2 text-xs text-muted-foreground">
          <Spinner className="size-3" /> Loading the stored record
        </p>
      ) : "error" in state ? (
        <p className="text-xs text-health-bad">{state.error}</p>
      ) : (
        <div className="grid gap-3">
          {state.excerpt.raw ? (
            <RawBlock>
              <UntrustedText value={state.excerpt.raw} multiline mono limit={4000} />
            </RawBlock>
          ) : (
            <p className="text-xs text-muted-foreground">No raw text was stored for this event (structured source).</p>
          )}
          <KeyValueList
            rows={[
              {
                label: "Parser",
                value: <UntrustedText value={`${state.excerpt.parser} ${state.excerpt.parserVersion}`} mono plain limit={80} />,
              },
              { label: "Ingested", value: <Timestamp value={state.excerpt.ingestedTime} /> },
              ...(state.excerpt.sourceNativeId
                ? [{ label: "Source id", value: <UntrustedText value={state.excerpt.sourceNativeId} mono limit={120} /> }]
                : []),
              ...(state.excerpt.rawSha256
                ? [{ label: "Raw SHA-256", value: <UntrustedText value={state.excerpt.rawSha256} mono oneLine /> }]
                : []),
              {
                label: "Handling",
                value: `${
                  state.excerpt.redactionCount > 0
                    ? `${state.excerpt.redactionCount} value${state.excerpt.redactionCount === 1 ? "" : "s"} redacted at ingestion`
                    : "no redactions"
                }${state.excerpt.truncated ? " · truncated at ingestion" : ""}`,
              },
            ]}
          />
        </div>
      )}
    </DetailSection>
  );
}

/** One stored event in a right-hand sheet: message, reported fields, service, raw excerpt. */
export function EventSheet({ event: e, children }: { event: EventListItem; children: ReactElement }) {
  const href = e.service_id ? serviceHref(e.service_id) : null;
  return (
    <DetailSheet
      size="lg"
      titleClassName="font-mono text-base"
      trigger={children}
      title={<UntrustedText value={e.event_type} limit={120} />}
      description={
        <span>
          <Timestamp value={e.event_time} /> · <UntrustedText value={e.source_type} plain limit={48} />
        </span>
      }
      badges={
        <span
          className={cn(
            "inline-flex h-5 items-center rounded-md px-1.5 text-xs ring-1 ring-hairline-strong ring-inset",
            OUTCOME_TONE[e.outcome] ?? "text-muted-foreground",
          )}
        >
          <UntrustedText value={e.outcome} plain limit={24} />
        </span>
      }
    >
      {e.message ? (
        <DetailSection title="Message">
          <RawBlock className="font-sans text-sm">
            <UntrustedText value={e.message} multiline limit={4000} />
          </RawBlock>
        </DetailSection>
      ) : null}
      <DetailSection title="Service">
        {e.service_id && href ? (
          <Link href={href} className="text-sm text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
            {e.service_name ? <UntrustedText value={e.service_name} plain limit={80} /> : `Service ${e.service_id.slice(0, 8)}…`}
          </Link>
        ) : (
          <p className="text-sm text-muted-foreground">The producing adapter could not attribute this record to a service.</p>
        )}
      </DetailSection>
      {fieldGroups(e).map((group) => (
        <DetailSection key={group.title} title={group.title}>
          <KeyValueList
            rows={group.rows.map((r) => ({
              label: r.label,
              value: <UntrustedText value={String(r.value)} mono={r.mono} oneLine={r.mono} limit={240} />,
            }))}
          />
        </DetailSection>
      ))}
      <RawExcerptSection eventId={e.event_id} />
    </DetailSheet>
  );
}

function columns(showService: boolean): ColumnDef<EventListItem, unknown>[] {
  const cols: ColumnDef<EventListItem, unknown>[] = [
    {
      id: "time",
      header: "Time (UTC)",
      accessorFn: (e) => Date.parse(e.event_time),
      meta: { className: "w-40", label: "Time" },
      enableHiding: false,
      cell: ({ row }) => <Timestamp value={row.original.event_time} />,
    },
    {
      id: "event",
      header: "Event",
      accessorFn: (e) => [e.event_type, e.message, actorOf(e), e.src_ip, e.service_name].filter(Boolean).join(" "),
      sortingFn: (a, b) => a.original.event_type.localeCompare(b.original.event_type),
      meta: { className: "max-w-0 w-full min-w-64", label: "Event" },
      enableHiding: false,
      cell: ({ row }) => {
        const e = row.original;
        return (
          <div className="min-w-0">
            <EventSheet event={e}>
              <button
                type="button"
                data-row-open=""
                className="block w-full min-w-0 truncate rounded-sm text-left font-mono text-xs text-foreground underline-offset-2 outline-none hover:text-brand hover:underline focus-visible:ring-2 focus-visible:ring-ring/50"
              >
                <UntrustedText value={e.event_type} oneLine plain mono />
              </button>
            </EventSheet>
            <div className="mt-1 min-w-0 text-xs text-muted-foreground">
              {e.message ? <UntrustedText value={e.message} oneLine /> : <span className="text-fg-faint">{DASH}</span>}
            </div>
          </div>
        );
      },
    },
    {
      id: "source",
      header: "Source",
      accessorFn: (e) => e.source_type,
      meta: { className: "hidden lg:table-cell", label: "Source" },
      cell: ({ row }) => (
        <span className="font-mono text-xs text-fg-2">
          <UntrustedText value={row.original.source_type} plain limit={40} />
        </span>
      ),
    },
    {
      // Hidden: the event type as its own value, for the facet (the Event column searches it).
      id: "type",
      header: "Event type",
      accessorFn: (e) => e.event_type,
      enableHiding: false,
      enableSorting: false,
      cell: () => null,
    },
    {
      id: "actor",
      header: "Actor",
      accessorFn: (e) => actorOf(e) ?? "",
      meta: { className: "hidden max-w-44 md:table-cell", label: "Actor" },
      cell: ({ row }) => {
        const actor = actorOf(row.original);
        return actor ? (
          <span className="block min-w-0 text-xs text-fg-2">
            <UntrustedText value={actor} oneLine />
          </span>
        ) : (
          <span className="text-muted-foreground">{DASH}</span>
        );
      },
    },
    {
      id: "src",
      header: "Source IP",
      accessorFn: (e) => e.src_ip ?? "",
      meta: { className: "hidden xl:table-cell", label: "Source IP" },
      cell: ({ row }) =>
        row.original.src_ip ? (
          <span className="font-mono text-xs text-fg-2">
            <UntrustedText value={row.original.src_ip} plain limit={48} />
          </span>
        ) : (
          <span className="text-muted-foreground">{DASH}</span>
        ),
    },
    {
      id: "outcome",
      header: "Outcome",
      accessorFn: (e) => e.outcome,
      meta: { className: "w-24", label: "Outcome" },
      cell: ({ row }) => <Outcome outcome={row.original.outcome} />,
    },
  ];
  if (showService) {
    cols.push({
      id: "service",
      header: "Service",
      accessorFn: (e) => e.service_name ?? "",
      meta: { className: "hidden max-w-40 2xl:table-cell", label: "Service" },
      cell: ({ row }) => {
        const e = row.original;
        const href = e.service_id ? serviceHref(e.service_id) : null;
        if (e.service_name && href) {
          return (
            <Link href={href} className="block min-w-0 truncate text-xs text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
              <UntrustedText value={e.service_name} plain limit={40} />
            </Link>
          );
        }
        return <span className="text-muted-foreground">{DASH}</span>;
      },
    });
  }
  return cols;
}

/**
 * Stored events (newest first) as a data table: source and outcome facets with counts from these
 * rows, search over type, message, actor, address and service, and a details sheet per event
 * with the raw excerpt read on demand. Every string is attacker-controllable telemetry.
 */
export function EventsDataTable({
  events,
  showService = true,
  label = "Events",
  toolbar,
}: {
  events: EventListItem[];
  showService?: boolean;
  label?: string;
  toolbar?: ReactNode;
}) {
  const cols = useMemo(() => columns(showService), [showService]);
  const facets = useMemo<Facet[]>(() => {
    const sources = [...new Set(events.map((e) => e.source_type))].sort();
    const types = [...new Set(events.map((e) => e.event_type))].sort();
    const outcomes = [...new Set(events.map((e) => e.outcome))].sort();
    const list: Facet[] = [];
    if (sources.length > 1) list.push({ columnId: "source", title: "Source", options: sources.map((s) => ({ value: s, label: s })) });
    if (types.length > 1) list.push({ columnId: "type", title: "Event type", options: types.map((t) => ({ value: t, label: t })) });
    if (outcomes.length > 1) {
      list.push({ columnId: "outcome", title: "Outcome", options: outcomes.map((o) => ({ value: o, label: humanize(o) })) });
    }
    return list;
  }, [events]);
  const initialVisibility = useMemo(
    () => Object.fromEntries([["type", false], ...emptyOptionalColumns(events).map((id) => [id, false])]),
    [events],
  );

  return (
    <DataTable
      data={events}
      columns={cols}
      getRowId={(e) => e.event_id}
      label={label}
      facets={facets}
      search={{ placeholder: "Search events", columnIds: ["event"] }}
      initialSort={[{ id: "time", desc: true }]}
      initialColumnVisibility={initialVisibility}
      pageSize={25}
      onRowClick={clickRowOpener}
      toolbar={toolbar}
      emptyMessage="No event matches the current filters."
    />
  );
}

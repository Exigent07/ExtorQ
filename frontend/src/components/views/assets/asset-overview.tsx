import { cn } from "cn";
import { Activity, BellRing, Boxes, Clock, FileWarning, Layers, ListTree, Network, ShieldAlert, Tags } from "lucide-react";
import Link from "next/link";

import { Hint } from "@/components/console/hint";
import { KeyValueList } from "@/components/console/key-values";
import { KpiCard, KpiFigures, SplitBar } from "@/components/console/kpi-card";
import { CardLink, SectionCard } from "@/components/console/section-card";
import { EmptyState } from "@/components/console/states";
import { StatusDot } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AssetDetailResponse, AssetListItem } from "@/lib/api/schemas";
import { collectorsSummary } from "@/lib/assets";
import { DASH, formatCount, formatRelative, formatUtcShort, keyLabel } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";
import { SERVICE_GROUPS, serviceKindLabel } from "@/lib/services";

import { AlertList } from "./alert-list";
import {
  assetHealth,
  COVERAGE_PARTS,
  coverageParts,
  itemLabel,
  openAlertMix,
  partsInWords,
  relativeParts,
  severityParts,
  sourceRows,
  windowLabel,
} from "./model";

const RECENT_ALERT_ROWS = 6;

/** A split bar only when it shows a proportion (two or more non-zero parts). */
function proportion(parts: { value: number }[]): boolean {
  return parts.filter((p) => p.value > 0).length > 1;
}

/**
 * Headline figures of one asset: collectors fresh, last event, open alerts (severity mix only
 * when exact) and open findings by severity. Values as the API reports them.
 */
export function AssetKpis({
  detail,
  now,
  alertsHref,
  findingsHref,
}: {
  detail: AssetDetailResponse;
  now: string;
  alertsHref: string;
  findingsHref: string;
}) {
  const a = detail.asset;
  const health = assetHealth(a);
  const fresh = a.collectors_total - a.collectors_stale;
  const last = a.last_event_at ? relativeParts(formatRelative(a.last_event_at, now)) : null;
  const mix = openAlertMix(detail.recent_alerts, a.open_alerts);
  const fs = detail.findings_summary;
  const findingParts = severityParts(fs.counts);
  const unverified = fs.unverified?.total ?? 0;

  return (
    <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
      <KpiCard
        label="Collectors fresh"
        icon={Activity}
        value={a.collectors_total === 0 ? "0" : formatCount(fresh)}
        unit={a.collectors_total === 0 ? undefined : `/ ${formatCount(a.collectors_total)}`}
        status={{ tone: health.tone, label: health.label }}
        footer={
          a.collectors_stale > 0 && fresh > 0 ? (
            <SplitBar
              label={`${fresh} fresh, ${a.collectors_stale} stale`}
              parts={[
                { key: "fresh", value: fresh, className: "bg-health-ok" },
                { key: "stale", value: a.collectors_stale, className: "bg-health-warn" },
              ]}
            />
          ) : undefined
        }
        sub={
          a.collectors_total === 0
            ? "No collector reports for this asset."
            : a.collectors_inherited > 0
              ? `${collectorsSummary(a)}.`
              : health.reason
                ? `${health.reason}.`
                : "Every collector is fresh and reports OK."
        }
      />
      <KpiCard
        label="Last event"
        icon={Clock}
        value={last ? last.value : DASH}
        unit={last?.unit ?? undefined}
        sub={
          a.last_event_at ? (
            <>
              Newest event <span className="text-fg-2 tabular-nums">{formatUtcShort(a.last_event_at)} UTC</span>
            </>
          ) : a.asset_type === "kubernetes_node" ? (
            "Its events are stored under the cluster"
          ) : (
            "No event is stored for this asset."
          )
        }
      />
      <KpiCard
        label="Open alerts"
        icon={ShieldAlert}
        value={formatCount(a.open_alerts)}
        status={a.open_alerts === 0 ? { tone: "ok", label: "None open" } : undefined}
        footer={
          mix && proportion(severityParts(mix)) ? (
            <SplitBar label={partsInWords(severityParts(mix)) || "no open alert"} parts={severityParts(mix)} />
          ) : undefined
        }
        sub={
          a.open_alerts === 0 ? (
            "No open alert for this asset."
          ) : mix ? (
            <KpiFigures hideZero
              items={severityParts(mix).map((p) => ({ label: p.label, value: p.value, strong: p.key === "critical" || p.key === "high" }))}
            />
          ) : (
            "Severity mix on the Detections page"
          )
        }
        href={alertsHref}
      />
      <KpiCard
        label={fs.lifecycle_available ? "Open findings" : "Observed findings"}
        icon={FileWarning}
        value={formatCount(fs.counts.total)}
        footer={proportion(findingParts) ? <SplitBar label={partsInWords(findingParts) || "no finding"} parts={findingParts} /> : undefined}
        sub={
          fs.counts.total === 0 && unverified === 0 ? (
            fs.lifecycle_available ? "No open finding." : "No finding observed."
          ) : (
            <KpiFigures hideZero
              items={[
                { label: "critical", value: fs.counts.critical, strong: true },
                { label: "high", value: fs.counts.high, strong: true },
                { label: "medium", value: fs.counts.medium },
                { label: "low", value: fs.counts.low },
                { label: "unverified", value: unverified },
              ]}
            />
          )
        }
        href={findingsHref}
      />
    </div>
  );
}

/** Events stored per source type over the API window, as a bar list (bar = share of the largest). */
export function EventsBySourceCard({ detail, now, className }: { detail: AssetDetailResponse; now: string; className?: string }) {
  const rows = sourceRows(detail.event_counts, detail.collectors, detail.asset.asset_id);
  const max = Math.max(1, ...rows.map((r) => r.events));
  const total = rows.reduce((sum, r) => sum + r.events, 0);
  const range = detail.event_counts_range;
  return (
    <SectionCard
      title="Events by source"
      titleId="source-counts-title"
      icon={BellRing}
      description={
        <>
          <span className="text-fg-2 tabular-nums">{formatCount(total)}</span> events stored, {windowLabel(range, now)} (since{" "}
          {formatUtcShort(range.since)} UTC)
        </>
      }
      className={className}
    >
      {rows.length === 0 ? (
        <EmptyState>
          {detail.asset.asset_type === "kubernetes_node"
            ? "No event carries this node's own id in the window. The cluster's audit, container-log and inventory events are stored under the cluster."
            : "No event from this asset was stored in this window."}
        </EmptyState>
      ) : (
        <ul className="grid gap-1" aria-label="Events by source type">
          {rows.map((row) => (
            <li key={row.source_type} className="grid grid-cols-[minmax(0,11rem)_minmax(0,1fr)_auto] items-center gap-x-4 py-1.5 sm:grid-cols-[minmax(0,13rem)_minmax(0,1fr)_4.5rem_5.5rem]">
              <span className="min-w-0 font-mono text-xs text-fg-2">
                <UntrustedText value={row.source_type} oneLine mono />
              </span>
              <span aria-hidden="true" className="h-1.5 rounded-full bg-hairline">
                {row.events > 0 ? (
                  <span
                    className="block h-full rounded-full bg-[linear-gradient(90deg,color-mix(in_oklab,var(--xq-brand),transparent_45%),var(--xq-brand))]"
                    style={{ width: `${Math.max(2, (row.events / max) * 100)}%` }}
                  />
                ) : null}
              </span>
              <span className={cn("text-right text-sm tabular-nums", row.events > 0 ? "font-medium text-foreground" : "text-muted-foreground")}>
                {formatCount(row.events)}
              </span>
              <span className="hidden text-right text-xs text-muted-foreground sm:block">
                {row.last_event_at ? (
                  <RelativeTime value={row.last_event_at} now={now} className="text-muted-foreground" />
                ) : row.declared ? (
                  <Hint content="Declared by this asset's collector; no event of this source was stored in the window.">
                    <span>silent</span>
                  </Hint>
                ) : (
                  DASH
                )}
              </span>
            </li>
          ))}
        </ul>
      )}
    </SectionCard>
  );
}

/** Inventory items reported by the asset's collectors (counts per item type). */
export function InventoryCard({ detail, now, className }: { detail: AssetDetailResponse; now: string; className?: string }) {
  const rows = [...detail.inventory].sort((a, b) => b.items - a.items || a.item_type.localeCompare(b.item_type));
  const newest = rows.reduce<string | null>(
    (latest, r) => (r.last_observed_at && (!latest || Date.parse(r.last_observed_at) > Date.parse(latest)) ? r.last_observed_at : latest),
    null,
  );
  return (
    <SectionCard
      title="Inventory"
      titleId="inventory-title"
      icon={ListTree}
      description={newest ? <>Last snapshot {formatRelative(newest, now)}</> : "As last reported by the collectors"}
      className={className}
    >
      {rows.length === 0 ? (
        <EmptyState>No inventory snapshot has been reported for this asset.</EmptyState>
      ) : (
        <dl className="divide-y divide-hairline-soft">
          {rows.map((row) => (
            <div key={row.item_type} className="flex min-h-9 items-center justify-between gap-4 py-1.5">
              <dt className="min-w-0 truncate text-sm text-fg-2">{itemLabel(row.item_type)}</dt>
              <dd className="text-sm font-medium text-foreground tabular-nums">{formatCount(row.items)}</dd>
            </div>
          ))}
        </dl>
      )}
    </SectionCard>
  );
}

function attributeValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** The asset's reported attributes (telemetry: plain text, full values on hover). */
export function AttributesCard({
  detail,
  className,
  columns: columnCount = 3,
}: {
  detail: AssetDetailResponse;
  className?: string;
  /** 3: full-width card (balanced columns); 1: a rail card. */
  columns?: 1 | 3;
}) {
  const entries = Object.entries(detail.asset.attributes ?? {}).slice(0, 18);
  const total = Object.keys(detail.asset.attributes ?? {}).length;
  // Column-major, so the list reads top to bottom, then left to right.
  const perColumn = Math.ceil(entries.length / columnCount);
  const columns = Array.from({ length: columnCount }, (_, c) => entries.slice(c * perColumn, (c + 1) * perColumn));
  return (
    <SectionCard
      title="Attributes"
      titleId="asset-attributes-title"
      icon={Tags}
      description="As reported by the collector"
      meta={total > entries.length ? <span>{formatCount(entries.length)} of {formatCount(total)}</span> : null}
      className={className}
    >
      {entries.length === 0 ? (
        <EmptyState>The collector reported no attributes for this asset.</EmptyState>
      ) : (
        <div className={cn("grid gap-x-10", columnCount === 3 && "md:grid-cols-3")}>
          {columns.map((column, c) =>
            column.length === 0 ? null : (
              <KeyValueList
                key={c}
                className={c > 0 ? "border-t border-hairline-soft md:border-t-0" : undefined}
                rows={column.map(([key, value]) => {
                  const text = attributeValue(value);
                  return {
                    label: keyLabel(key),
                    value:
                      text === "" ? (
                        <span className="text-muted-foreground">{DASH}</span>
                      ) : (
                        <span className="flex min-w-0 justify-end">
                          <UntrustedText value={text} oneLine className="max-w-56 text-right" />
                        </span>
                      ),
                  };
                })}
              />
            ),
          )}
        </div>
      )}
    </SectionCard>
  );
}

/** The asset's alerts of the last 30 days (capped by the API at 20), newest first. */
export function RecentAlertsCard({
  detail,
  now,
  alertsHref,
  className,
}: {
  detail: AssetDetailResponse;
  now: string;
  alertsHref: string;
  className?: string;
}) {
  const alerts = detail.recent_alerts;
  return (
    <SectionCard
      title="Recent alerts"
      titleId="asset-alerts-title"
      icon={ShieldAlert}
      description={`Last 30 days · ${formatCount(detail.asset.open_alerts)} open`}
      action={
        <Link href={alertsHref} className="group/link">
          <CardLink>All alerts</CardLink>
        </Link>
      }
      flush
      className={className}
      footer={
        alerts.length > RECENT_ALERT_ROWS ? (
          <span>
            Showing the {formatCount(RECENT_ALERT_ROWS)} newest of {formatCount(alerts.length)}
            {alerts.length >= 20 ? " (the API returns at most 20 here)" : ""}.
          </span>
        ) : undefined
      }
    >
      {alerts.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No detection has fired for this asset in the last 30 days.</EmptyState>
        </div>
      ) : (
        <AlertList alerts={alerts} now={now} label="Recent alerts of this asset" limit={RECENT_ALERT_ROWS} />
      )}
    </SectionCard>
  );
}

/** Service coverage of the asset (rail): monitored share, the five states and the kinds. */
export function ServiceCoverageCard({
  detail,
  servicesHref,
  servicesLabel,
  className,
}: {
  detail: AssetDetailResponse;
  servicesHref: string;
  servicesLabel: string;
  className?: string;
}) {
  const summary = detail.services_summary;
  const node = detail.asset.asset_type === "kubernetes_node";
  return (
    <SectionCard
      title="Service coverage"
      titleId="asset-service-coverage-title"
      icon={Layers}
      description={summary?.reported ? "Discovered services and their telemetry adapters" : undefined}
      action={
        <Link href={servicesHref} className="group/link">
          <CardLink>{servicesLabel}</CardLink>
        </Link>
      }
      className={className}
    >
      {!summary ? (
        <EmptyState>This API version does not report service coverage.</EmptyState>
      ) : !summary.reported ? (
        <EmptyState>
          {node
            ? "No service is reported for the node itself (kubelet and the container runtime are not discovered). The cluster's workloads with Pods on this node are listed on the next tab."
            : "Service discovery has not reported for this asset yet, so its services are unknown, not absent."}
        </EmptyState>
      ) : (
        <div className="grid gap-4">
          <div>
            <p className="flex items-baseline gap-1.5">
              <span className="text-3xl leading-none font-semibold tracking-tight text-foreground tabular-nums">
                {formatCount(summary.coverage.monitored)}
              </span>
              <span className="text-base text-muted-foreground tabular-nums">/ {formatCount(summary.coverage.total)} monitored</span>
            </p>
            <SplitBar
              className="mt-3 h-2"
              label={`Service coverage: ${partsInWords(coverageParts(summary.coverage))}`}
              parts={coverageParts(summary.coverage)}
            />
          </div>
          <ul className="grid gap-0.5">
            {COVERAGE_PARTS.map((p) => {
              const value = summary.coverage[p.key];
              return (
                <li key={p.key} className="flex h-7 items-center gap-2.5 text-sm">
                  <span
                    aria-hidden="true"
                    className={cn(
                      "size-2 flex-none rounded-full",
                      p.key === "planned" ? "ring-1 ring-cov-planned ring-inset" : p.className,
                    )}
                  />
                  <span className="text-fg-2 first-letter:uppercase">{p.label}</span>
                  <span aria-hidden="true" className="mx-1 h-px min-w-4 flex-1 border-b border-dashed border-hairline" />
                  <span className={cn("tabular-nums", value > 0 ? "font-medium text-foreground" : "text-muted-foreground")}>
                    {formatCount(value)}
                  </span>
                </li>
              );
            })}
          </ul>
          {summary.by_kind.length > 1 ? (
            <div className="grid gap-2 border-t border-hairline-soft pt-3">
              {summary.by_kind.map((k) => (
                <div key={k.service_kind} className="flex items-center justify-between gap-3 text-xs">
                  <span className="text-fg-2">
                    {SERVICE_GROUPS.find((g) => g.kind === k.service_kind)?.title ?? serviceKindLabel(k.service_kind)}
                  </span>
                  <span className="text-muted-foreground tabular-nums">
                    <span className="text-fg-2">{formatCount(k.coverage.monitored)}</span> / {formatCount(k.coverage.total)} monitored
                  </span>
                </div>
              ))}
            </div>
          ) : null}
          {summary.removed > 0 || summary.truncated ? (
            <p className="text-xs text-muted-foreground">
              {summary.removed > 0
                ? `${formatCount(summary.removed)} removed service${summary.removed === 1 ? " is" : "s are"} not counted. `
                : ""}
              {summary.truncated ? "More service records exist than the API evaluated." : ""}
            </p>
          ) : null}
        </div>
      )}
    </SectionCard>
  );
}

/** The nodes of a cluster: each is an asset of its own (Kubernetes level 2). */
export function NodesCard({ nodes, now, className }: { nodes: AssetListItem[]; now: string; className?: string }) {
  return (
    <SectionCard
      title="Nodes"
      titleId="child-assets-title"
      icon={Network}
      description="Each node is an asset of its own; its Pods are instances of the cluster's workloads"
      flush
      className={className}
    >
      {nodes.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No node of this cluster has reported an inventory yet.</EmptyState>
        </div>
      ) : (
        <Table aria-label="Nodes of this cluster">
          <TableHeader>
            <TableRow>
              <TableHead>Node</TableHead>
              <TableHead>Health</TableHead>
              <TableHead className="hidden md:table-cell">Collectors</TableHead>
              <TableHead className="text-right">Last inventory</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {nodes.map((node) => {
              const health = assetHealth(node);
              return (
                <TableRow key={node.asset_id}>
                  <TableCell className="max-w-0 min-w-56">
                    <Link
                      href={assetHref(node.asset_id)}
                      className="flex min-w-0 items-center gap-2.5 font-medium text-foreground underline-offset-2 hover:underline"
                    >
                      <Boxes className="size-3.5 flex-none text-muted-foreground" aria-hidden="true" />
                      <span className="min-w-0 truncate">
                        <UntrustedText value={node.name} plain limit={80} />
                      </span>
                    </Link>
                    <div className="mt-0.5 truncate pl-6 font-mono text-xs text-muted-foreground">
                      <UntrustedText value={node.asset_id} plain limit={96} />
                    </div>
                  </TableCell>
                  <TableCell>
                    <StatusDot tone={health.tone} label={health.label} className="text-xs" />
                  </TableCell>
                  <TableCell className="hidden text-xs text-fg-2 md:table-cell">{collectorsSummary(node)}</TableCell>
                  <TableCell className="text-right">
                    <RelativeTime value={node.last_seen} now={now} className="text-xs" />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  );
}

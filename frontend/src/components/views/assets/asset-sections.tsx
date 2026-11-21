import Link from "next/link";

import { KeyValueList } from "@/components/console/key-values";
import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import { CoverageStatusDot } from "@/components/console/status-badge";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AssetDetailResponse, AssetListItem } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount, formatUtcShort, humanize } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";

/** Events stored per source type for the asset, over the API's stated window. */
export function SourceCountsPanel({ detail, now }: { detail: AssetDetailResponse; now: string }) {
  const range = detail.event_counts_range;
  const rows = [...detail.event_counts].sort((a, b) => b.events - a.events);
  return (
    <Panel
      title="Events by source"
      titleId="source-counts-title"
      meta={
        <span>
          {formatUtcShort(range.since)} to {formatUtcShort(range.until)} UTC
        </span>
      }
    >
      {rows.length === 0 ? (
        <EmptyState>No event from this asset was stored in this window.</EmptyState>
      ) : (
        <Table aria-label="Events by source type">
          <TableHeader>
            <TableRow>
              <TableHead>Source type</TableHead>
              <TableHead className="text-right">Events</TableHead>
              <TableHead className="text-right">Last event</TableHead>
              <TableHead className="hidden text-right sm:table-cell">Last ingested</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((row) => (
              <TableRow key={row.source_type}>
                <TableCell className="font-mono text-xs text-ink">
                  <UntrustedText value={row.source_type} limit={48} />
                </TableCell>
                <TableCell className="text-right font-mono text-xs text-ink">{formatCount(row.events)}</TableCell>
                <TableCell className="text-right">
                  <RelativeTime value={row.last_event_at} now={now} className="text-xs" />
                </TableCell>
                <TableCell className="hidden text-right sm:table-cell">
                  <RelativeTime value={row.last_ingested_at} now={now} className="text-xs" />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}

/** Inventory items reported by the asset's collectors (counts per item type). */
export function InventoryPanel({ detail, now }: { detail: AssetDetailResponse; now: string }) {
  const rows = [...detail.inventory].sort((a, b) => a.item_type.localeCompare(b.item_type));
  const attributes = Object.entries(detail.asset.attributes ?? {}).slice(0, 12);
  return (
    <Panel title="Inventory" titleId="inventory-title" meta={<span>As last reported by the collectors</span>}>
      {rows.length === 0 ? (
        <EmptyState>No inventory snapshot has been reported for this asset.</EmptyState>
      ) : (
        <ul className="divide-y divide-rule">
          {rows.map((row) => (
            <li key={row.item_type} className="flex min-h-9 items-center justify-between gap-4 py-1">
              <span className="text-sm text-ink-2 capitalize">{humanize(row.item_type)}</span>
              <span className="flex items-baseline gap-3">
                <span className="font-mono text-sm text-ink">{formatCount(row.items)}</span>
                <RelativeTime value={row.last_observed_at} now={now} className="w-20 text-right text-xs" />
              </span>
            </li>
          ))}
        </ul>
      )}
      {attributes.length > 0 ? (
        <div className="mt-4">
          <h3 className="mb-1 text-xs text-muted-foreground">Asset attributes</h3>
          <KeyValueList
            rows={attributes.map(([key, value]) => ({
              label: humanize(key),
              value: (
                <UntrustedText
                  value={typeof value === "string" ? value : JSON.stringify(value)}
                  limit={96}
                  mono={typeof value !== "string"}
                />
              ),
            }))}
          />
        </div>
      ) : null}
    </Panel>
  );
}

/** Asset identity: ids, environment, ownership and first/last seen. */
export function AssetFactsPanel({ detail }: { detail: AssetDetailResponse }) {
  const a = detail.asset;
  return (
    <Panel title="Asset" titleId="asset-facts-title">
      <KeyValueList
        rows={[
          { label: "Asset id", value: <UntrustedText value={a.asset_id} limit={96} mono /> },
          { label: "Type", value: assetTypeLabel(a.asset_type) },
          { label: "Environment", value: <UntrustedText value={a.environment} limit={32} /> },
          { label: "Criticality", value: <UntrustedText value={a.criticality} limit={32} /> },
          { label: "Owner", value: <UntrustedText value={a.owner} limit={64} /> },
          { label: "First seen", value: <Timestamp value={a.first_seen} /> },
          { label: "Last seen", value: <Timestamp value={a.last_seen} /> },
          { label: "Observed by", value: <UntrustedText value={a.observed_by} limit={64} mono /> },
        ]}
      />
    </Panel>
  );
}

/** Child assets (a cluster's nodes). */
export function ChildAssetsPanel({ nodes, now }: { nodes: AssetListItem[]; now: string }) {
  return (
    <Panel
      title="Nodes"
      titleId="child-assets-title"
      meta={<span>Each node is an asset of its own; its Pods are instances of the cluster&apos;s workloads</span>}
    >
      {nodes.length === 0 ? (
        <EmptyState>No node of this cluster has reported an inventory yet.</EmptyState>
      ) : (
        <ul className="divide-y divide-rule">
          {nodes.map((child) => (
            <li key={child.asset_id} className="flex items-center justify-between gap-4 py-2">
              <div className="min-w-0">
                <Link href={assetHref(child.asset_id)} className="text-ink hover:underline">
                  <UntrustedText value={child.display_name ?? child.name} limit={64} />
                </Link>
                <div className="font-mono text-xs text-muted-foreground">
                  <UntrustedText value={child.asset_id} limit={80} />
                </div>
              </div>
              <div className="flex flex-none flex-col items-end gap-0.5 text-xs">
                <CoverageStatusDot status={child.coverage_status} />
                <RelativeTime value={child.last_event_at} now={now} className="text-xs" />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

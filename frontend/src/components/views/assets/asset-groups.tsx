import { cn } from "cn";
import Link from "next/link";

import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import { CoverageStatusDot } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AssetListItem } from "@/lib/api/schemas";
import { collectorsSummary } from "@/lib/assets";
import { assetTypeLabel, formatCount } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";

/** The four monitored asset classes, in the order of the ExtorQ mark's arcs. */
export const ASSET_CLASSES: { key: string; title: string; types: string[]; empty: string }[] = [
  { key: "macos", title: "macOS hosts", types: ["macos_host"], empty: "No macOS host has reported an inventory yet." },
  { key: "linux", title: "Linux VMs", types: ["linux_host"], empty: "No Linux host has reported an inventory yet." },
  {
    key: "kubernetes",
    title: "Kubernetes",
    types: ["kubernetes_cluster", "kubernetes_node", "kubernetes_namespace", "kubernetes_workload"],
    empty: "No Kubernetes cluster or node has reported an inventory yet.",
  },
  {
    key: "github",
    title: "GitHub",
    types: ["github_repository", "github_account"],
    empty: "No GitHub repository has reported an inventory yet.",
  },
];

export function classOf(assetType: string): string {
  return ASSET_CLASSES.find((c) => c.types.includes(assetType))?.key ?? "other";
}

interface Row {
  asset: AssetListItem;
  depth: number;
}

/** Clusters first, each followed by its nodes (and other children); orphans keep their place. */
function hierarchy(assets: AssetListItem[]): Row[] {
  const ids = new Set(assets.map((a) => a.asset_id));
  const children = new Map<string, AssetListItem[]>();
  const roots: AssetListItem[] = [];
  for (const asset of assets) {
    const parent = asset.parent_asset_id;
    if (parent && parent !== asset.asset_id && ids.has(parent)) {
      const list = children.get(parent) ?? [];
      list.push(asset);
      children.set(parent, list);
    } else {
      roots.push(asset);
    }
  }
  const byName = (a: AssetListItem, b: AssetListItem) => a.asset_id.localeCompare(b.asset_id);
  const rows: Row[] = [];
  const visit = (asset: AssetListItem, depth: number) => {
    rows.push({ asset, depth });
    if (depth > 3) return;
    for (const child of (children.get(asset.asset_id) ?? []).sort(byName)) visit(child, depth + 1);
  };
  for (const root of roots.sort(byName)) visit(root, 0);
  return rows;
}

function collectorsText(asset: AssetListItem): string {
  return collectorsSummary(asset);
}

/** One asset as a two-line row: name and coverage, then id, collectors, recency and alerts. */
function AssetRow({ row, now }: { row: Row; now: string }) {
  const { asset, depth } = row;
  const name = asset.display_name ?? asset.name;
  return (
    <li className={cn("py-2.5", depth > 0 && "border-l border-border pl-4")} style={depth > 0 ? { marginLeft: `${(depth - 1) * 16}px` } : undefined}>
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <Link href={assetHref(asset.asset_id)} className="font-medium text-ink underline-offset-2 hover:underline">
              <UntrustedText value={name} limit={64} />
            </Link>
            <span className="text-xs text-muted-foreground">{assetTypeLabel(asset.asset_type)}</span>
          </div>
          <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-muted-foreground">
            <span className="font-mono text-ink-2">
              <UntrustedText value={asset.asset_id} limit={72} />
            </span>
            <span aria-hidden="true">·</span>
            <span className={asset.collectors_stale > 0 ? "text-warn" : undefined}>{collectorsText(asset)}</span>
            <span aria-hidden="true">·</span>
            <span>
              last event <RelativeTime value={asset.last_event_at} now={now} className="text-xs" />
            </span>
          </div>
        </div>
        <div className="flex flex-none flex-col items-end gap-1 text-xs">
          <CoverageStatusDot status={asset.coverage_status} />
          <span className={asset.open_alerts > 0 ? "text-ink" : "text-muted-foreground"}>
            <span className="font-mono">{formatCount(asset.open_alerts)}</span> open alert{asset.open_alerts === 1 ? "" : "s"}
          </span>
        </div>
      </div>
    </li>
  );
}

export function AssetClassPanel({
  title,
  titleId,
  assets,
  empty,
  now,
}: {
  title: string;
  titleId: string;
  assets: AssetListItem[];
  empty: string;
  now: string;
}) {
  const rows = hierarchy(assets);
  const attention = assets.filter((a) => a.coverage_status !== "ok").length;
  return (
    <Panel
      title={title}
      titleId={titleId}
      meta={
        assets.length > 0 ? (
          <span>
            {formatCount(assets.length)} asset{assets.length === 1 ? "" : "s"}
            {attention > 0 ? ` · ${formatCount(attention)} need attention` : ""}
          </span>
        ) : null
      }
    >
      {rows.length === 0 ? (
        <EmptyState>{empty}</EmptyState>
      ) : (
        <ul className="divide-y divide-rule">
          {rows.map((row) => (
            <AssetRow key={row.asset.asset_id} row={row} now={now} />
          ))}
        </ul>
      )}
    </Panel>
  );
}

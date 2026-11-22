import { formatCount } from "@/lib/format";

interface CollectorCounts {
  asset_type: string;
  collectors_total: number;
  collectors_stale: number;
  /** Collectors reporting for an ancestor asset (API >= session 3; older APIs omit it). */
  collectors_inherited?: number;
}

/** Who the inherited collectors belong to, in words. */
function ancestorWord(assetType: string): string {
  return assetType === "kubernetes_node" ? "the cluster" : "the parent asset";
}

/**
 * "3 of 4 collectors fresh", plus where they report when they cover the asset through an
 * ancestor ("via the cluster" for a Kubernetes node). Never claims a collector of its own
 * that the asset does not have.
 */
export function collectorsSummary(asset: CollectorCounts): string {
  const total = asset.collectors_total;
  if (total === 0) return "no collector reporting";
  const fresh = total - asset.collectors_stale;
  const base = `${formatCount(fresh)} of ${formatCount(total)} collector${total === 1 ? "" : "s"} fresh`;
  const inherited = asset.collectors_inherited ?? 0;
  if (inherited <= 0) return base;
  if (inherited >= total) return `${base} (via ${ancestorWord(asset.asset_type)})`;
  return `${base} (${formatCount(inherited)} via ${ancestorWord(asset.asset_type)})`;
}

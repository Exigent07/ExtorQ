import { Archive, Info } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { PageHeader } from "@/components/console/page-header";
import { ErrorState, Notice } from "@/components/console/states";
import { AssetClassGroup } from "@/components/views/assets/asset-groups";
import { ASSET_CLASSES, type AssetClass, assetsFinding, classOf, sortAssets } from "@/components/views/assets/model";
import type { ApiResult } from "@/lib/api/result";
import type { AssetDetailResponse, AssetListItem } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { retiredHiddenText } from "@/lib/lifecycle";
import { getAsset, listAssets } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";
import { listAssetsOnce } from "@/lib/server/shell";

export const metadata: Metadata = { title: "Assets" };

/**
 * Asset details (findings and service summaries) are read for at most this many monitored
 * assets per page view: each detail costs about a dozen queries of the API's shared ClickHouse
 * quota. The lab has 7; beyond the cap a card says its figures were not loaded.
 */
const MAX_DETAILS = 16;

const OTHER: AssetClass = {
  key: "other",
  title: "Other assets",
  types: [],
  contextTypes: [],
  empty: "",
};

const ASSET_NOUN = { one: "asset", many: "assets" };

/** A quiet in-text link for notices (show / hide retired assets). */
function NoticeLink({ href, children }: { href: string; children: string }) {
  return (
    <Link href={href} className="font-medium text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
      {children}
    </Link>
  );
}

/**
 * Assets: the monitored asset classes (macOS hosts, Linux VMs, Kubernetes, GitHub) with one
 * card per asset. Owner accounts are context, listed apart. Retired assets (no collector reports
 * and unobserved for the retirement window) are left out by the API unless `?retired=1`; the
 * page says how many and offers the toggle, so nothing disappears silently.
 */
export default async function AssetsPage({ searchParams }: PageProps<"/assets">) {
  const session = await requireSession();
  const query = await searchParams;
  const showRetired = (Array.isArray(query.retired) ? query.retired[0] : query.retired) === "1";
  // The default list is shared with the shell's palette (one API read per page view).
  const result = showRetired ? await listAssets(session, { includeRetired: true }) : await listAssetsOnce(session);

  if (!result.ok) {
    return (
      <>
        <PageHeader title="Assets" subtitle="Monitored hosts, clusters and repositories" />
        <ErrorState what="the asset inventory" error={result.error} />
      </>
    );
  }

  const assets = result.data.items;
  const now = result.receivedAt;
  const groups = [...ASSET_CLASSES, OTHER].map((cls) => {
    const members = assets.filter((a) => classOf(a.asset_type) === cls.key);
    return {
      cls,
      monitored: sortAssets(members.filter((a) => !cls.contextTypes.includes(a.asset_type))),
      context: sortAssets(members.filter((a) => cls.contextTypes.includes(a.asset_type))),
    };
  });

  // Details for the monitored assets, in display order, up to the cap; requested in parallel.
  const wanted: AssetListItem[] = groups.flatMap((g) => g.monitored).slice(0, MAX_DETAILS);
  const fetched = await Promise.all(wanted.map((a) => getAsset(session, a.asset_id)));
  const details = new Map<string, ApiResult<AssetDetailResponse>>(wanted.map((a, i) => [a.asset_id, fetched[i]!]));
  const monitoredTotal = groups.reduce((sum, g) => sum + g.monitored.length, 0);
  const retiredHidden = showRetired ? null : retiredHiddenText(result.data.retired_excluded, ASSET_NOUN);
  const retiredShown = assets.filter((a) => a.lifecycle_state === "retired").length;
  const staleCount = assets.filter((a) => a.lifecycle_state === "stale").length;

  return (
    <>
      <PageHeader title="Assets" subtitle={assetsFinding(assets)} freshness={result.receivedAt} />

      {retiredHidden || showRetired || staleCount > 0 ? (
        <Notice icon={Archive} className="mb-6">
          {staleCount > 0 ? (
            <>
              {formatCount(staleCount)} {staleCount === 1 ? "asset is" : "assets are"} stale (not observed recently,
              marked Stale); {staleCount === 1 ? "it counts" : "they count"} until retired after the retirement window
              without collector reports.{" "}
            </>
          ) : null}
          {showRetired ? (
            retiredShown === 0 ? (
              <>
                Retired assets are included: none is retired right now. <NoticeLink href="/assets">Hide retired</NoticeLink>
              </>
            ) : (
              <>
                Including {formatCount(retiredShown)} retired {retiredShown === 1 ? "asset" : "assets"} (marked Retired):
                kept, never deleted, and left out of coverage rollups. <NoticeLink href="/assets">Hide retired</NoticeLink>
              </>
            )
          ) : retiredHidden ? (
            <>
              {retiredHidden}: no collector reports for them and they were not observed within the retirement
              window. They are kept, never deleted. <NoticeLink href="/assets?retired=1">Show retired</NoticeLink>
            </>
          ) : null}
        </Notice>
      ) : null}

      {result.data.page.has_more || monitoredTotal > MAX_DETAILS ? (
        <div className="mb-6 grid gap-2">
          {result.data.page.has_more ? (
            <Notice tone="warn" icon={Info}>
              Showing the first {formatCount(assets.length)} assets of {formatCount(result.data.page.total ?? null)}; the
              list is capped by the API.
            </Notice>
          ) : null}
          {monitoredTotal > MAX_DETAILS ? (
            <Notice icon={Info}>
              Findings and service coverage are shown for the first {formatCount(MAX_DETAILS)} of{" "}
              {formatCount(monitoredTotal)} monitored assets; open an asset for its figures.
            </Notice>
          ) : null}
        </div>
      ) : null}

      <div className="grid gap-x-6 gap-y-10 lg:grid-cols-2">
        {groups.map(({ cls, monitored, context }) =>
          cls.key === "other" && monitored.length === 0 && context.length === 0 ? null : (
            <AssetClassGroup
              key={cls.key}
              cls={cls}
              assets={monitored}
              context={context}
              details={details}
              now={now}
            />
          ),
        )}
      </div>
    </>
  );
}

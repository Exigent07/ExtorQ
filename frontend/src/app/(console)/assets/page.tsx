import { Archive, Info } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { PageHeader } from "@/components/console/page-header";
import { ErrorState, Notice } from "@/components/console/states";
import { AssetClassGroup } from "@/components/views/assets/asset-groups";
import {
  ASSET_CLASSES,
  type AssetClass,
  assetsFinding,
  classOf,
  isContextAsset,
  sortAssets,
} from "@/components/views/assets/model";
import { RETIRED_SECTION_ID, RetiredAssetsSection } from "@/components/views/assets/retired-assets";
import type { ApiResult } from "@/lib/api/result";
import type { AssetDetailResponse, AssetListItem } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
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

/** A quiet in-text link for notices. */
function NoticeLink({ href, children }: { href: string; children: string }) {
  return (
    <Link href={href} className="font-medium text-fg-2 underline-offset-2 hover:text-foreground hover:underline">
      {children}
    </Link>
  );
}

/**
 * Assets: the monitored asset classes (macOS hosts, Linux VMs, Kubernetes, GitHub) with one
 * card per asset; owner accounts are context, listed apart. Retired assets (no collector reports
 * and unobserved for the retirement window) are left out of the API's default list: the page
 * counts them in its subtitle and lists them in a collapsed, muted section at the end (open
 * with `?retired=1`), so nothing disappears silently. Stale assets still count and say so.
 */
export default async function AssetsPage({ searchParams }: PageProps<"/assets">) {
  const session = await requireSession();
  const query = await searchParams;
  const openRetired = (Array.isArray(query.retired) ? query.retired[0] : query.retired) === "1";
  // The default list is shared with the shell's palette (one API read per page view).
  const result = await listAssetsOnce(session);

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
  const retiredCount = result.data.retired_excluded;
  const groups = [...ASSET_CLASSES, OTHER].map((cls) => {
    const members = assets.filter((a) => classOf(a.asset_type) === cls.key);
    return {
      cls,
      monitored: sortAssets(members.filter((a) => !cls.contextTypes.includes(a.asset_type))),
      context: sortAssets(members.filter((a) => cls.contextTypes.includes(a.asset_type))),
    };
  });

  // Details for the monitored assets, in display order, up to the cap; requested in parallel
  // with the retired list (read only when the API left retired assets out).
  const wanted: AssetListItem[] = groups.flatMap((g) => g.monitored).slice(0, MAX_DETAILS);
  const [fetched, retiredResult] = await Promise.all([
    Promise.all(wanted.map((a) => getAsset(session, a.asset_id))),
    retiredCount > 0 || openRetired ? listAssets(session, { includeRetired: true }) : Promise.resolve(null),
  ]);
  const details = new Map<string, ApiResult<AssetDetailResponse>>(wanted.map((a, i) => [a.asset_id, fetched[i]!]));
  const monitoredTotal = groups.reduce((sum, g) => sum + g.monitored.length, 0);
  const retired = retiredResult?.ok
    ? sortAssets(retiredResult.data.items.filter((a) => a.lifecycle_state === "retired"))
    : null;
  const retiredShown = Math.max(retiredCount, retired?.length ?? 0);
  const staleCount = assets.filter((a) => a.lifecycle_state === "stale").length;
  const staleContext = assets.filter((a) => a.lifecycle_state === "stale" && isContextAsset(a.asset_type)).length;
  const staleMonitored = staleCount - staleContext;

  return (
    <>
      <PageHeader title="Assets" subtitle={assetsFinding(assets, retiredShown)} freshness={result.receivedAt} />

      {staleCount > 0 || retiredShown > 0 || openRetired ? (
        <Notice icon={Archive} className="mb-6">
          {staleCount > 0 ? (
            <>
              {staleMonitored > 0
                ? `${formatCount(staleMonitored)} monitored asset${staleMonitored === 1 ? "" : "s"}${staleContext > 0 ? ` and ${formatCount(staleContext)} owner account${staleContext === 1 ? "" : "s"}` : ""}`
                : `${formatCount(staleContext)} owner account${staleContext === 1 ? "" : "s"}`}{" "}
              {staleCount === 1 ? "is" : "are"} stale: not observed recently and marked Stale.{" "}
              {staleCount === 1 ? "It still counts" : "They still count"} until retired (no collector report for the retirement
              window).{" "}
            </>
          ) : null}
          {retiredShown > 0 ? (
            <>
              {formatCount(retiredShown)} retired {retiredShown === 1 ? "asset is" : "assets are"} kept and listed apart, out of
              the coverage figures. <NoticeLink href={`/assets?retired=1#${RETIRED_SECTION_ID}`}>Show retired</NoticeLink>
            </>
          ) : openRetired ? (
            <>No asset is retired right now.</>
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

      {retiredShown > 0 ? (
        <RetiredAssetsSection
          count={retiredShown}
          assets={retired}
          error={retiredResult && !retiredResult.ok ? retiredResult.error : null}
          defaultOpen={openRetired}
          now={now}
        />
      ) : null}
    </>
  );
}

import type { Metadata } from "next";

import { Freshness } from "@/components/console/freshness";
import { PageHeader } from "@/components/console/page-header";
import { ErrorState } from "@/components/console/states";
import { AssetClassPanel, ASSET_CLASSES, classOf } from "@/components/views/assets/asset-groups";
import type { AssetListItem } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { listAssets } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "Assets" };

function finding(assets: AssetListItem[]): string {
  if (assets.length === 0) return "No asset has reported an inventory yet";
  const by = (status: string) => assets.filter((a) => a.coverage_status === status).length;
  const parts = [`${formatCount(assets.length)} asset${assets.length === 1 ? "" : "s"} known`];
  const healthy = by("ok");
  parts.push(`${formatCount(healthy)} healthy`);
  for (const status of ["degraded", "stale", "missing"] as const) {
    const n = by(status);
    if (n > 0) parts.push(`${formatCount(n)} ${status === "missing" ? "without telemetry" : status}`);
  }
  const silentClasses = ASSET_CLASSES.filter((c) => !assets.some((a) => c.types.includes(a.asset_type)));
  if (silentClasses.length > 0) {
    parts.push(`no ${silentClasses.map((c) => c.title).join(" or ")} asset reported yet`);
  }
  return parts.join(" · ");
}

export default async function AssetsPage() {
  const session = await requireSession();
  const result = await listAssets(session);

  if (!result.ok) {
    return (
      <>
        <PageHeader title="Assets" />
        <ErrorState what="the asset inventory" error={result.error} />
      </>
    );
  }

  const assets = result.data.items;
  const now = result.receivedAt;
  const other = assets.filter((a) => classOf(a.asset_type) === "other");

  return (
    <>
      <PageHeader
        title="Assets"
        finding={finding(assets)}
        actions={<Freshness at={result.receivedAt} />}
      />
      {result.data.page.has_more ? (
        <p className="mb-4 text-xs text-warn">
          Showing the first {formatCount(assets.length)} assets of {formatCount(result.data.page.total ?? null)}; the
          list is capped by the API.
        </p>
      ) : null}
      <div className="grid items-start gap-6 xl:grid-cols-2">
        {ASSET_CLASSES.map((c) => (
          <AssetClassPanel
            key={c.key}
            title={c.title}
            titleId={`class-${c.key}`}
            assets={assets.filter((a) => c.types.includes(a.asset_type))}
            empty={c.empty}
            now={now}
          />
        ))}
        {other.length > 0 ? (
          <AssetClassPanel title="Other assets" titleId="class-other" assets={other} empty="" now={now} />
        ) : null}
      </div>
    </>
  );
}

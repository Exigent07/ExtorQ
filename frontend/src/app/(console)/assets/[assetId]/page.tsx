import type { Metadata } from "next";

import { Freshness } from "@/components/console/freshness";
import { MetricStrip } from "@/components/console/key-values";
import { LinkTabs } from "@/components/console/link-tabs";
import { PageHeader } from "@/components/console/page-header";
import { Panel } from "@/components/console/panel";
import { EmptyState, ErrorState } from "@/components/console/states";
import { CoverageStatusDot, StaleBadge } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { AlertRows } from "@/components/views/alerts/alert-rows";
import {
  AssetFactsPanel,
  ChildAssetsPanel,
  InventoryPanel,
  SourceCountsPanel,
} from "@/components/views/assets/asset-sections";
import { CollectorTable } from "@/components/views/assets/collector-table";
import { EventsTable } from "@/components/views/events/events-table";
import { FindingsTable } from "@/components/views/findings/findings-table";
import { LifecycleNotice } from "@/components/views/overview/posture-panel";
import { AssetServices } from "@/components/views/services/asset-services";
import type { AssetDetailResponse } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount, formatRelative, formatUtcShort } from "@/lib/format";
import { assetHref, parseAssetIdSegment } from "@/lib/security/ids";
import { getAsset, listAssets, listAssetServices, listEvents, listFindings } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "Asset" };

const TABS = ["overview", "services", "findings", "events"] as const;
type Tab = (typeof TABS)[number];

function parseTab(raw: string | string[] | undefined): Tab {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return (TABS as readonly string[]).includes(value ?? "") ? (value as Tab) : "overview";
}

function tabLabel(tab: Tab, assetType: string): string {
  if (tab === "services") return assetType.startsWith("kubernetes_cluster") ? "Workloads and Services" : "Services";
  return { overview: "Overview", findings: "Findings", events: "Events" }[tab];
}

function finding(detail: AssetDetailResponse, now: string): string {
  const a = detail.asset;
  const parts: string[] = [];
  if (a.collectors_total === 0) parts.push("No collector reports for this asset");
  else {
    const fresh = a.collectors_total - a.collectors_stale;
    parts.push(`${formatCount(fresh)} of ${formatCount(a.collectors_total)} collectors fresh`);
  }
  parts.push(a.last_event_at ? `last event ${formatRelative(a.last_event_at, now)}` : "no event stored");
  parts.push(`${formatCount(a.open_alerts)} open alert${a.open_alerts === 1 ? "" : "s"}`);
  const f = detail.findings_summary;
  parts.push(
    `${formatCount(f.counts.total)} ${f.lifecycle_available ? "open" : "observed"} finding${f.counts.total === 1 ? "" : "s"}`,
  );
  return parts.join(" · ");
}

export default async function AssetPage({ params, searchParams }: PageProps<"/assets/[assetId]">) {
  const session = await requireSession();
  const [{ assetId: rawId }, query] = await Promise.all([params, searchParams]);
  const assetId = parseAssetIdSegment(rawId);
  const tab = parseTab(query.tab);
  const includeRemoved = query.removed === "1";

  if (!assetId) {
    return (
      <>
        <PageHeader title="Asset" crumbs={[{ label: "Assets", href: "/assets" }]} />
        <ErrorState what="this asset" error={{ kind: "not_found", message: "The asset id in the address is not valid.", requestId: "-" }} />
      </>
    );
  }

  const [detailResult, tabData] = await Promise.all([
    getAsset(session, assetId),
    tab === "services"
      ? listAssetServices(session, assetId, { includeRemoved }).then((r) => ({ tab: "services" as const, r }))
      : tab === "findings"
        ? listFindings(session, { assetId, limit: 200 }).then((r) => ({ tab: "findings" as const, r }))
        : tab === "events"
          ? listEvents(session, { assetId, limit: 50 }).then((r) => ({ tab: "events" as const, r }))
          : listAssets(session).then((r) => ({ tab: "overview" as const, r })),
  ]);
  // The asset list is fetched for the overview tab only to show each cluster node's coverage.

  if (!detailResult.ok) {
    return (
      <>
        <PageHeader title="Asset" crumbs={[{ label: "Assets", href: "/assets" }]} />
        <ErrorState what="this asset" error={detailResult.error} />
      </>
    );
  }

  const detail = detailResult.data;
  const asset = detail.asset;
  const now = detailResult.receivedAt;
  const base = assetHref(asset.asset_id);
  const name = asset.display_name ?? asset.name;
  const parentCrumb = asset.parent_asset_id
    ? [{ label: asset.parent_asset_id, href: assetHref(asset.parent_asset_id) }]
    : [];
  const fs = detail.findings_summary;

  return (
    <>
      <PageHeader
        title={<UntrustedText value={name} limit={80} />}
        crumbs={[{ label: "Assets", href: "/assets" }, ...parentCrumb]}
        titleMeta={
          <span className="flex items-center gap-3 text-sm text-muted-foreground">
            {assetTypeLabel(asset.asset_type)}
            <CoverageStatusDot status={asset.coverage_status} />
          </span>
        }
        finding={finding(detail, now)}
        actions={<Freshness at={detailResult.receivedAt} />}
      />

      <MetricStrip
        className="mb-6"
        items={[
          {
            label: "Collectors fresh",
            value: (
              <span className="font-mono">
                {formatCount(asset.collectors_total - asset.collectors_stale)}
                <span className="text-sm text-muted-foreground"> of {formatCount(asset.collectors_total)}</span>
              </span>
            ),
            sub: asset.collectors_stale > 0 ? <StaleBadge /> : undefined,
          },
          { label: "Last event", value: <RelativeTime value={asset.last_event_at} now={now} className="text-lg" /> },
          { label: "Open alerts", value: <span className="font-mono">{formatCount(asset.open_alerts)}</span> },
          {
            label: fs.lifecycle_available ? "Open findings" : "Observed findings",
            value: <span className="font-mono">{formatCount(fs.counts.total)}</span>,
            sub: `${formatCount(fs.counts.critical + fs.counts.high)} critical or high`,
          },
        ]}
      />

      <LinkTabs
        label="Asset views"
        active={tab}
        tabs={TABS.map((key) => ({
          key,
          label: tabLabel(key, asset.asset_type),
          href: key === "overview" ? base : `${base}?tab=${key}`,
          count:
            key === "services"
              ? detail.services_summary?.reported
                ? detail.services_summary.coverage.total
                : null
              : key === "findings"
                ? fs.counts.total
                : null,
        }))}
      />

      {tabData.tab === "overview" ? (
        <div className="grid gap-6">
          <Panel
            title="Telemetry sources"
            titleId="collectors-title"
            meta={<span>Collector health as last reported</span>}
            flush
            bodyClassName="px-5"
          >
            {detail.collectors.length === 0 ? (
              <EmptyState>No collector has reported health for this asset. Its telemetry coverage is unknown.</EmptyState>
            ) : (
              <CollectorTable collectors={detail.collectors} now={now} />
            )}
          </Panel>
          <div className="grid items-start gap-6 xl:grid-cols-2">
            <div className="grid min-w-0 gap-6">
              <SourceCountsPanel detail={detail} now={now} />
              <Panel
                title="Recent alerts"
                titleId="asset-alerts-title"
                meta={<span>{formatCount(asset.open_alerts)} open</span>}
              >
                {detail.recent_alerts.length === 0 ? (
                  <EmptyState>No detection has fired for this asset.</EmptyState>
                ) : (
                  <AlertRows alerts={detail.recent_alerts} now={now} showAsset={false} />
                )}
              </Panel>
            </div>
            <div className="grid min-w-0 gap-6">
              <InventoryPanel detail={detail} now={now} />
              <AssetFactsPanel detail={detail} />
            </div>
          </div>
          {asset.asset_type === "kubernetes_cluster" || detail.child_assets.length > 0 ? (
            tabData.r.ok ? (
              <ChildAssetsPanel
                nodes={tabData.r.data.items.filter(
                  (a) =>
                    a.parent_asset_id === asset.asset_id || detail.child_assets.some((c) => c.asset_id === a.asset_id),
                )}
                now={now}
              />
            ) : (
              <ErrorState what="the nodes of this cluster" error={tabData.r.error} />
            )
          ) : null}
        </div>
      ) : null}

      {tabData.tab === "services" ? (
        <AssetServices
          result={tabData.r}
          assetType={asset.asset_type}
          baseHref={base}
          includeRemoved={includeRemoved}
          now={now}
        />
      ) : null}

      {tabData.tab === "findings" ? (
        <Panel
          title="Vulnerabilities and misconfigurations"
          titleId="findings-title"
          meta={tabData.r.ok ? <span>Source: {tabData.r.data.source}</span> : null}
        >
          {!tabData.r.ok ? (
            <ErrorState what="the findings of this asset" error={tabData.r.error} />
          ) : (
            <>
              <LifecycleNotice summary={{ lifecycle_available: tabData.r.data.lifecycle_available, note: tabData.r.data.note }} />
              <div className="mt-3">
                {tabData.r.data.items.length === 0 ? (
                  <EmptyState>
                    No finding is stored for this asset. Findings appear after a scanner run covers it; an asset that was
                    never scanned also shows none.
                  </EmptyState>
                ) : (
                  <FindingsTable findings={tabData.r.data.items} now={now} />
                )}
              </div>
              {tabData.r.data.page.has_more ? (
                <p className="mt-3 text-xs text-warn">Showing the first {formatCount(tabData.r.data.items.length)} findings.</p>
              ) : null}
            </>
          )}
        </Panel>
      ) : null}

      {tabData.tab === "events" ? (
        <Panel
          title="Recent events"
          titleId="events-title"
          meta={
            tabData.r.ok ? (
              <span>
                Newest {formatCount(tabData.r.data.items.length)} between {formatUtcShort(tabData.r.data.range.since)} and{" "}
                {formatUtcShort(tabData.r.data.range.until)} UTC
              </span>
            ) : null
          }
        >
          {!tabData.r.ok ? (
            <ErrorState what="the events of this asset" error={tabData.r.error} />
          ) : tabData.r.data.items.length === 0 ? (
            <EmptyState>No event from this asset was stored in this window.</EmptyState>
          ) : (
            <EventsTable events={tabData.r.data.items} />
          )}
        </Panel>
      ) : null}
    </>
  );
}

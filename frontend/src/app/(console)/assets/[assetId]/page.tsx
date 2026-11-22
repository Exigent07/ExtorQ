import { ArrowRight } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { LinkTabs } from "@/components/console/link-tabs";
import { PageHeader } from "@/components/console/page-header";
import { ErrorState } from "@/components/console/states";
import { LifecycleBadge, StatusPill } from "@/components/console/status-badge";
import { Button } from "@/components/ui/button";
import { AssetEventsTab } from "@/components/views/assets/asset-events";
import { AssetFindingsTab } from "@/components/views/assets/asset-findings";
import { AssetHeaderCard, AssetTitle } from "@/components/views/assets/asset-header";
import {
  AssetKpis,
  AttributesCard,
  EventsBySourceCard,
  InventoryCard,
  NodesCard,
  RecentAlertsCard,
  ServiceCoverageCard,
} from "@/components/views/assets/asset-overview";
import { assetHealth } from "@/components/views/assets/model";
import { TelemetrySourcesCard } from "@/components/views/assets/telemetry-sources";
import { AssetServices } from "@/components/views/services/asset-services";
import type { AssetDetailResponse } from "@/lib/api/schemas";
import { collectorsSummary } from "@/lib/assets";
import { alertFiltersToSearch } from "@/lib/filters";
import { formatCount, formatRelative } from "@/lib/format";
import { assetHref, parseAssetIdSegment } from "@/lib/security/ids";
import { getAsset, listAssetServices, listEvents, listFindings } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";
import { listAssetsOnce } from "@/lib/server/shell";

export const metadata: Metadata = { title: "Asset" };

const TABS = ["overview", "services", "findings", "events"] as const;
type Tab = (typeof TABS)[number];

/** Findings and events read per tab view (the API's page maximum is 200). */
const FINDINGS_LIMIT = 200;
const EVENTS_LIMIT = 100;

function parseTab(raw: string | string[] | undefined): Tab {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return (TABS as readonly string[]).includes(value ?? "") ? (value as Tab) : "overview";
}

function tabLabel(tab: Tab, assetType: string): string {
  if (tab === "services") {
    if (assetType === "kubernetes_cluster") return "Workloads and Services";
    if (assetType === "kubernetes_node") return "Workloads on node";
    return "Services";
  }
  return { overview: "Overview", findings: "Findings", events: "Events" }[tab];
}

/** The page's one-line finding, from the API's own figures. */
function finding(detail: AssetDetailResponse, now: string): string {
  const a = detail.asset;
  const parts: string[] = [];
  parts.push(a.collectors_total === 0 ? "No collector reports for this asset" : collectorsSummary(a));
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
        <PageHeader title="Asset" />
        <ErrorState
          what="this asset"
          error={{ kind: "not_found", message: "The asset id in the address is not valid.", requestId: "-" }}
        />
      </>
    );
  }

  const [detailResult, tabData] = await Promise.all([
    getAsset(session, assetId),
    tab === "services"
      ? listAssetServices(session, assetId, { includeRemoved }).then((r) => ({ tab: "services" as const, r }))
      : tab === "findings"
        ? listFindings(session, { assetId, limit: FINDINGS_LIMIT }).then((r) => ({ tab: "findings" as const, r }))
        : tab === "events"
          ? listEvents(session, { assetId, limit: EVENTS_LIMIT }).then((r) => ({ tab: "events" as const, r }))
          : Promise.resolve({ tab: "overview" as const }),
  ]);

  if (!detailResult.ok) {
    return (
      <>
        <PageHeader title="Asset" />
        <ErrorState what="this asset" error={detailResult.error} />
      </>
    );
  }

  const detail = detailResult.data;
  const asset = detail.asset;
  const now = detailResult.receivedAt;
  const base = assetHref(asset.asset_id);
  const health = assetHealth(asset);
  const fs = detail.findings_summary;
  const alertsHref = `/detections${alertFiltersToSearch({ asset: asset.asset_id, range: "30d" })}`;
  const isCluster = asset.asset_type === "kubernetes_cluster";
  // The cluster's nodes with their coverage come from the asset list (shared with the shell).
  const assetList = tab === "overview" && (isCluster || detail.child_assets.length > 0) ? await listAssetsOnce(session) : null;
  const childIds = new Set(detail.child_assets.map((c) => c.asset_id));
  const nodes = assetList?.ok
    ? assetList.data.items.filter((a) => a.parent_asset_id === asset.asset_id || childIds.has(a.asset_id))
    : [];

  return (
    <>
      <PageHeader
        title={<AssetTitle assetType={asset.asset_type} name={asset.display_name ?? asset.name} />}
        titleMeta={
          <>
            {asset.lifecycle_state === "retired" ? null : <StatusPill tone={health.tone} label={health.label} />}
            <LifecycleBadge state={asset.lifecycle_state} reason={asset.lifecycle_reason} />
          </>
        }
        subtitle={finding(detail, now)}
        freshness={detailResult.receivedAt}
        actions={
          <Button asChild size="lg" className="h-9 px-3.5">
            <Link href={alertsHref}>
              View alerts
              <ArrowRight data-icon="inline-end" aria-hidden="true" />
            </Link>
          </Button>
        }
      />

      <AssetHeaderCard detail={detail} now={now} />

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
          <AssetKpis detail={detail} now={now} alertsHref={alertsHref} findingsHref={`${base}?tab=findings`} />
          <div className="grid items-start gap-6 xl:grid-cols-12">
            <div className="grid min-w-0 content-start gap-6 xl:col-span-8">
              <TelemetrySourcesCard
                collectors={detail.collectors}
                assetId={asset.asset_id}
                assetType={asset.asset_type}
                inherited={asset.collectors_inherited}
                now={now}
              />
              <EventsBySourceCard detail={detail} now={now} />
              {isCluster || detail.child_assets.length > 0 ? (
                assetList && !assetList.ok ? (
                  <ErrorState what="the nodes of this cluster" error={assetList.error} />
                ) : (
                  <NodesCard nodes={nodes} now={now} />
                )
              ) : null}
              <RecentAlertsCard detail={detail} now={now} alertsHref={alertsHref} />
            </div>
            <div className="grid min-w-0 content-start gap-6 xl:col-span-4">
              {asset.asset_type === "github_repository" ? null : (
                <ServiceCoverageCard
                  detail={detail}
                  servicesHref={`${base}?tab=services`}
                  servicesLabel={tabLabel("services", asset.asset_type)}
                />
              )}
              <InventoryCard detail={detail} now={now} />
              <AttributesCard detail={detail} />
            </div>
          </div>
        </div>
      ) : null}

      {tabData.tab === "services" ? (
        <AssetServices result={tabData.r} detail={detail} baseHref={base} includeRemoved={includeRemoved} now={now} />
      ) : null}

      {tabData.tab === "findings" ? <AssetFindingsTab result={tabData.r} summary={fs} limit={FINDINGS_LIMIT} now={now} /> : null}

      {tabData.tab === "events" ? <AssetEventsTab result={tabData.r} now={now} /> : null}
    </>
  );
}

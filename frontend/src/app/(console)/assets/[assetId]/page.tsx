import { Archive, ArrowRight, Clock } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { LinkTabs } from "@/components/console/link-tabs";
import { PageHeader } from "@/components/console/page-header";
import { PageCrumbs } from "@/components/console/route-breadcrumbs";
import { ErrorState, NotFoundState, Notice } from "@/components/console/states";
import { LifecycleBadge, StatusPill } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
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
import { alertFiltersToSearch, rangeBounds, TIME_RANGES, type TimeRangeKey } from "@/lib/filters";
import { formatCount, formatRelative } from "@/lib/format";
import { lifecycleView } from "@/lib/lifecycle";
import { crumbLabel } from "@/lib/navigation";
import { assetHref, isAssetId, parseAssetIdSegment } from "@/lib/security/ids";
import { getAsset, listAssetServices, listEvents, listFindings } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";
import { listAssetsOnce } from "@/lib/server/shell";

export const metadata: Metadata = { title: "Asset" };

const TABS = ["overview", "services", "findings", "events"] as const;
type Tab = (typeof TABS)[number];

/** Findings and events read per tab view (the API's page maximum is 200). */
const FINDINGS_LIMIT = 200;
const EVENTS_LIMIT = 100;

/** Windows of the Events tab (the API's event search spans at most 31 days). */
const EVENT_RANGES = ["24h", "7d", "30d"] as const satisfies readonly TimeRangeKey[];
type EventRange = (typeof EVENT_RANGES)[number];
const DEFAULT_EVENT_RANGE: EventRange = "24h";
const RANGE_SHORT: Record<EventRange, string> = { "24h": "24 h", "7d": "7 d", "30d": "30 d" };

/** GitHub repositories and accounts never carry services: no Services tab for them. */
const GITHUB_TYPES = new Set(["github_repository", "github_account"]);

function parseTab(raw: string | string[] | undefined): Tab {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return (TABS as readonly string[]).includes(value ?? "") ? (value as Tab) : "overview";
}

/**
 * API window of an event range. 24 h is the API's default (it ends the window a day ahead to
 * tolerate skewed source clocks). Longer windows end one hour ahead of this server's clock, so
 * a 30-day window stays inside the API's 31-day maximum whatever the clock difference.
 */
function eventWindow(range: EventRange): { since?: string; until?: string } {
  if (range === DEFAULT_EVENT_RANGE) return {};
  const now = new Date();
  return { since: rangeBounds(range, now).since, until: new Date(now.getTime() + 3_600_000).toISOString() };
}

function parseEventRange(raw: string | string[] | undefined): EventRange {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return (EVENT_RANGES as readonly string[]).includes(value ?? "") ? (value as EventRange) : DEFAULT_EVENT_RANGE;
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
  const eventRange = parseEventRange(query.range);

  if (!assetId) {
    return (
      <>
        <PageHeader title="Asset not found" />
        <NotFoundState backHref="/assets" backLabel="Back to Assets">
          The address does not hold a valid asset id.
        </NotFoundState>
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
          ? listEvents(session, { assetId, limit: EVENTS_LIMIT, ...eventWindow(eventRange) }).then((r) => ({
              tab: "events" as const,
              r,
            }))
          : Promise.resolve({ tab: "overview" as const }),
  ]);

  if (!detailResult.ok) {
    if (detailResult.error.kind === "not_found") {
      return (
        <>
          <PageHeader title="Asset not found" />
          <NotFoundState backHref="/assets" backLabel="Back to Assets" requestId={detailResult.error.requestId}>
            No asset{" "}
            <span className="font-mono text-foreground">
              <UntrustedText value={assetId} limit={64} plain />
            </span>{" "}
            is in the inventory; it may never have reported, or the link is wrong.
          </NotFoundState>
        </>
      );
    }
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
  const lifecycle = lifecycleView(asset.lifecycle_state, asset.lifecycle_reason);
  // A node's events and findings are stored under its cluster: its empty tabs point there.
  const clusterHref =
    asset.asset_type === "kubernetes_node" && asset.parent_asset_id && isAssetId(asset.parent_asset_id)
      ? assetHref(asset.parent_asset_id)
      : null;
  const fs = detail.findings_summary;
  const alertsHref = `/detections${alertFiltersToSearch({ asset: asset.asset_id, range: "30d" })}`;
  const isCluster = asset.asset_type === "kubernetes_cluster";
  // The cluster's nodes with their coverage come from the asset list (shared with the shell).
  const assetList = tab === "overview" && (isCluster || detail.child_assets.length > 0) ? await listAssetsOnce(session) : null;
  const childIds = new Set(detail.child_assets.map((c) => c.asset_id));
  const nodes = assetList?.ok
    ? assetList.data.items.filter((a) => a.parent_asset_id === asset.asset_id || childIds.has(a.asset_id))
    : [];

  // A node's display name repeats its cluster's; the trail and the title use the node's own name.
  const displayName = asset.asset_type === "kubernetes_node" ? asset.name : (asset.display_name ?? asset.name);

  return (
    <>
      <PageCrumbs crumbs={[{ label: crumbLabel(displayName) }]} />
      <PageHeader
        title={<AssetTitle assetType={asset.asset_type} name={displayName} />}
        titleMeta={
          // One status: the lifecycle state when the asset is stale or retired (with the API's
          // reason on hover), otherwise its health. The subtitle carries the collector figures.
          asset.lifecycle_state && asset.lifecycle_state !== "active" ? (
            <LifecycleBadge state={asset.lifecycle_state} reason={asset.lifecycle_reason} />
          ) : (
            <StatusPill tone={health.tone} label={health.label} />
          )
        }
        subtitle={finding(detail, now)}
        freshness={detailResult.receivedAt}
        actions={
          // The primary action only when there is something to act on.
          <Button asChild size="lg" variant={asset.open_alerts > 0 ? "default" : "outline"} className="h-9 px-3.5">
            <Link href={alertsHref}>
              {asset.open_alerts > 0
                ? `View ${formatCount(asset.open_alerts)} open alert${asset.open_alerts === 1 ? "" : "s"}`
                : "Alert history"}
              <ArrowRight data-icon="inline-end" aria-hidden="true" />
            </Link>
          </Button>
        }
      />

      <AssetHeaderCard detail={detail} now={now} />

      {lifecycle ? (
        <Notice icon={lifecycle.state === "retired" ? Archive : Clock} className="-mt-2 mb-6">
          <span className="font-medium text-fg-2">{lifecycle.label}.</span> {lifecycle.meaning}
          {lifecycle.reason ? <> API: {lifecycle.reason}.</> : null}
        </Notice>
      ) : null}

      <LinkTabs
        label="Asset views"
        active={tab}
        tabs={TABS.filter((key) => key !== "services" || !GITHUB_TYPES.has(asset.asset_type)).map((key) => ({
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
            </div>
            {/* The rail holds what fits beside the telemetry; GitHub assets have no service
                coverage, so their attributes take its place and the columns end close together. */}
            <div className="grid min-w-0 content-start gap-6 xl:col-span-4">
              {GITHUB_TYPES.has(asset.asset_type) ? null : (
                <ServiceCoverageCard
                  detail={detail}
                  servicesHref={`${base}?tab=services`}
                  servicesLabel={tabLabel("services", asset.asset_type)}
                />
              )}
              <InventoryCard detail={detail} now={now} />
              {GITHUB_TYPES.has(asset.asset_type) ? <AttributesCard detail={detail} columns={1} /> : null}
            </div>
          </div>
          <RecentAlertsCard detail={detail} now={now} alertsHref={alertsHref} />
          {GITHUB_TYPES.has(asset.asset_type) ? null : <AttributesCard detail={detail} />}
        </div>
      ) : null}

      {tabData.tab === "services" ? (
        <AssetServices result={tabData.r} detail={detail} baseHref={base} includeRemoved={includeRemoved} now={now} />
      ) : null}

      {tabData.tab === "findings" ? (
        <AssetFindingsTab
          result={tabData.r}
          summary={fs}
          limit={FINDINGS_LIMIT}
          now={now}
          clusterFindingsHref={clusterHref ? `${clusterHref}?tab=findings` : null}
        />
      ) : null}

      {tabData.tab === "events" ? (
        <AssetEventsTab
          result={tabData.r}
          now={now}
          limit={EVENTS_LIMIT}
          range={eventRange}
          ranges={EVENT_RANGES.map((key) => ({
            key,
            short: RANGE_SHORT[key],
            label: TIME_RANGES[key].label,
            href: key === DEFAULT_EVENT_RANGE ? `${base}?tab=events` : `${base}?tab=events&range=${key}`,
          }))}
          clusterEventsHref={clusterHref ? `${clusterHref}?tab=events` : null}
        />
      ) : null}
    </>
  );
}

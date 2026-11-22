import { cn } from "cn";
import Link from "next/link";
import type { ReactNode } from "react";

import { SplitBar } from "@/components/console/kpi-card";
import { ErrorState } from "@/components/console/states";
import { LifecycleBadge, StatusDot } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ApiResult } from "@/lib/api/result";
import type { AssetDetailResponse, AssetListItem } from "@/lib/api/schemas";
import { assetTypeLabel, DASH, formatCount } from "@/lib/format";
import { lifecycleView } from "@/lib/lifecycle";
import { assetHref } from "@/lib/security/ids";

import { AssetIconTile } from "./asset-icon";
import {
  assetHealth,
  coverageParts,
  itemCount,
  partsInWords,
  severityParts,
  unhealthyCollectors,
} from "./model";

/** A labelled figure in the card's metric well. */
function Metric({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 px-3 py-2.5 first:pl-3.5">
      <dt className="truncate text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 truncate text-lg leading-6 font-semibold tracking-tight text-foreground tabular-nums">{children}</dd>
    </div>
  );
}

/** Track for a proportion the API did not report: dashed, so it never reads as zero. */
function UnknownTrack({ label }: { label: string }) {
  return (
    <div
      role="img"
      aria-label={label}
      className="h-1.5 w-full rounded-full border border-dashed border-hairline-strong"
    />
  );
}

/** A labelled proportion: label and headline figure, the split bar, the parts in words. */
function BarRow({
  label,
  figure,
  bar,
  caption,
}: {
  label: string;
  figure: ReactNode;
  bar: ReactNode;
  caption: ReactNode;
}) {
  return (
    <div className="grid min-w-0 gap-1.5">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-xs text-muted-foreground">{label}</span>
        <span className="text-xs whitespace-nowrap text-muted-foreground tabular-nums">{figure}</span>
      </div>
      {bar}
      <p className="truncate text-xs text-muted-foreground">{caption}</p>
    </div>
  );
}

function FindingsRow({ detail }: { detail: AssetDetailResponse }) {
  const summary = detail.findings_summary;
  const parts = severityParts(summary.counts);
  const words = partsInWords(parts);
  const unverified = summary.unverified?.total ?? 0;
  const label = summary.lifecycle_available ? "Open findings" : "Observed findings";
  return (
    <BarRow
      label={label}
      figure={<span className="text-sm font-medium text-foreground">{formatCount(summary.counts.total)}</span>}
      bar={<SplitBar parts={parts} label={`${label}: ${words || "none"}`} />}
      caption={
        <>
          {words || (summary.lifecycle_available ? "No open finding" : "No finding observed")}
          {unverified > 0 ? ` · ${formatCount(unverified)} unverified` : ""}
        </>
      }
    />
  );
}

function ServicesRow({ asset, detail }: { asset: AssetListItem; detail: AssetDetailResponse }) {
  const summary = detail.services_summary;
  if (asset.asset_type === "github_repository") {
    // Repositories carry no service inventory: their monitored inventory is workflows and branches.
    const items = [...detail.inventory].sort((a, b) => a.item_type.localeCompare(b.item_type));
    return (
      <div className="grid min-w-0 gap-2">
        <span className="text-xs text-muted-foreground">Monitored inventory</span>
        {items.length > 0 ? (
          <ul className="flex flex-wrap gap-1.5">
            {items.map((i) => (
              <li
                key={i.item_type}
                className="inline-flex h-6 items-center rounded-md px-2 text-xs text-fg-2 tabular-nums ring-1 ring-hairline-strong ring-inset"
              >
                {itemCount(i.item_type, i.items)}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-xs text-muted-foreground">No inventory reported</p>
        )}
      </div>
    );
  }
  if (!summary) {
    return <BarRow label="Services" figure={DASH} bar={<UnknownTrack label="Services: not reported" />} caption="Not reported by this API" />;
  }
  if (!summary.reported) {
    return (
      <BarRow
        label="Services"
        figure={DASH}
        bar={<UnknownTrack label="Services: not reported" />}
        caption={asset.asset_type === "kubernetes_node" ? "None reported for the node itself" : "Discovery has not reported yet"}
      />
    );
  }
  const parts = coverageParts(summary.coverage);
  const covered = summary.coverage.monitored;
  return (
    <BarRow
      label="Services"
      figure={
        <>
          <span className="text-sm font-medium text-foreground">{formatCount(covered)}</span> of{" "}
          {formatCount(summary.coverage.total)} monitored
        </>
      }
      bar={<SplitBar parts={parts} label={`Service coverage: ${partsInWords(parts) || "none"}`} />}
      caption={partsInWords(parts.filter((p) => p.key !== "monitored")) || "Every discovered service is monitored"}
    />
  );
}

/**
 * The footer line: the lifecycle reason of a stale or retired asset (API text, durations spelled
 * out), else why the asset is not healthy (collector names as text), else its recency.
 */
function Footer({ asset, detail, now }: { asset: AssetListItem; detail: AssetDetailResponse | null; now: string }) {
  const health = assetHealth(asset);
  const lifecycle = lifecycleView(asset.lifecycle_state, asset.lifecycle_reason);
  const unhealthy = detail ? unhealthyCollectors(detail.collectors) : [];
  let body: ReactNode;
  if (lifecycle) {
    body = (
      <span className="flex min-w-0 items-center gap-1.5 text-fg-2">
        <span className="flex-none">{lifecycle.label}:</span>
        <span className="min-w-0 truncate text-muted-foreground">{lifecycle.reason ?? lifecycle.meaning}</span>
      </span>
    );
  } else if (health.reason && unhealthy.length > 0) {
    const names = unhealthy.map((c) => c.collector_id).join(", ");
    const word = unhealthy.every((c) => c.stale) ? "Stale" : "Unhealthy";
    body = (
      <span className="flex min-w-0 items-center gap-1.5 text-fg-2">
        <span className="flex-none">
          {word} collector{unhealthy.length === 1 ? "" : "s"}
        </span>
        <span className="min-w-0 font-mono text-muted-foreground">
          <UntrustedText value={names} oneLine plain mono />
        </span>
      </span>
    );
  } else if (health.reason) {
    body = <span className="text-fg-2">{health.reason}</span>;
  } else if (asset.collectors_inherited > 0 && asset.collectors_inherited >= asset.collectors_total) {
    body = <span>Collectors report through the {asset.asset_type === "kubernetes_node" ? "cluster" : "parent asset"}</span>;
  } else {
    body = (
      <span>
        Last inventory <RelativeTime value={asset.last_seen} now={now} plain className="text-xs text-muted-foreground" />
      </span>
    );
  }
  return (
    <footer className="mt-auto flex min-h-11 items-center justify-between gap-3 border-t border-hairline-soft px-5 py-2.5 text-xs text-muted-foreground">
      <span className="min-w-0 flex-1 truncate">{body}</span>
      <span
        aria-hidden="true"
        className="flex-none font-medium transition-colors duration-150 group-hover/card:text-foreground"
      >
        Open{" "}
        <span className="inline-block transition-transform duration-150 group-hover/card:translate-x-0.5">→</span>
      </span>
    </footer>
  );
}

/**
 * One monitored asset as a card: identity and health, a metric well (collectors fresh, last
 * event, open alerts), open findings by severity and service coverage as split bars, and a
 * footer with the reason when the asset is not healthy. The whole card links to the asset.
 *
 * `detail` is the asset's detail response (findings and service summaries); when it failed,
 * the card says so in place of the bars and keeps everything the list reported.
 */
export function AssetCard({
  asset,
  detail,
  now,
  context,
  className,
}: {
  asset: AssetListItem;
  /** The asset's detail response; null when the page did not request it (list beyond the cap). */
  detail: ApiResult<AssetDetailResponse> | null;
  now: string;
  /** Relationship line in place of the type, e.g. "Node of extorq-lab" (names via UntrustedText). */
  context?: ReactNode;
  className?: string;
}) {
  const health = assetHealth(asset);
  const name = asset.display_name ?? asset.name;
  const href = assetHref(asset.asset_id);
  const inherited = asset.collectors_inherited > 0;
  const retired = asset.lifecycle_state === "retired";
  return (
    <article
      className={cn(
        "group/card relative flex h-full min-w-0 flex-col rounded-xl bg-card shadow-card ring-1 ring-hairline transition-colors duration-150",
        "hover:bg-[color-mix(in_oklab,var(--card),white_2%)] has-[a:focus-visible]:ring-2 has-[a:focus-visible]:ring-ring/60",
        retired && "bg-card/60",
        className,
      )}
    >
      <header className="flex items-start gap-3 px-5 pt-5">
        <AssetIconTile assetType={asset.asset_type} />
        <div className="min-w-0 flex-1">
          <h3 className={cn("min-w-0 text-base leading-5 font-semibold tracking-tight", retired ? "text-fg-2" : "text-foreground")}>
            <Link href={href} className="block min-w-0 truncate outline-none after:absolute after:inset-0 after:rounded-xl">
              <UntrustedText value={name} oneLine plain />
            </Link>
          </h3>
          <p className="mt-1 flex min-w-0 items-center gap-1.5 text-xs text-muted-foreground">
            <span className="flex-none">{context ?? assetTypeLabel(asset.asset_type)}</span>
            <span aria-hidden="true" className="text-fg-faint">
              ·
            </span>
            <span className="min-w-0 truncate font-mono">
              <UntrustedText value={asset.asset_id} oneLine plain />
            </span>
          </p>
        </div>
        {retired ? (
          // Above the stretched link so the hint stays reachable.
          <span className="relative z-10 flex-none">
            <LifecycleBadge state={asset.lifecycle_state} reason={asset.lifecycle_reason} />
          </span>
        ) : (
          <StatusDot tone={health.tone} label={health.label} className="mt-0.5 text-xs" />
        )}
      </header>

      <dl className="mx-5 mt-4 grid grid-cols-3 divide-x divide-hairline-soft rounded-lg bg-white/[0.02] ring-1 ring-hairline-soft ring-inset">
        <Metric label={inherited ? "Collectors (cluster)" : "Collectors fresh"}>
          {asset.collectors_total === 0 ? (
            <span className="text-muted-foreground">0</span>
          ) : (
            <>
              <span className={asset.collectors_stale > 0 ? "text-health-warn" : undefined}>
                {formatCount(asset.collectors_total - asset.collectors_stale)}
              </span>
              <span className="text-muted-foreground"> / {formatCount(asset.collectors_total)}</span>
            </>
          )}
        </Metric>
        <Metric label="Last event">
          <RelativeTime value={asset.last_event_at} now={now} plain className="text-foreground" />
        </Metric>
        <Metric label="Open alerts">
          <span className={asset.open_alerts > 0 ? "text-foreground" : "text-muted-foreground"}>{formatCount(asset.open_alerts)}</span>
        </Metric>
      </dl>

      <div className="grid gap-4 px-5 pt-4 pb-5">
        {detail === null ? (
          <p className="rounded-lg px-3.5 py-3 text-xs leading-relaxed text-muted-foreground ring-1 ring-hairline-soft ring-inset">
            Findings and service coverage are loaded for the first assets of the list only; open the asset for its figures.
          </p>
        ) : detail.ok ? (
          <>
            <FindingsRow detail={detail.data} />
            <ServicesRow asset={asset} detail={detail.data} />
          </>
        ) : (
          // Above the card's stretched link so the retry button stays clickable.
          <div className="relative z-10">
            <ErrorState what="the findings and services of this asset" error={detail.error} />
          </div>
        )}
      </div>

      <Footer asset={asset} detail={detail?.ok ? detail.data : null} now={now} />
    </article>
  );
}

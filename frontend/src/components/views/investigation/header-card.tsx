import { cn } from "cn";
import { TriangleAlert } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { ConfidenceBadge } from "@/components/console/badges";
import { Hint } from "@/components/console/hint";
import { IdText } from "@/components/console/id-text";
import { SeverityBadge } from "@/components/console/severity";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AlertDetailResponse } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount, formatDuration, formatRelative, formatVersion } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";

import { AssetTile, Chip, StatusMark } from "./marks";
import { evidenceMix, secondsBetween } from "./model";

function Fact({
  label,
  children,
  sub,
  className,
  wrapSub = false,
}: {
  label: string;
  children: ReactNode;
  sub?: ReactNode;
  className?: string;
  /** Let the sub-label take two lines (a list such as the evidence mix) instead of truncating. */
  wrapSub?: boolean;
}) {
  return (
    <div className={cn("min-w-0 bg-card px-5 py-3 @lg:px-6 @lg:py-4", className)}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1.5 min-w-0 text-base font-medium text-foreground">{children}</dd>
      {sub ? (
        <dd className={cn("mt-1 min-w-0 text-xs text-muted-foreground", wrapSub ? "line-clamp-2 tabular-nums" : "truncate")}>{sub}</dd>
      ) : null}
    </div>
  );
}

/**
 * The alert at a glance: rule, title, severity, ATT&CK techniques, the detector's summary,
 * and the facts that frame every tab (evidence confidence, asset, first and last seen, event
 * count). The analyst status picker sits top right for analysts; viewers see the status.
 */
export function HeaderCard({
  detail,
  now,
  canEdit,
  natSources,
}: {
  detail: AlertDetailResponse;
  now: string;
  canEdit: boolean;
  /** Evidence source addresses the correlation layer marks as shared NAT/gateway addresses (empty: none). */
  natSources: string[] | null;
}) {
  const alert = detail.alert;
  const asset = detail.asset;
  const assetName = asset?.name ?? null;
  const windowSeconds = secondsBetween(alert.first_seen, alert.last_seen);
  const mix = evidenceMix(detail.evidence, 2);
  const evidenceSub = alert.evidence_truncated
    ? "evidence list truncated by the detector"
    : detail.evidence_capped || detail.unresolved_evidence_ids.length > 0
      ? `${formatCount(detail.evidence.length)} of ${formatCount(detail.evidence_total)} cited events shown`
      : mix
        ? <UntrustedText value={mix} limit={160} plain />
        : `${formatCount(detail.evidence.length)} stored evidence event${detail.evidence.length === 1 ? "" : "s"}`;

  return (
    <section aria-labelledby="alert-title" className="@container mt-7 overflow-hidden rounded-xl bg-card shadow-card ring-1 ring-hairline">
      <div className="flex flex-col gap-5 px-6 pt-5 pb-6 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex min-w-0 gap-4">
          <AssetTile assetType={alert.asset_type} className="mt-0.5 hidden sm:flex" />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
              <span className="font-mono font-medium text-fg-2">{alert.rule_id}</span>
              <span className="font-mono">{formatVersion(alert.rule_version)}</span>
              <span aria-hidden="true" className="text-fg-faint">
                ·
              </span>
              <span className="inline-flex items-center gap-1">
                Alert <IdText id={alert.alert_id} />
              </span>
              <span aria-hidden="true" className="text-fg-faint">
                ·
              </span>
              <span>
                Detected <RelativeTime value={alert.created_at} now={now} className="text-xs" />
              </span>
            </div>
            <h1 id="alert-title" className="mt-1.5 text-2xl font-semibold tracking-tight text-balance text-foreground">
              <UntrustedText value={alert.rule_title} limit={140} />
            </h1>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={alert.severity} size="md" />
              {alert.mitre_techniques.map((technique) => (
                <Hint key={technique} content="MITRE ATT&CK technique mapped by the rule definition.">
                  <Chip mono className="h-6">
                    {technique}
                  </Chip>
                </Hint>
              ))}
              {natSources !== null ? (
                <Hint content="The evidence's source address is shared by NAT or a gateway (the VM's user-mode network, a cluster bridge): it does not identify one origin, so links through it stay unestablished on the Timeline and Correlation tabs.">
                  <span className="inline-flex h-6 items-center gap-1.5 rounded-md bg-health-warn/[0.06] px-2 text-xs text-fg-2 ring-1 ring-health-warn/25 ring-inset">
                    <TriangleAlert className="size-3 text-health-warn" aria-hidden="true" />
                    Shared NAT source
                    {natSources.length > 0 ? (
                      <span className="font-mono text-foreground">
                        <UntrustedText value={natSources.join(", ")} limit={60} plain />
                      </span>
                    ) : null}
                  </span>
                </Hint>
              ) : null}
            </div>
          </div>
        </div>
        <div className="flex flex-none flex-col gap-1 lg:items-end">
          <span className="text-xs text-muted-foreground">Analyst status</span>
          <span className="inline-flex h-9 items-center gap-3 rounded-lg px-3 text-sm ring-1 ring-hairline-strong ring-inset">
            <StatusMark status={detail.analyst_state.status} className="text-foreground" />
            {canEdit ? (
              <a
                href="#state-title"
                className="rounded-sm text-xs text-muted-foreground underline-offset-2 transition-colors duration-150 hover:text-foreground hover:underline focus-visible:ring-2 focus-visible:ring-ring/50 focus-visible:outline-none"
              >
                Change
              </a>
            ) : (
              <span className="text-xs text-muted-foreground">read-only</span>
            )}
          </span>
        </div>
      </div>

      {/* 1 / 2 / 3 / 5 columns by the card's width (a UTC timestamp needs ~170 px); the 1px gaps on a
          hairline ground draw the rules for any column count, and the last fact fills its row. */}
      <dl className="grid grid-cols-1 gap-px border-t border-hairline-soft bg-hairline-soft @lg:grid-cols-2 @2xl:grid-cols-3 @5xl:grid-cols-5">
        <Fact label="Evidence confidence" sub="Completeness, not a verdict">
          <ConfidenceBadge confidence={alert.confidence} className="text-foreground" />
        </Fact>
        <Fact
          label="Asset"
          sub={assetTypeLabel(asset?.asset_type ?? alert.asset_type)}
        >
          <Link href={assetHref(alert.asset_id)} className="block truncate hover:underline">
            <UntrustedText value={assetName ?? alert.asset_id} limit={48} plain />
          </Link>
        </Fact>
        <Fact label="First seen (UTC)" sub={formatRelative(alert.first_seen, now)}>
          <Timestamp value={alert.first_seen} className="text-sm text-foreground" />
        </Fact>
        <Fact
          label="Last seen (UTC)"
          sub={
            windowSeconds === null
              ? undefined
              : windowSeconds < 1
                ? "Same second as the first event"
                : `${formatDuration(windowSeconds)} after the first event`
          }
        >
          <Timestamp value={alert.last_seen} className="text-sm text-foreground" />
        </Fact>
        <Fact label="Evidence events" sub={evidenceSub} wrapSub className="@lg:col-span-2 @5xl:col-span-1">
          <span className="text-2xl leading-none font-semibold tracking-tight tabular-nums">{formatCount(alert.event_count)}</span>
        </Fact>
      </dl>
    </section>
  );
}

import { cn } from "cn";
import Link from "next/link";
import type { ReactNode } from "react";

import { ConfidenceBadge, SimulationBadge } from "@/components/console/badges";
import { Hint } from "@/components/console/hint";
import { IdText } from "@/components/console/id-text";
import { SeverityBadge } from "@/components/console/severity";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AlertDetailResponse } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount, formatDuration, formatVersion } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";

import { AssetTile, Chip, StatusMark } from "./marks";
import { secondsBetween } from "./model";
import { StatusPicker } from "./status-controls";

function Fact({ label, children, sub, className }: { label: string; children: ReactNode; sub?: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0 px-5 py-3 sm:px-6 sm:py-4", className)}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1.5 min-w-0 text-base font-medium text-foreground">{children}</dd>
      {sub ? <dd className="mt-1 min-w-0 truncate text-xs text-muted-foreground">{sub}</dd> : null}
    </div>
  );
}

/**
 * The alert at a glance: rule, title, severity, simulation marker, the detector's summary,
 * and the facts that frame every tab (evidence confidence, asset, first and last seen, event
 * count). The analyst status picker sits top right for analysts; viewers see the status.
 */
export function HeaderCard({ detail, now, canEdit }: { detail: AlertDetailResponse; now: string; canEdit: boolean }) {
  const alert = detail.alert;
  const asset = detail.asset;
  const assetName = asset?.name ?? null;
  const windowSeconds = secondsBetween(alert.first_seen, alert.last_seen);
  const evidenceSub = alert.evidence_truncated
    ? "evidence list truncated by the detector"
    : detail.evidence_capped
      ? `${formatCount(detail.evidence.length)} of ${formatCount(detail.evidence_total)} stored events shown`
      : `${formatCount(detail.evidence_total)} stored evidence event${detail.evidence_total === 1 ? "" : "s"}`;

  return (
    <section aria-labelledby="alert-title" className="mt-7 overflow-hidden rounded-xl bg-card shadow-card ring-1 ring-hairline">
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
              <SimulationBadge runIds={alert.simulation_run_ids} className="h-6" />
              {alert.mitre_techniques.map((technique) => (
                <Hint key={technique} content="MITRE ATT&CK technique mapped by the rule definition.">
                  <Chip mono className="h-6">
                    {technique}
                  </Chip>
                </Hint>
              ))}
            </div>
          </div>
        </div>
        <div className="flex flex-none flex-col gap-1 lg:items-end">
          <span className="text-xs text-muted-foreground">Analyst status</span>
          {canEdit ? (
            <StatusPicker alertId={alert.alert_id} state={detail.analyst_state} />
          ) : (
            <span className="inline-flex h-9 items-center gap-2 rounded-lg px-3 text-sm ring-1 ring-hairline-strong ring-inset">
              <StatusMark status={detail.analyst_state.status} className="text-foreground" />
              <span className="text-xs text-muted-foreground">read-only</span>
            </span>
          )}
        </div>
      </div>

      <dl className="grid grid-cols-1 divide-hairline-soft border-t border-hairline-soft sm:grid-cols-2 lg:grid-cols-5 lg:divide-x">
        <Fact label="Evidence confidence" sub="Completeness, not a verdict">
          <ConfidenceBadge confidence={alert.confidence} className="text-foreground" />
        </Fact>
        <Fact
          label="Asset"
          sub={
            asset ? (
              <>
                {assetTypeLabel(asset.asset_type)} · <UntrustedText value={asset.environment} limit={24} plain />
              </>
            ) : (
              assetTypeLabel(alert.asset_type)
            )
          }
          className="border-t border-hairline-soft sm:border-t-0"
        >
          <Link href={assetHref(alert.asset_id)} className="block truncate hover:underline">
            <UntrustedText value={assetName ?? alert.asset_id} limit={48} plain />
          </Link>
        </Fact>
        <Fact label="First seen" sub="UTC" className="border-t border-hairline-soft lg:border-t-0">
          <Timestamp value={alert.first_seen} className="text-sm text-foreground" />
        </Fact>
        <Fact
          label="Last seen"
          sub={
            windowSeconds === null
              ? undefined
              : windowSeconds < 1
                ? "Same second as the first event"
                : `${formatDuration(windowSeconds)} after the first event`
          }
          className="border-t border-hairline-soft lg:border-t-0"
        >
          <Timestamp value={alert.last_seen} className="text-sm text-foreground" />
        </Fact>
        <Fact label="Evidence events" sub={evidenceSub} className="border-t border-hairline-soft lg:border-t-0">
          <span className="text-2xl leading-none font-semibold tracking-tight tabular-nums">{formatCount(alert.event_count)}</span>
        </Fact>
      </dl>
    </section>
  );
}

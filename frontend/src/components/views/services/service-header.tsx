import { cn } from "cn";
import { AppWindow, Cog, Layers, type LucideIcon, Network, Workflow } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { HoverCard, HoverCardContent, HoverCardTrigger } from "@/components/ui/hover-card";
import type { ServiceDetailResponse } from "@/lib/api/schemas";
import { DASH, formatCount, isClosedStatus } from "@/lib/format";
import { assetHref, isAssetId } from "@/lib/security/ids";
import { categoryLabel, discoveryLabel, serviceCoverage, serviceKindLabel } from "@/lib/services";

import { AssetIconTile } from "../assets/asset-icon";
import { lastTelemetry } from "./model";
import { ReportStaleTag, ServiceCoveragePill } from "./service-badges";

const KIND_ICON: Record<string, LucideIcon> = {
  host_service: Cog,
  application: AppWindow,
  k8s_workload: Workflow,
  k8s_service: Network,
};

/** Page title of a service: its kind's icon on a tile and the name (telemetry: plain text). */
export function ServiceTitle({ kind, name }: { kind: string; name: string }) {
  const Icon = KIND_ICON[kind] ?? Layers;
  return (
    <span className="flex min-w-0 items-center gap-3">
      <span
        aria-hidden="true"
        className="flex size-10 flex-none items-center justify-center rounded-[10px] bg-white/[0.04] text-fg-2 ring-1 ring-hairline ring-inset"
      >
        <Icon className="size-5" strokeWidth={1.75} />
      </span>
      <span className="min-w-0">
        <UntrustedText value={name} limit={80} />
      </span>
    </span>
  );
}

function Fact({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 min-w-0 truncate text-sm text-fg-2">{children}</dd>
    </div>
  );
}

function Figure({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="min-w-0 px-5 py-3.5 sm:flex-1 sm:border-l sm:border-hairline-soft sm:first:border-l-0">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 text-xl leading-7 font-semibold tracking-tight text-foreground tabular-nums">{value}</dd>
      {sub ? <dd className="mt-0.5 truncate text-xs text-muted-foreground">{sub}</dd> : null}
    </div>
  );
}

/** Configuration paths (never contents): the first inline, all of them in a hover card. */
function ConfigRefs({ refs }: { refs: string[] }) {
  if (refs.length === 0) return <span className="text-muted-foreground">{DASH}</span>;
  const first = refs[0]!;
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span className="min-w-0 truncate font-mono text-xs">
        <UntrustedText value={first} oneLine mono />
      </span>
      {refs.length > 1 ? (
        <HoverCard openDelay={250} closeDelay={80}>
          <HoverCardTrigger asChild>
            <button
              type="button"
              className="flex-none rounded-sm text-xs text-muted-foreground underline decoration-dotted underline-offset-2 outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
            >
              +{formatCount(refs.length - 1)}
            </button>
          </HoverCardTrigger>
          <HoverCardContent align="end" className="w-[min(32rem,calc(100vw-2rem))] p-0">
            <p className="border-b border-hairline px-3 py-2 text-xs text-muted-foreground">
              Configuration references · paths only, contents are never collected
            </p>
            <ul className="grid max-h-72 gap-1 overflow-y-auto px-3 py-2">
              {refs.map((ref) => (
                <li key={ref} className="font-mono text-xs break-all text-fg-2">
                  <UntrustedText value={ref} mono limit={240} />
                </li>
              ))}
            </ul>
          </HoverCardContent>
        </HoverCard>
      ) : null}
    </span>
  );
}

/**
 * Header card of a service (every tab): where it runs and what it is, how it was discovered,
 * its coverage with the reason, and the headline figures. Values as reported; a stale discovery
 * report is marked once here.
 */
export function ServiceHeaderCard({ data, now }: { data: ServiceDetailResponse; now: string }) {
  const s = data.service;
  const badge = serviceCoverage(s);
  const assetName = data.asset ? (data.asset.display_name ?? data.asset.name) : s.asset_id;
  const assetType = data.asset?.asset_type ?? "";
  const openAlerts = data.alerts.filter((a) => !isClosedStatus(a.analyst_status)).length;
  const confirmed = s.endpoints.filter((e) => e.attribution === "confirmed").length;
  const product = [s.product, s.version].filter(Boolean).join(" ");
  const logical = s.service_kind === "k8s_service";

  return (
    <section aria-label="Service identity and coverage" className="mb-6 rounded-xl bg-card shadow-card ring-1 ring-hairline">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-4 px-5 pt-4 pb-4 sm:grid-cols-3 lg:grid-cols-5">
        <Fact label="Asset">
          {isAssetId(s.asset_id) ? (
            <Link
              href={assetHref(s.asset_id)}
              className="flex min-w-0 items-center gap-2 text-fg-2 underline-offset-2 transition-colors duration-150 hover:text-foreground hover:underline"
            >
              {assetType ? <AssetIconTile assetType={assetType} size="sm" className="size-5 rounded-md" /> : null}
              <span className="min-w-0 truncate">
                <UntrustedText value={assetName} plain limit={64} />
              </span>
            </Link>
          ) : (
            <UntrustedText value={assetName} plain limit={64} />
          )}
        </Fact>
        <Fact label="Kind">{serviceKindLabel(s.service_kind)}</Fact>
        <Fact label="Category">
          {s.category === "unknown" ? <span className="text-muted-foreground">Unknown</span> : categoryLabel(s.category)}
        </Fact>
        <Fact label="Product and version">
          {product ? <UntrustedText value={product} oneLine /> : <span className="text-muted-foreground">Not observed</span>}
        </Fact>
        <Fact label="Adapter">
          {s.adapter_id ? (
            <span className="flex min-w-0 items-center gap-1.5">
              <span className="truncate font-mono text-xs text-foreground">
                <UntrustedText value={s.adapter_id} plain limit={48} />
              </span>
              <span className="flex-none text-xs text-muted-foreground">
                · <UntrustedText value={s.adapter_support} plain limit={24} />
              </span>
            </span>
          ) : (
            <span className="text-muted-foreground">None ({s.adapter_support})</span>
          )}
        </Fact>
        <Fact label="Discovered via">
          {s.discovered_via.length > 0 ? s.discovered_via.map(discoveryLabel).join(", ") : <span className="text-muted-foreground">{DASH}</span>}
        </Fact>
        <Fact label="Configuration">
          <ConfigRefs refs={s.config_refs} />
        </Fact>
        <Fact label="First seen">
          <Timestamp value={s.first_seen} className="text-fg-2" />
        </Fact>
        <Fact label="Last discovery report">
          <span className="flex min-w-0 items-center gap-2">
            <RelativeTime value={s.last_seen} now={now} />
            {s.present && s.report_stale ? <ReportStaleTag ageSeconds={s.report_age_seconds} /> : null}
          </span>
        </Fact>
        <Fact label="Observed by">
          <span className="font-mono text-xs">
            <UntrustedText value={s.observed_by} oneLine mono />
          </span>
        </Fact>
      </dl>

      <div className="flex flex-col gap-2 border-t border-hairline-soft px-5 py-3.5 sm:flex-row sm:items-start sm:gap-4">
        <span className="flex flex-none items-center gap-3">
          <span className="text-xs text-muted-foreground">Coverage</span>
          <ServiceCoveragePill service={s} />
        </span>
        <div className="min-w-0 text-sm leading-relaxed text-fg-2">
          {badge.detail}
          {s.coverage_note ? (
            <span className="mt-0.5 flex min-w-0 items-baseline gap-1.5 text-xs text-muted-foreground">
              <span className="flex-none">Collector note:</span>
              <span className="min-w-0">
                <UntrustedText value={s.coverage_note} limit={240} />
              </span>
            </span>
          ) : null}
        </div>
      </div>

      <dl className="grid grid-cols-2 border-t border-hairline-soft sm:flex">
        <Figure
          label="Instances"
          value={logical && data.instances_total === 0 ? <span className="text-muted-foreground">{DASH}</span> : formatCount(data.instances_total)}
          sub={logical ? "logical object, no instances" : "currently observed"}
        />
        <Figure label="Ports" value={formatCount(s.endpoints.length)} sub={`${formatCount(confirmed)} with a confirmed owner`} />
        <Figure
          label="Last telemetry"
          value={<RelativeTime value={lastTelemetry(data)} now={now} className="text-foreground" />}
          sub="newest attributed event or report"
        />
        <Figure
          label="Alerts"
          value={formatCount(data.alerts_total)}
          sub={
            data.alerts.length < data.alerts_total
              ? `${formatCount(openAlerts)} open among the ${formatCount(data.alerts.length)} listed`
              : `${formatCount(openAlerts)} open`
          }
        />
        <Figure
          label="Findings"
          value={formatCount(data.findings_total)}
          sub={data.findings_lifecycle_available ? "attributed to this service" : "observed, lifecycle unavailable"}
        />
      </dl>
    </section>
  );
}

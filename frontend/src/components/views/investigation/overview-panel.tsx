import { Fingerprint, Layers, ScrollText } from "lucide-react";
import Link from "next/link";

import { Disclosure } from "@/components/console/disclosure";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import { CoverageBadge } from "@/components/console/status-badge";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ApiFailure } from "@/lib/api/result";
import type { AlertDetailResponse, InvestigationContext } from "@/lib/api/schemas";
import { assetTypeLabel, formatCount, formatDuration, formatWindowLength } from "@/lib/format";
import { assetHref, serviceHref } from "@/lib/security/ids";
import { categoryLabel, serviceKindLabel } from "@/lib/services";

import { FeatureTable } from "./feature-value";
import { KeySignals } from "./key-signals";
import { Eyebrow, KeyChip } from "./marks";
import { featureLabel, secondsBetween } from "./model";
import {
  contextFeatureGroups,
  DETECTOR_LABEL,
  type FeatureGroup,
  keySignals,
  remainingDetectorFeatures,
  sequenceStages,
  thresholdChecks,
  thresholdKeys,
} from "./signals";

/**
 * Overview tab: why the rule fired (its logic and what the detector found), the entities
 * and features the detector and the correlation layer computed from stored telemetry, and
 * the services involved with their telemetry coverage.
 */
export function OverviewPanel({
  detail,
  context,
  contextError,
}: {
  detail: AlertDetailResponse;
  context: InvestigationContext | null;
  contextError: ApiFailure | null;
}) {
  const alert = detail.alert;
  const ruleDescription = detail.rule?.description
    ?? (context?.rule.version === alert.rule_version ? context.rule.description : null);
  const entities = Object.entries(alert.entities);
  const detectorFeatures = context?.alert.features ?? alert.features ?? null;
  const contextFeatures = context?.features ?? null;

  // The decisive signals first; the lists below keep only what these do not already show.
  const sequence = sequenceStages(detectorFeatures);
  const checks = thresholdChecks(detectorFeatures);
  const signals = keySignals(detectorFeatures, contextFeatures);
  const windowSeconds = typeof detectorFeatures?.window_seconds === "number" ? detectorFeatures.window_seconds : null;
  const consumed = new Set<string>([
    ...(sequence?.consumes ?? []),
    ...thresholdKeys(checks),
    ...signals.flatMap((sig) => sig.consumes),
    // The shared-NAT caveat is stated once, in the header and the context limitations.
    "d:src_ip_shared_nat",
    "d:source_ip_shared_nat",
    ...(checks.length > 0 && windowSeconds !== null ? ["d:window_seconds"] : []),
  ]);
  const remaining = remainingDetectorFeatures(detectorFeatures, consumed);
  const groups = context ? contextFeatureGroups(contextFeatures, detectorFeatures, consumed) : [];
  const span = secondsBetween(alert.window_start, alert.window_end);

  return (
    <div className="grid gap-6">
      <SectionCard
        title="Why this rule fired"
        titleId="established-title"
        icon={ScrollText}
        description="The rule's logic and what the detector found in stored telemetry (deterministic)"
      >
        <div className="grid gap-5">
          {ruleDescription ? (
            <p className="max-w-[85ch] text-base leading-relaxed text-fg-2">
              <UntrustedText value={ruleDescription} limit={900} />
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">The rule definition for this alert&apos;s version is unavailable.</p>
          )}
          <div className="rounded-lg bg-white/[0.02] px-4 py-3.5 ring-1 ring-hairline ring-inset">
            <Eyebrow>What the detector found</Eyebrow>
            <p className="mt-1.5 text-base leading-relaxed text-foreground">
              <UntrustedText value={alert.summary} limit={900} />
            </p>
          </div>
          <KeySignals sequence={sequence} checks={checks} signals={signals} windowSeconds={windowSeconds} />
          <dl className="grid gap-x-6 gap-y-4 border-t border-hairline-soft pt-4 text-sm sm:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)_minmax(0,1fr)]">
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">Evaluated span (UTC)</dt>
              <dd className="mt-1 grid gap-0.5">
                <Timestamp value={alert.window_start} />
                <Timestamp value={alert.window_end} />
                <span className="text-xs text-muted-foreground tabular-nums">
                  {span !== null ? `${formatDuration(span)} of rule runs` : null}
                  {windowSeconds !== null ? ` · ${formatWindowLength(windowSeconds)} sliding window` : null}
                </span>
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">Group key</dt>
              <dd className="mt-1 text-fg-2">
                <UntrustedText value={alert.group_key} limit={120} oneLine mono />
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-xs text-muted-foreground">Detector</dt>
              <dd className="mt-1 font-mono text-xs text-fg-2">
                <UntrustedText value={alert.detector_version} limit={60} />
              </dd>
            </div>
          </dl>
        </div>
      </SectionCard>

      <SectionCard
        title="Entities and features"
        titleId="entities-title"
        icon={Fingerprint}
        description="Computed from stored telemetry by the detector and the correlation layer; nothing here is AI output"
      >
        <div className="grid gap-6">
          <div>
            <Eyebrow className="mb-2">Grouping entities</Eyebrow>
            {entities.length === 0 ? (
              <p className="text-sm text-muted-foreground">The rule recorded no grouping entity.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {entities.map(([key, value]) => (
                  <KeyChip key={key} label={featureLabel(key)}>
                    <UntrustedText value={value} limit={80} />
                  </KeyChip>
                ))}
              </div>
            )}
          </div>
          <div className="min-w-0 border-t border-hairline-soft pt-5">
            <Eyebrow>Detector features</Eyebrow>
            <FeatureTable
              features={remaining}
              labels={DETECTOR_LABEL}
              empty={
                Object.keys(detectorFeatures ?? {}).length > 0
                  ? "Every detector feature is shown under Key signals above."
                  : "The detector recorded no features for this alert."
              }
            />
          </div>
          <div className="min-w-0 border-t border-hairline-soft pt-5">
            <Eyebrow>Correlation context</Eyebrow>
            {context ? (
              <ContextGroups groups={groups} />
            ) : (
              <ErrorState
                what="the investigation context"
                error={contextError ?? { kind: "server", message: "No context was returned.", requestId: "-" }}
                className="mt-2"
              />
            )}
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="Involved services and assets"
        titleId="involved-title"
        icon={Layers}
        description="Services whose telemetry is evidence or related activity, with their telemetry coverage"
      >
        {!context ? (
          <ErrorState
            what="the investigation context"
            error={contextError ?? { kind: "server", message: "No context was returned.", requestId: "-" }}
          />
        ) : (
          <InvolvedServices context={context} />
        )}
      </SectionCard>
    </div>
  );
}

/**
 * Correlation-layer features grouped by source (SSH, HTTP, application, host changes,
 * Kubernetes, GitHub, scope); counters that are exactly 0 fold behind one line per page.
 */
function ContextGroups({ groups }: { groups: FeatureGroup[] }) {
  const zeros = groups.flatMap((g) => g.zeros);
  const shown = groups.filter((g) => g.rows.length > 0);
  if (shown.length === 0 && zeros.length === 0) {
    return <FeatureTable entries={[]} empty="The investigation context holds no further computed features." />;
  }
  return (
    <div className="mt-3 grid gap-5">
      {shown.map((group) => (
        <div key={group.id} className="grid gap-0.5">
          <p className="text-sm font-medium text-foreground">{group.title}</p>
          <FeatureTable entries={group.rows} empty="" />
        </div>
      ))}
      {zeros.length > 0 ? (
        <Disclosure
          label={`Show ${formatCount(zeros.length)} zero counter${zeros.length === 1 ? "" : "s"}`}
          openLabel={`Hide ${formatCount(zeros.length)} zero counter${zeros.length === 1 ? "" : "s"}`}
          triggerClassName="text-muted-foreground"
        >
          <div className="mt-2">
            <FeatureTable entries={zeros} empty="" />
          </div>
        </Disclosure>
      ) : null}
    </div>
  );
}

function InvolvedServices({ context }: { context: InvestigationContext }) {
  const services = [...context.services].sort((a, b) =>
    a.role === b.role ? a.name.localeCompare(b.name) : a.role === "evidence" ? -1 : 1,
  );
  return (
    <div className="grid gap-4">
      {services.length === 0 ? (
        <EmptyState>No service is attributed to this alert&apos;s evidence or related activity.</EmptyState>
      ) : (
        <ul className="divide-y divide-hairline-soft">
          {services.map((service) => {
            const href = serviceHref(service.service_id);
            return (
              <li key={service.service_id} className="grid gap-x-4 gap-y-1.5 py-3 first:pt-0 last:pb-0 sm:grid-cols-[minmax(0,1fr)_9rem_9rem] sm:items-center">
                <div className="min-w-0">
                  {href ? (
                    <Link href={href} className="block truncate text-sm font-medium text-foreground hover:underline">
                      <UntrustedText value={service.name} limit={80} plain />
                    </Link>
                  ) : (
                    <span className="block truncate text-sm font-medium text-foreground">
                      <UntrustedText value={service.name} limit={80} />
                    </span>
                  )}
                  <span className="mt-0.5 flex min-w-0 flex-wrap items-center gap-x-1.5 text-xs text-muted-foreground">
                    {serviceKindLabel(service.service_kind)} · {categoryLabel(service.category)} ·
                    <span className="min-w-0 font-mono">
                      <UntrustedText value={service.asset_id} limit={64} />
                    </span>
                  </span>
                </div>
                <span className={service.role === "evidence" ? "text-sm text-foreground" : "text-sm text-muted-foreground"}>
                  {service.role === "evidence" ? "Evidence source" : service.role === "related" ? "Related activity" : service.role}
                </span>
                <span className="text-sm">
                  <CoverageBadge service={service} />
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {context.related_assets.length > 0 ? (
        <div className="border-t border-hairline-soft pt-4">
          <Eyebrow className="mb-2">Other assets with related activity</Eyebrow>
          <ul className="grid gap-1.5">
            {context.related_assets.map((asset) => (
              <li key={asset.asset_id} className="flex items-baseline gap-2 text-sm">
                <Link href={assetHref(asset.asset_id)} className="text-fg-2 hover:text-foreground hover:underline">
                  <UntrustedText value={asset.name} limit={64} plain />
                </Link>
                <span className="text-xs text-muted-foreground">{assetTypeLabel(asset.asset_type)}</span>
              </li>
            ))}
          </ul>
          <Notice className="mt-3">
            Cross-asset links are drawn only with identity evidence; each observation&apos;s basis is in Correlation.
          </Notice>
        </div>
      ) : null}
      {context.truncated.services ? (
        <Notice>The context builder capped the service list; {formatCount(services.length)} are shown.</Notice>
      ) : null}
    </div>
  );
}

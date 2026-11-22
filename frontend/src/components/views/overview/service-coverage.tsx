import { cn } from "cn";
import { Layers } from "lucide-react";
import Link from "next/link";

import { CardLink, SectionCard } from "@/components/console/section-card";
import { EmptyState } from "@/components/console/states";
import { Hint } from "@/components/console/hint";
import type { ServicesSummary } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { SERVICE_GROUPS, serviceKindLabel } from "@/lib/services";

import { CoverageDonut } from "./coverage-donut";

const PARTS = [
  {
    key: "monitored",
    label: "Monitored",
    fill: "bg-cov-monitored",
    color: "var(--xq-cov-monitored)",
    hint: "Adapter enabled and its telemetry sources are fresh.",
  },
  {
    key: "degraded",
    label: "Degraded",
    fill: "bg-cov-degraded",
    color: "var(--xq-cov-degraded)",
    hint: "Adapter enabled, but its telemetry sources are stale, failing or partly unavailable.",
  },
  {
    key: "unmonitored",
    label: "Unmonitored",
    fill: "bg-cov-unmonitored",
    color: "var(--xq-cov-unmonitored)",
    hint: "A telemetry adapter exists, but it is not enabled or not configured for this service.",
  },
  {
    key: "planned",
    label: "Planned adapter",
    fill: "bg-cov-planned",
    color: "var(--xq-cov-planned)",
    hint: "An adapter is planned but not implemented; no service-specific telemetry is collected.",
  },
  {
    key: "unsupported",
    label: "Unsupported",
    fill: "bg-cov-unsupported",
    color: "var(--xq-cov-unsupported)",
    hint: "No telemetry adapter exists for this service type. Listed so the gap stays visible.",
  },
] as const;

function Stacked({ coverage, label }: { coverage: ServicesSummary["coverage"]; label: string }) {
  const total = Math.max(1, coverage.total);
  return (
    <div
      role="img"
      aria-label={`${label}: ${PARTS.map((p) => `${coverage[p.key]} ${p.label.toLowerCase()}`).join(", ")}`}
      className="flex h-2 w-full gap-px overflow-hidden rounded-full bg-hairline"
    >
      {coverage.total > 0
        ? PARTS.map((p) =>
            coverage[p.key] > 0 ? (
              <span key={p.key} className={cn("h-full", p.fill)} style={{ width: `${(coverage[p.key] / total) * 100}%` }} />
            ) : null,
          )
        : null}
    </div>
  );
}

/**
 * Service coverage across every asset: a donut of the five coverage states (true proportions)
 * with the counts listed beside it, then one stacked bar per service kind. Unsupported and
 * unmonitored services are shown, never hidden.
 */
export function ServiceCoverageCard({
  summary,
  className,
}: {
  summary: ServicesSummary | null | undefined;
  className?: string;
}) {
  const kinds = summary
    ? [...summary.by_kind].sort(
        (a, b) =>
          SERVICE_GROUPS.findIndex((g) => g.kind === a.service_kind) - SERVICE_GROUPS.findIndex((g) => g.kind === b.service_kind),
      )
    : [];
  const covered = summary ? summary.coverage.monitored + summary.coverage.degraded : 0;
  return (
    <SectionCard
      title="Service coverage"
      titleId="service-coverage-title"
      icon={Layers}
      description={
        summary?.reported ? (
          <>
            <span className="text-fg-2 tabular-nums">{formatCount(summary.coverage.total)}</span> services discovered across all
            assets
          </>
        ) : (
          "Services discovered on every asset"
        )
      }
      className={className}
      action={
        <Link href="/assets" className="group/link">
          <CardLink>Assets</CardLink>
        </Link>
      }
    >
      {!summary ? (
        <EmptyState>The analyst API did not report service coverage.</EmptyState>
      ) : !summary.reported ? (
        <EmptyState>Service discovery has not reported for any asset yet, so service coverage is unknown.</EmptyState>
      ) : (
        <div className="grid gap-x-8 gap-y-6 lg:grid-cols-[minmax(0,11fr)_minmax(0,9fr)]">
          <div className="flex flex-col items-center gap-6 sm:flex-row">
            <CoverageDonut
              parts={PARTS.map((p) => ({ key: p.key, label: p.label, value: summary.coverage[p.key], color: p.color }))}
              centerValue={`${formatCount(covered)}/${formatCount(summary.coverage.total)}`}
              centerLabel="with an enabled adapter"
              label={`Service coverage: ${PARTS.map((p) => `${summary.coverage[p.key]} ${p.label.toLowerCase()}`).join(", ")}`}
            />
            <ul className="grid w-full min-w-0 flex-1 gap-0.5">
              {PARTS.map((p) => {
                const value = summary.coverage[p.key];
                return (
                  <li key={p.key} className="flex h-8 items-center gap-2.5 text-sm">
                    <span aria-hidden="true" className={cn("size-2 flex-none rounded-full", p.fill)} />
                    <Hint content={p.hint}>
                      <span className="text-fg-2">{p.label}</span>
                    </Hint>
                    <span aria-hidden="true" className="mx-1 h-px min-w-4 flex-1 border-b border-dashed border-hairline" />
                    <span className={cn("tabular-nums", value > 0 ? "font-medium text-foreground" : "text-muted-foreground")}>
                      {formatCount(value)}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>

          <div className="grid content-center gap-3.5 border-t border-hairline-soft pt-5 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-8">
            <p className="text-xs text-muted-foreground">By service kind</p>
            {kinds.map((k) => {
              const gaps = k.coverage.degraded + k.coverage.unmonitored;
              return (
                <div key={k.service_kind} className="grid gap-1.5">
                  <div className="flex items-baseline justify-between gap-3 text-xs">
                    <span className="truncate text-sm text-fg-2">
                      {SERVICE_GROUPS.find((g) => g.kind === k.service_kind)?.title ?? serviceKindLabel(k.service_kind)}
                    </span>
                    <span className="flex-none text-muted-foreground tabular-nums">
                      <span className="text-fg-2">{formatCount(k.coverage.monitored)}</span>/{formatCount(k.coverage.total)}{" "}
                      monitored
                      {gaps > 0 ? (
                        <>
                          {" · "}
                          <span className="text-health-warn">{formatCount(gaps)}</span> {gaps === 1 ? "gap" : "gaps"}
                        </>
                      ) : null}
                    </span>
                  </div>
                  <Stacked coverage={k.coverage} label={serviceKindLabel(k.service_kind)} />
                </div>
              );
            })}
          </div>

          {summary.removed > 0 || summary.truncated || summary.note ? (
            <p className="text-xs text-muted-foreground lg:col-span-2">
              {summary.removed > 0 ? `${formatCount(summary.removed)} removed services are not counted. ` : ""}
              {summary.truncated ? "More service records exist than the API evaluated. " : ""}
              {summary.note ?? ""}
            </p>
          ) : null}
        </div>
      )}
    </SectionCard>
  );
}

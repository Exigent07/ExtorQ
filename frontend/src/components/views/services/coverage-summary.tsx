import { cn } from "cn";
import type { ReactNode } from "react";

import { Hint } from "@/components/console/hint";
import { SplitBar } from "@/components/console/kpi-card";
import type { ServicesSummary } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

const STATES = [
  {
    key: "monitored",
    label: "Monitored",
    sub: "adapter enabled, sources fresh",
    dot: "bg-cov-monitored",
    hint: "Adapter enabled and its telemetry sources are fresh.",
  },
  {
    key: "degraded",
    label: "Degraded",
    sub: "stale or failing sources",
    dot: "bg-cov-degraded",
    hint: "Adapter enabled, but its telemetry sources are stale, failing or partly unavailable.",
  },
  {
    key: "unmonitored",
    label: "Unmonitored",
    sub: "adapter exists, not enabled",
    dot: "bg-cov-unmonitored",
    hint: "A telemetry adapter exists, but it is not enabled or not configured for this service.",
  },
  {
    key: "planned",
    label: "Planned adapter",
    sub: "discovered only",
    dot: "ring-1 ring-cov-planned ring-inset",
    hint: "An adapter is planned but not implemented; no service-specific telemetry is collected.",
  },
  {
    key: "unsupported",
    label: "Unsupported",
    sub: "no adapter for the type",
    dot: "bg-cov-unsupported",
    hint: "No telemetry adapter exists for this service type. Listed so the gap stays visible.",
  },
] as const;

const BAR_FILL: Record<(typeof STATES)[number]["key"], string> = {
  monitored: "bg-cov-monitored",
  degraded: "bg-cov-degraded",
  unmonitored: "bg-cov-unmonitored",
  planned: "bg-cov-planned",
  unsupported: "bg-cov-unsupported",
};

/**
 * Service coverage of one asset (or one level of it): how many services discovery reports and
 * how many of them are monitored, degraded, unmonitored, planned or unsupported, as figures
 * and as one proportional bar. Counts are the API's (present services; removed apart).
 */
export function CoverageSummaryCard({
  summary,
  title = "Discovered",
  footer,
  className,
}: {
  summary: ServicesSummary;
  /** Label of the total (smoke markers rely on "Discovered"). */
  title?: string;
  footer?: ReactNode;
  className?: string;
}) {
  const c = summary.coverage;
  return (
    <section aria-label="Service coverage" className={cn("rounded-xl bg-card shadow-card ring-1 ring-hairline", className)}>
      <dl className="grid grid-cols-2 gap-y-4 px-5 pt-4 sm:grid-cols-3 lg:grid-cols-6">
        <div className="min-w-0 pr-4">
          <dt className="text-sm text-muted-foreground">{title}</dt>
          <dd className="mt-1 text-2xl leading-8 font-semibold tracking-tight text-foreground tabular-nums">{formatCount(c.total)}</dd>
          <dd className="mt-0.5 text-xs text-muted-foreground">
            {summary.removed > 0 ? `${formatCount(summary.removed)} removed, not counted` : "currently present"}
          </dd>
        </div>
        {STATES.map((s) => (
          <div key={s.key} className="min-w-0 border-hairline-soft pr-4 lg:border-l lg:pl-5">
            <dt className="flex items-center gap-2 text-sm text-muted-foreground">
              <span aria-hidden="true" className={cn("size-2 flex-none rounded-full", s.dot)} />
              <Hint content={s.hint}>
                <span>{s.label}</span>
              </Hint>
            </dt>
            <dd
              className={cn(
                "mt-1 text-2xl leading-8 font-semibold tracking-tight tabular-nums",
                c[s.key] > 0 ? "text-foreground" : "text-muted-foreground",
              )}
            >
              {formatCount(c[s.key])}
            </dd>
            <dd className="mt-0.5 text-xs text-muted-foreground">{s.sub}</dd>
          </div>
        ))}
      </dl>
      <div className="px-5 pt-4 pb-4">
        <SplitBar
          className="h-2"
          label={`Service coverage: ${STATES.map((s) => `${c[s.key]} ${s.label.toLowerCase()}`).join(", ")}`}
          parts={STATES.map((s) => ({ key: s.key, value: c[s.key], className: BAR_FILL[s.key] }))}
        />
      </div>
      {footer ? <div className="border-t border-hairline-soft px-5 py-3 text-xs text-muted-foreground">{footer}</div> : null}
    </section>
  );
}

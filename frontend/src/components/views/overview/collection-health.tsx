import { Activity, CircleX, Clock, Cpu, FileWarning, ListChecks, Radio } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { CardLink, SectionCard } from "@/components/console/section-card";
import { StatusDot, type Tone } from "@/components/console/status-badge";
import type { CollectionHealthSummary } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

function Row({
  icon: Icon,
  label,
  detail,
  children,
}: {
  icon: typeof Activity;
  label: string;
  detail?: ReactNode;
  children: ReactNode;
}) {
  return (
    <li className="flex min-h-12 items-center gap-3 py-2">
      <Icon className="size-4 flex-none text-muted-foreground" strokeWidth={1.75} aria-hidden="true" />
      <span className="grid min-w-0 flex-1">
        <span className="truncate text-sm text-fg-2">{label}</span>
        {detail ? <span className="truncate text-xs text-muted-foreground">{detail}</span> : null}
      </span>
      <span className="flex-none text-right text-sm">{children}</span>
    </li>
  );
}

function Count({ value, tone }: { value: number; tone: Tone }) {
  return (
    <span className={value > 0 ? (tone === "bad" ? "font-medium text-health-bad" : "font-medium text-health-warn") : "text-fg-2"}>
      <span className="tabular-nums">{formatCount(value)}</span>
    </span>
  );
}

/** Collectors, pipeline and rule execution at a glance; zeros print as 0, missing reports say so. */
export function CollectionHealthCard({ summary, className }: { summary: CollectionHealthSummary; className?: string }) {
  const collectorsTone: Tone = summary.collectors_failing > 0 ? "bad" : summary.collectors_stale > 0 ? "warn" : "ok";
  // The API counts a component that is stale, failing or disabled by configuration; the summary
  // does not say which, so the row is amber and System health names the component.
  const pipelineTone: Tone = summary.pipeline_unhealthy > 0 ? "warn" : "ok";
  const rulesTone: Tone = summary.rules_failing > 0 ? "bad" : "ok";
  return (
    <SectionCard
      title="Collection health"
      titleId="collection-title"
      icon={Activity}
      description="Is telemetry arriving and are the rules running?"
      className={className}
      footer={
        <Link href="/health" className="group/link flex items-center justify-end">
          <CardLink>Open system health</CardLink>
        </Link>
      }
    >
      <ul className="divide-y divide-hairline-soft">
        <Row icon={Radio} label="Collectors reporting OK" detail="Status OK and not stale">
          {summary.no_collector_reports ? (
            <StatusDot tone="bad" label="No collector has reported" />
          ) : (
            <StatusDot
              tone={collectorsTone}
              label={`${formatCount(summary.collectors_ok)} of ${formatCount(summary.collectors_total)}`}
              className="tabular-nums"
            />
          )}
        </Row>
        <Row icon={Clock} label="Stale collectors" detail="No successful collection within 3 intervals">
          <Count value={summary.collectors_stale} tone="warn" />
        </Row>
        <Row icon={CircleX} label="Failing collectors" detail="Last report failed or degraded">
          <Count value={summary.collectors_failing} tone="bad" />
        </Row>
        <Row icon={Cpu} label="Pipeline components not OK" detail="Stale, failing or disabled">
          {summary.no_pipeline_reports ? (
            <StatusDot tone="bad" label="No pipeline reports" />
          ) : (
            <StatusDot
              tone={pipelineTone}
              label={`${formatCount(summary.pipeline_unhealthy)} of ${formatCount(summary.pipeline_components)}`}
              className="tabular-nums"
            />
          )}
        </Row>
        <Row icon={ListChecks} label="Rules failing (last run)">
          {summary.no_rule_runs ? (
            <StatusDot tone="warn" label="No rule has run yet" />
          ) : (
            <StatusDot
              tone={rulesTone}
              label={`${formatCount(summary.rules_failing)} of ${formatCount(summary.rules_total)}`}
              className="tabular-nums"
            />
          )}
        </Row>
        <Row icon={FileWarning} label="Rule failures, last 24 h">
          <Count value={summary.rule_failures_24h} tone="bad" />
        </Row>
      </ul>
    </SectionCard>
  );
}

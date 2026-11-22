import { Activity, CircleX, Clock, Cpu, ListChecks, Radio } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Fraction } from "@/components/console/kpi-card";
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

/**
 * The value column: a plain figure; a status dot only when the value is abnormal (never a
 * green dot on a zero).
 */
function Value({ children, tone }: { children: ReactNode; tone: Tone | null }) {
  return (
    <span className="inline-flex items-center gap-2 tabular-nums">
      {tone && tone !== "ok" ? <StatusDot tone={tone} label="" className="gap-0" /> : null}
      <span className={tone && tone !== "ok" ? "font-medium text-foreground" : "text-fg-2"}>{children}</span>
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
            <Value tone={summary.collectors_ok < summary.collectors_total ? collectorsTone : null}>
              <Fraction value={summary.collectors_ok} total={summary.collectors_total} />
            </Value>
          )}
        </Row>
        <Row icon={Clock} label="Stale collectors" detail="No successful collection within 3 intervals">
          <Value tone={summary.collectors_stale > 0 ? "warn" : null}>{formatCount(summary.collectors_stale)}</Value>
        </Row>
        <Row icon={CircleX} label="Failing collectors" detail="Last report failed or degraded">
          <Value tone={summary.collectors_failing > 0 ? "bad" : null}>{formatCount(summary.collectors_failing)}</Value>
        </Row>
        <Row icon={Cpu} label="Pipeline components not OK" detail="Stale, failing or disabled">
          {summary.no_pipeline_reports ? (
            <StatusDot tone="bad" label="No pipeline reports" />
          ) : (
            <Value tone={summary.pipeline_unhealthy > 0 ? pipelineTone : null}>
              {formatCount(summary.pipeline_unhealthy)} <span className="text-muted-foreground">of {formatCount(summary.pipeline_components)}</span>
            </Value>
          )}
        </Row>
        <Row
          icon={ListChecks}
          label="Rule failures"
          detail={summary.no_rule_runs ? undefined : `${formatCount(summary.rules_total)} rules: last run, and runs in 24 h`}
        >
          {summary.no_rule_runs ? (
            <StatusDot tone="warn" label="No rule has run yet" />
          ) : (
            <Value tone={summary.rules_failing > 0 || summary.rule_failures_24h > 0 ? rulesTone === "bad" ? "bad" : "warn" : null}>
              {formatCount(summary.rules_failing)} <span className="text-muted-foreground">last run ·</span>{" "}
              {formatCount(summary.rule_failures_24h)} <span className="text-muted-foreground">in 24 h</span>
            </Value>
          )}
        </Row>
      </ul>
    </SectionCard>
  );
}

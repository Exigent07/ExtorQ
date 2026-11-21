import Link from "next/link";

import { Panel } from "@/components/console/panel";
import { StatusDot } from "@/components/console/status-badge";
import type { CollectionHealthSummary } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <li className="flex min-h-8 items-center justify-between gap-4 py-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="text-right text-sm">{children}</span>
    </li>
  );
}

/** Collection health strip: collectors, pipeline and rule execution at a glance. */
export function CollectionHealthPanel({ summary }: { summary: CollectionHealthSummary }) {
  const collectorsTone =
    summary.collectors_failing > 0 ? "bad" : summary.collectors_stale > 0 ? "warn" : "ok";
  const pipelineTone = summary.pipeline_unhealthy > 0 ? "bad" : "ok";
  const rulesTone = summary.rules_failing > 0 ? "bad" : "ok";
  return (
    <Panel
      titleId="collection-title"
      title="Collection health"
      action={
        <Link href="/health" className="hover:text-ink">
          Details
        </Link>
      }
    >
      <ul className="divide-y divide-rule">
        <Row label="Collectors reporting OK">
          {summary.no_collector_reports ? (
            <StatusDot tone="bad" label="No collector has reported" />
          ) : (
            <StatusDot
              tone={collectorsTone}
              label={`${formatCount(summary.collectors_ok)} of ${formatCount(summary.collectors_total)}`}
            />
          )}
        </Row>
        <Row label="Stale collectors">
          <span className={summary.collectors_stale > 0 ? "font-mono text-warn" : "font-mono text-muted-foreground"}>
            {formatCount(summary.collectors_stale)}
          </span>
        </Row>
        <Row label="Failing collectors">
          <span className={summary.collectors_failing > 0 ? "font-mono text-bad" : "font-mono text-muted-foreground"}>
            {formatCount(summary.collectors_failing)}
          </span>
        </Row>
        <Row label="Pipeline components unhealthy">
          {summary.no_pipeline_reports ? (
            <StatusDot tone="bad" label="No pipeline reports" />
          ) : (
            <StatusDot
              tone={pipelineTone}
              label={`${formatCount(summary.pipeline_unhealthy)} of ${formatCount(summary.pipeline_components)}`}
            />
          )}
        </Row>
        <Row label="Rules failing (last run)">
          {summary.no_rule_runs ? (
            <StatusDot tone="warn" label="No rule has run yet" />
          ) : (
            <StatusDot
              tone={rulesTone}
              label={`${formatCount(summary.rules_failing)} of ${formatCount(summary.rules_total)}`}
            />
          )}
        </Row>
        <Row label="Rule failures, last 24 h">
          <span className={summary.rule_failures_24h > 0 ? "font-mono text-bad" : "font-mono text-muted-foreground"}>
            {formatCount(summary.rule_failures_24h)}
          </span>
        </Row>
      </ul>
    </Panel>
  );
}

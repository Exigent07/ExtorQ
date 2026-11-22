import type { Metadata } from "next";

import { Freshness } from "@/components/console/freshness";
import { MetricStrip } from "@/components/console/key-values";
import { PageHeader } from "@/components/console/page-header";
import { Panel } from "@/components/console/panel";
import { EmptyState, ErrorState } from "@/components/console/states";
import { StatusDot } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import { CollectorTable } from "@/components/views/assets/collector-table";
import {
  AIHealthPanel,
  IngestSecurityPanel,
  PipelinePanel,
  RuleHealthPanel,
} from "@/components/views/health/health-sections";
import type { HealthResponse } from "@/lib/api/schemas";
import { DASH, formatCount, formatDuration } from "@/lib/format";
import { spoolBacklog } from "@/lib/health";
import { getHealth } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "System health" };

function summarize(data: HealthResponse) {
  const collectorsOk = data.collectors.filter((c) => c.status === "ok" && !c.stale).length;
  const stale = data.collectors.filter((c) => c.stale).length;
  const failing = data.collectors.filter((c) => c.status === "failed").length;
  const pipeline = data.pipeline.filter((p) => !p.superseded);
  // One shared spool: gateway and writer report the same depth (not summed); other
  // components' queues (detector backlog, AI triage) are not ingestion.
  const { depth: queue, oldestSeconds: oldest } = spoolBacklog(data.pipeline);
  const ruleFailures = data.rules.reduce((sum, r) => sum + (r.last_run?.failures_24h ?? 0), 0);
  return { collectorsOk, stale, failing, queue, oldest, ruleFailures, pipelineCount: pipeline.length };
}

function finding(data: HealthResponse): string {
  const s = summarize(data);
  const parts = [data.storage.reachable ? "Storage reachable" : "Storage unreachable"];
  parts.push(
    data.collectors.length === 0
      ? "no collector has reported"
      : `${formatCount(s.collectorsOk)} of ${formatCount(data.collectors.length)} collectors healthy and fresh`,
  );
  if (s.queue !== null) parts.push(`${formatCount(s.queue)} record${s.queue === 1 ? "" : "s"} in the ingestion spool`);
  if (data.ingest) parts.push(`${formatCount(data.ingest.quarantined_records)} quarantined in ${data.ingest.window_hours} h`);
  parts.push(`${formatCount(s.ruleFailures)} rule failure${s.ruleFailures === 1 ? "" : "s"} in 24 h`);
  return parts.join(" · ");
}

export default async function HealthPage() {
  const session = await requireSession();
  const result = await getHealth(session);
  if (!result.ok) {
    return (
      <>
        <PageHeader title="System health" />
        <ErrorState what="system health" error={result.error} />
      </>
    );
  }
  const data = result.data;
  const now = data.generated_at;
  const s = summarize(data);

  return (
    <>
      <PageHeader title="System health" finding={finding(data)} actions={<Freshness at={result.receivedAt} />} />
      <MetricStrip
        className="mb-6"
        items={[
          {
            label: "Storage",
            value: data.storage.reachable ? <StatusDot tone="ok" label="Reachable" /> : <StatusDot tone="bad" label="Unreachable" />,
            sub: data.storage.error ? <UntrustedText value={data.storage.error} limit={80} /> : undefined,
          },
          {
            label: "Collectors healthy",
            value: (
              <span className="font-mono">
                {formatCount(s.collectorsOk)}
                <span className="text-sm text-muted-foreground"> of {formatCount(data.collectors.length)}</span>
              </span>
            ),
            sub: `${formatCount(s.stale)} stale · ${formatCount(s.failing)} failed`,
          },
          {
            label: "Ingestion spool",
            value: <span className="font-mono">{s.queue === null ? DASH : formatCount(s.queue)}</span>,
            sub:
              s.queue === null
                ? "no current gateway or writer report"
                : s.oldest === null
                  ? "records queued; oldest: none"
                  : `records queued; oldest ${formatDuration(s.oldest)}`,
          },
          {
            label: "Quarantined",
            value: <span className="font-mono">{data.ingest ? formatCount(data.ingest.quarantined_records) : DASH}</span>,
            sub: data.ingest ? `last ${data.ingest.window_hours} h` : "not reported",
          },
          {
            label: "Rule failures",
            value: <span className={s.ruleFailures > 0 ? "font-mono text-bad" : "font-mono"}>{formatCount(s.ruleFailures)}</span>,
            sub: "last 24 h",
          },
        ]}
      />
      <div className="grid gap-6">
        <Panel title="Collectors" titleId="collectors-title" meta={<span>Latest report per collector</span>}>
          {data.collectors.length === 0 ? (
            <EmptyState>No collector has reported health yet, so telemetry coverage cannot be confirmed.</EmptyState>
          ) : (
            <CollectorTable collectors={data.collectors} now={now} showAsset />
          )}
        </Panel>
        <PipelinePanel pipeline={data.pipeline} now={now} />
        <div className="grid items-start gap-6 xl:grid-cols-2">
          <RuleHealthPanel rules={data.rules} now={now} />
          <div className="grid gap-6">
            <IngestSecurityPanel ingest={data.ingest} />
            <AIHealthPanel ai={data.ai} source={data.ai_configuration_source} now={now} />
          </div>
        </div>
        {data.notes.length > 0 ? (
          <Panel title="Notes from the API" titleId="health-notes-title">
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-ink-2">
              {data.notes.map((note) => (
                <li key={note}>
                  <UntrustedText value={note} limit={300} />
                </li>
              ))}
            </ul>
          </Panel>
        ) : null}
      </div>
    </>
  );
}

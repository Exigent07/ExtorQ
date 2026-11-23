import { Activity } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { PageHeader } from "@/components/console/page-header";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import { StatusPill } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import { CollectorsTable } from "@/components/views/health/collectors-table";
import {
  AITriageCard,
  HealthNotesCard,
  PipelineCard,
  QuarantineCard,
  RuleExecutionCard,
} from "@/components/views/health/health-sections";
import { HealthKpiRow } from "@/components/views/health/kpi-row";
import { collectorCounts, healthFinding } from "@/components/views/health/model";
import { formatCount } from "@/lib/format";
import { retiredHiddenText } from "@/lib/lifecycle";
import { getHealth } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "System health" };

/**
 * System health: can the telemetry behind every alert be trusted right now? Collectors
 * (fresh, stale, failing), the ingestion pipeline (backlog, rejections, write errors), rule
 * execution and advisory AI triage (Jev). One API read; every figure is the API's.
 */
export default async function HealthPage({ searchParams }: PageProps<"/health">) {
  const session = await requireSession();
  const query = await searchParams;
  const showRetired = (Array.isArray(query.retired) ? query.retired[0] : query.retired) === "1";
  const result = await getHealth(session, { includeRetired: showRetired });
  if (!result.ok) {
    return (
      <>
        <PageHeader title="System health" subtitle="Collectors, ingestion pipeline, rule execution and AI triage" />
        <ErrorState what="system health" error={result.error} />
      </>
    );
  }
  const data = result.data;
  const now = data.generated_at;
  const collectors = collectorCounts(data.collectors);
  const retiredHidden = showRetired ? null : retiredHiddenText(data.collectors_retired, { one: "collector", many: "collectors" });
  const retiredShown = showRetired ? data.collectors.filter((c) => c.lifecycle_state === "retired").length : 0;
  const toggle = "text-fg-2 underline-offset-2 transition-colors duration-150 hover:text-foreground hover:underline";

  return (
    <>
      <PageHeader
        title="System health"
        titleMeta={
          data.storage.reachable ? (
            <StatusPill tone="ok" label="Storage reachable" />
          ) : (
            <StatusPill tone="bad" label="Storage unreachable" />
          )
        }
        subtitle={healthFinding(data)}
        freshness={result.receivedAt}
      />
      <div className="grid gap-6">
        {!data.storage.reachable ? (
          <Notice tone="warn">
            The analyst API cannot reach ClickHouse, so every figure below may be incomplete.{" "}
            {data.storage.error ? <UntrustedText value={data.storage.error} limit={200} /> : null}
          </Notice>
        ) : null}

        <HealthKpiRow data={data} />

        <SectionCard
          title="Collectors"
          titleId="collectors-title"
          icon={Activity}
          description="Latest report per collector, problems first. The bar is the time since the last success against the staleness budget of 3 collection intervals."
          meta={
            data.collectors.length > 0 || retiredHidden || showRetired ? (
              <span className="tabular-nums">
                {formatCount(collectors.healthy)} of {formatCount(collectors.total)} healthy and fresh
                {retiredHidden ? (
                  <>
                    {" · "}
                    <Link href="/health?retired=1" className={toggle}>
                      {retiredHidden}
                    </Link>
                  </>
                ) : null}
                {showRetired ? (
                  <>
                    {` · ${formatCount(retiredShown)} retired shown · `}
                    <Link href="/health" className={toggle}>
                      Hide retired
                    </Link>
                  </>
                ) : null}
              </span>
            ) : null
          }
          flush
        >
          {data.collectors.length === 0 ? (
            <div className="px-5 pb-3">
              <EmptyState>No collector has reported health yet, so telemetry coverage cannot be confirmed.</EmptyState>
            </div>
          ) : (
            <CollectorsTable collectors={data.collectors} now={now} />
          )}
        </SectionCard>

        <PipelineCard pipeline={data.pipeline} now={now} />

        <div className="grid gap-6 xl:grid-cols-12">
          <RuleExecutionCard rules={data.rules} now={now} className="xl:col-span-8" />
          {/* The stack ends level with the rule table: the last card takes the remaining height. */}
          <div className="flex flex-col gap-6 xl:col-span-4">
            <QuarantineCard ingest={data.ingest} />
            <AITriageCard ai={data.ai} source={data.ai_configuration_source} now={now} className="flex-1" />
          </div>
        </div>

        {data.notes.length > 0 ? <HealthNotesCard notes={data.notes} /> : null}
      </div>
    </>
  );
}

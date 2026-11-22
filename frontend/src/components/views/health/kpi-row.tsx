import { KpiCard, KpiFigures, SplitBar } from "@/components/console/kpi-card";
import type { Tone } from "@/components/console/status-badge";
import type { HealthResponse } from "@/lib/api/schemas";
import { DASH, formatCount, formatDuration } from "@/lib/format";
import { spoolBacklog } from "@/lib/health";

import { collectorCounts, gatewayRejections, ruleExecution } from "./model";

/**
 * System health headline figures: collectors healthy and fresh, the ingestion spool backlog,
 * quarantined records and gateway rejections, and rule failures (the AI providers have their own card).
 * Each figure is the API's number or a sum of the API's rows; unknown values are a dash.
 */
export function HealthKpiRow({ data }: { data: HealthResponse }) {
  const collectors = collectorCounts(data.collectors);
  const spool = spoolBacklog(data.pipeline);
  const gateway = gatewayRejections(data.ingest);
  const rules = ruleExecution(data.rules);

  const spoolStatus: { tone: Tone; label: string } =
    spool.depth === null
      ? { tone: "off", label: "Unknown" }
      : spool.depth === 0
        ? { tone: "ok", label: "Drained" }
        : { tone: "warn", label: "Backlog" };

  const ruleStatus: { tone: Tone; label: string } =
    rules.total === 0
      ? { tone: "warn", label: "No rules" }
      : rules.failingNow > 0
        ? { tone: "bad", label: `${formatCount(rules.failingNow)} failing` }
        : rules.overdue > 0
          ? { tone: "warn", label: `${formatCount(rules.overdue)} overdue` }
          : rules.neverRan > 0
            ? { tone: "warn", label: `${formatCount(rules.neverRan)} never ran` }
            : rules.failures24h > 0
              ? { tone: "warn", label: "Recovered" }
              : { tone: "ok", label: "None" };

  return (
    // 4 cards (DESIGN §3): one row at xl, 2 + 2 below. The AI providers have their own card
    // further down; detection never waits for them.
    <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
      <KpiCard
        label="Collectors"
        value={formatCount(collectors.healthy)}
        unit={`/ ${formatCount(collectors.total)}`}
        status={{ tone: collectors.tone, label: collectors.label }}
        footer={
          <SplitBar
            label={`${collectors.healthy} healthy, ${collectors.degraded} degraded, ${collectors.stale} stale, ${collectors.failed} failed, ${collectors.other} disabled or unknown`}
            parts={[
              { key: "healthy", value: collectors.healthy, className: "bg-health-ok" },
              { key: "degraded", value: collectors.degraded, className: "bg-health-warn" },
              { key: "stale", value: collectors.stale, className: "bg-health-warn" },
              { key: "failed", value: collectors.failed, className: "bg-health-bad" },
              { key: "other", value: collectors.other, className: "bg-health-off" },
            ]}
          />
        }
        sub={
          collectors.total === 0 ? (
            "No collector has reported health yet."
          ) : (
            <KpiFigures
              items={[
                { label: "stale", value: collectors.stale, tone: "warn" as const },
                { label: "failed", value: collectors.failed, tone: "bad" as const },
                ...(collectors.degraded > 0 ? [{ label: "degraded", value: collectors.degraded, tone: "warn" as const }] : []),
              ]}
            />
          )
        }
        href="#collectors-title"
      />

      <KpiCard
        label="Ingestion spool"
        value={spool.depth === null ? DASH : formatCount(spool.depth)}
        unit={spool.depth === null ? undefined : spool.depth === 1 ? "record" : "records"}
        status={spoolStatus}
        sub={
          spool.depth === null
            ? "No current gateway or writer report."
            : spool.oldestSeconds === null
              ? "Nothing queued · one spool, gateway and writer"
              : `Oldest queued ${formatDuration(spool.oldestSeconds)} · one spool`
        }
        href="#pipeline-title"
      />

      <KpiCard
        label="Quarantined"
        value={data.ingest ? formatCount(data.ingest.quarantined_records) : DASH}
        unit={data.ingest ? (data.ingest.quarantined_records === 1 ? "record" : "records") : undefined}
        status={
          data.ingest
            ? data.ingest.quarantined_records > 0
              ? { tone: "warn", label: "Held" }
              : { tone: "ok", label: "None held" }
            : undefined
        }
        sub={
          gateway && data.ingest ? (
            <>
              <span className={gateway.rejected > 0 ? "font-medium text-health-warn tabular-nums" : "text-fg-2 tabular-nums"}>
                {formatCount(gateway.rejected)}
              </span>{" "}
              rejected at the gateway · last {formatCount(data.ingest.window_hours)} h
            </>
          ) : (
            "The API did not report ingestion security counters."
          )
        }
        href="#ingest-title"
      />

      <KpiCard
        label="Rule failures"
        value={formatCount(rules.failures24h)}
        status={ruleStatus}
        sub={
          <>
            Last 24 h · <span className="text-fg-2 tabular-nums">{formatCount(rules.runs24h)}</span> runs across{" "}
            <span className="text-fg-2 tabular-nums">{formatCount(rules.total)}</span> rule{rules.total === 1 ? "" : "s"}
          </>
        }
        href="#rule-health-title"
      />

    </div>
  );
}

import { KpiCard, SplitBar } from "@/components/console/kpi-card";
import type { Tone } from "@/components/console/status-badge";
import type { HealthResponse } from "@/lib/api/schemas";
import { DASH, formatCount, formatDuration, formatRelative } from "@/lib/format";
import { spoolBacklog } from "@/lib/health";

import { aiStatusLabel, aiSummary, collectorCounts, gatewayRejections, providerName, ruleExecution } from "./model";

function Figures({ items }: { items: { label: string; value: number; tone?: Tone }[] }) {
  return (
    <span className="flex flex-wrap gap-x-3 gap-y-1">
      {items.map((item) => (
        <span key={item.label} className="whitespace-nowrap">
          <span
            className={
              item.value > 0 && item.tone === "bad"
                ? "font-medium text-health-bad tabular-nums"
                : item.value > 0 && item.tone === "warn"
                  ? "font-medium text-health-warn tabular-nums"
                  : "text-fg-2 tabular-nums"
            }
          >
            {formatCount(item.value)}
          </span>{" "}
          {item.label}
        </span>
      ))}
    </span>
  );
}

/**
 * System health headline figures: collectors healthy and fresh, the ingestion spool backlog,
 * quarantined records and gateway rejections, rule failures and the AI providers (advisory).
 * Each figure is the API's number or a sum of the API's rows; unknown values are a dash.
 */
export function HealthKpiRow({ data }: { data: HealthResponse }) {
  const now = data.generated_at;
  const collectors = collectorCounts(data.collectors);
  const spool = spoolBacklog(data.pipeline);
  const gateway = gatewayRejections(data.ingest);
  const rules = ruleExecution(data.rules);
  const ai = aiSummary(data.ai);

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
    // 5 cards: one row at xl; 3 + 2 at lg (6-column grid, the second row's cards span half
    // each); 2 + 2 + 1 at sm (the last card spans the row). Rows always end level.
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-6 xl:grid-cols-5">
      <KpiCard
        label="Collectors"
        className="lg:col-span-2 xl:col-span-1"
        value={formatCount(collectors.healthy)}
        unit={`/ ${formatCount(collectors.total)}`}
        status={{ tone: collectors.tone, label: collectors.label }}
        footer={
          <SplitBar
            label={`${collectors.healthy} healthy, ${collectors.degraded} degraded, ${collectors.stale} stale, ${collectors.failed} failed, ${collectors.other} disabled or unknown`}
            parts={[
              { key: "healthy", value: collectors.healthy, className: "bg-health-ok" },
              { key: "degraded", value: collectors.degraded, className: "bg-health-warn" },
              { key: "stale", value: collectors.stale, className: "bg-health-warn/60" },
              { key: "failed", value: collectors.failed, className: "bg-health-bad" },
              { key: "other", value: collectors.other, className: "bg-health-off" },
            ]}
          />
        }
        sub={
          collectors.total === 0 ? (
            "No collector has reported health yet."
          ) : (
            <Figures
              items={[
                { label: "stale", value: collectors.stale, tone: "warn" },
                { label: "failed", value: collectors.failed, tone: "bad" },
                ...(collectors.degraded > 0 ? [{ label: "degraded", value: collectors.degraded, tone: "warn" as Tone }] : []),
              ]}
            />
          )
        }
        href="#collectors-title"
      />

      <KpiCard
        label="Ingestion spool"
        className="lg:col-span-2 xl:col-span-1"
        value={spool.depth === null ? DASH : formatCount(spool.depth)}
        unit={spool.depth === null ? undefined : spool.depth === 1 ? "record" : "records"}
        status={spoolStatus}
        sub={
          spool.depth === null
            ? "No current gateway or writer report."
            : spool.oldestSeconds === null
              ? "Oldest queued: none · shared by gateway and writer"
              : `Oldest queued ${formatDuration(spool.oldestSeconds)} · shared by gateway and writer`
        }
        href="#pipeline-title"
      />

      <KpiCard
        label="Quarantined"
        className="lg:col-span-2 xl:col-span-1"
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
        className="lg:col-span-3 xl:col-span-1"
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

      <KpiCard
        label="AI providers"
        className="sm:col-span-2 lg:col-span-3 xl:col-span-1"
        value={formatCount(ai.enabled)}
        unit={`/ ${formatCount(ai.total)} enabled`}
        status={ai.total === 0 ? { tone: "off", label: "None" } : ai.enabled === 0 ? { tone: "off", label: "Off" } : { tone: "ok", label: "On" }}
        sub={
          ai.lastCall ? (
            <>
              Advisory · last call {formatRelative(ai.lastCall.at, now)} ({providerName(ai.lastCall.provider)}
              {ai.lastCall.status ? `, ${aiStatusLabel(ai.lastCall.status)}` : ""})
            </>
          ) : (
            "Advisory · no assessment recorded. Detection never waits for AI."
          )
        }
        href="#ai-health-title"
      />
    </div>
  );
}

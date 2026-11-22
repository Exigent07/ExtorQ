import { cn } from "cn";
import { Bot, Cpu, ListChecks, NotebookText, ShieldBan } from "lucide-react";
import Link from "next/link";

import { Hint } from "@/components/console/hint";
import { CardLink, SectionCard } from "@/components/console/section-card";
import { EmptyState } from "@/components/console/states";
import { HealthBadge, StatusDot, StatusPill } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { RelativeTime } from "@/components/console/time";
import type { AIProviderHealth, HealthResponse, PipelineComponentHealth, RuleHealthItem } from "@/lib/api/schemas";
import { DASH, formatCount, formatDuration, formatInterval, formatMs, humanize } from "@/lib/format";
import { isRuleId } from "@/lib/security/ids";

import { aiStatusLabel, aiStatusTone, currentPipeline, gatewayRejections, providerName, ruleExecution } from "./model";

/** A counter: zeros muted, a real 0 printed as 0, unknown as a dash; tone only above a threshold. */
function Num({ value, tone }: { value: number | null | undefined; tone?: "warn" | "bad" }) {
  if (value === null || value === undefined) return <span className="text-muted-foreground">{DASH}</span>;
  return (
    <span
      className={cn(
        "tabular-nums",
        value === 0
          ? "text-muted-foreground"
          : tone === "bad"
            ? "font-medium text-health-bad"
            : tone === "warn"
              ? "font-medium text-health-warn"
              : "text-fg-2",
      )}
    >
      {formatCount(value)}
    </span>
  );
}

const COMPONENT_NAME: Record<string, string> = {
  ingest: "Ingest gateway",
  writer: "Writer",
  detector: "Detector",
  ai_worker: "AI worker",
};

/**
 * Ingestion gateway, writer, detector and AI worker: status, queue and the cumulative counters
 * of each component's latest health report.
 */
export function PipelineCard({ pipeline, now }: { pipeline: PipelineComponentHealth[]; now: string }) {
  const { current, superseded } = currentPipeline(pipeline);
  return (
    <SectionCard
      title="Ingestion pipeline"
      titleId="pipeline-title"
      icon={Cpu}
      description="Gateway, spool writer, detector and AI worker: queue depth and counters from each component's latest report."
      meta={
        superseded > 0 ? <span className="hidden tabular-nums sm:inline">{plural(superseded, "superseded report")} hidden</span> : null
      }
      flush
      footer="Counters are cumulative since each component instance started. The gateway and the writer share one ingestion spool."
    >
      {current.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No pipeline component has reported health. Queue depth and write errors are unknown.</EmptyState>
        </div>
      ) : (
        <div className="@container">
          <Table aria-label="Pipeline components">
            <TableHeader>
              <TableRow>
                <TableHead>Component</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Queue</TableHead>
                <TableHead className="hidden text-right @3xl:table-cell">Oldest queued</TableHead>
                <TableHead className="hidden text-right @2xl:table-cell">Accepted</TableHead>
                <TableHead className="hidden text-right @5xl:table-cell">Duplicates</TableHead>
                <TableHead className="hidden text-right @2xl:table-cell">Rejected</TableHead>
                <TableHead className="hidden text-right @3xl:table-cell">Quarantined</TableHead>
                <TableHead className="hidden text-right @4xl:table-cell">Written</TableHead>
                <TableHead className="hidden text-right @4xl:table-cell">Write errors</TableHead>
                <TableHead className="hidden text-right @5xl:table-cell">Dead letter</TableHead>
                <TableHead className="text-right">Reported</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {current.map((p) => (
                <TableRow key={`${p.component}|${p.instance}`}>
                  <TableCell className="py-3">
                    <div className="grid min-w-0 gap-1">
                      <span className="text-sm font-medium text-foreground">
                        {COMPONENT_NAME[p.component] ?? <UntrustedText value={p.component} plain limit={40} />}
                      </span>
                      <span className="max-w-48 font-mono text-xs text-muted-foreground">
                        <UntrustedText value={p.instance} oneLine mono />
                      </span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className="flex flex-wrap items-center gap-2">
                      <HealthBadge status={p.status} className="text-sm" />
                      {p.stale ? <StatusPill tone="warn" label="Report stale" /> : null}
                    </span>
                  </TableCell>
                  <TableCell className="text-right">
                    <Num value={p.queue_depth} tone="warn" />
                  </TableCell>
                  <TableCell className="hidden text-right text-sm tabular-nums @3xl:table-cell">
                    <span className={p.oldest_queued_age_seconds ? "text-fg-2" : "text-muted-foreground"}>
                      {formatDuration(p.oldest_queued_age_seconds)}
                    </span>
                  </TableCell>
                  <TableCell className="hidden text-right @2xl:table-cell">
                    <Num value={p.accepted_total} />
                  </TableCell>
                  <TableCell className="hidden text-right @5xl:table-cell">
                    <Num value={p.duplicate_total} />
                  </TableCell>
                  <TableCell className="hidden text-right @2xl:table-cell">
                    <Num value={p.rejected_total} tone="warn" />
                  </TableCell>
                  <TableCell className="hidden text-right @3xl:table-cell">
                    <Num value={p.quarantined_total} tone="warn" />
                  </TableCell>
                  <TableCell className="hidden text-right @4xl:table-cell">
                    <Num value={p.written_total} />
                  </TableCell>
                  <TableCell className="hidden text-right @4xl:table-cell">
                    <Num value={p.write_errors_total} tone="bad" />
                  </TableCell>
                  <TableCell className="hidden text-right @5xl:table-cell">
                    <Num value={p.dead_letter_total} tone="bad" />
                  </TableCell>
                  <TableCell className="text-right text-sm">
                    <RelativeTime value={p.last_reported_at} now={now} side="left" className="text-fg-2" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </SectionCard>
  );
}

function plural(count: number, one: string, many = `${one}s`): string {
  return `${formatCount(count)} ${count === 1 ? one : many}`;
}

const RUN_TONE: Record<string, "ok" | "warn" | "bad"> = { succeeded: "ok", skipped: "warn", failed: "bad" };
const RUN_LABEL: Record<string, string> = { succeeded: "Succeeded", skipped: "Skipped", failed: "Failed" };

/** Rule execution health: last run outcome and age, 24 h runs and failures, quiet sources. */
export function RuleExecutionCard({ rules, now, className }: { rules: RuleHealthItem[]; now: string; className?: string }) {
  const stats = ruleExecution(rules);
  return (
    <SectionCard
      title="Rule execution"
      titleId="rule-health-title"
      icon={ListChecks}
      description="Last evaluation of every registered rule and its runs in the last 24 hours."
      className={className}
      flush
      footer={
        <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
          <span className="tabular-nums">
            {rules.length > 0
              ? `${formatCount(stats.runs24h)} runs and ${plural(stats.failures24h, "failure")} in the last 24 h across ${plural(stats.total, "rule")}`
              : "No rule run recorded"}
          </span>
          <Link href="/detections?tab=rules" className="group/link">
            <CardLink>Detection rules</CardLink>
          </Link>
        </div>
      }
    >
      {rules.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No rule has been registered or run yet.</EmptyState>
        </div>
      ) : (
        <div className="@container">
          <Table aria-label="Rule execution">
            <TableHeader>
              <TableRow>
                <TableHead>Rule</TableHead>
                <TableHead className="w-[150px] @max-lg:pr-(--table-edge) @lg:w-[212px]">Last run</TableHead>
                <TableHead className="hidden w-[104px] text-right @lg:table-cell">Last 24 h</TableHead>
                <TableHead className="hidden w-[176px] @2xl:table-cell">
                  <Hint content="Source types with no events at all in the rule's last evaluation window. A quiet source can hide detections; it is not a rule failure.">
                    <span className="underline decoration-hairline-strong decoration-dotted underline-offset-4">Quiet sources</span>
                  </Hint>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((r) => {
                const run = r.last_run;
                return (
                  <TableRow key={r.rule_id}>
                    <TableCell className="py-3 whitespace-normal">
                      <p className="min-w-0 leading-snug">
                        <span className="mr-2 font-mono text-xs text-muted-foreground">{r.rule_id}</span>
                        {isRuleId(r.rule_id) ? (
                          <Link
                            href={`/detections?rule=${encodeURIComponent(r.rule_id)}`}
                            className="text-sm text-foreground underline-offset-4 transition-colors duration-150 hover:text-brand hover:underline"
                          >
                            <UntrustedText value={r.title ?? r.rule_id} plain limit={140} />
                          </Link>
                        ) : (
                          <UntrustedText value={r.title} limit={140} className="text-sm text-foreground" />
                        )}
                        {r.enabled === false ? <StatusPill tone="off" label="Disabled" className="ml-2 align-middle" /> : null}
                      </p>
                    </TableCell>
                    <TableCell className="@max-lg:pr-(--table-edge)">
                      {run ? (
                        <div className="grid min-w-0 gap-1">
                          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
                            <StatusDot tone={RUN_TONE[run.last_status] ?? "off"} label={RUN_LABEL[run.last_status] ?? run.last_status} />
                            <RelativeTime value={run.last_run_at} now={now} className="text-muted-foreground" />
                            {r.run_stale ? <StatusPill tone="warn" label="Overdue" /> : null}
                          </span>
                          {run.last_error ? (
                            <span className="min-w-0 text-xs text-health-bad">
                              <UntrustedText value={run.last_error} oneLine />
                            </span>
                          ) : (
                            <span className="text-xs text-muted-foreground tabular-nums">
                              {formatMs(run.last_duration_ms)} · {formatInterval(r.interval_seconds)}
                            </span>
                          )}
                        </div>
                      ) : (
                        <div className="grid gap-1">
                          <StatusDot tone="off" label="Never ran" className="text-sm" />
                          <span className="text-xs text-muted-foreground">{formatInterval(r.interval_seconds)}</span>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="hidden text-right @lg:table-cell">
                      {run ? (
                        <div className="grid justify-items-end gap-1 tabular-nums">
                          <span className="text-sm text-fg-2">{plural(run.runs_24h, "run")}</span>
                          <span className={cn("text-xs", run.failures_24h > 0 ? "font-medium text-health-bad" : "text-muted-foreground")}>
                            {plural(run.failures_24h, "failure")}
                          </span>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">{DASH}</span>
                      )}
                    </TableCell>
                    <TableCell className="hidden whitespace-normal @2xl:table-cell">
                      {!run ? (
                        <span className="text-muted-foreground">{DASH}</span>
                      ) : run.missing_sources.length === 0 ? (
                        <span className="text-sm text-muted-foreground">None</span>
                      ) : (
                        <ul aria-label="Sources without events" className="flex flex-wrap gap-1">
                          {run.missing_sources.slice(0, 3).map((source) => (
                            <li
                              key={source}
                              className="inline-flex h-5 items-center rounded-md bg-white/[0.03] px-1.5 font-mono text-xs text-muted-foreground ring-1 ring-hairline ring-inset"
                            >
                              <UntrustedText value={source} plain limit={40} />
                            </li>
                          ))}
                          {run.missing_sources.length > 3 ? (
                            <li className="text-xs text-muted-foreground">+{formatCount(run.missing_sources.length - 3)}</li>
                          ) : null}
                        </ul>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </SectionCard>
  );
}

/** Quarantined records and gateway authorisation rejections over the API's window. */
export function QuarantineCard({ ingest, className }: { ingest: HealthResponse["ingest"]; className?: string }) {
  const gateway = gatewayRejections(ingest);
  return (
    <SectionCard
      title="Quarantine and rejections"
      titleId="ingest-title"
      icon={ShieldBan}
      description="Held records and refused gateway requests."
      meta={ingest ? <span className="tabular-nums">Last {formatCount(ingest.window_hours)} h</span> : null}
      className={className}
    >
      {!ingest || !gateway ? (
        <EmptyState>The API did not report ingestion security counters.</EmptyState>
      ) : (
        <div className="grid gap-4">
          <dl className="grid grid-cols-2 gap-3">
            <div className="rounded-lg bg-white/[0.02] px-3.5 py-3 ring-1 ring-hairline ring-inset">
              <dt className="text-xs text-muted-foreground">Quarantined records</dt>
              <dd className="mt-1 text-xl font-semibold tracking-tight tabular-nums">
                <span className={ingest.quarantined_records > 0 ? "text-health-warn" : "text-foreground"}>
                  {formatCount(ingest.quarantined_records)}
                </span>
              </dd>
            </div>
            <div className="rounded-lg bg-white/[0.02] px-3.5 py-3 ring-1 ring-hairline ring-inset">
              <dt className="text-xs text-muted-foreground">Rejected at the gateway</dt>
              <dd className="mt-1 text-xl font-semibold tracking-tight tabular-nums">
                <span className={gateway.rejected > 0 ? "text-health-warn" : "text-foreground"}>{formatCount(gateway.rejected)}</span>
              </dd>
            </div>
          </dl>
          {gateway.decisions.length === 0 ? (
            <p className="text-sm text-muted-foreground">No gateway authorisation decision was audited in this window.</p>
          ) : (
            <ul aria-label="Gateway decisions" className="grid gap-2.5">
              {gateway.decisions.map((d) => {
                const max = gateway.decisions[0]?.count ?? 1;
                const share = gateway.rejected > 0 && d.rejection ? Math.round((d.count / gateway.rejected) * 100) : null;
                return (
                  <li key={d.decision} className="grid gap-1.5">
                    <span className="flex items-baseline justify-between gap-3 text-sm">
                      <span className="min-w-0 truncate text-fg-2 capitalize">
                        <UntrustedText value={humanize(d.decision)} plain limit={48} />
                      </span>
                      <span className="flex-none tabular-nums">
                        <span className="font-medium text-foreground">{formatCount(d.count)}</span>
                        {share !== null ? <span className="ml-2 text-xs text-muted-foreground">{share}%</span> : null}
                      </span>
                    </span>
                    <span aria-hidden="true" className="block h-1.5 w-full overflow-hidden rounded-full bg-white/[0.05]">
                      <span
                        className={cn("block h-full rounded-full", d.rejection ? "bg-health-warn/70" : "bg-fg-2/40")}
                        style={{ width: `${max > 0 ? (d.count / max) * 100 : 0}%` }}
                      />
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      )}
    </SectionCard>
  );
}

function ProviderRow({ provider, now }: { provider: AIProviderHealth; now: string }) {
  const counts = Object.entries(provider.status_counts).sort((a, b) => b[1] - a[1]);
  const enabled = provider.enabled;
  return (
    <li className="grid gap-2.5 py-3.5 first:pt-0 last:pb-0">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-medium text-foreground">
            {providerName(provider.provider)} <span className="font-normal text-muted-foreground">·</span>{" "}
            <span className="font-normal text-fg-2 capitalize">
              <UntrustedText value={provider.task} plain limit={32} />
            </span>
          </p>
          <p className="mt-0.5 font-mono text-xs text-muted-foreground">
            <UntrustedText value={provider.provider} plain limit={40} />
          </p>
        </div>
        <span className="flex flex-none flex-col items-end gap-1 text-xs">
          {enabled === null || enabled === undefined ? (
            <StatusDot tone="off" label="Flag unknown" />
          ) : enabled ? (
            <StatusDot tone="ok" label="Enabled" />
          ) : (
            <StatusDot tone="off" label="Disabled" />
          )}
          <span className="text-muted-foreground">
            {provider.configured === null || provider.configured === undefined
              ? "Key presence unknown"
              : provider.configured
                ? "Key configured"
                : "No key configured"}
          </span>
        </span>
      </div>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
        <div className="grid gap-0.5">
          <dt className="text-xs text-muted-foreground">Last call</dt>
          <dd className="flex flex-wrap items-center gap-x-2 text-fg-2">
            {provider.last_assessment_at ? (
              <>
                {provider.last_status ? (
                  <StatusDot tone={aiStatusTone(provider.last_status)} label={aiStatusLabel(provider.last_status)} />
                ) : null}
                <RelativeTime value={provider.last_assessment_at} now={now} className="text-muted-foreground" />
              </>
            ) : (
              <span className="text-muted-foreground">None recorded</span>
            )}
          </dd>
        </div>
        <div className="grid gap-0.5">
          <dt className="text-xs text-muted-foreground">Last successful</dt>
          <dd className="text-fg-2">
            {provider.last_ok_at ? <RelativeTime value={provider.last_ok_at} now={now} className="text-inherit" /> : <span className="text-muted-foreground">None recorded</span>}
          </dd>
        </div>
        <div className="col-span-2 grid gap-0.5">
          <dt className="text-xs text-muted-foreground">Last {formatCount(provider.window_hours)} h</dt>
          <dd className="flex flex-wrap gap-1.5">
            {counts.length === 0 ? (
              <span className="text-muted-foreground">No assessments</span>
            ) : (
              counts.map(([status, count]) => (
                <span
                  key={status}
                  className="inline-flex h-5 items-center gap-1 rounded-md px-1.5 text-fg-2 ring-1 ring-hairline-strong ring-inset"
                >
                  <span className="tabular-nums">{formatCount(count)}</span>
                  <span className="text-muted-foreground">{aiStatusLabel(status)}</span>
                </span>
              ))
            )}
          </dd>
        </div>
      </dl>
      {provider.last_error ? (
        <p className="min-w-0 text-xs text-health-warn">
          <UntrustedText value={provider.last_error} oneLine />
        </p>
      ) : null}
    </li>
  );
}

/** AI providers (advisory only): flags, key presence and recent outcomes per provider and task. */
export function AIProvidersCard({
  ai,
  source,
  now,
  className,
}: {
  ai: AIProviderHealth[];
  source: string;
  now: string;
  className?: string;
}) {
  return (
    <SectionCard
      title="AI providers"
      titleId="ai-health-title"
      icon={Bot}
      description="Advisory only: AI never changes alerts."
      meta={
        <Hint content="AI output is stored as advisory assessments. Detection, severity and analyst state never depend on it.">
          <span className="inline-flex h-5 items-center rounded-md px-1.5 text-xs font-medium text-fg-2 ring-1 ring-hairline-strong ring-inset">
            Advisory
          </span>
        </Hint>
      }
      className={className}
    >
      {ai.length === 0 ? (
        <EmptyState>No AI provider is configured or has produced an assessment.</EmptyState>
      ) : (
        <ul className="divide-y divide-hairline-soft">
          {ai.map((provider) => (
            <ProviderRow key={`${provider.provider}|${provider.task}`} provider={provider} now={now} />
          ))}
        </ul>
      )}
      <p className="mt-4 text-xs leading-relaxed text-muted-foreground">
        Configuration source: <UntrustedText value={source} limit={96} />.
      </p>
    </SectionCard>
  );
}

/** Free-text notes the API attached to the health response (shown as text). */
export function HealthNotesCard({ notes }: { notes: string[] }) {
  return (
    <SectionCard title="Notes from the API" titleId="health-notes-title" icon={NotebookText}>
      <ul className="grid gap-2 text-sm text-fg-2">
        {notes.map((note) => (
          <li key={note} className="flex gap-2.5">
            <span aria-hidden="true" className="mt-2 size-1 flex-none rounded-full bg-fg-faint" />
            <span className="min-w-0">
              <UntrustedText value={note} limit={400} />
            </span>
          </li>
        ))}
      </ul>
    </SectionCard>
  );
}


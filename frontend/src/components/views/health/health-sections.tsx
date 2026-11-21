import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import { HealthStatusDot, StatusDot, StatusPill } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AIProviderHealth, HealthResponse, PipelineComponentHealth, RuleHealthItem } from "@/lib/api/schemas";
import { DASH, formatCount, formatDuration, humanize } from "@/lib/format";

function Num({ value, warnAbove, badAbove }: { value: number | null | undefined; warnAbove?: number; badAbove?: number }) {
  if (value === null || value === undefined) return <span className="text-muted-foreground">{DASH}</span>;
  const tone =
    badAbove !== undefined && value > badAbove
      ? "text-bad"
      : warnAbove !== undefined && value > warnAbove
        ? "text-warn"
        : value === 0
          ? "text-muted-foreground"
          : "text-ink-2";
  return <span className={`font-mono text-xs ${tone}`}>{formatCount(value)}</span>;
}

/** Ingestion gateway, spool and writer: queue depth, age of the oldest record, counters. */
export function PipelinePanel({ pipeline, now }: { pipeline: PipelineComponentHealth[]; now: string }) {
  const current = pipeline.filter((p) => !p.superseded);
  const superseded = pipeline.length - current.length;
  return (
    <Panel
      title="Ingestion pipeline"
      titleId="pipeline-title"
      meta={superseded > 0 ? <span>{formatCount(superseded)} superseded instance reports hidden</span> : null}
    >
      {current.length === 0 ? (
        <EmptyState>No pipeline component has reported health. Queue depth and write errors are unknown.</EmptyState>
      ) : (
        <Table aria-label="Pipeline components">
          <TableHeader>
            <TableRow>
              <TableHead>Component</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Queue</TableHead>
              <TableHead className="text-right">Oldest queued</TableHead>
              <TableHead className="hidden text-right md:table-cell">Accepted</TableHead>
              <TableHead className="hidden text-right lg:table-cell">Duplicates</TableHead>
              <TableHead className="hidden text-right md:table-cell">Rejected</TableHead>
              <TableHead className="hidden text-right md:table-cell">Quarantined</TableHead>
              <TableHead className="hidden text-right lg:table-cell">Written</TableHead>
              <TableHead className="hidden text-right lg:table-cell">Write errors</TableHead>
              <TableHead className="hidden text-right xl:table-cell">Dead letter</TableHead>
              <TableHead className="text-right">Reported</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {current.map((p) => (
              <TableRow key={`${p.component}|${p.instance}`}>
                <TableCell className="py-2">
                  <div className="text-ink">
                    <UntrustedText value={p.component} limit={32} />
                  </div>
                  <div className="font-mono text-xs text-muted-foreground">
                    <UntrustedText value={p.instance} limit={48} />
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap items-center gap-2">
                    <HealthStatusDot status={p.status} />
                    {p.stale ? <StatusPill tone="warn" label="Report stale" /> : null}
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  <Num value={p.queue_depth} warnAbove={0} />
                </TableCell>
                <TableCell className="text-right font-mono text-xs text-ink-2">{formatDuration(p.oldest_queued_age_seconds)}</TableCell>
                <TableCell className="hidden text-right md:table-cell">
                  <Num value={p.accepted_total} />
                </TableCell>
                <TableCell className="hidden text-right lg:table-cell">
                  <Num value={p.duplicate_total} />
                </TableCell>
                <TableCell className="hidden text-right md:table-cell">
                  <Num value={p.rejected_total} warnAbove={0} />
                </TableCell>
                <TableCell className="hidden text-right md:table-cell">
                  <Num value={p.quarantined_total} warnAbove={0} />
                </TableCell>
                <TableCell className="hidden text-right lg:table-cell">
                  <Num value={p.written_total} />
                </TableCell>
                <TableCell className="hidden text-right lg:table-cell">
                  <Num value={p.write_errors_total} badAbove={0} />
                </TableCell>
                <TableCell className="hidden text-right xl:table-cell">
                  <Num value={p.dead_letter_total} badAbove={0} />
                </TableCell>
                <TableCell className="text-right">
                  <RelativeTime value={p.last_reported_at} now={now} className="text-xs" />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      <p className="mt-3 text-xs text-muted-foreground">
        Counters are cumulative since each component instance started, as reported in its latest health record.
      </p>
    </Panel>
  );
}

/** Quarantine and authorisation decisions at the gateway over the API's window. */
export function IngestSecurityPanel({ ingest }: { ingest: HealthResponse["ingest"] }) {
  if (!ingest) {
    return (
      <Panel title="Quarantine and rejections" titleId="ingest-title">
        <EmptyState>The API did not report ingestion security counters.</EmptyState>
      </Panel>
    );
  }
  const decisions = Object.entries(ingest.audit_decisions).sort((a, b) => b[1] - a[1]);
  return (
    <Panel title="Quarantine and rejections" titleId="ingest-title" meta={<span>Last {formatCount(ingest.window_hours)} h</span>}>
      <ul className="divide-y divide-rule">
        <li className="flex min-h-9 items-center justify-between gap-4 py-1">
          <span className="text-sm text-ink-2">Quarantined records</span>
          <Num value={ingest.quarantined_records} warnAbove={0} />
        </li>
        {decisions.length === 0 ? (
          <li className="py-2 text-xs text-muted-foreground">No gateway authorisation decision was audited in this window.</li>
        ) : (
          decisions.map(([decision, count]) => (
            <li key={decision} className="flex min-h-9 items-center justify-between gap-4 py-1">
              <span className="text-sm text-ink-2">
                Gateway decision: <UntrustedText value={humanize(decision)} limit={48} />
              </span>
              <Num value={count} warnAbove={decision === "accepted" || decision === "allowed" ? undefined : 0} />
            </li>
          ))
        )}
      </ul>
    </Panel>
  );
}

/** Rule execution health: last run outcome, failures and missing telemetry per rule. */
export function RuleHealthPanel({ rules, now }: { rules: RuleHealthItem[]; now: string }) {
  return (
    <Panel title="Rule execution" titleId="rule-health-title">
      {rules.length === 0 ? (
        <EmptyState>No rule has been registered or run yet.</EmptyState>
      ) : (
        <Table aria-label="Rule execution">
          <TableHeader>
            <TableRow>
              <TableHead>Rule</TableHead>
              <TableHead>Last run</TableHead>
              <TableHead className="text-right">Failures 24 h</TableHead>
              <TableHead className="hidden md:table-cell">Missing sources</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.map((r) => (
              <TableRow key={r.rule_id}>
                <TableCell className="py-2 whitespace-normal">
                  <span className="font-mono text-xs text-muted-foreground">{r.rule_id}</span>{" "}
                  <UntrustedText value={r.title} limit={120} className="text-ink" />
                  {r.enabled === false ? <span className="ml-2 text-xs text-muted-foreground">disabled</span> : null}
                </TableCell>
                <TableCell>
                  {r.last_run ? (
                    <span className="flex flex-wrap items-center gap-2 text-xs">
                      <StatusDot
                        tone={r.last_run.last_status === "succeeded" ? "ok" : r.last_run.last_status === "failed" ? "bad" : "warn"}
                        label={r.last_run.last_status}
                      />
                      <RelativeTime value={r.last_run.last_run_at} now={now} className="text-xs" />
                      {r.run_stale ? <StatusPill tone="warn" label="Overdue" /> : null}
                    </span>
                  ) : (
                    <span className="text-xs text-muted-foreground">Never ran</span>
                  )}
                </TableCell>
                <TableCell className="text-right">
                  <Num value={r.last_run?.failures_24h} badAbove={0} />
                </TableCell>
                <TableCell className="hidden max-w-72 text-xs whitespace-normal md:table-cell">
                  {r.last_run && r.last_run.missing_sources.length > 0 ? (
                    <span className="font-mono text-warn">
                      <UntrustedText value={r.last_run.missing_sources.join(", ")} limit={120} />
                    </span>
                  ) : (
                    <span className="text-muted-foreground">{r.last_run ? "None" : DASH}</span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}

function boolText(value: boolean | null | undefined, yes: string, no: string) {
  if (value === null || value === undefined) return <span className="text-muted-foreground">unknown</span>;
  return value ? <span className="text-ink-2">{yes}</span> : <span className="text-muted-foreground">{no}</span>;
}

/** AI providers (advisory only): configuration and recent outcomes per provider and task. */
export function AIHealthPanel({ ai, source, now }: { ai: AIProviderHealth[]; source: string; now: string }) {
  return (
    <Panel
      title="AI providers"
      titleId="ai-health-title"
      meta={
        <span>
          Advisory only · configuration from <UntrustedText value={source} limit={96} />
        </span>
      }
    >
      {ai.length === 0 ? (
        <EmptyState>No AI provider is configured or has produced an assessment.</EmptyState>
      ) : (
        <ul className="divide-y divide-rule">
          {ai.map((p) => {
            const counts = Object.entries(p.status_counts).sort((a, b) => b[1] - a[1]);
            return (
              <li key={`${p.provider}|${p.task}`} className="py-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="text-ink">
                    <UntrustedText value={p.provider} limit={32} /> <span className="text-muted-foreground">·</span>{" "}
                    <UntrustedText value={p.task} limit={32} />
                  </span>
                  <span className="flex gap-3 text-xs">
                    {boolText(p.configured, "configured", "not configured")}
                    {boolText(p.enabled, "enabled", "disabled")}
                  </span>
                </div>
                <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
                  <span>
                    last ok <RelativeTime value={p.last_ok_at} now={now} className="text-xs" />
                  </span>
                  <span>
                    last assessment <RelativeTime value={p.last_assessment_at} now={now} className="text-xs" />
                    {p.last_status ? (
                      <>
                        {" "}
                        (<UntrustedText value={p.last_status} limit={24} />)
                      </>
                    ) : null}
                  </span>
                  <span>
                    last {formatCount(p.window_hours)} h:{" "}
                    {counts.length === 0
                      ? "no assessments"
                      : counts.map(([status, count]) => `${humanize(status)} ${formatCount(count)}`).join(", ")}
                  </span>
                </div>
                {p.last_error ? (
                  <div className="mt-1 text-xs text-warn">
                    <UntrustedText value={p.last_error} limit={160} />
                  </div>
                ) : null}
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}

import { TriangleAlert } from "lucide-react";

import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import { StatusPill } from "@/components/console/status-badge";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AIAssessment, EvidenceStatement, InvestigationSummary } from "@/lib/api/schemas";
import { formatCount, formatMs, formatUtc, humanize } from "@/lib/format";
import { providerTime } from "@/lib/investigation";

import { aiStatusText } from "./ai-labels";
import { SummaryRequestButton } from "./summary-request";

/**
 * Evidence chips of one statement. Verified ids (present in the evidence bundle the model was
 * given) jump to their evidence row; unverified ids are flagged and never styled as verified.
 */
function EvidenceChips({
  ids,
  unverified,
  onPage,
}: {
  ids: string[];
  unverified: string[];
  onPage: Set<string>;
}) {
  if (ids.length === 0 && unverified.length === 0) {
    return <span className="text-xs text-warn">No evidence cited</span>;
  }
  return (
    <span className="inline-flex flex-wrap gap-1.5 align-middle">
      {ids.map((id) =>
        onPage.has(id) ? (
          <a
            key={id}
            href={`#evidence-${id}`}
            title={`Verified evidence ${id}: jump to the evidence row`}
            className="inline-flex h-5 items-center rounded-sm border border-control px-1.5 font-mono text-xs text-ink-2 hover:border-ink-2 hover:text-ink"
          >
            {id.slice(0, 8)}
          </a>
        ) : (
          <span
            key={id}
            title={`Verified against the evidence bundle (${id}), but not among the evidence rows shown on this page`}
            className="inline-flex h-5 items-center rounded-sm border border-control px-1.5 font-mono text-xs text-muted-foreground"
          >
            {id.slice(0, 8)}
          </span>
        ),
      )}
      {unverified.map((id) => (
        <span
          key={`u-${id}`}
          title="Not present in the evidence given to the model: unverified, possibly invented"
          className="inline-flex h-5 items-center gap-1 rounded-sm border border-dashed border-warn/60 px-1.5 text-xs text-warn"
        >
          <TriangleAlert className="size-3" aria-hidden="true" />
          <span className="font-mono">
            <UntrustedText value={id} limit={16} />
          </span>
          unverified
        </span>
      ))}
    </span>
  );
}

function Statement({ statement, onPage }: { statement: EvidenceStatement; onPage: Set<string> }) {
  return (
    <li className="py-1.5">
      <span className={statement.verified ? "text-ink" : "text-ink-2"}>
        <UntrustedText value={statement.text} limit={600} />
      </span>{" "}
      <EvidenceChips ids={statement.evidence_ids} unverified={statement.unverified_ids} onPage={onPage} />
    </li>
  );
}

function TextList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <section>
      <h3 className="mb-1 text-sm font-medium text-ink">{title}</h3>
      <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-ink-2">
        {items.map((item, i) => (
          <li key={i}>
            <UntrustedText value={item} limit={400} />
          </li>
        ))}
      </ul>
    </section>
  );
}

function SummaryBody({ summary, onPage }: { summary: InvestigationSummary; onPage: Set<string> }) {
  return (
    <div className="flex flex-col gap-4">
      <section>
        <h3 className="mb-1 text-sm font-medium text-ink">What happened</h3>
        <ul className="divide-y divide-rule text-sm">
          {summary.what_happened.map((s, i) => (
            <Statement key={i} statement={s} onPage={onPage} />
          ))}
        </ul>
      </section>
      <section>
        <h3 className="mb-1 text-sm font-medium text-ink">Why the rule fired</h3>
        <ul className="text-sm">
          <Statement statement={summary.why_rule_fired} onPage={onPage} />
        </ul>
      </section>
      {summary.timeline.length > 0 ? (
        <section>
          <h3 className="mb-1 text-sm font-medium text-ink">Timeline as summarised</h3>
          <ol className="divide-y divide-rule text-sm">
            {summary.timeline.map((item, i) => (
              <li key={i} className="grid gap-x-3 py-1.5 sm:grid-cols-[10.5rem_minmax(0,1fr)]">
                <span className="font-mono text-xs text-muted-foreground" title={item.time}>
                  <UntrustedText value={providerTime(item.time, formatUtc)} limit={32} />
                </span>
                <span>
                  <span className={item.verified ? "text-ink" : "text-ink-2"}>
                    <UntrustedText value={item.description} limit={400} />
                  </span>{" "}
                  <EvidenceChips ids={item.evidence_ids} unverified={item.unverified_ids} onPage={onPage} />
                </span>
              </li>
            ))}
          </ol>
        </section>
      ) : null}
      {summary.related_activity.length > 0 ? (
        <section>
          <h3 className="mb-1 text-sm font-medium text-ink">Related activity</h3>
          <ul className="divide-y divide-rule text-sm">
            {summary.related_activity.map((s, i) => (
              <Statement key={i} statement={s} onPage={onPage} />
            ))}
          </ul>
        </section>
      ) : null}
      <TextList title="Possible benign explanations" items={summary.benign_explanations} />
      <TextList title="Missing information" items={summary.missing_information} />
      <TextList title="Limitations" items={summary.limitations} />
      <TextList title="Suggested next steps (read-only checks)" items={summary.recommended_next_steps} />
    </div>
  );
}

/** Gemini investigation overview: advisory, on demand, every statement tied to evidence ids. */
export function GeminiPanel({
  alertId,
  assessment,
  canRequest,
  evidenceOnPage,
}: {
  alertId: string;
  assessment: AIAssessment | null;
  canRequest: boolean;
  evidenceOnPage: Set<string>;
}) {
  const summary = assessment?.status === "ok" ? assessment.summary : null;
  return (
    <Panel title="Gemini overview" titleId="gemini-title" meta={<StatusPill tone="off" label="Advisory" />}>
      <div className="mb-4">
        <SummaryRequestButton alertId={alertId} canRequest={canRequest} hasSummary={Boolean(summary)} />
      </div>
      {!assessment ? (
        <EmptyState>No overview has been generated for this alert.</EmptyState>
      ) : assessment.status !== "ok" || !summary ? (
        <p className="rounded-md border border-border px-3 py-2 text-sm text-ink-2">
          The latest request did not produce an overview: {aiStatusText(assessment.status).toLowerCase()}.
          {assessment.error ? (
            <span className="block text-xs text-muted-foreground">
              <UntrustedText value={assessment.error} limit={200} />
            </span>
          ) : null}
        </p>
      ) : (
        <>
          <SummaryBody summary={summary} onPage={evidenceOnPage} />
          {assessment.validation ? (
            <p className="mt-4 text-xs text-muted-foreground">
              Evidence check: {formatCount(assessment.validation.evidence_ids_verified)} of{" "}
              {formatCount(assessment.validation.evidence_ids_cited)} cited ids verified
              {assessment.validation.evidence_ids_rejected > 0 ? (
                <span className="text-warn"> · {formatCount(assessment.validation.evidence_ids_rejected)} rejected</span>
              ) : null}
              {assessment.validation.statements_without_evidence > 0
                ? ` · ${formatCount(assessment.validation.statements_without_evidence)} statements without evidence`
                : ""}
              . Overall model confidence: {humanize(summary.overall_confidence)}.
            </p>
          ) : null}
        </>
      )}
      {assessment ? (
        <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 border-t border-rule pt-3 text-xs">
          <dt className="text-muted-foreground">Model</dt>
          <dd className="font-mono text-ink-2">
            <UntrustedText value={`${assessment.provider} ${assessment.model} · ${assessment.prompt_version}`} limit={96} />
          </dd>
          <dt className="text-muted-foreground">Input hash</dt>
          <dd className="font-mono break-all text-ink-2">{assessment.context_input_hash}</dd>
          <dt className="text-muted-foreground">Requested</dt>
          <dd>
            <Timestamp value={assessment.created_at} />
            <span className="text-muted-foreground">
              {" by "}
              <UntrustedText value={assessment.requested_by} limit={40} /> · {formatMs(assessment.latency_ms)}
            </span>
          </dd>
        </dl>
      ) : null}
    </Panel>
  );
}

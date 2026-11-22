import { cn } from "cn";
import { BrainCircuit, CircleCheck, FileWarning, Sparkles, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { EvidenceChip } from "@/components/console/evidence-chip";
import { Hint } from "@/components/console/hint";
import { IdText } from "@/components/console/id-text";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ApiFailure } from "@/lib/api/result";
import type { AIAssessment, EvidenceStatement, InvestigationSummary, JevAnswer, JevTriageResult } from "@/lib/api/schemas";
import { formatCount, formatMs, formatProbability, formatUtc, humanize } from "@/lib/format";
import { providerTime } from "@/lib/investigation";
import { shortId } from "@/lib/security/display";

import { aiStatusText, QUESTION_LABEL, questionTypeLabel, recommendationLabel } from "./ai-labels";
import { Eyebrow } from "./marks";
import { choiceOptions, JEV_BANDS, jevZone, percent, statementChips } from "./model";
import { SummaryRequestButton } from "./summary-request";

/** The label every AI block carries: advisory, never authoritative. */
function AdvisoryBadge() {
  return (
    <Hint content="AI output is advisory: it never changes severity, analyst state or evidence. Deterministic detection and correlation establish the evidence.">
      <span className="inline-flex h-6 items-center gap-1 rounded-md px-2 text-xs font-medium text-fg-2 ring-1 ring-hairline-strong ring-inset">
        <Sparkles className="size-3" aria-hidden="true" />
        Advisory
      </span>
    </Hint>
  );
}

function Flag({ tone, children }: { tone: "warn" | "neutral"; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex h-6 items-center gap-1.5 rounded-md px-2 text-xs font-medium ring-1 ring-inset",
        tone === "warn" ? "bg-health-warn/10 text-health-warn ring-health-warn/25" : "bg-white/[0.03] text-fg-2 ring-hairline-strong",
      )}
    >
      <span aria-hidden="true" className={cn("size-1.5 rounded-full", tone === "warn" ? "bg-health-warn" : "bg-fg-2")} />
      {children}
    </span>
  );
}

function Footer({ rows }: { rows: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="flex flex-wrap gap-x-6 gap-y-2 text-xs">
      {rows.map((row) => (
        <div key={row.label} className="flex min-w-0 items-center gap-1.5">
          <dt className="text-muted-foreground">{row.label}</dt>
          <dd className="min-w-0 text-fg-2">{row.value}</dd>
        </div>
      ))}
    </dl>
  );
}

// ── Jev ───────────────────────────────────────────────────────────────────────────

/**
 * Sufficient-context probability on its documented bands: below 0.30 insufficient, 0.30 to
 * 0.70 the uncertain band (a human decides), above 0.70 sufficient. The marker is the value.
 */
function ContextMeter({ value }: { value: number }) {
  const zone = jevZone(value);
  const low = JEV_BANDS.insufficientBelow * 100;
  const high = JEV_BANDS.confidentAbove * 100;
  return (
    <div className="grid gap-2">
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-xs text-muted-foreground">Sufficient-context probability</span>
        <span className="text-3xl leading-none font-semibold tracking-tight text-foreground tabular-nums">{formatProbability(value)}</span>
      </div>
      <div
        role="meter"
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuenow={value}
        aria-valuetext={`${formatProbability(value)}, ${zone}`}
        aria-label="Sufficient-context probability"
        className="relative h-2.5"
      >
        <span className="absolute inset-y-0 left-0 rounded-l-full bg-white/[0.06]" style={{ width: `calc(${low}% - 1px)` }} />
        <span className="absolute inset-y-0 bg-health-warn/[0.22]" style={{ left: `${low}%`, width: `calc(${high - low}% - 1px)` }} />
        <span className="absolute inset-y-0 right-0 rounded-r-full bg-white/[0.12]" style={{ width: `${100 - high}%` }} />
        <span
          aria-hidden="true"
          className="absolute top-1/2 size-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-brand shadow-card ring-[3px] ring-card"
          style={{ left: `${percent(value)}%` }}
        />
      </div>
      <div aria-hidden="true" className="relative h-4 font-mono text-xs text-muted-foreground tabular-nums">
        <span className="absolute left-0">0</span>
        <span className="absolute -translate-x-1/2" style={{ left: `${low}%` }}>
          {formatProbability(JEV_BANDS.insufficientBelow)}
        </span>
        <span className="absolute -translate-x-1/2" style={{ left: `${high}%` }}>
          {formatProbability(JEV_BANDS.confidentAbove)}
        </span>
        <span className="absolute right-0">1</span>
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">
        {zone === "sufficient"
          ? "Above the uncertain band: Jev judged the context sufficient."
          : zone === "uncertain"
            ? "Inside the uncertain band (0.30 to 0.70): the procedure leaves the decision to a human."
            : "Below 0.30: Jev judged the context insufficient."}
      </p>
    </div>
  );
}

function AnswerBar({ answer }: { answer: JevAnswer }) {
  if (answer.type === "choice") {
    const options = choiceOptions(answer);
    return (
      <div className="grid gap-1.5">
        <div className="flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full bg-white/[0.05]" aria-hidden="true">
          {options.map((o) => (
            <span
              key={o.label}
              className={cn("h-full first:rounded-l-full last:rounded-r-full", o.chosen ? "bg-foreground/80" : "bg-white/20")}
              style={{ width: `${percent(o.probability)}%` }}
            />
          ))}
        </div>
        <span className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs">
          {options.map((o) => (
            <span key={o.label} className={o.chosen ? "text-foreground" : "text-muted-foreground"}>
              {recommendationLabel(o.label)} <span className="font-mono tabular-nums">{formatProbability(o.probability)}</span>
            </span>
          ))}
        </span>
      </div>
    );
  }
  if (typeof answer.value === "number") {
    return (
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/[0.05]" aria-hidden="true">
        <span className="block h-full rounded-full bg-fg-2/70" style={{ width: `${percent(answer.value)}%` }} />
      </div>
    );
  }
  return null;
}

function answerText(answer: JevAnswer): string {
  if (typeof answer.value === "number") return answer.type === "noul" ? `P(yes) ${formatProbability(answer.value)}` : formatProbability(answer.value);
  return recommendationLabel(answer.value);
}

function JevBody({ triage }: { triage: JevTriageResult }) {
  return (
    <div className="@container">
      <div className="grid gap-x-8 gap-y-6 @3xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        <div className="grid content-start gap-5">
          <div>
            <Eyebrow>Recommendation</Eyebrow>
            <p className="mt-1 text-xl font-semibold tracking-tight text-foreground">{recommendationLabel(triage.recommendation)}</p>
            <div className="mt-3 flex flex-wrap gap-2">
              {triage.uncertain ? <Flag tone="warn">Uncertain: a human decides</Flag> : <Flag tone="neutral">Not flagged uncertain</Flag>}
              {triage.order_consistent ? (
                <Flag tone="neutral">Consistent across option orders</Flag>
              ) : (
                <Flag tone="warn">Order-sensitive: answers changed with option order</Flag>
              )}
            </div>
          </div>
          <ContextMeter value={triage.sufficient_context_probability} />
          {triage.rationale_codes.length > 0 ? (
            <div className="grid gap-2">
              <Eyebrow>Rationale codes</Eyebrow>
              <div className="flex flex-wrap gap-1.5">
                {triage.rationale_codes.map((code) => (
                  <span
                    key={code}
                    className="inline-flex h-6 items-center rounded-md bg-white/[0.03] px-1.5 font-mono text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset"
                  >
                    <UntrustedText value={code} limit={48} plain />
                  </span>
                ))}
              </div>
            </div>
          ) : null}
        </div>
        <div className="min-w-0">
          <Eyebrow>Typed answers</Eyebrow>
          <ul className="mt-1 divide-y divide-hairline-soft" aria-label="Jev typed answers">
            {triage.answers.map((answer) => (
              <li key={answer.question_id} className="grid gap-2 py-3">
                <div className="flex items-baseline justify-between gap-3">
                  <span className="min-w-0 text-sm text-fg-2">
                    {QUESTION_LABEL[answer.question_id] ?? <UntrustedText value={answer.question_id} limit={64} />}
                    <span className="ml-2 text-xs text-muted-foreground">{questionTypeLabel(answer.type)}</span>
                  </span>
                  <span className={cn("flex-none text-xs text-foreground tabular-nums", typeof answer.value === "number" && "font-mono")}>
                    {answerText(answer)}
                  </span>
                </div>
                <AnswerBar answer={answer} />
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

function JevCard({ assessment, currentInputHash }: { assessment: AIAssessment | null; currentInputHash: string | null }) {
  const outdated = assessment !== null && currentInputHash !== null && assessment.context_input_hash !== currentInputHash;
  return (
    <SectionCard
      title="Jev contextual assessment"
      titleId="jev-title"
      icon={BrainCircuit}
      description="Typed triage questions answered by TypeSafe Jev over the investigation context"
      meta={<AdvisoryBadge />}
      footer={
        assessment ? (
          <Footer
            rows={[
              { label: "Model", value: <UntrustedText value={`${assessment.provider} ${assessment.model}`} limit={80} mono /> },
              {
                label: "Question set",
                value: <UntrustedText value={assessment.triage?.question_set_version ?? assessment.prompt_version} limit={80} mono />,
              },
              { label: "Input hash", value: <IdText id={assessment.context_input_hash} head={12} /> },
              {
                label: "Assessed",
                value: (
                  <span>
                    <Timestamp value={assessment.created_at} /> <span className="text-muted-foreground">· {formatMs(assessment.latency_ms)}</span>
                  </span>
                ),
              },
            ]}
          />
        ) : undefined
      }
    >
      {!assessment ? (
        <EmptyState>
          No Jev triage exists for this alert. The ai-worker assesses new alerts only when Jev is enabled and within its budget; the
          deterministic investigation stands on its own.
        </EmptyState>
      ) : (
        <div className="grid gap-5">
          {outdated ? (
            <Notice tone="warn" icon={TriangleAlert}>
              Made on an earlier version of the investigation context (its input hash differs from the current one).
            </Notice>
          ) : null}
          {assessment.status !== "ok" || !assessment.triage ? (
            <Notice icon={FileWarning}>
              Jev did not produce a triage: {aiStatusText(assessment.status).toLowerCase()}.
              {assessment.error ? (
                <span className="mt-1 block font-mono">
                  <UntrustedText value={assessment.error} limit={200} />
                </span>
              ) : null}
            </Notice>
          ) : (
            <JevBody triage={assessment.triage} />
          )}
        </div>
      )}
    </SectionCard>
  );
}

// ── Gemini ────────────────────────────────────────────────────────────────────────

/** A verified id that is a related observation of the context, not one of the evidence rows. */
function ContextChip({ eventId }: { eventId: string }) {
  return (
    <Hint content="Verified: found in the investigation context the model received (a related observation), not one of this alert's evidence rows.">
      <span className="inline-flex h-6 items-center gap-1 rounded-md px-1.5 font-mono text-xs text-muted-foreground ring-1 ring-hairline-strong ring-inset">
        <CircleCheck className="size-3 text-fg-2" aria-hidden="true" />
        {shortId(eventId, 8)}
        <span className="sr-only">(verified, related observation)</span>
      </span>
    </Hint>
  );
}

function Chips({ statement, evidenceRows }: { statement: Pick<EvidenceStatement, "evidence_ids" | "unverified_ids">; evidenceRows: ReadonlySet<string> }) {
  const chips = statementChips(statement, evidenceRows);
  if (chips.length === 0) {
    return (
      <span className="inline-flex items-center gap-1 text-xs text-health-warn">
        <TriangleAlert className="size-3" aria-hidden="true" /> No evidence cited
      </span>
    );
  }
  return (
    <span className="flex flex-wrap gap-1.5">
      {chips.map((chip) =>
        chip.kind === "context" ? (
          <ContextChip key={`c:${chip.id}`} eventId={chip.id} />
        ) : (
          <EvidenceChip key={`${chip.kind}:${chip.id}`} eventId={chip.id} verified={chip.kind === "evidence"} />
        ),
      )}
    </span>
  );
}

function Statement({ statement, evidenceRows }: { statement: EvidenceStatement; evidenceRows: ReadonlySet<string> }) {
  return (
    <li className="grid gap-2 py-3 first:pt-0 last:pb-0">
      <p className={cn("text-sm leading-relaxed", statement.verified ? "text-foreground" : "text-fg-2")}>
        <UntrustedText value={statement.text} limit={600} />
      </p>
      <Chips statement={statement} evidenceRows={evidenceRows} />
    </li>
  );
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="grid gap-2">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      {children}
    </section>
  );
}

function TextList({ title, items }: { title: string; items: string[] }) {
  return (
    <section className="grid content-start gap-2 rounded-lg bg-white/[0.02] p-4 ring-1 ring-hairline ring-inset">
      <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      {items.length === 0 ? (
        <p className="text-sm text-muted-foreground">None given.</p>
      ) : (
        <ul className="grid list-disc gap-1.5 pl-4 text-sm leading-relaxed text-fg-2 marker:text-fg-faint">
          {items.map((item, i) => (
            <li key={i}>
              <UntrustedText value={item} limit={400} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function SummaryBody({ summary, evidenceRows }: { summary: InvestigationSummary; evidenceRows: ReadonlySet<string> }) {
  return (
    <div className="grid gap-7 @container">
      <Section title="What happened">
        <ul className="divide-y divide-hairline-soft">
          {summary.what_happened.map((s, i) => (
            <Statement key={i} statement={s} evidenceRows={evidenceRows} />
          ))}
        </ul>
      </Section>
      <Section title="Why the rule fired">
        <ul>
          <Statement statement={summary.why_rule_fired} evidenceRows={evidenceRows} />
        </ul>
      </Section>
      {summary.timeline.length > 0 ? (
        <Section title="Timeline as summarised">
          <ol className="divide-y divide-hairline-soft">
            {summary.timeline.map((item, i) => (
              <li key={i} className="grid gap-x-4 gap-y-1.5 py-2.5 first:pt-0 last:pb-0 sm:grid-cols-[10.5rem_minmax(0,1fr)]">
                <span className="font-mono text-xs text-muted-foreground tabular-nums">
                  <UntrustedText value={providerTime(item.time, formatUtc)} limit={32} />
                </span>
                <span className="grid gap-1.5">
                  <span className={cn("text-sm leading-relaxed", item.verified ? "text-foreground" : "text-fg-2")}>
                    <UntrustedText value={item.description} limit={400} />
                  </span>
                  <Chips statement={item} evidenceRows={evidenceRows} />
                </span>
              </li>
            ))}
          </ol>
        </Section>
      ) : null}
      {summary.related_activity.length > 0 ? (
        <Section title="Related activity">
          <ul className="divide-y divide-hairline-soft">
            {summary.related_activity.map((s, i) => (
              <Statement key={i} statement={s} evidenceRows={evidenceRows} />
            ))}
          </ul>
        </Section>
      ) : null}
      <div className="grid gap-3 @3xl:grid-cols-2">
        <TextList title="Possible benign explanations" items={summary.benign_explanations} />
        <TextList title="Missing information" items={summary.missing_information} />
        <TextList title="Limitations" items={summary.limitations} />
        <TextList title="Suggested next steps (read-only checks)" items={summary.recommended_next_steps} />
      </div>
    </div>
  );
}

function EvidenceCheck({ assessment, summary }: { assessment: AIAssessment; summary: InvestigationSummary }) {
  const v = assessment.validation;
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-2 rounded-lg bg-white/[0.02] px-4 py-3 text-xs ring-1 ring-hairline ring-inset">
      <span className="font-medium text-fg-2">Evidence check</span>
      {v ? (
        <>
          <span className="inline-flex items-center gap-1.5 text-fg-2">
            <CircleCheck className="size-3.5 text-health-ok" aria-hidden="true" />
            <span className="font-mono tabular-nums">{formatCount(v.evidence_ids_verified)}</span> of{" "}
            <span className="font-mono tabular-nums">{formatCount(v.evidence_ids_cited)}</span> cited ids verified
          </span>
          <span className={v.evidence_ids_rejected > 0 ? "text-health-warn" : "text-muted-foreground"}>
            <span className="font-mono tabular-nums">{formatCount(v.evidence_ids_rejected)}</span> rejected
          </span>
          <span className={v.statements_without_evidence > 0 ? "text-health-warn" : "text-muted-foreground"}>
            <span className="font-mono tabular-nums">{formatCount(v.statements_without_evidence)}</span> statements without evidence
          </span>
        </>
      ) : (
        <span className="text-muted-foreground">No validation record was stored with this overview.</span>
      )}
      <span className="text-muted-foreground">
        Model&apos;s own confidence: <span className="text-fg-2">{humanize(summary.overall_confidence)}</span>
      </span>
    </div>
  );
}

function GeminiCard({
  alertId,
  assessment,
  canRequest,
  evidenceRows,
  currentInputHash,
}: {
  alertId: string;
  assessment: AIAssessment | null;
  canRequest: boolean;
  evidenceRows: ReadonlySet<string>;
  currentInputHash: string | null;
}) {
  const summary = assessment?.status === "ok" ? (assessment.summary ?? null) : null;
  const outdated = assessment !== null && currentInputHash !== null && assessment.context_input_hash !== currentInputHash;
  return (
    <SectionCard
      title="Gemini overview"
      titleId="gemini-title"
      icon={Sparkles}
      description="A narrative overview of the investigation context; every statement cites evidence ids checked by the backend"
      meta={<AdvisoryBadge />}
      footer={
        assessment ? (
          <Footer
            rows={[
              { label: "Model", value: <UntrustedText value={`${assessment.model} · ${assessment.prompt_version}`} limit={80} mono /> },
              { label: "Input hash", value: <IdText id={assessment.context_input_hash} head={12} /> },
              {
                label: "Requested",
                value: (
                  <span>
                    <Timestamp value={assessment.created_at} />
                    <span className="text-muted-foreground">
                      {" by "}
                      <UntrustedText value={assessment.requested_by} limit={40} /> · {formatMs(assessment.latency_ms)}
                    </span>
                  </span>
                ),
              },
            ]}
          />
        ) : undefined
      }
    >
      <div className="grid gap-6">
        <SummaryRequestButton alertId={alertId} canRequest={canRequest} hasSummary={Boolean(summary)} />
        {!assessment ? (
          <EmptyState>No overview has been generated for this alert.</EmptyState>
        ) : !summary ? (
          <Notice icon={FileWarning}>
            The latest request did not produce an overview: {aiStatusText(assessment.status).toLowerCase()}.
            {assessment.error ? (
              <span className="mt-1 block font-mono">
                <UntrustedText value={assessment.error} limit={200} />
              </span>
            ) : null}
          </Notice>
        ) : (
          <>
            {outdated ? (
              <Notice tone="warn" icon={TriangleAlert}>
                Generated from an earlier version of the investigation context (its input hash differs). Generate a new overview for the
                current one.
              </Notice>
            ) : null}
            <EvidenceCheck assessment={assessment} summary={summary} />
            <SummaryBody summary={summary} evidenceRows={evidenceRows} />
          </>
        )}
      </div>
    </SectionCard>
  );
}

/**
 * AI tab: Jev's typed triage and Gemini's evidence-cited overview, both advisory. Evidence
 * chips jump to their evidence row only when the backend verified the id and it is one of
 * this alert's evidence events; unverified ids are flagged and never links.
 */
export function AiPanel({
  alertId,
  assessments,
  assessmentsError,
  currentInputHash,
  canRequest,
  evidenceRows,
  triage,
  summary,
}: {
  alertId: string;
  assessments: AIAssessment[];
  assessmentsError: ApiFailure | null;
  currentInputHash: string | null;
  canRequest: boolean;
  evidenceRows: ReadonlySet<string>;
  triage: AIAssessment | null;
  summary: AIAssessment | null;
}) {
  return (
    <div className="grid gap-6">
      {assessmentsError ? <ErrorState what="the AI assessments" error={assessmentsError} /> : null}
      <JevCard assessment={triage} currentInputHash={currentInputHash} />
      <GeminiCard
        alertId={alertId}
        assessment={summary}
        canRequest={canRequest}
        evidenceRows={evidenceRows}
        currentInputHash={currentInputHash}
      />
      {assessments.length > 2 ? (
        <p className="text-xs text-muted-foreground">
          {formatCount(assessments.length)} AI assessments are stored for this alert; the newest of each kind is shown.
        </p>
      ) : null}
    </div>
  );
}

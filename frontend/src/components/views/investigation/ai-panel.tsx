import { cn } from "cn";
import { BrainCircuit, FileWarning, Sparkles, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { Hint } from "@/components/console/hint";
import { IdText } from "@/components/console/id-text";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { ApiFailure } from "@/lib/api/result";
import type { AIAssessment, JevAnswer, JevTriageResult } from "@/lib/api/schemas";
import { formatCount, formatMs, formatProbability } from "@/lib/format";

import { aiStatusText, QUESTION_LABEL, questionTypeLabel, rationaleLabel, recommendationLabel } from "./ai-labels";
import { Eyebrow } from "./marks";
import { choiceOptions, JEV_BANDS, jevZone, percent, type ProviderAvailability } from "./model";

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
        <span className="absolute inset-y-0 left-0 rounded-l-full bg-white/[0.05]" style={{ width: `calc(${low}% - 1px)` }} />
        <span
          className="absolute inset-y-0 bg-white/[0.11] ring-1 ring-hairline-strong ring-inset"
          style={{ left: `${low}%`, width: `calc(${high - low}% - 1px)` }}
        />
        <span className="absolute inset-y-0 right-0 rounded-r-full bg-white/[0.05]" style={{ width: `${100 - high}%` }} />
        <span
          aria-hidden="true"
          className="absolute top-1/2 size-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-foreground shadow-card ring-[3px] ring-card"
          style={{ left: `${percent(value)}%` }}
        />
      </div>
      <div aria-hidden="true" className="relative h-4 text-xs text-muted-foreground tabular-nums">
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
              {recommendationLabel(o.label)} <span className="tabular-nums">{formatProbability(o.probability)}</span>
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
                {triage.rationale_codes.map((code) => {
                  const label = rationaleLabel(code);
                  return label ? (
                    <Hint key={code} content={<span className="font-mono">{code}</span>}>
                      <span className="inline-flex h-6 items-center rounded-md bg-white/[0.03] px-2 text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset">
                        {label}
                      </span>
                    </Hint>
                  ) : (
                    <span
                      key={code}
                      className="inline-flex h-6 items-center rounded-md bg-white/[0.03] px-1.5 font-mono text-xs text-fg-2 ring-1 ring-hairline-strong ring-inset"
                    >
                      <UntrustedText value={code} limit={48} plain />
                    </span>
                  );
                })}
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
                  <span className="flex-none text-xs text-foreground tabular-nums">
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

const RUNTIME_MARK: Record<string, { dot: string; label: (name: string) => string; hint: string }> = {
  disabled: {
    dot: "bg-health-off",
    label: (name) => `${name} disabled now`,
    hint: "The ai-worker reports Jev turned off or without a key: it assesses no new alert. Stored assessments stay readable.",
  },
  degraded: {
    dot: "bg-health-warn",
    label: () => "ai-worker degraded",
    hint: "The ai-worker reports problems (provider failures, write errors or paused calls): new assessments may be missing.",
  },
  failed: {
    dot: "bg-health-bad",
    label: () => "ai-worker failing",
    hint: "The ai-worker's last cycle failed: no new assessment is being produced.",
  },
};

/**
 * The worker's state beside the advisory label, read from System health (the ai-worker's own
 * report, never the API process's flags). Nothing is shown while it runs normally; "not
 * reporting" when no fresh report exists, so a missing assessment is never blamed on a guess.
 */
function ProviderState({ name, availability }: { name: string; availability: ProviderAvailability }) {
  if (availability.runtime === "ok") return null;
  const mark = availability.runtime === null ? null : RUNTIME_MARK[availability.runtime];
  const label = mark ? mark.label(name) : "ai-worker not reporting";
  const hint = mark
    ? mark.hint
    : "No fresh ai-worker health report: whether Jev is assessing new alerts is unknown (System health, AI triage).";
  return (
    <Hint content={hint}>
      <span className="inline-flex h-6 items-center gap-1.5 text-xs text-muted-foreground">
        <span aria-hidden="true" className={cn("size-1.5 rounded-full", mark?.dot ?? "bg-health-off")} />
        {label}
      </span>
    </Hint>
  );
}

function JevCard({
  assessment,
  currentInputHash,
  availability,
}: {
  assessment: AIAssessment | null;
  currentInputHash: string | null;
  availability: ProviderAvailability;
}) {
  const outdated = assessment !== null && currentInputHash !== null && assessment.context_input_hash !== currentInputHash;
  return (
    <SectionCard
      title="Jev contextual assessment"
      titleId="jev-title"
      icon={BrainCircuit}
      description="Typed triage questions answered by TypeSafe Jev over the investigation context"
      meta={
        <span className="flex items-center gap-3">
          <ProviderState name="Jev" availability={availability} />
          <AdvisoryBadge />
        </span>
      }
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
          No Jev triage exists for this alert.{" "}
          {availability.enabled === false
            ? "The ai-worker reports Jev disabled, so it does not assess new alerts; "
            : "The ai-worker assesses new alerts only while Jev is enabled and within its daily budget; "}
          the deterministic investigation stands on its own.
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

/**
 * AI tab: Jev's typed triage of the investigation context, advisory only. Jev is the one AI
 * provider (contracts 2.0); the ai-worker assesses new alerts on its own, so the console
 * never triggers a provider call. The newest assessment is shown; older attempts stay stored.
 */
export function AiPanel({
  assessments,
  assessmentsError,
  currentInputHash,
  triage,
  triageAvailability,
}: {
  assessments: AIAssessment[];
  assessmentsError: ApiFailure | null;
  currentInputHash: string | null;
  /** The newest triage assessment (null when none is stored). */
  triage: AIAssessment | null;
  /** Jev's flags from System health (null fields when health could not be read). */
  triageAvailability: ProviderAvailability;
}) {
  return (
    <div className="grid gap-6">
      {assessmentsError ? <ErrorState what="the AI assessments" error={assessmentsError} /> : null}
      <JevCard assessment={triage} currentInputHash={currentInputHash} availability={triageAvailability} />
      {assessments.length > 1 ? (
        <p className="text-xs text-muted-foreground">
          {formatCount(assessments.length)} Jev assessments are stored for this alert (one per attempt); the newest is shown.
        </p>
      ) : null}
    </div>
  );
}

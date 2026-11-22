import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import { StatusPill } from "@/components/console/status-badge";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AIAssessment, JevAnswer } from "@/lib/api/schemas";
import { formatMs, formatProbability, humanize } from "@/lib/format";

import { aiStatusText, QUESTION_LABEL, questionTypeLabel, RECOMMENDATION_LABEL } from "./ai-labels";

function answerValue(answer: JevAnswer): string {
  if (answer.type === "noul" && typeof answer.value === "number") return `P(true) ${formatProbability(answer.value)}`;
  if (typeof answer.value === "number") return formatProbability(answer.value);
  return humanize(answer.value);
}

/** Small probability bar: the fill is the true ratio, both ends implied by 0..1. */
function ProbabilityBar({ value }: { value: number }) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  return (
    <span aria-hidden="true" className="relative inline-block h-1 w-16 rounded-full bg-raised align-middle">
      <span className="absolute inset-y-0 left-0 rounded-full bg-ink-2" style={{ width: `${pct}%` }} />
    </span>
  );
}

/**
 * Jev contextual triage: advisory only. It never changes severity or state; its inputs are
 * pinned by the context input hash, which is compared with the current context's hash.
 */
export function JevPanel({
  assessment,
  currentInputHash,
}: {
  assessment: AIAssessment | null;
  currentInputHash: string | null;
}) {
  return (
    <Panel
      title="Jev contextual assessment"
      titleId="jev-title"
      meta={<StatusPill tone="off" label="Advisory" />}
    >
      {!assessment ? (
        <EmptyState>
          No Jev triage exists for this alert. The ai-worker assesses new alerts only when Jev is enabled and within its
          budget; the deterministic investigation stands on its own.
        </EmptyState>
      ) : (
        <JevBody assessment={assessment} currentInputHash={currentInputHash} />
      )}
    </Panel>
  );
}

function JevBody({ assessment, currentInputHash }: { assessment: AIAssessment; currentInputHash: string | null }) {
  const triage = assessment.triage;
  const outdated = currentInputHash !== null && assessment.context_input_hash !== currentInputHash;
  return (
    <div className="flex flex-col gap-4">
      {assessment.status !== "ok" || !triage ? (
        <p className="rounded-md border border-border px-3 py-2 text-sm text-ink-2">
          {aiStatusText(assessment.status)}.
          {assessment.error ? (
            <span className="block text-xs text-muted-foreground">
              <UntrustedText value={assessment.error} limit={200} />
            </span>
          ) : null}
        </p>
      ) : (
        <>
          <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
            <div>
              <p className="text-xs text-muted-foreground">Recommendation</p>
              <p className="text-lg text-ink">{RECOMMENDATION_LABEL[triage.recommendation] ?? humanize(triage.recommendation)}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Sufficient-context probability</p>
              <p className="font-mono text-lg text-ink">{formatProbability(triage.sufficient_context_probability)}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Uncertainty</p>
              <p className={triage.uncertain ? "text-lg text-warn" : "text-lg text-ink-2"}>
                {triage.uncertain ? "Uncertain" : "Within confidence band"}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Option-order consistency</p>
              <p className={triage.order_consistent ? "text-lg text-ink-2" : "text-lg text-warn"}>
                {triage.order_consistent ? "Consistent" : "Answers changed with option order"}
              </p>
            </div>
          </div>

          <table className="w-full text-sm" aria-label="Jev typed answers">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="py-1.5 font-normal">Question</th>
                <th className="py-1.5 font-normal">Type</th>
                <th className="py-1.5 text-right font-normal">Answer</th>
                <th className="hidden py-1.5 text-right font-normal sm:table-cell">Probabilities</th>
              </tr>
            </thead>
            <tbody>
              {triage.answers.map((answer) => (
                <tr key={answer.question_id} className="border-b border-rule last:border-0">
                  <td className="py-2 pr-3 text-ink-2">
                    {QUESTION_LABEL[answer.question_id] ?? <UntrustedText value={answer.question_id} limit={48} />}
                  </td>
                  <td className="py-2 pr-3 text-xs whitespace-nowrap text-muted-foreground">{questionTypeLabel(answer.type)}</td>
                  <td className="py-2 text-right whitespace-nowrap">
                    <span className="font-mono text-xs text-ink">{answerValue(answer)}</span>
                    {answer.type === "noul" && typeof answer.value === "number" ? (
                      <span className="ml-2">
                        <ProbabilityBar value={answer.value} />
                      </span>
                    ) : null}
                  </td>
                  <td className="hidden py-2 text-right text-xs text-muted-foreground sm:table-cell">
                    {Object.keys(answer.probabilities).length === 0
                      ? null
                      : Object.entries(answer.probabilities)
                          .sort((a, b) => b[1] - a[1])
                          .map(([label, p]) => `${humanize(label)} ${formatProbability(p)}`)
                          .join(" · ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {triage.rationale_codes.length > 0 ? (
            <p className="text-xs text-muted-foreground">
              Rationale codes: <UntrustedText value={triage.rationale_codes.join(", ")} limit={200} mono />
            </p>
          ) : null}
        </>
      )}

      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 border-t border-rule pt-3 text-xs">
        <dt className="text-muted-foreground">Model</dt>
        <dd className="font-mono text-ink-2">
          <UntrustedText value={`${assessment.provider} ${assessment.model}`} limit={80} />
        </dd>
        <dt className="text-muted-foreground">Question set</dt>
        <dd className="font-mono text-ink-2">
          <UntrustedText value={triage?.question_set_version ?? assessment.prompt_version} limit={80} />
        </dd>
        <dt className="text-muted-foreground">Input hash</dt>
        <dd className="font-mono break-all text-ink-2">
          {assessment.context_input_hash}
          {outdated ? (
            <span className="mt-0.5 block font-sans text-warn">
              Made on an earlier version of the investigation context (current hash differs).
            </span>
          ) : null}
        </dd>
        <dt className="text-muted-foreground">Assessed</dt>
        <dd>
          <Timestamp value={assessment.created_at} /> <span className="text-muted-foreground">· {formatMs(assessment.latency_ms)}</span>
        </dd>
      </dl>
    </div>
  );
}

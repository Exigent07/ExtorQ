import { cn } from "cn";
import { CircleCheck, TriangleAlert } from "lucide-react";

import { UntrustedText } from "@/components/console/untrusted-text";
import { formatCount, formatDuration, formatUtc, formatUtcTime, formatWindowLength } from "@/lib/format";

import { ValueChips } from "./feature-value";
import { Eyebrow } from "./marks";
import { type KeySignal, type Sequence, stageGap, type ThresholdCheck } from "./signals";

/** CORR-002 and other sequence rules: the ordered stages as a stepper with the gaps between them. */
function SequenceStepper({ sequence }: { sequence: Sequence }) {
  return (
    <div className="@container rounded-lg bg-white/[0.02] px-4 py-4 ring-1 ring-hairline ring-inset">
      <ol className="grid gap-4 @2xl:grid-flow-col @2xl:auto-cols-fr @2xl:gap-0" aria-label="Ordered stages of the sequence">
        {sequence.stages.map((stage, index) => {
          const next = sequence.stages[index + 1];
          return (
            <li key={`${stage.token}-${index}`} className="grid min-w-0 grid-cols-[1.75rem_minmax(0,1fr)] gap-x-3 @2xl:grid-cols-1 @2xl:gap-y-3">
              <div className="flex items-center">
                <span
                  aria-hidden="true"
                  className="flex size-7 flex-none items-center justify-center rounded-full bg-raised text-xs font-medium text-foreground ring-1 ring-hairline-strong tabular-nums"
                >
                  {index + 1}
                </span>
                {next ? (
                  <span aria-hidden="true" className="relative mx-3 hidden h-px flex-1 bg-hairline-strong @2xl:block">
                    {next.sincePrevious !== null ? (
                      <span className="absolute bottom-1.5 left-1/2 -translate-x-1/2 text-xs whitespace-nowrap text-muted-foreground tabular-nums">
                        {stageGap(next.sincePrevious)}
                      </span>
                    ) : null}
                  </span>
                ) : null}
              </div>
              <div className="min-w-0 @2xl:pr-4">
                <p className="flex flex-wrap items-baseline gap-x-2 text-sm font-medium text-foreground">
                  <span>
                    <UntrustedText value={stage.label} limit={64} plain />
                  </span>
                  {stage.sincePrevious !== null ? (
                    <span className="text-xs font-normal text-muted-foreground tabular-nums @2xl:sr-only">
                      {stageGap(stage.sincePrevious)} after the previous stage
                    </span>
                  ) : null}
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {stage.at ? (
                    <time dateTime={stage.at} title={formatUtc(stage.at)} className="font-mono text-fg-2">
                      {formatUtcTime(stage.at)}Z
                    </time>
                  ) : (
                    "time not recorded"
                  )}
                </p>
                {stage.facts.length > 0 ? (
                  <p className="mt-1.5 text-xs leading-relaxed text-fg-2 tabular-nums">{stage.facts.join(" · ")}</p>
                ) : null}
              </div>
            </li>
          );
        })}
      </ol>
      <p className="mt-4 border-t border-hairline-soft pt-3 text-xs leading-relaxed text-muted-foreground">
        {sequence.totalSeconds !== null ? (
          <>
            Whole sequence within <span className="text-fg-2 tabular-nums">{formatDuration(sequence.totalSeconds)}</span> on one
            host.{" "}
          </>
        ) : null}
        The order is what the rule checks: an ordered co-occurrence, never proof that one stage caused the next.
      </p>
    </div>
  );
}

/** Observed values against the rule's thresholds (the rule fires when any one is met). */
function ThresholdChecks({ checks, windowSeconds }: { checks: ThresholdCheck[]; windowSeconds: number | null }) {
  return (
    <div className="grid gap-2">
      <Eyebrow>
        Threshold checks{" "}
        <span className="font-normal">
          · the rule fires when any one is met{windowSeconds !== null ? ` inside one ${formatWindowLength(windowSeconds)} sliding window` : ""}
        </span>
      </Eyebrow>
      <ul className="divide-y divide-hairline-soft rounded-lg ring-1 ring-hairline ring-inset">
        {checks.map((check) => (
          <li key={check.key} className="flex items-center justify-between gap-4 px-4 py-2.5 text-sm">
            <span className="min-w-0 text-fg-2">{check.label}</span>
            <span className="flex flex-none items-center gap-4">
              <span className="tabular-nums">
                <span className="font-semibold text-foreground">{formatCount(check.observed)}</span>
                <span className="text-muted-foreground"> / {formatCount(check.threshold)}</span>
              </span>
              <span
                className={cn(
                  "inline-flex w-20 items-center justify-end gap-1.5 text-xs",
                  check.met ? "font-medium text-foreground" : "text-muted-foreground",
                )}
              >
                <span
                  aria-hidden="true"
                  className={cn("size-1.5 rounded-full", check.met ? "bg-foreground" : "bg-transparent ring-1 ring-fg-faint ring-inset")}
                />
                {check.met ? "Fired" : "Not met"}
              </span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function SignalRow({ signal }: { signal: KeySignal }) {
  const risk = signal.tone === "risk";
  return (
    <li
      className={cn(
        "grid grid-cols-[1rem_minmax(0,1fr)] gap-x-3 rounded-lg px-4 py-3 ring-1 ring-inset",
        risk ? "bg-health-warn/[0.05] ring-health-warn/20" : "bg-white/[0.02] ring-hairline",
      )}
    >
      {risk ? (
        <TriangleAlert className="mt-0.5 size-4 text-health-warn" aria-hidden="true" />
      ) : (
        <CircleCheck className="mt-0.5 size-4 text-fg-2" aria-hidden="true" />
      )}
      <div className="grid min-w-0 gap-1.5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
          <span className="text-sm font-medium text-foreground">
            {signal.title}
            <span className="sr-only">{risk ? " (risk signal)" : " (corroboration)"}</span>
          </span>
          {signal.values.length > 0 ? <ValueChips values={signal.values} title={`${signal.title}: all values`} preview={6} align="start" /> : null}
        </div>
        {signal.note ? <p className="text-xs leading-relaxed text-muted-foreground">{signal.note}</p> : null}
      </div>
    </li>
  );
}

/**
 * The decisive signals of the alert, above the feature lists: a sequence rule's ordered stages,
 * the rule's threshold checks, then risk signals (amber) and corroboration (neutral). Every
 * value comes from the detector or the correlation layer; nothing here is AI output.
 */
export function KeySignals({
  sequence,
  checks,
  signals,
  windowSeconds,
}: {
  sequence: Sequence | null;
  checks: ThresholdCheck[];
  signals: KeySignal[];
  windowSeconds: number | null;
}) {
  if (!sequence && checks.length === 0 && signals.length === 0) return null;
  return (
    <section aria-labelledby="key-signals-title" className="grid gap-3">
      <h3 id="key-signals-title" className="text-sm font-semibold text-foreground">
        Key signals
      </h3>
      {sequence ? <SequenceStepper sequence={sequence} /> : null}
      {checks.length > 0 ? <ThresholdChecks checks={checks} windowSeconds={windowSeconds} /> : null}
      {signals.length > 0 ? (
        <ul className="grid gap-2" aria-label="Risk signals and corroboration">
          {signals.map((signal) => (
            <SignalRow key={signal.id} signal={signal} />
          ))}
        </ul>
      ) : null}
    </section>
  );
}

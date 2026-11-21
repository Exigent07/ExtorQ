import { ChevronRight } from "lucide-react";
import type { ReactNode } from "react";

import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { InvestigationContext, Relationship, TimelineEntry } from "@/lib/api/schemas";
import { formatCount, formatDuration, formatUtc } from "@/lib/format";

import { basisLabel, EvidenceMark, RelationshipBadge, STRENGTH_LABEL } from "./relationship";

/** Relationship time offsets are measured from the alert's first_seen (contracts/context.py). */
function delta(seconds: number): string {
  if (!Number.isFinite(seconds)) return "time offset unknown";
  if (Math.abs(seconds) < 1) return "at the alert's first evidence";
  return `${formatDuration(Math.abs(seconds))} ${seconds < 0 ? "before" : "after"} the alert's first evidence`;
}

/** Candidate (inferred) links drawn in the timeline: the ones closest in time to the evidence. */
const MAX_TIMELINE_CANDIDATES = 20;

function typeOf(entry: TimelineEntry, rel: Relationship | undefined): string | null {
  return entry.relationship_type ?? rel?.relationship_type ?? null;
}

/**
 * Split the timeline into what is drawn (evidence, direct links and the candidates nearest
 * to the evidence) and what is only summarised (further candidates, unestablished).
 */
function splitTimeline(entries: TimelineEntry[], relationships: Map<string, Relationship>) {
  const candidates = entries
    .filter((e) => !e.is_evidence && typeOf(e, relationships.get(e.event_id)) === "candidate")
    .sort(
      (a, b) =>
        Math.abs(relationships.get(a.event_id)?.time_delta_seconds ?? Infinity) -
        Math.abs(relationships.get(b.event_id)?.time_delta_seconds ?? Infinity),
    );
  const keptCandidates = new Set(candidates.slice(0, MAX_TIMELINE_CANDIDATES).map((e) => e.event_id));
  const drawn = entries.filter(
    (e) => e.is_evidence || typeOf(e, relationships.get(e.event_id)) === "direct" || keptCandidates.has(e.event_id),
  );
  const drawnIds = new Set(drawn.map((e) => e.event_id));
  const summarised = entries.filter((e) => !drawnIds.has(e.event_id));
  return { drawn, summarised, hiddenCandidates: candidates.length - keptCandidates.size };
}

/** "149 × k8s.api.request" style counts of folded observations, largest first. */
function typeCounts(entries: { event_type: string }[]): [string, number][] {
  const counts = new Map<string, number>();
  for (const e of entries) counts.set(e.event_type, (counts.get(e.event_type) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
}

function TimelineRow({
  entry,
  rel,
  jump,
}: {
  entry: TimelineEntry;
  rel: Relationship | undefined;
  jump: string | null;
}) {
  // Related observations are one compact line (details live in "Correlated observations");
  // evidence rows keep their full summary and a link to the evidence table.
  const linkText = rel ? `${STRENGTH_LABEL[rel.strength] ?? rel.strength} · ${rel.bases.map(basisLabel).join(", ")} · ${delta(rel.time_delta_seconds)}` : undefined;
  return (
    <li
      className={
        entry.is_evidence
          ? "grid items-baseline gap-x-3 border-b border-rule bg-raised/40 py-2 last:border-0 sm:grid-cols-[10.5rem_7.5rem_minmax(0,1fr)]"
          : "grid items-baseline gap-x-3 border-b border-rule py-1.5 last:border-0 sm:grid-cols-[10.5rem_7.5rem_minmax(0,1fr)]"
      }
    >
      <time dateTime={entry.time} className="font-mono text-xs text-ink-2">
        {formatUtc(entry.time)}
      </time>
      <span>{entry.is_evidence ? <EvidenceMark /> : <RelationshipBadge type={entry.relationship_type ?? rel?.relationship_type} />}</span>
      <div className="min-w-0" title={linkText}>
        <span className="mr-2 font-mono text-xs text-ink">
          <UntrustedText value={entry.event_type} limit={48} />
        </span>
        <span className={entry.is_evidence ? "text-sm text-ink" : "text-sm text-ink-2"}>
          <UntrustedText value={entry.summary} limit={entry.is_evidence ? 300 : 140} />
        </span>
        {jump ? (
          <a href={jump} className="ml-2 text-xs whitespace-nowrap text-muted-foreground hover:text-ink hover:underline">
            Evidence row
          </a>
        ) : null}
      </div>
    </li>
  );
}

function Folded({ count, what, children }: { count: number; what: string; children: ReactNode }) {
  return (
    <details className="group mt-2 rounded-md border border-border">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:text-ink [&::-webkit-details-marker]:hidden">
        <ChevronRight className="size-3 flex-none transition-transform group-open:rotate-90" aria-hidden="true" />
        <span>
          {formatCount(count)} {what}
        </span>
      </summary>
      <div className="border-t border-border px-3 pb-2">{children}</div>
    </details>
  );
}

/**
 * Ordered event timeline of the investigation context: the evidence the rule cited and the
 * related observations with an established (direct or candidate) link, in time order.
 * Unestablished observations are kept but folded: they were considered and have no
 * supported link to the alert.
 */
export function TimelinePanel({
  context,
  evidenceIds,
}: {
  context: InvestigationContext;
  evidenceIds: Set<string>;
}) {
  const relationships = new Map<string, Relationship>(context.relationships.map((r) => [r.event_id, r]));
  const entries = [...context.timeline].sort((a, b) => Date.parse(a.time) - Date.parse(b.time));
  const { drawn: prominent, summarised: folded, hiddenCandidates } = splitTimeline(entries, relationships);
  const evidence = entries.filter((e) => e.is_evidence).length;
  const unestablished = folded.length - hiddenCandidates;
  const jumpFor = (e: TimelineEntry) => (evidenceIds.has(e.event_id) ? `#evidence-${e.event_id}` : null);

  return (
    <Panel
      title="Event timeline"
      titleId="timeline-title"
      meta={
        <span>
          {formatCount(evidence)} evidence · {formatCount(entries.length - evidence - unestablished)} linked · {formatCount(unestablished)} unestablished
          {context.truncated.timeline ? " · truncated by the context builder" : ""}
        </span>
      }
    >
      {entries.length === 0 ? (
        <EmptyState>The investigation context holds no timeline entries.</EmptyState>
      ) : (
        <>
          {prominent.length === 0 ? (
            <EmptyState>No timeline entry is evidence or has an established link to the alert.</EmptyState>
          ) : (
            <ol className="flex flex-col">
              {prominent.map((entry) => (
                <TimelineRow key={`${entry.event_id}-${entry.time}`} entry={entry} rel={relationships.get(entry.event_id)} jump={jumpFor(entry)} />
              ))}
            </ol>
          )}
          {folded.length > 0 ? (
            <p className="mt-2 rounded-md border border-border px-3 py-2 text-xs text-muted-foreground">
              {formatCount(folded.length)} more observations are not drawn here
              {hiddenCandidates > 0
                ? `: ${formatCount(hiddenCandidates)} further candidate (inferred) links beyond the ${MAX_TIMELINE_CANDIDATES} closest in time, and ${formatCount(unestablished)} unestablished (no supported link)`
                : " (unestablished: considered by the correlation layer, no supported link to this alert)"}
              . Most frequent:{" "}
              {typeCounts(folded)
                .map(([type, n]) => `${type} ${formatCount(n)}`)
                .join(" · ")}
              .{" "}
              <a href="#correlations-title" className="text-ink-2 hover:text-ink hover:underline">
                Reasons per observation
              </a>
            </p>
          ) : null}
        </>
      )}
    </Panel>
  );
}

function CorrelationRow({ r, entry }: { r: Relationship; entry: TimelineEntry | undefined }) {
  return (
    <li className="py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <RelationshipBadge type={r.relationship_type} />
        <span className="text-xs text-muted-foreground">{STRENGTH_LABEL[r.strength] ?? r.strength}</span>
        {entry ? (
          <span className="font-mono text-xs text-ink-2">
            <UntrustedText value={entry.event_type} limit={64} />
          </span>
        ) : null}
        <span className="text-xs text-muted-foreground">{delta(r.time_delta_seconds)}</span>
      </div>
      {entry ? (
        <div className="mt-0.5 text-sm text-ink-2">
          <UntrustedText value={entry.summary} limit={200} />
        </div>
      ) : null}
      <p className="mt-0.5 text-xs text-muted-foreground">
        <UntrustedText value={r.explanation} limit={240} />
      </p>
      <p className="mt-0.5 text-xs text-muted-foreground">Basis: {r.bases.map(basisLabel).join(", ")}</p>
    </li>
  );
}

const VISIBLE_LINKED = 8;
/** Unestablished observations listed at most (the context holds up to 300 relationships). */
const MAX_UNESTABLISHED = 50;

/** Related observations with the correlation layer's own explanation; unestablished ones folded. */
export function CorrelationsPanel({ context }: { context: InvestigationContext }) {
  const related = context.relationships.filter((r) => !r.bases.includes("evidence"));
  const byEvent = new Map(context.timeline.map((t) => [t.event_id, t]));
  const order = ["direct", "candidate"];
  const linked = related
    .filter((r) => order.includes(r.relationship_type))
    .sort(
      (a, b) =>
        order.indexOf(a.relationship_type) - order.indexOf(b.relationship_type) ||
        Math.abs(a.time_delta_seconds) - Math.abs(b.time_delta_seconds),
    );
  const unestablished = related.filter((r) => !order.includes(r.relationship_type));
  const direct = linked.filter((r) => r.relationship_type === "direct").length;

  return (
    <Panel
      title="Correlated observations"
      titleId="correlations-title"
      meta={<span>Temporal proximity alone is never treated as causation</span>}
    >
      {related.length === 0 ? (
        <EmptyState>The correlation layer found no related observation for this alert.</EmptyState>
      ) : (
        <>
          <p className="mb-1 text-xs text-muted-foreground">
            {formatCount(direct)} direct (shared identifier) · {formatCount(linked.length - direct)} candidate (inferred) ·{" "}
            {formatCount(unestablished.length)} unestablished
          </p>
          {linked.length === 0 ? (
            <EmptyState>No related observation has a direct or candidate link to this alert.</EmptyState>
          ) : (
            <>
              <ul className="divide-y divide-rule">
                {linked.slice(0, VISIBLE_LINKED).map((r) => (
                  <CorrelationRow key={r.event_id} r={r} entry={byEvent.get(r.event_id)} />
                ))}
              </ul>
              {linked.length > VISIBLE_LINKED ? (
                <Folded count={linked.length - VISIBLE_LINKED} what="more linked observations (direct first, then candidates closest in time)">
                  <ul className="divide-y divide-rule">
                    {linked.slice(VISIBLE_LINKED, VISIBLE_LINKED + MAX_UNESTABLISHED).map((r) => (
                      <CorrelationRow key={r.event_id} r={r} entry={byEvent.get(r.event_id)} />
                    ))}
                  </ul>
                  {linked.length > VISIBLE_LINKED + MAX_UNESTABLISHED ? (
                    <p className="py-2 text-xs text-muted-foreground">
                      {formatCount(linked.length - VISIBLE_LINKED - MAX_UNESTABLISHED)} more are in the stored investigation context and
                      not listed here.
                    </p>
                  ) : null}
                </Folded>
              ) : null}
            </>
          )}
          {unestablished.length > 0 ? (
            <Folded count={unestablished.length} what="unestablished observations with the reason each link was not established">
              <ul className="divide-y divide-rule">
                {unestablished.slice(0, MAX_UNESTABLISHED).map((r) => (
                  <CorrelationRow key={r.event_id} r={r} entry={byEvent.get(r.event_id)} />
                ))}
              </ul>
              {unestablished.length > MAX_UNESTABLISHED ? (
                <p className="py-2 text-xs text-muted-foreground">
                  {formatCount(unestablished.length - MAX_UNESTABLISHED)} more are in the stored investigation context and not listed here.
                </p>
              ) : null}
            </Folded>
          ) : null}
        </>
      )}
    </Panel>
  );
}

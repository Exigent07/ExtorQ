import { ArrowUpRight, GitCommitVertical } from "lucide-react";

import { SectionCard } from "@/components/console/section-card";
import { EmptyState, Notice } from "@/components/console/states";
import { Timeline, type TimelineItem as SharedTimelineItem } from "@/components/console/timeline";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { InvestigationContext } from "@/lib/api/schemas";
import { formatCount, formatDuration, formatUtcTime } from "@/lib/format";

import { ActivityStrip } from "./activity-strip";
import { BurstRows } from "./burst-rows";
import { TabLink } from "./investigation-tabs";
import { StrengthMeter } from "./correlation-table";
import { basisLabel, orderedBases } from "./labels";
import { buildTimeline, offsetLabel, secondsBetween, TIMELINE_LIMITS, type TimelineItem, type TimelineRow } from "./model";
import { RelationshipHover } from "./relationship";

function EvidenceJump({ eventId, evidenceIds }: { eventId: string; evidenceIds: ReadonlySet<string> }) {
  if (!evidenceIds.has(eventId)) return null;
  return (
    <a
      href={`#evidence-${eventId}`}
      className="inline-flex flex-none items-center gap-0.5 rounded-sm text-xs whitespace-nowrap text-muted-foreground transition-colors duration-150 hover:text-foreground"
    >
      Evidence row
      <ArrowUpRight className="size-3" aria-hidden="true" />
    </a>
  );
}

function relDetail(row: TimelineRow) {
  return row.rel
    ? {
        type: row.kind,
        strength: row.rel.strength,
        bases: row.rel.bases,
        offsetSeconds: row.rel.time_delta_seconds,
        explanation: row.rel.explanation,
      }
    : null;
}

/** Strength as a dot meter, the most telling basis and the offset; the explanation on hover. */
function LinkSummary({ row }: { row: TimelineRow }) {
  const detail = relDetail(row);
  if (!detail) return null;
  const top = orderedBases(detail.bases)[0];
  return (
    <RelationshipHover rel={detail} className="gap-2 no-underline">
      <StrengthMeter strength={detail.strength} />
      <span className="text-muted-foreground underline decoration-fg-faint decoration-dotted underline-offset-4">
        {top ? `${basisLabel(top)} · ` : ""}
        <span className="tabular-nums">{offsetLabel(detail.offsetSeconds)}</span>
      </span>
    </RelationshipHover>
  );
}

/** Summary text unless it only repeats the event type (the title already shows it). */
function Summary({ row, limit }: { row: TimelineRow; limit: number }) {
  if (!row.summary || row.summary === row.eventType) return null;
  return <UntrustedText value={row.summary} limit={limit} />;
}

function toTimelineItem(item: TimelineItem, evidenceIds: ReadonlySet<string>): SharedTimelineItem {
  const single = item.rows.length === 1 ? item.rows[0] : undefined;
  const source = (
    <span className="font-mono text-xs text-muted-foreground">
      <UntrustedText value={item.sourceType} limit={40} />
    </span>
  );
  if (single) {
    return {
      id: item.key,
      time: item.first,
      kind: item.kind,
      meta: (
        <>
          {item.kind === "evidence" ? null : <LinkSummary row={single} />}
          {source}
        </>
      ),
      title: (
        <span className="flex min-w-0 flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <code className="font-mono text-xs text-foreground">
            <UntrustedText value={item.eventType} limit={64} />
          </code>
          <span className="min-w-0 text-sm text-fg-2">
            <Summary row={single} limit={item.kind === "evidence" ? 240 : 160} />
          </span>
          {item.kind === "evidence" ? <EvidenceJump eventId={single.eventId} evidenceIds={evidenceIds} /> : null}
        </span>
      ),
    };
  }
  const span = secondsBetween(item.first, item.last);
  return {
    id: item.key,
    time: item.first,
    kind: item.kind,
    meta: (
      <>
        <span className="font-mono text-xs text-muted-foreground tabular-nums">→ {formatUtcTime(item.last)}Z</span>
        {source}
      </>
    ),
    title: (
      <BurstRows
        count={item.rows.length}
        summary={
          <span className="flex flex-wrap items-baseline gap-x-2">
            <code className="font-mono text-xs text-foreground">
              <UntrustedText value={item.eventType} limit={64} />
            </code>
            <span className="text-sm text-fg-2 tabular-nums">
              {formatCount(item.rows.length)} observations
              {span === null ? "" : span < 1 ? " within one second" : ` in ${formatDuration(span)}`}
            </span>
          </span>
        }
      >
        {item.rows.map((row) => (
          <li key={row.key} className="flex min-w-0 items-center gap-3 px-3 py-1.5">
            <time dateTime={row.time} className="flex-none font-mono text-xs text-muted-foreground tabular-nums">
              {formatUtcTime(row.time)}
            </time>
            <span className="min-w-0 flex-1 text-xs text-fg-2">
              {row.summary && row.summary !== row.eventType ? <UntrustedText value={row.summary} limit={200} oneLine /> : null}
            </span>
            {row.kind === "evidence" ? <EvidenceJump eventId={row.eventId} evidenceIds={evidenceIds} /> : <LinkSummary row={row} />}
          </li>
        ))}
      </BurstRows>
    ),
  };
}

/**
 * Timeline tab: the investigation context on one time axis (activity strip), then the drawn
 * timeline: evidence and direct links in full, the candidate and unestablished observations
 * closest in time, bursts folded. Relationship explanations are on hover; observations linked
 * only through a NAT-shared source IP carry the caveat.
 */
export function TimelinePanel({
  context,
  evidenceIds,
  firstSeen,
  lastSeen,
}: {
  context: InvestigationContext;
  evidenceIds: ReadonlySet<string>;
  firstSeen: string;
  lastSeen: string;
}) {
  const model = buildTimeline(context);
  const linked = model.totals.direct + model.totals.candidate;
  const hiddenCandidates = model.totals.candidate - model.drawn.candidate;
  const hiddenUnestablished = model.totals.unestablished - model.drawn.unestablished;

  return (
    <SectionCard
      title="Event timeline"
      titleId="timeline-title"
      icon={GitCommitVertical}
      description="Evidence the rule cited and related observations, in time order (UTC)"
      meta={
        <span className="tabular-nums">
          {formatCount(model.totals.evidence)} evidence · {formatCount(linked)} linked · {formatCount(model.totals.unestablished)} unestablished
        </span>
      }
    >
      {model.rows.length === 0 ? (
        <EmptyState>The investigation context holds no timeline entries.</EmptyState>
      ) : (
        <div className="grid gap-6">
          <ActivityStrip
            rows={model.rows}
            windowStart={context.window_start}
            windowEnd={context.window_end}
            firstSeen={firstSeen}
            lastSeen={lastSeen}
          />
          <div className="border-t border-hairline-soft pt-6">
            {model.items.length === 0 ? (
              <EmptyState>No timeline entry is evidence or has an established link to the alert.</EmptyState>
            ) : (
              <Timeline items={model.items.map((item) => toTimelineItem(item, evidenceIds))} />
            )}
          </div>
          {model.hidden > 0 || context.truncated.timeline ? (
            <Notice>
              {model.hidden > 0 ? (
                <>
                  {formatCount(model.hidden)} more observation{model.hidden === 1 ? " is" : "s are"} not drawn
                  {hiddenCandidates > 0 ? `: ${formatCount(hiddenCandidates)} candidate links beyond the ${TIMELINE_LIMITS.candidates} closest in time` : ""}
                  {hiddenUnestablished > 0
                    ? `${hiddenCandidates > 0 ? " and" : ":"} ${formatCount(hiddenUnestablished)} unestablished beyond the ${TIMELINE_LIMITS.unestablished} closest`
                    : ""}
                  . Most frequent: {model.hiddenTypes.map(([type, n]) => `${type} ${formatCount(n)}`).join(" · ")}.{" "}
                </>
              ) : null}
              {context.truncated.timeline ? "The context builder truncated the timeline. " : ""}
              Every observation and its reason is listed in <TabLink tab="correlation">Correlation</TabLink>.
            </Notice>
          ) : null}
        </div>
      )}
    </SectionCard>
  );
}

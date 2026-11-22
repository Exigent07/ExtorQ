import { ListChecks, ShieldAlert } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { PageHeader } from "@/components/console/page-header";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import { AlertsTable } from "@/components/views/detections/alerts-table";
import type { FacetOption } from "@/components/console/data-table";
import { DetectionsKpiRow } from "@/components/views/detections/kpi-row";
import {
  alertFigures,
  ALERTS_PER_REQUEST,
  apiFilters,
  detectionsFinding,
  detectionsSearch,
  type FacetSelection,
  hasFacetFilters,
  parseDetectionsQuery,
  ruleFigures,
  toAlertRow,
} from "@/components/views/detections/model";
import { RulesTable } from "@/components/views/detections/rules-table";
import { DetectionsProvider, DetectionsTabs, TimeRangeToggle } from "@/components/views/detections/workspace";
import { TIME_RANGES } from "@/lib/filters";
import { formatCount } from "@/lib/format";
import { listAlerts, listRules } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";


export const metadata: Metadata = { title: "Detections" };

/**
 * Detections: what fired in the selected range (alert history) and whether the rules behind
 * it run (rules). Two API reads in parallel: the alerts with activity in the range (one page
 * of up to 200, which usually holds the whole range, so facets filter it in the browser
 * without further API reads) and the rule list. When the range holds more alerts than one
 * page, a third read asks the API for the filtered set and the page says what it covers.
 */
export default async function DetectionsPage({ searchParams }: PageProps<"/detections">) {
  const session = await requireSession();
  const query = parseDetectionsQuery(await searchParams);
  const selection: FacetSelection = {
    severity: query.severity,
    rule: query.rule,
    asset: query.asset,
    status: query.status,
    sim: query.sim,
  };
  const [inRange, rules] = await Promise.all([listAlerts(session, { range: query.range }), listRules(session)]);

  const complete = inRange.ok && !inRange.data.page.has_more;
  let table = inRange;
  let serverFiltered = false;
  if (inRange.ok && !complete && (hasFacetFilters(selection) || query.offset > 0)) {
    const filters = apiFilters(selection);
    table = await listAlerts(session, {
      range: query.range,
      offset: query.offset,
      severity: filters.severity,
      status: filters.status,
      ruleId: filters.ruleId,
      assetId: filters.assetId,
    });
    serverFiltered = hasFacetFilters(selection);
  }

  const rangeLabel = TIME_RANGES[query.range].label.toLowerCase();
  const alerts = inRange.ok ? alertFigures(inRange.data.items, inRange.data.page.total, inRange.data.page.has_more) : null;
  const ruleStats = rules.ok ? ruleFigures(rules.data.items) : null;
  const now = table.ok ? table.receivedAt : rules.ok ? rules.receivedAt : new Date().toISOString();
  const ruleOptions: FacetOption[] = rules.ok
    ? [...rules.data.items]
        .sort((a, b) => a.rule_id.localeCompare(b.rule_id))
        .map((r) => ({ value: r.rule_id, label: r.rule_id, description: r.title }))
    : [];

  const page = table.ok ? table.data.page : null;
  const olderOffset = page?.has_more ? (page.next_offset ?? query.offset + ALERTS_PER_REQUEST) : null;
  const newerOffset = query.offset > 0 ? Math.max(0, query.offset - ALERTS_PER_REQUEST) : null;
  const pageLink = (offset: number) =>
    `/detections${detectionsSearch({ ...selection, range: query.range, offset, tab: "alerts" })}`;

  const alertsPanel = (
    <SectionCard
      title="Alert history"
      titleId="alert-history-title"
      icon={ShieldAlert}
      description={`Alerts with activity in the ${rangeLabel}, newest activity first. A row opens its investigation.`}
      action={<TimeRangeToggle />}
      flush
    >
      {!table.ok ? (
        <div className="px-5 pb-3">
          <ErrorState what="the alert history" error={table.error} />
        </div>
      ) : table.data.items.length === 0 && !hasFacetFilters(selection) ? (
        <div className="px-5 pb-3">
          <EmptyState compact={false} icon={ShieldAlert}>
            No alert had activity in the {rangeLabel}. Detections write alerts only when their rule fires on stored
            telemetry; a longer range may show older ones.
          </EmptyState>
        </div>
      ) : (
        <div className="grid gap-3">
          {!complete ? (
            <div className="px-5">
              <Notice tone="warn">
                More alerts had activity in the {rangeLabel} than one API page holds ({formatCount(ALERTS_PER_REQUEST)}). This
                table holds {formatCount(table.data.items.length)}
                {serverFiltered ? " that the API matched to the filters" : " with the most recent activity"}
                {query.offset > 0 ? `, starting after the newest ${formatCount(query.offset)}` : ""}; the search and the
                counts cover these rows only. Narrow the time range or page through them:{" "}
                {newerOffset !== null ? (
                  <Link href={pageLink(newerOffset)} className="font-medium text-foreground hover:underline">
                    Newer
                  </Link>
                ) : null}
                {newerOffset !== null && olderOffset !== null ? " · " : null}
                {olderOffset !== null ? (
                  <Link href={pageLink(olderOffset)} className="font-medium text-foreground hover:underline">
                    Older
                  </Link>
                ) : null}
                {newerOffset === null && olderOffset === null ? "this is the only page for these filters." : "."}
              </Notice>
            </div>
          ) : null}
          <AlertsTable
            rows={table.data.items.map(toAlertRow)}
            now={now}
            ruleOptions={ruleOptions}
            loadedNote={complete ? null : "loaded rows only"}
          />
        </div>
      )}
    </SectionCard>
  );

  const rulesPanel = (
    <SectionCard
      title="Detection rules"
      titleId="rules-title"
      icon={ListChecks}
      description="Versioned SQL rules run by the detector: last run, execution in the last 24 hours and the alerts each produced."
      meta={rules.ok ? <span className="tabular-nums">{formatCount(rules.data.items.length)} loaded</span> : null}
      flush
    >
      {!rules.ok ? (
        <div className="px-5 pb-3">
          <ErrorState what="the detection rules" error={rules.error} />
        </div>
      ) : rules.data.items.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No rule has been registered by the detector yet.</EmptyState>
        </div>
      ) : (
        <RulesTable rules={rules.data.items} now={rules.receivedAt} />
      )}
    </SectionCard>
  );

  return (
    <>
      <PageHeader
        title="Detections"
        subtitle={detectionsFinding(alerts, ruleStats, query.range)}
        freshness={inRange.ok ? inRange.receivedAt : rules.ok ? rules.receivedAt : undefined}
      />
      <div className="grid gap-6">
        <DetectionsKpiRow alerts={alerts} rules={ruleStats} rangeLabel={rangeLabel} now={now} />
        <DetectionsProvider
          initialTab={query.tab}
          initialSelection={selection}
          range={query.range}
          offset={query.offset}
          complete={complete}
        >
          <DetectionsTabs
            alerts={alertsPanel}
            rules={rulesPanel}
            alertCount={alerts ? alerts.total : null}
            ruleCount={rules.ok ? rules.data.items.length : null}
          />
        </DetectionsProvider>
      </div>
    </>
  );
}

import type { Metadata } from "next";
import Link from "next/link";

import { Freshness } from "@/components/console/freshness";
import { PageHeader } from "@/components/console/page-header";
import { Panel } from "@/components/console/panel";
import { EmptyState, ErrorState } from "@/components/console/states";
import { AlertFilterForm } from "@/components/views/detections/alert-filters";
import { AlertHistoryTable } from "@/components/views/detections/alert-history";
import { RulesTable } from "@/components/views/detections/rules-table";
import type { AlertListResponse, RuleListResponse } from "@/lib/api/schemas";
import { alertFiltersToSearch, type AlertFilters, ALERT_PAGE_SIZE, parseAlertFilters, TIME_RANGES } from "@/lib/filters";
import { formatCount, formatUtcShort } from "@/lib/format";
import type { ApiResult } from "@/lib/server/api-client";
import { listAlerts, listAssets, listRules } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "Detections" };

function finding(alerts: ApiResult<AlertListResponse>, rules: ApiResult<RuleListResponse>, filters: AlertFilters): string {
  const parts: string[] = [];
  if (alerts.ok) {
    const total = alerts.data.page.total ?? alerts.data.items.length;
    const filtered = filters.asset || filters.severity || filters.rule || filters.status;
    parts.push(
      `${formatCount(total)} alert${total === 1 ? "" : "s"} ${filtered ? "match the filters" : "with activity"} in the ${TIME_RANGES[filters.range].label.toLowerCase()}`,
    );
  }
  if (rules.ok) {
    const items = rules.data.items;
    const enabled = items.filter((r) => r.enabled).length;
    const failing = items.filter((r) => r.last_run?.last_status === "failed").length;
    const never = items.filter((r) => r.enabled && !r.last_run).length;
    parts.push(`${formatCount(enabled)} of ${formatCount(items.length)} rules enabled`);
    if (failing > 0) parts.push(`${formatCount(failing)} failing`);
    if (never > 0) parts.push(`${formatCount(never)} never ran`);
  }
  return parts.join(" · ");
}

export default async function DetectionsPage({ searchParams }: PageProps<"/detections">) {
  const session = await requireSession();
  const filters = parseAlertFilters(await searchParams);
  const [alerts, rules, assets] = await Promise.all([
    listAlerts(session, filters),
    listRules(session),
    listAssets(session),
  ]);
  const now = alerts.ok ? alerts.receivedAt : new Date().toISOString();

  const assetOptions = assets.ok
    ? assets.data.items.map((a) => ({ id: a.asset_id, label: a.asset_id })).sort((a, b) => a.id.localeCompare(b.id))
    : [];
  const ruleOptions = rules.ok
    ? rules.data.items.map((r) => ({ id: r.rule_id, label: `${r.rule_id} ${r.title}` })).sort((a, b) => a.id.localeCompare(b.id))
    : [];

  const page = alerts.ok ? alerts.data.page : null;
  const prevOffset = Math.max(0, filters.offset - ALERT_PAGE_SIZE);
  const nextOffset = page?.next_offset ?? (page?.has_more ? filters.offset + ALERT_PAGE_SIZE : null);

  return (
    <>
      <PageHeader
        title="Detections"
        finding={finding(alerts, rules, filters)}
        actions={alerts.ok ? <Freshness at={alerts.receivedAt} /> : null}
      />
      <div className="grid gap-6">
        <Panel
          title="Alert history"
          titleId="alert-history-title"
          meta={
            alerts.ok ? (
              <span>
                {formatUtcShort(alerts.data.range.since)} to {formatUtcShort(alerts.data.range.until)} UTC
              </span>
            ) : null
          }
        >
          <div className="mb-4">
            <AlertFilterForm filters={filters} assets={assetOptions} rules={ruleOptions} />
          </div>
          {!alerts.ok ? (
            <ErrorState what="the alert history" error={alerts.error} />
          ) : alerts.data.items.length === 0 ? (
            <EmptyState>
              {filters.offset > 0
                ? "No more alerts on this page."
                : "No alert matches these filters in this time range. Detections write alerts only when their rule fires on stored telemetry."}
            </EmptyState>
          ) : (
            <>
              <AlertHistoryTable alerts={alerts.data.items} now={now} />
              <nav aria-label="Alert history pages" className="mt-3 flex items-center justify-between gap-4 text-xs text-muted-foreground">
                <span>
                  {formatCount(filters.offset + 1)}–{formatCount(filters.offset + alerts.data.items.length)}
                  {page?.total !== null && page?.total !== undefined ? ` of ${formatCount(page.total)}` : ""}
                </span>
                <span className="flex gap-4">
                  {filters.offset > 0 ? (
                    <Link href={`/detections${alertFiltersToSearch({ ...filters, offset: prevOffset })}`} className="hover:text-ink">
                      Newer
                    </Link>
                  ) : null}
                  {nextOffset !== null ? (
                    <Link href={`/detections${alertFiltersToSearch({ ...filters, offset: nextOffset })}`} className="hover:text-ink">
                      Older
                    </Link>
                  ) : null}
                </span>
              </nav>
            </>
          )}
        </Panel>

        <Panel
          title="Detection rules"
          titleId="rules-title"
          meta={rules.ok ? <span>{formatCount(rules.data.items.length)} loaded</span> : null}
        >
          {!rules.ok ? (
            <ErrorState what="the detection rules" error={rules.error} />
          ) : rules.data.items.length === 0 ? (
            <EmptyState>No rule has been registered by the detector yet.</EmptyState>
          ) : (
            <RulesTable rules={rules.data.items} now={rules.receivedAt} />
          )}
        </Panel>
      </div>
    </>
  );
}

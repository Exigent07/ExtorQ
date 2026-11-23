import { ShieldAlert } from "lucide-react";
import Link from "next/link";

import { CardLink, SectionCard } from "@/components/console/section-card";
import { SEVERITY_LABEL, SeverityBadge, SeverityDot } from "@/components/console/severity";
import { EmptyState } from "@/components/console/states";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AnalystStatusText } from "@/components/views/alerts/alert-bits";
import type { AlertListItem } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { assetHref, investigationHref } from "@/lib/security/ids";

/**
 * High and critical alerts of the last 7 days (the API's selection), open ones first. The
 * rule title links to the investigation; the summary is one line with the full text on hover.
 */
export function RecentAlertsCard({
  alerts,
  openTotal,
  now,
  className,
}: {
  alerts: AlertListItem[];
  openTotal: number;
  now: string;
  className?: string;
}) {
  return (
    <SectionCard
      title="Recent important alerts"
      titleId="recent-alerts-title"
      icon={ShieldAlert}
      description="High and critical in the last 7 days · open first"
      className={className}
      flush
      meta={<span className="tabular-nums">{formatCount(openTotal)} open in total</span>}
      action={
        <Link href="/detections" className="group/link">
          <CardLink>All alerts</CardLink>
        </Link>
      }
    >
      {alerts.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No high or critical alert in the last 7 days. Detections that fire appear here first.</EmptyState>
        </div>
      ) : (
        <Table aria-label="Recent important alerts" className="table-fixed">
          <colgroup>
            <col className="hidden w-[96px] sm:table-column" />
            <col />
            <col className="w-[92px]" />
            <col className="hidden w-[148px] sm:table-column" />
          </colgroup>
          <TableHeader>
            <TableRow>
              <TableHead className="hidden sm:table-cell">Severity</TableHead>
              <TableHead>Alert</TableHead>
              <TableHead className="text-right">Last seen</TableHead>
              <TableHead className="hidden sm:table-cell">Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {alerts.map((alert) => {
              const href = investigationHref(alert.alert_id);
              return (
                <TableRow key={alert.alert_id}>
                  <TableCell className="hidden align-top pt-3 sm:table-cell">
                    <SeverityBadge severity={alert.severity} />
                  </TableCell>
                  <TableCell className="min-w-0 py-2.5 whitespace-normal">
                    <div className="flex min-w-0 items-baseline gap-2">
                      <SeverityDot severity={alert.severity} className="translate-y-[-1px] sm:hidden" />
                      <span className="sr-only sm:hidden">{SEVERITY_LABEL[alert.severity]}</span>
                      <span className="flex-none font-mono text-xs text-muted-foreground">{alert.rule_id}</span>
                      {href ? (
                        <Link
                          href={href}
                          className="min-w-0 truncate font-medium text-foreground underline-offset-4 transition-colors duration-150 hover:text-brand hover:underline"
                        >
                          {alert.rule_title}
                        </Link>
                      ) : (
                        <span className="min-w-0 truncate font-medium text-foreground">{alert.rule_title}</span>
                      )}
                    </div>
                    <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                      <Link
                        href={assetHref(alert.asset_id)}
                        className="flex-none font-mono text-fg-2 transition-colors duration-150 hover:text-foreground"
                      >
                        {alert.asset_id}
                      </Link>
                      <span aria-hidden="true" className="text-fg-faint">
                        ·
                      </span>
                      <span className="min-w-0 flex-1">
                        <UntrustedText value={alert.summary} oneLine />
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="align-top pt-3 text-right text-xs">
                    <RelativeTime value={alert.last_seen} now={now} className="text-xs" />
                  </TableCell>
                  <TableCell className="hidden align-top pt-3 text-xs sm:table-cell">
                    <AnalystStatusText status={alert.analyst_status} recorded={alert.analyst_state_recorded} />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
    </SectionCard>
  );
}

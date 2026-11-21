import Link from "next/link";

import { SeverityTag } from "@/components/console/severity";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AlertListItem } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { assetHref, investigationHref } from "@/lib/security/ids";

import { AnalystStatusText, ConfidenceText, SimulationTag } from "../alerts/alert-bits";

import { EvidenceDrilldown } from "./evidence-drilldown";

/** Alert history: one row per alert (deduplicated by the detector), newest activity first. */
export function AlertHistoryTable({ alerts, now }: { alerts: AlertListItem[]; now: string }) {
  return (
    <Table aria-label="Alert history">
      <TableHeader>
        <TableRow>
          <TableHead className="w-24">Severity</TableHead>
          <TableHead>Alert</TableHead>
          <TableHead className="hidden lg:table-cell">Asset</TableHead>
          <TableHead className="hidden md:table-cell">Confidence</TableHead>
          <TableHead className="hidden text-right sm:table-cell">Events</TableHead>
          <TableHead className="text-right">Last seen</TableHead>
          <TableHead className="hidden text-right md:table-cell">State</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {alerts.map((alert) => {
          const href = investigationHref(alert.alert_id);
          return (
            <TableRow key={alert.alert_id}>
              <TableCell className="align-top pt-3">
                <SeverityTag severity={alert.severity} />
              </TableCell>
              <TableCell className="min-w-72 py-2.5 whitespace-normal">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="font-mono text-xs text-muted-foreground">{alert.rule_id}</span>
                  {href ? (
                    <Link href={href} className="font-medium text-ink underline-offset-2 hover:underline">
                      <UntrustedText value={alert.rule_title} limit={96} />
                    </Link>
                  ) : (
                    <UntrustedText value={alert.rule_title} limit={96} className="font-medium text-ink" />
                  )}
                  <SimulationTag runIds={alert.simulation_run_ids} />
                </div>
                <div className="mt-1 text-xs text-muted-foreground">
                  <UntrustedText value={alert.summary} limit={180} />
                </div>
                <div className="mt-0.5 text-xs text-muted-foreground lg:hidden">
                  <UntrustedText value={alert.asset_id} limit={64} mono />
                </div>
                {href ? <EvidenceDrilldown alertId={alert.alert_id} eventCount={alert.event_count} /> : null}
              </TableCell>
              <TableCell className="hidden align-top pt-3 lg:table-cell">
                <Link href={assetHref(alert.asset_id)} className="font-mono text-xs text-ink-2 hover:text-ink">
                  <UntrustedText value={alert.asset_id} limit={48} />
                </Link>
                {alert.service_ids.length > 0 ? (
                  <div className="mt-0.5 text-xs text-muted-foreground">
                    {formatCount(alert.service_ids.length)} service{alert.service_ids.length === 1 ? "" : "s"}
                  </div>
                ) : null}
              </TableCell>
              <TableCell className="hidden align-top pt-3 text-xs md:table-cell">
                <ConfidenceText confidence={alert.confidence} />
              </TableCell>
              <TableCell className="hidden align-top pt-3 text-right font-mono text-xs text-ink-2 sm:table-cell">
                {formatCount(alert.event_count)}
              </TableCell>
              <TableCell className="align-top pt-3 text-right">
                <RelativeTime value={alert.last_seen} now={now} className="text-xs" />
                <div className="hidden text-xs text-muted-foreground xl:block">
                  first <Timestamp value={alert.first_seen} className="text-muted-foreground" />
                </div>
              </TableCell>
              <TableCell className="hidden align-top pt-3 text-right text-xs md:table-cell">
                <AnalystStatusText status={alert.analyst_status} recorded={alert.analyst_state_recorded} />
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

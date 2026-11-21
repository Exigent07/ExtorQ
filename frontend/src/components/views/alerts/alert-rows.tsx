import Link from "next/link";

import { SeverityTag } from "@/components/console/severity";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AlertListItem } from "@/lib/api/schemas";
import { assetHref, investigationHref } from "@/lib/security/ids";

import { AnalystStatusText, SimulationTag } from "./alert-bits";

/** Compact alert list (overview, asset detail): severity, rule + summary, asset, recency, state. */
export function AlertRows({
  alerts,
  now,
  showAsset = true,
}: {
  alerts: AlertListItem[];
  now: string;
  showAsset?: boolean;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-24">Severity</TableHead>
          <TableHead>Alert</TableHead>
          {showAsset ? <TableHead className="hidden w-44 lg:table-cell">Asset</TableHead> : null}
          <TableHead className="text-right">Last seen</TableHead>
          <TableHead className="hidden text-right sm:table-cell">State</TableHead>
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
              <TableCell className="min-w-64 py-2.5 whitespace-normal">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="font-mono text-xs text-muted-foreground">{alert.rule_id}</span>
                  {href ? (
                    <Link href={href} className="font-medium text-ink hover:underline underline-offset-2">
                      {alert.rule_title}
                    </Link>
                  ) : (
                    <span className="font-medium text-ink">{alert.rule_title}</span>
                  )}
                  <SimulationTag runIds={alert.simulation_run_ids} />
                </div>
                <div className="mt-1 truncate text-xs text-muted-foreground">
                  <UntrustedText value={alert.summary} limit={140} />
                </div>
              </TableCell>
              {showAsset ? (
                <TableCell className="hidden align-top pt-3 lg:table-cell">
                  <Link href={assetHref(alert.asset_id)} className="font-mono text-xs text-ink-2 hover:text-ink">
                    {alert.asset_id}
                  </Link>
                </TableCell>
              ) : null}
              <TableCell className="align-top pt-3 text-right">
                <RelativeTime value={alert.last_seen} now={now} className="text-xs" />
              </TableCell>
              <TableCell className="hidden align-top pt-3 text-right text-xs sm:table-cell">
                <AnalystStatusText status={alert.analyst_status} recorded={alert.analyst_state_recorded} />
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

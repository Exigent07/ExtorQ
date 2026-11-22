import { cn } from "cn";
import Link from "next/link";

import { SimulationBadge } from "@/components/console/badges";
import { Hint } from "@/components/console/hint";
import { SeverityBadge } from "@/components/console/severity";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AlertListItem } from "@/lib/api/schemas";
import { analystStatusLabel, isClosedStatus } from "@/lib/format";
import { investigationHref } from "@/lib/security/ids";

const STATUS_DOT: Record<string, string> = {
  new: "bg-foreground",
  acknowledged: "bg-fg-2",
  investigating: "bg-sev-medium",
};

/** Analyst workflow state: open states with a small mark, closed ones in grey (not a severity). */
function AnalystState({ status, recorded }: { status: string; recorded: boolean }) {
  const closed = isClosedStatus(status);
  const body = (
    <span className={cn("inline-flex items-center gap-1.5 whitespace-nowrap", closed ? "text-muted-foreground" : "text-fg-2")}>
      <span
        aria-hidden="true"
        className={cn(
          "size-1.5 flex-none rounded-full",
          closed ? "ring-1 ring-fg-faint ring-inset" : (STATUS_DOT[status] ?? "bg-fg-2"),
        )}
      />
      {analystStatusLabel(status)}
    </span>
  );
  return recorded ? body : <Hint content="No analyst has acted on this alert yet.">{body}</Hint>;
}

/**
 * Alerts of one asset or service, newest activity first as the API returned them: severity,
 * rule and title (a link to the investigation), the summary on one line (telemetry: plain
 * text with a hover card for the full value), analyst state and recency.
 */
export function AlertList({
  alerts,
  now,
  label,
  limit,
}: {
  alerts: AlertListItem[];
  now: string;
  label: string;
  /** Rows shown (the rest is counted below the table by the caller). */
  limit?: number;
}) {
  const rows = limit ? alerts.slice(0, limit) : alerts;
  return (
    <Table aria-label={label}>
      <TableHeader>
        <TableRow>
          <TableHead className="hidden w-24 sm:table-cell">Severity</TableHead>
          <TableHead className="max-sm:pl-(--table-edge)">Alert</TableHead>
          <TableHead className="hidden w-32 md:table-cell">State</TableHead>
          <TableHead className="hidden w-24 text-right sm:table-cell">Last seen</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rows.map((alert) => {
          const href = investigationHref(alert.alert_id);
          return (
            <TableRow key={alert.alert_id}>
              <TableCell className="hidden align-top sm:table-cell">
                <SeverityBadge severity={alert.severity} />
              </TableCell>
              <TableCell className="max-w-0 min-w-56 whitespace-normal max-sm:min-w-0 max-sm:pl-(--table-edge) max-sm:pr-(--table-edge)">
                {/* Phones: severity and recency move into the cell (their columns are hidden). */}
                <div className="mb-1.5 flex items-center gap-2 sm:hidden">
                  <SeverityBadge severity={alert.severity} />
                  <RelativeTime value={alert.last_seen} now={now} className="text-xs" />
                </div>
                <div className="flex min-w-0 items-center gap-2">
                  <span className="flex-none font-mono text-xs text-muted-foreground">{alert.rule_id}</span>
                  {href ? (
                    <Link
                      href={href}
                      className="min-w-0 truncate font-medium text-foreground underline-offset-2 transition-colors duration-150 hover:text-brand hover:underline"
                    >
                      <UntrustedText value={alert.rule_title} plain limit={120} />
                    </Link>
                  ) : (
                    <span className="min-w-0 truncate font-medium text-foreground">
                      <UntrustedText value={alert.rule_title} plain limit={120} />
                    </span>
                  )}
                </div>
                <div className="mt-1 flex min-w-0 items-center gap-2 text-xs text-muted-foreground">
                  {alert.simulation_run_ids.length > 0 ? (
                    <span className="flex-none">
                      <SimulationBadge runIds={alert.simulation_run_ids} />
                    </span>
                  ) : null}
                  <span className="min-w-0 flex-1">
                    <UntrustedText value={alert.summary} oneLine />
                  </span>
                </div>
              </TableCell>
              <TableCell className="hidden align-top text-xs md:table-cell">
                <AnalystState status={alert.analyst_status} recorded={alert.analyst_state_recorded} />
              </TableCell>
              <TableCell className="hidden align-top text-right sm:table-cell">
                <RelativeTime value={alert.last_seen} now={now} className="text-xs" />
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}


import Link from "next/link";

import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { EventListItem } from "@/lib/api/schemas";
import { DASH } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";

import { RawExcerptToggle } from "./raw-excerpt";

/** The acting principal as reported by the source (never inferred). */
export function eventActor(event: EventListItem): string | null {
  return event.actor_name ?? event.k8s_user ?? event.gh_actor_login ?? null;
}

const OUTCOME_CLASS: Record<string, string> = {
  failure: "text-warn",
  denied: "text-warn",
  success: "text-ink-2",
};

/**
 * Stored events, newest first, as recorded. Every string cell is attacker-controllable
 * telemetry and goes through UntrustedText; nothing is linkified.
 */
export function EventsTable({ events, showService = true }: { events: EventListItem[]; showService?: boolean }) {
  return (
    <Table aria-label="Events">
      <TableHeader>
        <TableRow>
          <TableHead className="w-44">Time (UTC)</TableHead>
          <TableHead>Event</TableHead>
          <TableHead className="hidden lg:table-cell">Source</TableHead>
          <TableHead className="hidden md:table-cell">Actor</TableHead>
          <TableHead className="hidden md:table-cell">Source IP</TableHead>
          <TableHead className="hidden sm:table-cell">Outcome</TableHead>
          {showService ? <TableHead className="hidden xl:table-cell">Service</TableHead> : null}
        </TableRow>
      </TableHeader>
      <TableBody>
        {events.map((event) => {
          const actor = eventActor(event);
          const href = event.service_id ? serviceHref(event.service_id) : null;
          return (
            <TableRow key={event.event_id}>
              <TableCell className="align-top pt-3">
                <Timestamp value={event.event_time} />
              </TableCell>
              <TableCell className="min-w-64 py-2 whitespace-normal">
                <div className="font-mono text-xs text-ink">
                  <UntrustedText value={event.event_type} limit={80} />
                </div>
                {event.message ? (
                  <div className="mt-0.5 text-xs text-muted-foreground">
                    <UntrustedText value={event.message} limit={160} />
                  </div>
                ) : null}
                <div className="mt-1">
                  <RawExcerptToggle eventId={event.event_id} />
                </div>
              </TableCell>
              <TableCell className="hidden align-top pt-3 font-mono text-xs text-ink-2 lg:table-cell">
                <UntrustedText value={event.source_type} limit={40} />
              </TableCell>
              <TableCell className="hidden max-w-48 align-top pt-3 text-xs whitespace-normal text-ink-2 md:table-cell">
                {actor ? <UntrustedText value={actor} limit={64} /> : <span className="text-muted-foreground">{DASH}</span>}
              </TableCell>
              <TableCell className="hidden align-top pt-3 font-mono text-xs text-ink-2 md:table-cell">
                {event.src_ip ? <UntrustedText value={event.src_ip} limit={48} /> : <span className="text-muted-foreground">{DASH}</span>}
              </TableCell>
              <TableCell className={`hidden align-top pt-3 text-xs sm:table-cell ${OUTCOME_CLASS[event.outcome] ?? "text-muted-foreground"}`}>
                <UntrustedText value={event.outcome} limit={24} />
              </TableCell>
              {showService ? (
                <TableCell className="hidden align-top pt-3 text-xs xl:table-cell">
                  {event.service_name && href ? (
                    <Link href={href} className="text-ink-2 hover:text-ink hover:underline">
                      <UntrustedText value={event.service_name} limit={40} />
                    </Link>
                  ) : event.service_name ? (
                    <UntrustedText value={event.service_name} limit={40} />
                  ) : (
                    <span className="text-muted-foreground" title="The producing adapter could not attribute this record to a service">
                      {DASH}
                    </span>
                  )}
                </TableCell>
              ) : null}
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

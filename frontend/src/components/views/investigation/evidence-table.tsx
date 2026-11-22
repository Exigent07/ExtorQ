import Link from "next/link";

import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { RawExcerptToggle } from "@/components/views/events/raw-excerpt";
import type { EvidenceEvent } from "@/lib/api/schemas";
import { DASH, humanize } from "@/lib/format";
import { chronological } from "@/lib/investigation";
import { serviceHref } from "@/lib/security/ids";

function actorOf(e: EvidenceEvent): string | null {
  return e.actor_name ?? e.k8s_user ?? e.gh_actor_login ?? null;
}

/** Kubernetes / GitHub / HTTP identifiers that make an evidence row checkable at its source. */
function identifiers(e: EvidenceEvent): string[] {
  const ids: string[] = [];
  if (e.k8s_audit_id) ids.push(`audit ${e.k8s_audit_id}`);
  if (e.k8s_namespace || e.k8s_pod_name) ids.push(`pod ${[e.k8s_namespace, e.k8s_pod_name].filter(Boolean).join("/")}`);
  if (e.k8s_pod_uid) ids.push(`pod uid ${e.k8s_pod_uid}`);
  if (e.k8s_container_id) ids.push(`container ${e.k8s_container_id}`);
  if (e.k8s_node) ids.push(`node ${e.k8s_node}`);
  if (e.http_request_id) ids.push(`request ${e.http_request_id}`);
  if (e.http_method || e.http_route) ids.push(`${e.http_method ?? ""} ${e.http_route ?? ""}`.trim());
  if (e.gh_repository) ids.push(`repo ${e.gh_repository}`);
  if (e.gh_commit_sha) ids.push(`commit ${e.gh_commit_sha.slice(0, 12)}`);
  if (e.gh_workflow_path) ids.push(`workflow ${e.gh_workflow_path}`);
  if (e.resource_path) ids.push(e.resource_path);
  return ids;
}

/**
 * Supporting evidence: the stored events the detector cited, oldest first. Each row is an
 * anchor target (`#evidence-<event_id>`) so AI statements can point at it; raw excerpts load
 * on demand.
 */
export function EvidenceTable({ evidence }: { evidence: EvidenceEvent[] }) {
  return (
    <Table aria-label="Supporting evidence">
      <TableHeader>
        <TableRow>
          <TableHead className="w-44">Time (UTC)</TableHead>
          <TableHead>Event</TableHead>
          <TableHead className="hidden md:table-cell">Actor</TableHead>
          <TableHead className="hidden md:table-cell">Source IP</TableHead>
          <TableHead className="hidden lg:table-cell">Role</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {chronological(evidence).map((e) => {
          const actor = actorOf(e);
          const ids = identifiers(e);
          const href = e.service_id ? serviceHref(e.service_id) : null;
          return (
            <TableRow key={e.event_id} id={`evidence-${e.event_id}`} tabIndex={-1} className="evidence-row scroll-mt-24">
              <TableCell className="align-top pt-3">
                <Timestamp value={e.event_time} />
                <div className="mt-0.5 font-mono text-xs text-muted-foreground" title={e.event_id}>
                  {e.event_id.slice(0, 12)}
                </div>
              </TableCell>
              <TableCell className="min-w-[22rem] py-2.5 whitespace-normal">
                <div className="flex flex-wrap items-center gap-x-2">
                  <span className="font-mono text-xs text-ink">
                    <UntrustedText value={e.event_type} limit={64} />
                  </span>
                  <span className="text-xs text-muted-foreground">
                    <UntrustedText value={e.source_type} limit={40} /> · <UntrustedText value={e.outcome} limit={16} />
                  </span>
                  {e.service_name ? (
                    href ? (
                      <Link href={href} className="text-xs text-ink-2 hover:text-ink hover:underline">
                        <UntrustedText value={e.service_name} limit={72} />
                      </Link>
                    ) : (
                      <span className="text-xs text-ink-2">
                        <UntrustedText value={e.service_name} limit={40} />
                      </span>
                    )
                  ) : null}
                </div>
                {e.message ? (
                  <div className="mt-0.5 text-sm text-ink-2">
                    <UntrustedText value={e.message} limit={220} />
                  </div>
                ) : null}
                {ids.length > 0 ? (
                  <div className="mt-0.5 font-mono text-xs text-muted-foreground">
                    <UntrustedText value={ids.join(" · ")} limit={220} />
                  </div>
                ) : null}
                <div className="mt-1">
                  <RawExcerptToggle eventId={e.event_id} />
                </div>
              </TableCell>
              <TableCell className="hidden max-w-48 align-top pt-3 text-xs whitespace-normal text-ink-2 md:table-cell">
                {actor ? <UntrustedText value={actor} limit={64} /> : <span className="text-muted-foreground">{DASH}</span>}
              </TableCell>
              <TableCell className="hidden align-top pt-3 font-mono text-xs text-ink-2 md:table-cell">
                {e.src_ip ? <UntrustedText value={e.src_ip} limit={48} /> : <span className="text-muted-foreground">{DASH}</span>}
              </TableCell>
              <TableCell className="hidden align-top pt-3 text-xs text-muted-foreground lg:table-cell">
                {e.role ? humanize(e.role) : DASH}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

import Link from "next/link";

import { Panel } from "@/components/console/panel";
import { StaleBadge } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { HostedService, ServiceInstance } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { serviceHref } from "@/lib/security/ids";
import { INSTANCE_KIND_LABEL, serviceKindLabel } from "@/lib/services";

import { ServiceCoverageDot } from "./service-badges";

/** Pods first with their containers nested under them, then anything without a parent here. */
function nested(instances: ServiceInstance[]): { instance: ServiceInstance; depth: number }[] {
  const ids = new Set(instances.map((i) => i.instance_id));
  const roots = instances.filter((i) => !i.parent_instance_id || !ids.has(i.parent_instance_id));
  const out: { instance: ServiceInstance; depth: number }[] = [];
  for (const root of roots) {
    out.push({ instance: root, depth: 0 });
    for (const child of instances.filter((i) => i.parent_instance_id === root.instance_id)) out.push({ instance: child, depth: 1 });
  }
  return out;
}

function title(i: ServiceInstance): string {
  return (i.instance_kind === "container" ? i.container_name : i.pod_name) ?? i.pod_name ?? i.container_name ?? i.instance_key;
}

/**
 * What runs on this asset but belongs to an ancestor's inventory: on a Kubernetes node, the
 * cluster's workloads with their Pods and containers scheduled here (from the API's `hosted`).
 * The workload's coverage is the cluster-level service's own; the instances are this node's.
 */
export function HostedServicesPanel({
  hosted,
  truncated,
  assetType,
  now,
}: {
  hosted: HostedService[];
  truncated: boolean;
  assetType: string;
  now: string;
}) {
  const instances = hosted.reduce((sum, h) => sum + h.instances_on_asset, 0);
  const node = assetType === "kubernetes_node";
  return (
    <Panel
      title={node ? "Workloads running on this node" : "Instances of parent-asset services"}
      titleId="hosted-title"
      meta={
        <span>
          {formatCount(hosted.length)} workload{hosted.length === 1 ? "" : "s"} · {formatCount(instances)} Pod and container
          instance{instances === 1 ? "" : "s"}
        </span>
      }
    >
      <p className="-mt-1 mb-3 text-xs text-muted-foreground">
        {node
          ? "Workloads belong to the cluster's inventory; the Pods and containers listed are the ones reported on this node."
          : "These services belong to a parent asset; only their instances reported on this asset are listed."}
      </p>
      <Table aria-label="Workloads and their instances on this asset">
        <TableHeader>
          <TableRow>
            <TableHead>Workload</TableHead>
            <TableHead>Instance</TableHead>
            <TableHead className="hidden md:table-cell">Namespace</TableHead>
            <TableHead>State</TableHead>
            <TableHead className="hidden text-right sm:table-cell">Observed</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {hosted.map((h) => {
            const href = serviceHref(h.service.service_id);
            return nested(h.instances).map(({ instance: i, depth }, index) => (
              <TableRow key={i.instance_id}>
                <TableCell className="py-2 align-top whitespace-normal">
                  {index === 0 ? (
                    <>
                      {href ? (
                        <Link href={href} className="text-ink hover:underline">
                          <UntrustedText value={h.service.name} limit={72} />
                        </Link>
                      ) : (
                        <span className="text-ink">
                          <UntrustedText value={h.service.name} limit={72} />
                        </span>
                      )}
                      <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        {serviceKindLabel(h.service.service_kind)}
                        <ServiceCoverageDot service={h.service} />
                      </div>
                      {h.instances_on_asset > h.instances.length ? (
                        <div className="mt-0.5 text-xs text-warn">
                          {formatCount(h.instances.length)} of {formatCount(h.instances_on_asset)} instances shown
                        </div>
                      ) : null}
                    </>
                  ) : null}
                </TableCell>
                <TableCell className="py-2 whitespace-normal">
                  <div className={depth > 0 ? "border-l border-border pl-3" : undefined}>
                    <span className="mr-2 text-xs text-muted-foreground">{INSTANCE_KIND_LABEL[i.instance_kind] ?? i.instance_kind}</span>
                    <span className="text-ink-2">
                      <UntrustedText value={title(i)} limit={64} />
                    </span>
                    {i.stale ? (
                      <span className="ml-2">
                        <StaleBadge reason="Not re-observed within the service staleness threshold" />
                      </span>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell className="hidden text-xs text-ink-2 md:table-cell">
                  <UntrustedText value={i.namespace} limit={48} />
                </TableCell>
                <TableCell className="text-xs text-ink-2">
                  <UntrustedText value={i.state} limit={16} />
                </TableCell>
                <TableCell className="hidden text-right sm:table-cell">
                  <RelativeTime value={i.observed_at} now={now} className="text-xs" />
                </TableCell>
              </TableRow>
            ));
          })}
        </TableBody>
      </Table>
      {truncated ? (
        <p className="mt-2 text-xs text-warn">More instances run on this asset than the API reads in one request.</p>
      ) : null}
    </Panel>
  );
}

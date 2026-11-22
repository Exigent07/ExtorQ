import Link from "next/link";

import { MetricStrip } from "@/components/console/key-values";
import { Panel } from "@/components/console/panel";
import { EmptyState, ErrorState } from "@/components/console/states";
import type { ApiResult } from "@/lib/api/result";
import type { AssetServicesResponse } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { groupServices, SERVICE_GROUPS, serviceKindLabel } from "@/lib/services";

import { HostedServicesPanel } from "./hosted-services";
import { ServicesTable } from "./services-table";

/** True when the API answered 404 because the service endpoints are not deployed yet. */
export function serviceApiMissing(result: ApiResult<unknown>): boolean {
  return !result.ok && result.error.kind === "not_found" && result.error.status === 404;
}

/**
 * The Services / Workloads tab of an asset: the API's coverage summary, then one table per
 * service kind. Kubernetes workloads and logical Kubernetes Services are separate levels and
 * separate tables; neither is ever shown as a host operating-system service.
 */
export function AssetServices({
  result,
  assetType,
  baseHref,
  includeRemoved,
  now,
}: {
  result: ApiResult<AssetServicesResponse>;
  assetType: string;
  baseHref: string;
  includeRemoved: boolean;
  now: string;
}) {
  if (serviceApiMissing(result)) {
    return (
      <EmptyState>
        The analyst API on this deployment does not provide the service inventory yet (
        <span className="font-mono">GET /api/v1/assets/&#123;id&#125;/services</span> answered 404). Service
        discovery data cannot be shown until it does; nothing is inferred in its place.
      </EmptyState>
    );
  }
  if (!result.ok) return <ErrorState what="the services of this asset" error={result.error} />;

  const { items, summary, hosted, hosted_truncated: hostedTruncated } = result.data;
  const c = summary.coverage;
  const groups = groupServices(items);
  const isCluster = assetType === "kubernetes_cluster";
  const hostedPanel =
    hosted.length > 0 ? <HostedServicesPanel hosted={hosted} truncated={hostedTruncated} assetType={assetType} now={now} /> : null;
  const removedToggle =
    summary.removed > 0 ? (
      <Link
        href={includeRemoved ? `${baseHref}?tab=services` : `${baseHref}?tab=services&removed=1`}
        className="text-xs text-muted-foreground hover:text-ink"
      >
        {includeRemoved
          ? "Hide removed services"
          : `Show ${formatCount(summary.removed)} removed service${summary.removed === 1 ? "" : "s"}`}
      </Link>
    ) : null;

  if (!summary.reported && items.length === 0) {
    if (hostedPanel) {
      // A Kubernetes node: no service of its own is reported (workloads and Kubernetes
      // Services belong to the cluster), but the Pods scheduled on it are known.
      return (
        <div className="grid gap-6">
          {hostedPanel}
          <p className="text-xs text-muted-foreground">
            No host service is reported for this asset itself: node-level discovery (kubelet, container runtime) is not
            collected, so its own services are unknown, not absent.
          </p>
        </div>
      );
    }
    return (
      <EmptyState>
        Service discovery has not reported for this asset yet, so its services are unknown (not absent). Discovery lists
        systemd units, launchd jobs, listening sockets, configured applications and Kubernetes objects only with
        evidence for each.
      </EmptyState>
    );
  }

  return (
    <div className="grid gap-6">
      <MetricStrip
        items={[
          {
            label: "Discovered",
            value: <span className="font-mono">{formatCount(c.total)}</span>,
            sub: summary.removed > 0 ? `${formatCount(summary.removed)} removed, not counted` : "currently present",
          },
          {
            label: "Monitored",
            value: <span className={c.monitored > 0 ? "font-mono text-ok" : "font-mono"}>{formatCount(c.monitored)}</span>,
            sub: "adapter enabled, sources fresh",
          },
          {
            label: "Degraded",
            value: <span className={c.degraded > 0 ? "font-mono text-warn" : "font-mono"}>{formatCount(c.degraded)}</span>,
            sub: "stale or failing sources",
          },
          {
            label: "Unmonitored",
            value: <span className={c.unmonitored > 0 ? "font-mono text-warn" : "font-mono"}>{formatCount(c.unmonitored)}</span>,
            sub: "adapter exists, not enabled",
          },
          {
            label: "No adapter",
            value: <span className="font-mono">{formatCount(c.planned + c.unsupported)}</span>,
            sub: `${formatCount(c.planned)} planned · ${formatCount(c.unsupported)} unsupported`,
          },
        ]}
      />
      {summary.truncated || result.data.page.has_more ? (
        <p className="text-xs text-warn">
          More services exist than the API evaluated in one request; the counts and tables cover the {formatCount(items.length)}{" "}
          shown.
        </p>
      ) : null}
      {summary.note ? <p className="text-xs text-muted-foreground">{summary.note}</p> : null}
      {result.data.invalid_records > 0 ? (
        <p className="text-xs text-warn">
          {formatCount(result.data.invalid_records)} stored service record{result.data.invalid_records === 1 ? "" : "s"} failed
          validation and {result.data.invalid_records === 1 ? "is" : "are"} not shown.
        </p>
      ) : null}

      {items.length === 0 ? (
        <EmptyState>No present service was discovered on this asset. {removedToggle}</EmptyState>
      ) : (
        groups.map((group, index) => {
          const meta = SERVICE_GROUPS.find((g) => g.kind === group.kind);
          const title = meta?.title ?? serviceKindLabel(group.kind);
          return (
            <Panel
              key={group.kind}
              title={title}
              titleId={`services-${group.kind}`}
              meta={<span>{formatCount(group.items.length)} listed</span>}
              action={index === 0 ? removedToggle : null}
            >
              {meta ? <p className="-mt-1 mb-3 text-xs text-muted-foreground">{meta.description}</p> : null}
              <ServicesTable services={group.items} now={now} label={title} />
            </Panel>
          );
        })
      )}
      {hostedPanel}
      {isCluster ? (
        <p className="text-xs text-muted-foreground">
          Nodes are assets of their own (Overview tab). Pods and containers are instances: open a workload to see them with
          their node, Pod UID and container id.
        </p>
      ) : null}
    </div>
  );
}

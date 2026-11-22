import { Info, Layers, Network, TriangleAlert, Workflow } from "lucide-react";
import Link from "next/link";

import { SectionCard } from "@/components/console/section-card";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import type { ApiResult } from "@/lib/api/result";
import type { AssetDetailResponse, AssetServicesResponse, ServiceItem } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { assetHref, isAssetId } from "@/lib/security/ids";

import { CoverageSummaryCard } from "./coverage-summary";
import { InstancesDataTable, type InstanceTableRow } from "./instances-data-table";
import { KubernetesLevels, type Level } from "./k8s-levels";
import { instanceRows, staleSentence, staleSummary } from "./model";
import { ServicesDataTable } from "./services-data-table";

const K8S_KINDS = new Set(["k8s_workload", "k8s_service"]);

/** True when the API answered 404 because the service endpoints are not deployed yet. */
export function serviceApiMissing(result: ApiResult<unknown>): boolean {
  return !result.ok && result.error.kind === "not_found" && result.error.status === 404;
}

function RemovedToggle({ baseHref, removed, includeRemoved }: { baseHref: string; removed: number; includeRemoved: boolean }) {
  if (removed <= 0) return null;
  return (
    <Link
      href={includeRemoved ? `${baseHref}?tab=services` : `${baseHref}?tab=services&removed=1`}
      className="inline-flex h-7 items-center rounded-lg px-2.5 text-xs text-muted-foreground ring-1 ring-hairline ring-inset transition-colors duration-150 hover:bg-hover hover:text-foreground"
    >
      {includeRemoved ? "Hide removed" : `Show ${formatCount(removed)} removed`}
    </Link>
  );
}

/** API caveats of one service listing, each stated once. */
function ListingNotices({ data, shown }: { data: AssetServicesResponse; shown: ServiceItem[] }) {
  const stale = shown.filter((s) => s.present && s.report_stale).length;
  const notices = [
    data.summary.truncated || data.page.has_more ? (
      <Notice key="capped" tone="warn" icon={Info}>
        More services exist than the API evaluated in one request; the counts and tables cover the{" "}
        {formatCount(data.items.length)} shown.
      </Notice>
    ) : null,
    data.invalid_records > 0 ? (
      <Notice key="invalid" tone="warn" icon={TriangleAlert}>
        {formatCount(data.invalid_records)} stored service record{data.invalid_records === 1 ? "" : "s"} failed validation and{" "}
        {data.invalid_records === 1 ? "is" : "are"} not shown.
      </Notice>
    ) : null,
    stale > 0 ? (
      <Notice key="stale" tone="warn" icon={Info}>
        {formatCount(stale)} service record{stale === 1 ? " was" : "s were"} not re-reported by discovery within the staleness
        threshold, so {stale === 1 ? "its" : "their"} current state cannot be confirmed. Filter them with “Discovery report”.
      </Notice>
    ) : null,
  ].filter(Boolean);
  return notices.length > 0 ? <div className="grid gap-2">{notices}</div> : null;
}

/** A Kubernetes node: the cluster's workloads with their Pods and containers on this node. */
function NodeWorkloads({ data, detail, now }: { data: AssetServicesResponse; detail: AssetDetailResponse; now: string }) {
  const { hosted, hosted_truncated: truncated } = data;
  const rows: InstanceTableRow[] = hosted.flatMap((h) =>
    instanceRows(h.instances).map((r) => ({ id: r.instance.instance_id, instance: r.instance, children: r.children, workload: h.service })),
  );
  const instances = hosted.flatMap((h) => h.instances);
  const pods = instances.filter((i) => i.instance_kind === "pod").length;
  const containers = instances.filter((i) => i.instance_kind === "container").length;
  const stale = staleSentence(staleSummary(instances), now);
  const partial = hosted.filter((h) => h.instances_on_asset > h.instances.length);
  const cluster = detail.asset.parent_asset_id && isAssetId(detail.asset.parent_asset_id) ? detail.asset.parent_asset_id : null;
  const levels: Level[] = [
    { key: "cluster", label: "Cluster", count: cluster ? 1 : null, description: "Owns the workloads", href: cluster ? assetHref(cluster) : null },
    { key: "nodes", label: "This node", count: 1, description: "An asset of its own", current: true },
    { key: "workloads", label: "Workloads with Pods here", count: hosted.length, description: "From the cluster's inventory", href: "#hosted-title" },
    { key: "pods", label: "Pods on this node", count: pods, description: "Instances of those workloads" },
    { key: "containers", label: "Containers", count: containers, description: "Inside those Pods" },
  ];

  return (
    <div className="grid gap-6">
      <KubernetesLevels levels={levels} label="Kubernetes levels of this node" />
      <SectionCard
        title="Workloads running on this node"
        titleId="hosted-title"
        icon={Workflow}
        description="Workloads belong to the cluster's inventory; the Pods and containers listed are the ones reported on this node."
        meta={
          <span className="tabular-nums">
            {formatCount(hosted.length)} workload{hosted.length === 1 ? "" : "s"} · {formatCount(pods)} Pod{pods === 1 ? "" : "s"}
          </span>
        }
        flush
      >
        {stale || truncated || partial.length > 0 ? (
          <div className="grid gap-2 px-5 pb-3">
            {stale ? (
              <Notice tone="warn" icon={Info}>
                {stale} Discovery last reported these instances then; the workloads&apos; own coverage is evaluated separately.
              </Notice>
            ) : null}
            {truncated || partial.length > 0 ? (
              <Notice tone="warn" icon={Info}>
                More instances run on this node than the API reads in one request; the table shows those returned.
              </Notice>
            ) : null}
          </div>
        ) : null}
        {rows.length === 0 ? (
          <div className="px-5 pb-3">
            <EmptyState>No Pod of the cluster&apos;s workloads is reported on this node.</EmptyState>
          </div>
        ) : (
          <InstancesDataTable rows={rows} now={now} kubernetes showNode={false} label="Pods and containers on this node" />
        )}
      </SectionCard>
      <p className="text-xs leading-relaxed text-muted-foreground">
        No host service is reported for this node itself: node-level discovery (kubelet, container runtime) is not
        collected, so its own services are unknown, not absent.
      </p>
    </div>
  );
}

/** A cluster: the Kubernetes levels, then workloads and Kubernetes Services as separate tables. */
function ClusterServices({
  data,
  detail,
  baseHref,
  includeRemoved,
  now,
}: {
  data: AssetServicesResponse;
  detail: AssetDetailResponse;
  baseHref: string;
  includeRemoved: boolean;
  now: string;
}) {
  const workloads = data.items.filter((s) => s.service_kind === "k8s_workload");
  const k8sServices = data.items.filter((s) => s.service_kind === "k8s_service");
  const others = data.items.filter((s) => !K8S_KINDS.has(s.service_kind));
  const pods = detail.inventory.find((i) => i.item_type === "k8s_pod")?.items ?? null;
  const nodes = detail.child_assets;
  const onlyNode = nodes.length === 1 && nodes[0] && isAssetId(nodes[0].asset_id) ? nodes[0].asset_id : null;
  const levels: Level[] = [
    { key: "cluster", label: "Cluster", count: 1, description: "This asset", current: true },
    {
      key: "nodes",
      label: "Nodes",
      count: nodes.length,
      description: "Assets of their own",
      href: onlyNode ? assetHref(onlyNode) : baseHref,
    },
    {
      key: "workloads",
      label: "Workloads",
      count: workloads.filter((s) => s.present).length,
      description: "Controllers and bare Pods",
      href: "#services-k8s_workload",
    },
    {
      key: "services",
      label: "Kubernetes Services",
      count: k8sServices.filter((s) => s.present).length,
      description: "Virtual IPs and ports, not host services",
      href: "#services-k8s_service",
    },
    {
      key: "pods",
      label: "Pods",
      count: pods,
      description: "In the inventory; listed per workload",
    },
  ];
  const toggle = <RemovedToggle baseHref={baseHref} removed={data.summary.removed} includeRemoved={includeRemoved} />;

  return (
    <div className="grid gap-6">
      <KubernetesLevels levels={levels} label="Kubernetes levels of this cluster" />
      <CoverageSummaryCard summary={data.summary} />
      <ListingNotices data={data} shown={data.items} />
      <SectionCard
        title="Workloads"
        titleId="services-k8s_workload"
        icon={Workflow}
        description="Workload controllers and bare Pods. Open one for its Pods and containers with node, Pod UID and container id."
        meta={<span className="tabular-nums">{formatCount(workloads.length)} listed</span>}
        action={toggle}
        flush
      >
        {workloads.length === 0 ? (
          <div className="px-5 pb-3">
            <EmptyState>No workload of this cluster is reported.</EmptyState>
          </div>
        ) : (
          <ServicesDataTable services={workloads} now={now} variant="k8s_workload" label="Workloads" />
        )}
      </SectionCard>
      <SectionCard
        title="Kubernetes Services"
        titleId="services-k8s_service"
        icon={Network}
        description="Logical Service objects: virtual IPs and ports inside the cluster, implemented by kube-proxy. Not operating-system services."
        meta={<span className="tabular-nums">{formatCount(k8sServices.length)} listed</span>}
        flush
      >
        {k8sServices.length === 0 ? (
          <div className="px-5 pb-3">
            <EmptyState>No Kubernetes Service object of this cluster is reported.</EmptyState>
          </div>
        ) : (
          <ServicesDataTable services={k8sServices} now={now} variant="k8s_service" label="Kubernetes Services" />
        )}
      </SectionCard>
      {others.length > 0 ? (
        <SectionCard title="Other services" titleId="services-other" icon={Layers} flush>
          <ServicesDataTable services={others} now={now} variant="host" label="Other services" />
        </SectionCard>
      ) : null}
    </div>
  );
}

/**
 * The Services / Workloads tab of an asset. Hosts: coverage summary and one table of host
 * services and applications. Clusters: Kubernetes levels, workloads and Kubernetes Services
 * as separate tables. Nodes: the cluster's workloads with their Pods on the node. A Kubernetes
 * Service is never shown as a host operating-system service.
 */
export function AssetServices({
  result,
  detail,
  baseHref,
  includeRemoved,
  now,
}: {
  result: ApiResult<AssetServicesResponse>;
  detail: AssetDetailResponse;
  baseHref: string;
  includeRemoved: boolean;
  now: string;
}) {
  if (serviceApiMissing(result)) {
    return (
      <EmptyState compact={false}>
        The analyst API on this deployment does not provide the service inventory yet (
        <span className="font-mono">GET /api/v1/assets/&#123;id&#125;/services</span> answered 404). Service discovery data
        cannot be shown until it does; nothing is inferred in its place.
      </EmptyState>
    );
  }
  if (!result.ok) return <ErrorState what="the services of this asset" error={result.error} />;

  const data = result.data;
  const assetType = detail.asset.asset_type;

  if (assetType === "kubernetes_node" || (data.hosted.length > 0 && !data.summary.reported && data.items.length === 0)) {
    return <NodeWorkloads data={data} detail={detail} now={now} />;
  }

  if (!data.summary.reported && data.items.length === 0) {
    return (
      <EmptyState compact={false} icon={Layers}>
        {assetType === "github_repository" || assetType === "github_account"
          ? "Repositories and accounts have no service inventory: services are discovered on hosts and in Kubernetes. Its monitored inventory (workflows, branches) is on the Overview tab."
          : "Service discovery has not reported for this asset yet, so its services are unknown, not absent. Discovery lists systemd units, launchd jobs, listening sockets, configured applications and Kubernetes objects, each with evidence."}
      </EmptyState>
    );
  }

  if (assetType === "kubernetes_cluster") {
    return <ClusterServices data={data} detail={detail} baseHref={baseHref} includeRemoved={includeRemoved} now={now} />;
  }

  const hostItems = data.items.filter((s) => !K8S_KINDS.has(s.service_kind));
  const k8sItems = data.items.filter((s) => K8S_KINDS.has(s.service_kind));
  return (
    <div className="grid gap-6">
      <CoverageSummaryCard summary={data.summary} />
      <ListingNotices data={data} shown={data.items} />
      <SectionCard
        title="Services"
        titleId="services-host"
        icon={Layers}
        description="Host services (systemd units, launchd jobs) and applications found from process, socket or configuration evidence"
        meta={<span className="tabular-nums">{formatCount(hostItems.length)} listed</span>}
        action={<RemovedToggle baseHref={baseHref} removed={data.summary.removed} includeRemoved={includeRemoved} />}
        flush
      >
        {hostItems.length === 0 ? (
          <div className="px-5 pb-3">
            <EmptyState>No present service was discovered on this asset.</EmptyState>
          </div>
        ) : (
          <ServicesDataTable services={hostItems} now={now} variant="host" label="Services of this asset" />
        )}
      </SectionCard>
      {k8sItems.length > 0 ? (
        <SectionCard title="Kubernetes objects" titleId="services-k8s" icon={Network} flush>
          <ServicesDataTable services={k8sItems} now={now} variant="k8s_service" label="Kubernetes objects" />
        </SectionCard>
      ) : null}
      {data.hosted.length > 0 ? (
        <Notice icon={Info}>
          {formatCount(data.hosted.length)} service{data.hosted.length === 1 ? "" : "s"} of a parent asset also run instances here.
        </Notice>
      ) : null}
    </div>
  );
}

/**
 * Presentation rules of the service views (pure, unit-tested in model.test.ts): exposure
 * ranking, Pod/container nesting, the one staleness summary per section, the service page
 * finding. Figures come from the API response; nothing is inferred beyond it.
 */
import type { ServiceDetailResponse, ServiceEndpoint, ServiceInstance } from "@/lib/api/schemas";
import { formatCount, formatRelative, isClosedStatus } from "@/lib/format";
import { serviceCoverage } from "@/lib/services";

/** Wider exposure first: all interfaces, private network, loopback, unknown, no port. */
export const EXPOSURE_RANK: Record<string, number> = { any: 0, private: 1, loopback: 2, unknown: 3, none: 4 };

/** The widest exposure among a service's endpoints ("none" without endpoints). */
export function widestExposure(service: { endpoints: { exposure: string }[]; exposures?: string[] }): string {
  const tokens = [...service.endpoints.map((e) => e.exposure), ...(service.exposures ?? [])];
  if (tokens.length === 0) return "none";
  return tokens.reduce((best, t) => ((EXPOSURE_RANK[t] ?? 3) < (EXPOSURE_RANK[best] ?? 3) ? t : best));
}

/**
 * Endpoints in display order: the widest exposure first (the one a reader must see), then
 * port, protocol and address. Input order does not matter; nothing is dropped.
 */
export function sortEndpoints<T extends Pick<ServiceEndpoint, "exposure" | "port" | "protocol" | "address">>(endpoints: T[]): T[] {
  return [...endpoints].sort(
    (a, b) =>
      (EXPOSURE_RANK[a.exposure] ?? 3) - (EXPOSURE_RANK[b.exposure] ?? 3) ||
      a.port - b.port ||
      a.protocol.localeCompare(b.protocol) ||
      (a.address ?? "").localeCompare(b.address ?? ""),
  );
}

const KIND_NOUN: Record<string, [string, string]> = {
  pod: ["Pod", "Pods"],
  container: ["container", "containers"],
  process: ["process", "processes"],
};

/**
 * "2 Pods · 2 containers": the instances on screen counted by kind, Pods first (unknown kinds
 * as their token). Empty string for no instance.
 */
export function instanceBreakdown(instances: Pick<ServiceInstance, "instance_kind">[]): string {
  const counts = new Map<string, number>();
  for (const i of instances) counts.set(i.instance_kind, (counts.get(i.instance_kind) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => (KIND_ORDER[a[0]] ?? 9) - (KIND_ORDER[b[0]] ?? 9) || a[0].localeCompare(b[0]))
    .map(([kind, n]) => {
      const noun = KIND_NOUN[kind];
      return `${formatCount(n)} ${noun ? (n === 1 ? noun[0] : noun[1]) : kind}`;
    })
    .join(" · ");
}

export interface InstanceHeadline {
  /** The figure: rows of the instances table (Pods with their containers nested), or the API total when the list is capped. */
  value: number;
  /** "Pods" when every row is a Pod, otherwise "Instances". */
  label: string;
  /** What else the rows hold ("2 containers"), or the breakdown; empty when there is nothing to add. */
  sub: string;
  /** True when the API listed fewer instances than it counted (the figure is then the API total). */
  capped: boolean;
}

/**
 * The instance figure exactly as the instances table shows it: a workload's Pods (each Pod's
 * containers nested under it, counted in the sub-label), a host service's processes. Pods
 * and containers are never added into one number. When the API capped the list the figure is
 * its total and the sub-label says how many are listed.
 */
export function instanceHeadline(
  instances: Pick<ServiceInstance, "instance_id" | "instance_kind" | "parent_instance_id">[],
  total: number,
): InstanceHeadline {
  if (total > instances.length) {
    return { value: total, label: "Instances", sub: `${formatCount(instances.length)} listed`, capped: true };
  }
  const ids = new Set(instances.map((i) => i.instance_id));
  const nested = instances.filter((i) => i.parent_instance_id && i.parent_instance_id !== i.instance_id && ids.has(i.parent_instance_id));
  const roots = instances.filter((i) => !nested.includes(i));
  const allPods = roots.length > 0 && roots.every((i) => i.instance_kind === "pod");
  return {
    value: roots.length,
    label: allPods ? "Pods" : "Instances",
    sub: nested.length > 0 ? instanceBreakdown(nested) : allPods ? "" : instanceBreakdown(roots),
    capped: false,
  };
}

export interface InstanceRow {
  instance: ServiceInstance;
  /** Containers whose parent is this instance (a Pod's containers). */
  children: ServiceInstance[];
}

const KIND_ORDER: Record<string, number> = { pod: 0, process: 1, container: 2 };

/**
 * Instances grouped as the hierarchy reports them: each Pod (or process) with the containers
 * whose `parent_instance_id` points at it; a container whose parent is not in the list stays a
 * row of its own. Order: kind (Pods first), then name, then id. Input order does not matter.
 */
export function instanceRows(instances: ServiceInstance[]): InstanceRow[] {
  const ids = new Set(instances.map((i) => i.instance_id));
  const childrenOf = new Map<string, ServiceInstance[]>();
  const roots: ServiceInstance[] = [];
  for (const instance of instances) {
    const parent = instance.parent_instance_id;
    if (parent && parent !== instance.instance_id && ids.has(parent)) {
      childrenOf.set(parent, [...(childrenOf.get(parent) ?? []), instance]);
    } else {
      roots.push(instance);
    }
  }
  const byName = (a: ServiceInstance, b: ServiceInstance) =>
    (KIND_ORDER[a.instance_kind] ?? 9) - (KIND_ORDER[b.instance_kind] ?? 9) ||
    instanceName(a).localeCompare(instanceName(b)) ||
    a.instance_id.localeCompare(b.instance_id);
  return roots.sort(byName).map((instance) => ({
    instance,
    children: (childrenOf.get(instance.instance_id) ?? []).sort(byName),
  }));
}

/** Display name of an instance: the Pod, container or process name the source reported. */
export function instanceName(i: ServiceInstance): string {
  if (i.instance_kind === "container") return i.container_name ?? i.pod_name ?? i.instance_key;
  if (i.instance_kind === "pod") return i.pod_name ?? i.instance_key;
  return i.process_name ?? i.pod_name ?? i.container_name ?? i.instance_key;
}

export interface StaleSummary {
  stale: number;
  total: number;
  /** Newest `observed_at` among the stale instances (when they were last seen at all). */
  lastObserved: string | null;
}

/**
 * The one staleness statement of a section: how many instances were not re-observed within the
 * service staleness threshold, and when the newest of them was last observed.
 */
export function staleSummary(instances: Pick<ServiceInstance, "stale" | "observed_at">[]): StaleSummary {
  const stale = instances.filter((i) => i.stale);
  const lastObserved = stale.reduce<string | null>((latest, i) => {
    const t = Date.parse(i.observed_at);
    if (!Number.isFinite(t)) return latest;
    return latest === null || t > Date.parse(latest) ? i.observed_at : latest;
  }, null);
  return { stale: stale.length, total: instances.length, lastObserved };
}

/** Sentence for a StaleSummary (null when nothing is stale). */
export function staleSentence(summary: StaleSummary, now: string, noun = "instance"): string | null {
  if (summary.stale === 0) return null;
  const all = summary.stale === summary.total;
  const subject = all
    ? summary.total === 1
      ? `The only ${noun}`
      : `All ${formatCount(summary.total)} ${noun}s`
    : `${formatCount(summary.stale)} of ${formatCount(summary.total)} ${noun}s`;
  const when = summary.lastObserved ? ` (last observed ${formatRelative(summary.lastObserved, now)})` : "";
  const one = summary.stale === 1;
  return `${subject} ${one ? "was" : "were"} not re-observed within the staleness threshold${when}; ${one ? "its" : "their"} current state cannot be confirmed.`;
}

/**
 * Latest service telemetry: the discovery record's own timestamp or the newest attributed
 * event per source, whichever is later (either may be missing).
 */
export function lastTelemetry(data: Pick<ServiceDetailResponse, "service" | "telemetry">): string | null {
  const times = [data.service.last_telemetry_at, ...data.telemetry.map((t) => t.last_event_at)].filter(
    (t): t is string => typeof t === "string" && Number.isFinite(Date.parse(t)),
  );
  if (times.length === 0) return null;
  return times.reduce((a, b) => (Date.parse(a) >= Date.parse(b) ? a : b));
}

/** The service page's one-line finding, from the API's figures. */
export function serviceFinding(data: ServiceDetailResponse, now: string): string {
  const s = data.service;
  const parts = [serviceCoverage(s).label];
  const last = lastTelemetry(data);
  parts.push(last ? `last service telemetry ${formatRelative(last, now)}` : "no service telemetry in the window");
  if (data.auth_activity.total > 0) {
    const failed = (data.auth_activity.by_outcome.failure ?? 0) + (data.auth_activity.by_outcome.denied ?? 0);
    parts.push(
      `${formatCount(failed)} failed or denied authentication${failed === 1 ? "" : "s"} from ${formatCount(data.auth_activity.distinct_sources)} source${data.auth_activity.distinct_sources === 1 ? "" : "s"}`,
    );
  }
  const open = data.alerts.filter((a) => !isClosedStatus(a.analyst_status)).length;
  parts.push(`${formatCount(open)} open alert${open === 1 ? "" : "s"}`);
  parts.push(`${formatCount(data.findings_total)} finding${data.findings_total === 1 ? "" : "s"}`);
  return parts.join(" · ");
}

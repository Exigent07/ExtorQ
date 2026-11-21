/**
 * Presentation rules for the service model (contracts/service.py, PLAN §10.1).
 *
 * Pure functions (unit-tested): coverage badges, labels for kinds, categories, exposure and
 * port attribution, and the grouping used by the Services / Workloads tab. Unknown tokens are
 * rendered as themselves, never mapped onto a known state.
 */

export type Tone = "ok" | "warn" | "bad" | "off";

export type CoverageKind = "monitored" | "degraded" | "unmonitored" | "planned" | "unsupported" | "unknown";

export interface CoverageBadge {
  kind: CoverageKind;
  label: string;
  tone: Tone;
  /** One sentence for the tooltip / detail view: what the state means. */
  detail: string;
}

const STATE_BADGE: Record<string, Omit<CoverageBadge, "detail"> & { detail: string }> = {
  monitored: { kind: "monitored", label: "Monitored", tone: "ok", detail: "Adapter enabled and its telemetry sources are fresh." },
  degraded: {
    kind: "degraded",
    label: "Degraded",
    tone: "warn",
    detail: "Adapter enabled, but its telemetry sources are stale, failing or partly unavailable.",
  },
  unmonitored: {
    kind: "unmonitored",
    label: "Unmonitored",
    tone: "warn",
    detail: "A telemetry adapter exists, but it is not enabled or not configured for this service.",
  },
  planned: {
    kind: "planned",
    label: "Planned adapter",
    tone: "off",
    detail: "An adapter is planned but not implemented; no service-specific telemetry is collected.",
  },
  unsupported: {
    kind: "unsupported",
    label: "Unsupported",
    tone: "off",
    detail: "No telemetry adapter exists for this service type. It is listed so the gap stays visible.",
  },
};

/** The state implied by the collector's report alone (used when the API sent no effective state). */
function reportedState(support: string, status: string): string | null {
  if (support === "none") return "unsupported";
  if (support === "planned") return "planned";
  if (support === "implemented" && (status === "monitored" || status === "degraded" || status === "unmonitored")) return status;
  return null;
}

/**
 * The one coverage badge of a service. The API's effective `coverage_state` wins (it can
 * downgrade "monitored" when discovery or the source collectors are stale) and its reasons
 * are appended to the explanation. Without it, adapter support decides first: a planned or
 * missing adapter means no service telemetry, whatever the monitoring status says.
 */
export function serviceCoverage(service: {
  adapter_support: string;
  monitoring_status: string;
  coverage_state?: string | null;
  coverage_reasons?: string[];
}): CoverageBadge {
  const state = service.coverage_state ?? reportedState(service.adapter_support, service.monitoring_status);
  const base = state ? STATE_BADGE[state] : undefined;
  const reasons = service.coverage_reasons ?? [];
  if (!base) {
    return {
      kind: "unknown",
      label: state ?? `${service.adapter_support} / ${service.monitoring_status}`,
      tone: "off",
      detail: "The API reported a coverage state this console version does not know; shown as reported.",
    };
  }
  const detail = reasons.length > 0 ? `${base.detail} ${reasons.map((r) => `${r.charAt(0).toUpperCase()}${r.slice(1)}.`).join(" ")}` : base.detail;
  return { ...base, detail };
}

export const SERVICE_KIND_LABEL: Record<string, string> = {
  host_service: "Host service",
  application: "Application",
  k8s_workload: "Kubernetes workload",
  k8s_service: "Kubernetes Service",
};

export function serviceKindLabel(kind: string): string {
  return SERVICE_KIND_LABEL[kind] ?? kind;
}

/** Section headings of the Services / Workloads tab, one per service kind. */
export const SERVICE_GROUPS: { kind: string; title: string; description: string }[] = [
  {
    kind: "host_service",
    title: "Host services",
    description: "Operating-system managed services (systemd units, launchd jobs).",
  },
  {
    kind: "application",
    title: "Applications",
    description: "Applications identified from configuration or process evidence, without their own service unit.",
  },
  {
    kind: "k8s_workload",
    title: "Workloads",
    description: "Kubernetes workload controllers and bare Pods. Their Pods and containers are listed as instances.",
  },
  {
    kind: "k8s_service",
    title: "Kubernetes Services",
    description: "Logical Service objects (virtual IP and ports inside the cluster). Not operating-system services.",
  },
];

export const CATEGORY_LABEL: Record<string, string> = {
  ssh: "SSH",
  http_server: "HTTP server",
  web_application: "Web application",
  service_manager: "Service manager",
  ftp: "FTP",
  database: "Database",
  dns: "DNS",
  cache: "Cache",
  kubernetes_component: "Kubernetes component",
  security_agent: "Security agent",
  other: "Other",
  unknown: "Unknown",
};

export function categoryLabel(category: string): string {
  return CATEGORY_LABEL[category] ?? category;
}

export const EXPOSURE: Record<string, { label: string; tone: Tone; detail: string }> = {
  loopback: { label: "Loopback only", tone: "off", detail: "Bound to 127.0.0.0/8 or ::1; reachable from the host itself only." },
  private: { label: "Private network", tone: "off", detail: "Bound to a private (RFC 1918 / ULA) address." },
  any: { label: "All interfaces", tone: "warn", detail: "Bound to 0.0.0.0 or ::, so reachable on every interface of the host." },
  unknown: { label: "Exposure unknown", tone: "off", detail: "The bind address was not reported." },
};

export function exposureOf(token: string): { label: string; tone: Tone; detail: string } {
  return EXPOSURE[token] ?? { label: token, tone: "off", detail: "Exposure reported in a form this console does not know." };
}

export const ATTRIBUTION: Record<string, { label: string; detail: string }> = {
  confirmed: { label: "Owner confirmed", detail: "The socket's owning process was observed and belongs to this service." },
  inferred: {
    label: "Owner inferred",
    detail: "Attributed from configuration or a well-known port; the owning process was not observed.",
  },
  unknown: {
    label: "Owner unknown",
    detail: "The port was observed, but its owning process could not be determined with the collector's privileges. It is not attributed to this service.",
  },
};

export function attributionOf(token: string): { label: string; detail: string } {
  return ATTRIBUTION[token] ?? { label: token, detail: "Attribution reported in a form this console does not know." };
}

export const DISCOVERY_LABEL: Record<string, string> = {
  systemd_unit: "systemd unit",
  launchd_job: "launchd job",
  process: "running process",
  listening_socket: "listening socket",
  configuration: "configuration",
  k8s_api: "Kubernetes API",
  adapter_config: "adapter configuration",
};

export function discoveryLabel(token: string): string {
  return DISCOVERY_LABEL[token] ?? token;
}

export interface CoverageCounts {
  discovered: number;
  implemented: number;
  monitored: number;
  degraded: number;
  unmonitored: number;
  planned: number;
  unsupported: number;
  unknown: number;
  removed: number;
}

/** Coverage counts computed from rows (present services only; tombstones counted apart). */
export function coverageCounts(
  services: {
    adapter_support: string;
    monitoring_status: string;
    coverage_state?: string | null;
    present: boolean;
  }[],
): CoverageCounts {
  const counts: CoverageCounts = {
    discovered: 0,
    implemented: 0,
    monitored: 0,
    degraded: 0,
    unmonitored: 0,
    planned: 0,
    unsupported: 0,
    unknown: 0,
    removed: 0,
  };
  for (const service of services) {
    if (!service.present) {
      counts.removed += 1;
      continue;
    }
    counts.discovered += 1;
    if (service.adapter_support === "implemented") counts.implemented += 1;
    counts[serviceCoverage(service).kind] += 1;
  }
  return counts;
}

/** Group services by kind in the order of SERVICE_GROUPS; unknown kinds go last under their own token. */
export function groupServices<T extends { service_kind: string }>(services: T[]): { kind: string; items: T[] }[] {
  const known = SERVICE_GROUPS.map((group) => group.kind);
  const byKind = new Map<string, T[]>();
  for (const service of services) {
    const list = byKind.get(service.service_kind) ?? [];
    list.push(service);
    byKind.set(service.service_kind, list);
  }
  const ordered = [...byKind.keys()].sort((a, b) => {
    const ia = known.indexOf(a);
    const ib = known.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib) || a.localeCompare(b);
  });
  return ordered.map((kind) => ({ kind, items: byKind.get(kind) ?? [] }));
}

export const INSTANCE_KIND_LABEL: Record<string, string> = {
  process: "Process",
  container: "Container",
  pod: "Pod",
};

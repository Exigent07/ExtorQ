/**
 * Presentation rules of the Assets views (pure, unit-tested in model.test.ts).
 *
 * Every figure is computed from the API response as received: counts come from the API or from
 * the rows on screen, unknown values stay unknown (null), and no state is inferred that the API
 * does not report. Lifecycle (stale / retired) is the API's own `lifecycle_state`; retired assets
 * appear only when the page asks for them and are never counted as monitored or healthy.
 */
import type {
  AlertListItem,
  AssetListItem,
  CollectorStatus,
  CoverageStatus,
  ServiceCoverageCounts,
  Severity,
  SeverityCounts,
} from "@/lib/api/schemas";
import { formatCount, formatDuration, isClosedStatus } from "@/lib/format";

export type Tone = "ok" | "warn" | "bad" | "off";

// ── Asset classes ─────────────────────────────────────────────────────────────────

export type ClassKey = "macos" | "linux" | "kubernetes" | "github" | "other";

export interface AssetClass {
  key: ClassKey;
  /** Group heading (smoke markers rely on "macOS hosts", "Linux VMs", "Kubernetes", "GitHub"). */
  title: string;
  /** Monitored asset types of the class, in display order. */
  types: string[];
  /** Types that belong to the class as context only: no collector is expected for them. */
  contextTypes: string[];
  empty: string;
}

/** The four monitored asset classes, in the order of the ExtorQ mark's arcs. */
export const ASSET_CLASSES: AssetClass[] = [
  {
    key: "macos",
    title: "macOS hosts",
    types: ["macos_host"],
    contextTypes: [],
    empty: "No macOS host has reported an inventory yet.",
  },
  {
    key: "linux",
    title: "Linux VMs",
    types: ["linux_host"],
    contextTypes: [],
    empty: "No Linux host has reported an inventory yet.",
  },
  {
    key: "kubernetes",
    title: "Kubernetes",
    types: ["kubernetes_cluster", "kubernetes_node", "kubernetes_namespace", "kubernetes_workload"],
    contextTypes: [],
    empty: "No Kubernetes cluster or node has reported an inventory yet.",
  },
  {
    key: "github",
    title: "GitHub",
    types: ["github_repository"],
    contextTypes: ["github_account"],
    empty: "No GitHub repository has reported an inventory yet.",
  },
];

export function classOf(assetType: string): ClassKey {
  return (
    ASSET_CLASSES.find((c) => c.types.includes(assetType) || c.contextTypes.includes(assetType))?.key ?? "other"
  );
}

/** Context assets (GitHub accounts): owners of monitored assets, never monitored themselves. */
export function isContextAsset(assetType: string): boolean {
  return ASSET_CLASSES.some((c) => c.contextTypes.includes(assetType));
}

const TYPE_RANK: Record<string, number> = {
  kubernetes_cluster: 0,
  kubernetes_node: 1,
  kubernetes_namespace: 2,
  kubernetes_workload: 3,
};

/**
 * Display order inside a class: parents before their children (a cluster, then its nodes),
 * then assets with a collector before those without one, then the most recently inventoried
 * first, then the id. Ordering never hides an asset.
 */
export function sortAssets(assets: AssetListItem[]): AssetListItem[] {
  return [...assets].sort((a, b) => {
    const rank = (TYPE_RANK[a.asset_type] ?? 9) - (TYPE_RANK[b.asset_type] ?? 9);
    if (rank !== 0) return rank;
    const withCollector = Number(b.collectors_total > 0) - Number(a.collectors_total > 0);
    if (withCollector !== 0) return withCollector;
    const seen = Date.parse(b.last_seen) - Date.parse(a.last_seen);
    if (Number.isFinite(seen) && seen !== 0) return seen;
    return a.asset_id.localeCompare(b.asset_id);
  });
}

// ── Health of one asset ───────────────────────────────────────────────────────────

const COVERAGE_TONE: Record<CoverageStatus, Tone> = { ok: "ok", degraded: "warn", stale: "warn", missing: "bad" };

export interface AssetHealth {
  tone: Tone;
  label: string;
  /** One line explaining a non-healthy state, from the API's own counts (null when healthy). */
  reason: string | null;
}

/**
 * Health of an asset from the API's coverage verdict. "missing" with no collector at all says
 * so ("No collector") instead of a bare "Missing"; the reason is built from API counts only.
 */
export function assetHealth(asset: Pick<AssetListItem, "coverage_status" | "collectors_total" | "collectors_stale">): AssetHealth {
  const { coverage_status: status, collectors_total: total, collectors_stale: stale } = asset;
  if (status === "missing") {
    return {
      tone: "bad",
      label: total === 0 ? "No collector" : "Missing",
      reason: total === 0 ? "No collector reports for this asset" : "No collector report",
    };
  }
  if (status === "stale") {
    return {
      tone: "warn",
      label: "Stale",
      reason: total > 0 ? `${total === 1 ? "Its only collector is" : `All ${formatCount(total)} collectors are`} stale` : null,
    };
  }
  if (status === "degraded") {
    return {
      tone: "warn",
      label: "Degraded",
      reason:
        stale > 0
          ? `${formatCount(stale)} of ${formatCount(total)} collector${total === 1 ? "" : "s"} stale`
          : "A collector reports a failure",
    };
  }
  return { tone: COVERAGE_TONE[status] ?? "off", label: "Healthy", reason: null };
}

/**
 * The one status shown for an asset in a list or card: its lifecycle state when the API marks
 * it stale or retired (not observed recently says more than a collector verdict), otherwise
 * its health. Never both, so a stale asset does not carry two "Stale" marks.
 */
export function assetStatus(
  asset: Pick<AssetListItem, "coverage_status" | "collectors_total" | "collectors_stale" | "lifecycle_state">,
): { kind: "lifecycle"; state: string } | { kind: "health"; health: AssetHealth } {
  if (asset.lifecycle_state && asset.lifecycle_state !== "active") return { kind: "lifecycle", state: asset.lifecycle_state };
  return { kind: "health", health: assetHealth(asset) };
}

/** Collectors that are stale or not OK, for the reason line (names are telemetry: render as text). */
export function unhealthyCollectors(collectors: CollectorStatus[]): CollectorStatus[] {
  return collectors.filter((c) => c.stale || c.status !== "ok");
}

// ── Page finding (subtitle) ───────────────────────────────────────────────────────

/**
 * One line for the page subtitle: how many monitored assets are healthy and what the others
 * are. Context assets (GitHub accounts) are not monitored and are counted apart; retired assets
 * (in the rows, or left out by the API and listed apart: `retiredApart`) are counted, never
 * dropped silently.
 */
export function assetsFinding(
  all: Pick<AssetListItem, "asset_type" | "coverage_status" | "collectors_total" | "lifecycle_state">[],
  retiredApart = 0,
): string {
  const retired = all.filter((a) => a.lifecycle_state === "retired").length + Math.max(0, retiredApart);
  const assets = all.filter((a) => a.lifecycle_state !== "retired");
  if (assets.length === 0) {
    return retired > 0 ? `Only retired assets: ${formatCount(retired)}` : "No asset has reported an inventory yet";
  }
  // Kubernetes nodes report through their cluster (inherited collectors): counted with it, as on
  // the Overview, and named apart so the two pages give the same "x of y".
  const nodes = assets.filter((a) => a.asset_type === "kubernetes_node").length;
  const monitored = assets.filter((a) => !isContextAsset(a.asset_type) && a.asset_type !== "kubernetes_node");
  const context = assets.length - monitored.length - nodes;
  // A stale asset (not observed recently; the API's lifecycle) is said once as "stale", the word
  // its card shows; collector verdicts are stated for the assets still observed.
  const stale = monitored.filter((a) => a.lifecycle_state === "stale").length;
  const observed = monitored.filter((a) => a.lifecycle_state !== "stale");
  const count = (test: (a: (typeof monitored)[number]) => boolean) => observed.filter(test).length;
  const healthy = count((a) => a.coverage_status === "ok");
  const parts = [`${formatCount(healthy)} of ${formatCount(monitored.length)} monitored asset${monitored.length === 1 ? "" : "s"} healthy`];
  const degraded = count((a) => a.coverage_status === "degraded");
  const staleCollectors = count((a) => a.coverage_status === "stale");
  const noCollector = count((a) => a.coverage_status === "missing" && a.collectors_total === 0);
  const missing = count((a) => a.coverage_status === "missing" && a.collectors_total > 0);
  if (stale > 0) parts.push(`${formatCount(stale)} monitored asset${stale === 1 ? "" : "s"} stale`);
  if (degraded > 0) parts.push(`${formatCount(degraded)} degraded`);
  if (staleCollectors > 0) parts.push(`${formatCount(staleCollectors)} with stale collectors`);
  if (noCollector > 0) parts.push(`${formatCount(noCollector)} without a collector`);
  if (missing > 0) parts.push(`${formatCount(missing)} missing`);
  if (nodes > 0) parts.push(`${formatCount(nodes)} Kubernetes node${nodes === 1 ? "" : "s"} via ${nodes === 1 ? "its" : "their"} cluster`);
  if (context > 0) parts.push(`${formatCount(context)} GitHub owner account${context === 1 ? "" : "s"}`);
  if (retired > 0) parts.push(`${formatCount(retired)} retired${retiredApart > 0 ? " (listed apart)" : ""}`);
  return parts.join(" · ");
}

export interface ClassStatus {
  tone: Tone;
  label: string;
  /** "1 of 3 reporting" style summary from the class's monitored assets. */
  summary: string;
}

/**
 * Status of a class heading, with the API's class rule (backend `asset_class_coverage`): missing
 * when nothing reports, healthy when every asset is, stale when none is healthy or degraded,
 * degraded otherwise. Context assets (accounts) do not count.
 */
export function classStatus(
  assets: Pick<AssetListItem, "asset_type" | "coverage_status" | "collectors_total" | "lifecycle_state">[],
): ClassStatus {
  // Retired assets are left out of the class verdict, as in the API's rollups.
  const monitored = assets.filter((a) => !isContextAsset(a.asset_type) && a.lifecycle_state !== "retired");
  const total = monitored.length;
  const ok = monitored.filter((a) => a.coverage_status === "ok").length;
  const degraded = monitored.filter((a) => a.coverage_status === "degraded").length;
  const missing = monitored.filter((a) => a.coverage_status === "missing").length;
  const summary = `${formatCount(ok + degraded)} of ${formatCount(total)} reporting`;
  if (total === 0 || missing === total) return { tone: "bad", label: "Missing", summary };
  if (ok === total) return { tone: "ok", label: "Healthy", summary };
  if (ok === 0 && degraded === 0) return { tone: "warn", label: "Stale", summary };
  return { tone: "warn", label: "Degraded", summary };
}

// ── Mini-bars ─────────────────────────────────────────────────────────────────────

export const SEVERITIES_DESC: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_FILL: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

export interface BarPart {
  key: string;
  label: string;
  value: number;
  className: string;
}

/** Severity parts of a count set, most severe first; zero parts kept (SplitBar omits them). */
export function severityParts(counts: SeverityCounts): BarPart[] {
  return SEVERITIES_DESC.map((severity) => ({
    key: severity,
    label: severity,
    value: counts[severity],
    className: SEVERITY_FILL[severity],
  }));
}

export const COVERAGE_PARTS = [
  { key: "monitored", label: "monitored", className: "bg-cov-monitored" },
  { key: "degraded", label: "degraded", className: "bg-cov-degraded" },
  { key: "unmonitored", label: "unmonitored", className: "bg-cov-unmonitored" },
  { key: "planned", label: "planned adapter", className: "bg-cov-planned" },
  { key: "unsupported", label: "unsupported", className: "bg-cov-unsupported" },
] as const;

export function coverageParts(coverage: ServiceCoverageCounts): BarPart[] {
  return COVERAGE_PARTS.map((p) => ({ key: p.key, label: p.label, value: coverage[p.key], className: p.className }));
}

/** "4 high · 2 medium": non-zero parts in words (empty string when all are zero). */
export function partsInWords(parts: BarPart[]): string {
  return parts
    .filter((p) => p.value > 0)
    .map((p) => `${formatCount(p.value)} ${p.label}`)
    .join(" · ");
}

// ── Open alerts by severity ───────────────────────────────────────────────────────

/**
 * Severity mix of the open alerts, only when it can be stated exactly: the open alerts among
 * the asset's recent alerts (30 days, capped by the API) must add up to the asset's open-alert
 * count. Otherwise null (the caller shows the total alone rather than a partial mix).
 */
export function openAlertMix(recent: Pick<AlertListItem, "severity" | "analyst_status">[], openTotal: number): SeverityCounts | null {
  const open = recent.filter((a) => !isClosedStatus(a.analyst_status));
  if (open.length !== openTotal) return null;
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: open.length };
  for (const alert of open) counts[alert.severity] += 1;
  return counts;
}

// ── Collector freshness ───────────────────────────────────────────────────────────

/** The API's staleness rule: no successful collection within 3 collection intervals. */
export const STALE_FACTOR = 3;

export interface Freshness {
  /** Age of the last success as a share of the staleness threshold (0..1), null when unknown. */
  ratio: number | null;
  tone: Tone;
  /** Word for the state ("Fresh", "Stale", "Never succeeded", ...). */
  label: string;
  /** "stale after 15 min" (null when the interval is unknown). */
  threshold: string | null;
}

/**
 * Freshness of one collector for the bar: the age of its last successful collection against the
 * API's staleness threshold (3 intervals). The API's own `stale` verdict decides the tone; the
 * bar only visualises how far into the threshold the age is.
 */
export function collectorFreshness(
  c: Pick<CollectorStatus, "stale" | "status" | "interval_seconds" | "seconds_since_success" | "last_success_at">,
): Freshness {
  const threshold = c.interval_seconds > 0 ? STALE_FACTOR * c.interval_seconds : null;
  const age = c.seconds_since_success ?? null;
  const ratio = threshold && age !== null && Number.isFinite(age) ? Math.min(1, Math.max(0, age / threshold)) : null;
  const thresholdText = threshold ? `stale after ${formatDuration(threshold)}` : null;
  if (!c.last_success_at) return { ratio: null, tone: "bad", label: "Never succeeded", threshold: thresholdText };
  if (c.stale) return { ratio: ratio ?? 1, tone: "warn", label: "Stale", threshold: thresholdText };
  if (c.status === "failed") return { ratio, tone: "bad", label: "Failing", threshold: thresholdText };
  if (c.status === "degraded") return { ratio, tone: "warn", label: "Degraded", threshold: thresholdText };
  if (c.status === "disabled") return { ratio, tone: "off", label: "Disabled", threshold: thresholdText };
  if (c.status === "unknown") return { ratio, tone: "off", label: "Unknown", threshold: thresholdText };
  return { ratio, tone: "ok", label: "Fresh", threshold: thresholdText };
}

// ── Events by source ──────────────────────────────────────────────────────────────

export interface SourceRow {
  source_type: string;
  events: number;
  last_event_at: string | null;
  last_ingested_at: string | null;
  /** Declared by one of the asset's own collectors. */
  declared: boolean;
}

/**
 * Event counts per source type over the API window, plus the sources the asset's own
 * collectors declare but that stored no event in the window (a real 0, shown as such).
 * Collectors of an ancestor asset (a node's cluster) add nothing: their events carry the
 * ancestor's id, so a 0 under this asset would misstate them. Most events first.
 */
export function sourceRows(
  counts: { source_type: string; events: number; last_event_at?: string | null; last_ingested_at?: string | null }[],
  collectors: Pick<CollectorStatus, "asset_id" | "source_types">[],
  assetId: string,
): SourceRow[] {
  const declared = new Set(collectors.filter((c) => c.asset_id === assetId).flatMap((c) => c.source_types));
  const rows = new Map<string, SourceRow>();
  for (const c of counts) {
    rows.set(c.source_type, {
      source_type: c.source_type,
      events: c.events,
      last_event_at: c.last_event_at ?? null,
      last_ingested_at: c.last_ingested_at ?? null,
      declared: declared.has(c.source_type),
    });
  }
  for (const source of declared) {
    if (!rows.has(source)) {
      rows.set(source, { source_type: source, events: 0, last_event_at: null, last_ingested_at: null, declared: true });
    }
  }
  return [...rows.values()].sort((a, b) => b.events - a.events || a.source_type.localeCompare(b.source_type));
}

// ── Windows ───────────────────────────────────────────────────────────────────────

/**
 * Label of an API window whose end may lie in the future (the API adds a tolerance): "last
 * 24 h" when it ends at or after `now`, otherwise the plain duration.
 */
export function windowLabel(range: { since: string; until: string }, now: string): string {
  const since = Date.parse(range.since);
  const until = Date.parse(range.until);
  const ref = Date.parse(now);
  if (!Number.isFinite(since) || !Number.isFinite(until) || !Number.isFinite(ref)) return "in the API window";
  const end = Math.min(until, ref);
  const hours = Math.max(0, Math.round((end - since) / 3_600_000));
  if (hours >= 48 && hours % 24 === 0) return until >= ref ? `last ${hours / 24} days` : `${hours / 24} days`;
  return until >= ref ? `last ${hours} h` : `${hours} h`;
}

const ITEM_NOUN: Record<string, [string, string]> = {
  github_branch: ["branch", "branches"],
  github_workflow: ["workflow", "workflows"],
  package: ["package", "packages"],
  process: ["process", "processes"],
  listener: ["listener", "listeners"],
  user: ["user", "users"],
  group: ["group", "groups"],
  systemd_unit: ["systemd unit", "systemd units"],
  config_file: ["config file", "config files"],
  launch_item: ["launch item", "launch items"],
  software: ["software item", "software items"],
  k8s_binding: ["binding", "bindings"],
  k8s_namespace: ["namespace", "namespaces"],
  k8s_pod: ["Pod", "Pods"],
  k8s_role: ["role", "roles"],
  k8s_service_account: ["service account", "service accounts"],
  k8s_workload: ["workload", "workloads"],
};

/** "3 workflows": an inventory count with its item noun (unknown types as their token). */
export function itemCount(itemType: string, count: number): string {
  const noun = ITEM_NOUN[itemType];
  if (noun) return `${formatCount(count)} ${count === 1 ? noun[0] : noun[1]}`;
  return `${formatCount(count)} ${itemType.replace(/[_.]+/g, " ")}`;
}

/** Item noun for a table row ("Systemd units"), unknown types as their token. */
export function itemLabel(itemType: string): string {
  const noun = ITEM_NOUN[itemType]?.[1] ?? itemType.replace(/[_.]+/g, " ");
  return noun.charAt(0).toUpperCase() + noun.slice(1);
}

// ── Event tables ──────────────────────────────────────────────────────────────────

/**
 * Optional event columns that no loaded row fills (no actor, no source address, no service):
 * hidden at first so a table of system events is not a wall of dashes; the column menu brings
 * them back. Ids are the EventsDataTable column ids.
 */
export function emptyOptionalColumns(
  events: { actor_name?: string | null; k8s_user?: string | null; gh_actor_login?: string | null; src_ip?: string | null; service_name?: string | null }[],
): string[] {
  const empty: string[] = [];
  if (!events.some((e) => e.actor_name || e.k8s_user || e.gh_actor_login)) empty.push("actor");
  if (!events.some((e) => e.src_ip)) empty.push("src");
  if (!events.some((e) => e.service_name)) empty.push("service");
  return empty;
}

/** Split "4 min ago" into a figure and its unit for KPI display ("4 min" + "ago"). */
export function relativeParts(text: string): { value: string; unit: string | null } {
  const match = /^(.*\S)\s+ago$/.exec(text);
  return match && match[1] ? { value: match[1], unit: "ago" } : { value: text, unit: null };
}

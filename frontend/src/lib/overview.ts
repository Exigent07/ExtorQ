/**
 * Overview presentation rules (pure, unit-tested). Every figure is computed from the API
 * response as received; nothing is rounded up, invented or carried over from a fixture.
 */
import type {
  AlertListItem,
  AssetClassCoverage,
  AssetListItem,
  CollectionHealthSummary,
  FindingsSummary,
  OverviewResponse,
  Severity,
  SeverityCounts,
  TimeSeriesResponse,
} from "@/lib/api/schemas";
import { assetTypeLabel, formatCount } from "@/lib/format";
import { buildSeverityLanes } from "@/lib/series";

type Tone = "ok" | "warn" | "bad" | "off";

/** The four monitored classes, in the order of the ExtorQ mark's arcs (clockwise from top). */
export const CLASS_ORDER = ["macos_host", "linux_host", "kubernetes_cluster", "github_repository"] as const;

export const CLASS_NOUN: Record<string, { one: string; many: string }> = {
  macos_host: { one: "host", many: "hosts" },
  linux_host: { one: "VM", many: "VMs" },
  kubernetes_cluster: { one: "cluster", many: "clusters" },
  github_repository: { one: "repository", many: "repositories" },
};

export const COVERAGE_TONE: Record<string, Tone> = { ok: "ok", degraded: "warn", stale: "warn", missing: "bad" };

export function plural(count: number, one: string, many: string): string {
  return `${formatCount(count)} ${count === 1 ? one : many}`;
}

// ── Open alerts ─────────────────────────────────────────────────────────────────

export interface AlertKpi {
  total: number;
  serious: number;
  parts: { severity: Severity; count: number }[];
  tone: Tone;
}

const ALERT_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export function alertKpi(open: SeverityCounts): AlertKpi {
  const parts = ALERT_SEVERITIES.map((severity) => ({ severity, count: open[severity] }));
  const serious = open.critical + open.high;
  const tone: Tone = open.critical > 0 ? "bad" : open.high > 0 ? "warn" : "ok";
  return { total: open.total, serious, parts, tone };
}

// ── Asset coverage ──────────────────────────────────────────────────────────────

export interface ClassRow {
  assetType: string;
  label: string;
  coverage: AssetClassCoverage | null;
  /** Assets of this class from the asset list, healthiest first (null: list not loaded). */
  assets: AssetListItem[] | null;
  reporting: number;
  total: number;
  /** Retired assets of the class the API left out of every count (never deleted). */
  retired: number;
  tone: Tone;
  statusLabel: string;
  /** Plain-language reason when the class is not healthy, built only from API counts. */
  reason: string | null;
}

const STATUS_LABEL: Record<string, string> = { ok: "Healthy", degraded: "Degraded", stale: "Stale", missing: "Missing" };
const STATUS_RANK: Record<string, number> = { ok: 0, degraded: 1, stale: 2, missing: 3 };

export function classRows(coverage: AssetClassCoverage[], assets: AssetListItem[] | null): ClassRow[] {
  return CLASS_ORDER.map((assetType) => {
    const item = coverage.find((c) => c.asset_type === assetType) ?? null;
    const noun = CLASS_NOUN[assetType] ?? { one: "asset", many: "assets" };
    const ofClass = assets
      ? assets
          .filter((a) => a.asset_type === assetType)
          .sort((a, b) => (STATUS_RANK[a.coverage_status] ?? 9) - (STATUS_RANK[b.coverage_status] ?? 9))
      : null;
    if (!item) {
      return {
        assetType,
        label: assetTypeLabel(assetType),
        coverage: null,
        assets: ofClass,
        reporting: 0,
        total: 0,
        retired: 0,
        tone: "off" as Tone,
        statusLabel: "Not reported",
        reason: "The API reported no coverage for this class.",
      };
    }
    const reporting = item.assets_ok + item.assets_degraded;
    const reasons: string[] = [];
    // Collector staleness of the class's assets (asset list), the usual cause of "degraded".
    const collectors = (ofClass ?? []).reduce((sum, a) => sum + a.collectors_total, 0);
    const staleCollectors = (ofClass ?? []).reduce((sum, a) => sum + a.collectors_stale, 0);
    if (item.assets_total === 0) reasons.push(`no ${noun.one} reporting`);
    if (item.assets_degraded > 0) {
      reasons.push(
        staleCollectors > 0
          ? `${formatCount(staleCollectors)} of ${plural(collectors, "collector", "collectors")} stale`
          : `${plural(item.assets_degraded, noun.one, noun.many)} degraded`,
      );
    }
    if (item.assets_stale > 0) reasons.push(`${formatCount(item.assets_stale)} stale`);
    if (item.assets_without_collector > 0) reasons.push(`${formatCount(item.assets_without_collector)} without collector`);
    return {
      assetType,
      label: assetTypeLabel(assetType),
      coverage: item,
      assets: ofClass,
      reporting,
      total: item.assets_total,
      retired: item.assets_retired,
      tone: COVERAGE_TONE[item.status] ?? "off",
      statusLabel: STATUS_LABEL[item.status] ?? item.status,
      reason: item.status === "ok" || reasons.length === 0 ? null : reasons.join(" · "),
    };
  });
}

export interface AssetKpi {
  reporting: number;
  total: number;
  classesHealthy: number;
  classesTotal: number;
  tone: Tone;
}

export function assetKpi(rows: ClassRow[]): AssetKpi {
  const reported = rows.filter((r) => r.coverage !== null);
  const reporting = reported.reduce((sum, r) => sum + r.reporting, 0);
  const total = reported.reduce((sum, r) => sum + r.total, 0);
  const classesHealthy = reported.filter((r) => r.coverage?.status === "ok").length;
  const anyBad = rows.some((r) => r.tone === "bad");
  const tone: Tone = anyBad ? "bad" : classesHealthy < rows.length ? "warn" : "ok";
  return { reporting, total, classesHealthy, classesTotal: rows.length, tone };
}

/** Classes outside the four monitored ones that the API also reports (e.g. GitHub accounts). */
export function otherClasses(coverage: AssetClassCoverage[]): AssetClassCoverage[] {
  return coverage.filter(
    (c) => !(CLASS_ORDER as readonly string[]).includes(c.asset_type) && c.assets_total > 0,
  );
}

// ── Findings ────────────────────────────────────────────────────────────────────

export interface FindingsKpi {
  serious: number;
  critical: number;
  high: number;
  total: number;
  unverified: number;
  lifecycle: boolean;
  tone: Tone;
}

export function findingsKpi(summary: FindingsSummary): FindingsKpi {
  const { counts } = summary;
  return {
    serious: counts.critical + counts.high,
    critical: counts.critical,
    high: counts.high,
    total: counts.total,
    unverified: summary.unverified?.total ?? 0,
    lifecycle: summary.lifecycle_available,
    tone: counts.critical > 0 ? "bad" : counts.high > 0 ? "warn" : "ok",
  };
}

// ── Collection health ───────────────────────────────────────────────────────────

export interface CollectionKpi {
  ok: number;
  total: number;
  tone: Tone;
  statusLabel: string;
}

export function collectionKpi(summary: CollectionHealthSummary): CollectionKpi {
  if (summary.no_collector_reports) return { ok: 0, total: 0, tone: "bad", statusLabel: "No reports" };
  const failing = summary.collectors_failing > 0 || summary.pipeline_unhealthy > 0 || summary.rules_failing > 0;
  const tone: Tone = summary.collectors_failing > 0 ? "bad" : failing || summary.collectors_stale > 0 ? "warn" : "ok";
  const statusLabel = tone === "ok" ? "Healthy" : tone === "bad" ? "Failing" : "Degraded";
  return { ok: summary.collectors_ok, total: summary.collectors_total, tone, statusLabel };
}

// ── Page finding ────────────────────────────────────────────────────────────────

const CLASS_PLURAL: Record<string, string> = {
  macos_host: "macOS hosts",
  linux_host: "Linux VMs",
  kubernetes_cluster: "Kubernetes clusters",
  github_repository: "GitHub repositories",
};

/**
 * The cause of an unhealthy class in words: "2 stale GitHub repositories" when every asset of
 * the class that is not healthy is lifecycle-stale (not observed recently, the Assets page's
 * word), otherwise the class's coverage verdict.
 */
function classCause(
  coverage: AssetClassCoverage,
  assets: readonly Pick<AssetListItem, "asset_type" | "coverage_status" | "lifecycle_state">[] | null,
): string {
  const label = assetTypeLabel(coverage.asset_type);
  if (assets) {
    const notOk = assets.filter(
      (a) => a.asset_type === coverage.asset_type && a.lifecycle_state !== "retired" && a.coverage_status !== "ok",
    );
    if (notOk.length > 0 && notOk.every((a) => a.lifecycle_state === "stale")) {
      const many = CLASS_PLURAL[coverage.asset_type] ?? `${label} assets`;
      return `${formatCount(notOk.length)} stale ${notOk.length === 1 ? label : many}`;
    }
  }
  return `${label} coverage ${coverage.status}`;
}

/** One line computed from the data: what most needs attention right now. */
export function overviewFinding(
  data: Pick<OverviewResponse, "open_alerts" | "asset_coverage">,
  assets: readonly Pick<AssetListItem, "asset_type" | "coverage_status" | "lifecycle_state">[] | null = null,
): string {
  const parts: string[] = [];
  const open = data.open_alerts;
  const serious = open.critical + open.high;
  if (open.total === 0) parts.push("No open alerts");
  else {
    const severe = open.critical > 0 ? `${formatCount(open.critical)} critical` : serious > 0 ? `${formatCount(serious)} high` : null;
    parts.push(`${plural(open.total, "open alert", "open alerts")}${severe ? `, ${severe}` : ""}`);
  }
  const unhealthy = data.asset_coverage.filter((c) => c.expected && c.status !== "ok");
  if (unhealthy.length === 0 && data.asset_coverage.length > 0) parts.push("all monitored classes reporting");
  else if (unhealthy.length > 0) {
    const causes = unhealthy.map((c) => classCause(c, assets));
    if (causes.every((c) => c.endsWith(" coverage degraded")) && causes.length > 1) {
      const names = unhealthy.slice(0, 2).map((c) => assetTypeLabel(c.asset_type));
      const more = unhealthy.length > 2 ? ` and ${unhealthy.length - 2} more` : "";
      parts.push(`${names.join(" and ")}${more} coverage degraded`);
    } else {
      parts.push(causes.slice(0, 2).join(" · ") + (causes.length > 2 ? ` · ${causes.length - 2} more classes` : ""));
    }
  }
  return parts.join(" · ");
}

// ── Alert activity chart ────────────────────────────────────────────────────────

export interface ActivityRow {
  start: string;
  end: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ActivitySeries {
  rows: ActivityRow[];
  bucketSeconds: number;
  totals: Record<Severity, number>;
  total: number;
  truncated: boolean;
  /** Group-less points (API without severity grouping) are not drawn by severity. */
  ungrouped: number;
}

/** Dense buckets (absent buckets are zero rows: nothing stored) stacked by severity. */
export function activitySeries(series: TimeSeriesResponse): ActivitySeries {
  const lanes = buildSeverityLanes(series);
  const bySeverity = new Map(lanes.lanes.map((lane) => [lane.severity, lane]));
  const totals = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  const rows = lanes.buckets.map((bucket, i) => {
    const row: ActivityRow = { start: bucket.start, end: bucket.end, critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 };
    for (const severity of ALERT_SEVERITIES) {
      const count = bySeverity.get(severity)?.counts[i] ?? 0;
      row[severity] = count;
      row.total += count;
      totals[severity] += count;
    }
    return row;
  });
  const ungrouped = bySeverity.get("all")?.total ?? 0;
  return {
    rows,
    bucketSeconds: lanes.bucketSeconds,
    totals,
    total: rows.reduce((sum, row) => sum + row.total, 0),
    truncated: series.truncated,
    ungrouped,
  };
}

/** Round y ticks: 2-4 integer steps of a round size, the top tick at or above the maximum. */
export function niceTicks(max: number): number[] {
  const steps = [1, 2, 4, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 2500, 5000];
  const step = steps.find((s) => Math.ceil(max / s) <= 4) ?? Math.ceil(max / 4);
  const count = Math.max(2, Math.ceil(max / step));
  return Array.from({ length: count + 1 }, (_, i) => i * step);
}

/** Recent important alerts for the overview table: open ones first, then by last activity. */
export function importantAlerts(alerts: AlertListItem[], limit = 6): AlertListItem[] {
  const closed = (a: AlertListItem) => a.analyst_status.startsWith("closed_");
  return [...alerts]
    .sort((a, b) => Number(closed(a)) - Number(closed(b)) || Date.parse(b.last_seen) - Date.parse(a.last_seen))
    .slice(0, limit);
}

/**
 * Detections view model: URL query (the allow-listed alert filters, multi-valued where the
 * API accepts arrays), lean table rows, facet semantics and the headline figures.
 *
 * Pure and isomorphic (no "use client", no server-only imports): the server page, the client
 * workspace and the unit tests share it. Every value read from the URL is validated against
 * an allow-list or a strict pattern (the same ones as src/lib/filters.ts); anything else is
 * dropped and never forwarded upstream.
 */
import {
  ANALYST_STATUSES,
  type AlertListItem,
  type AnalystStatus,
  type RuleListItem,
  SEVERITIES,
  type Severity,
} from "@/lib/api/schemas";
import { DEFAULT_RANGE, TIME_RANGES, type TimeRangeKey } from "@/lib/filters";
import { formatCount, isClosedStatus } from "@/lib/format";
import { isAssetId, isRuleId } from "@/lib/security/ids";

export type DetectionsTab = "alerts" | "rules";
export type SimulationFacet = "yes" | "no";

export const SIMULATION_VALUES: readonly SimulationFacet[] = ["yes", "no"];
export const RANGE_KEYS = Object.keys(TIME_RANGES) as TimeRangeKey[];

/** Facet dimensions of the alert table; the URL parameter has the same name. */
export const FACET_KEYS = ["severity", "rule", "asset", "status", "sim"] as const;
export type FacetKey = (typeof FACET_KEYS)[number];
export type FacetSelection = Record<FacetKey, string[]>;

export interface DetectionsQuery extends FacetSelection {
  severity: Severity[];
  status: AnalystStatus[];
  sim: SimulationFacet[];
  range: TimeRangeKey;
  offset: number;
  tab: DetectionsTab;
}

/** Alerts per API page (the API's maximum). */
export const ALERTS_PER_REQUEST = 200;
/** Values kept per multi-valued parameter (the API accepts 5 severities and 6 statuses). */
const MAX_VALUES = 12;
const MAX_VALUE_LENGTH = 200;

type RawParams = Record<string, string | string[] | undefined>;

function values(params: RawParams, key: string): string[] {
  const raw = params[key];
  const list = Array.isArray(raw) ? raw : raw === undefined ? [] : [raw];
  const out: string[] = [];
  for (const value of list) {
    if (typeof value !== "string" || value.length === 0 || value.length > MAX_VALUE_LENGTH) continue;
    if (!out.includes(value)) out.push(value);
    if (out.length >= MAX_VALUES) break;
  }
  return out;
}

function allowed<T extends string>(list: string[], allow: readonly T[]): T[] {
  // Canonical order (the allow-list's), so equal selections give equal URLs.
  return allow.filter((value) => list.includes(value));
}

export function emptySelection(): FacetSelection {
  return { severity: [], rule: [], asset: [], status: [], sim: [] };
}

/**
 * Parses the Detections URL. Compatible with the single-valued links of the first console
 * (`?severity=high&rule=VM-001&range=30d`) and accepts repeated parameters for multi-select.
 */
export function parseDetectionsQuery(params: RawParams): DetectionsQuery {
  const range = values(params, "range")[0];
  const offsetRaw = Number.parseInt(values(params, "offset")[0] ?? "0", 10);
  return {
    severity: allowed(values(params, "severity"), SEVERITIES),
    status: allowed(values(params, "status"), ANALYST_STATUSES),
    rule: values(params, "rule").filter(isRuleId).sort(),
    asset: values(params, "asset").filter(isAssetId).sort(),
    sim: allowed(values(params, "sim"), SIMULATION_VALUES),
    range: range && (RANGE_KEYS as string[]).includes(range) ? (range as TimeRangeKey) : DEFAULT_RANGE,
    offset: Number.isFinite(offsetRaw) && offsetRaw > 0 && offsetRaw <= 100000 ? offsetRaw : 0,
    tab: values(params, "tab")[0] === "rules" ? "rules" : "alerts",
  };
}

/** Validates a facet selection coming back from the browser (same allow-lists as the URL). */
export function sanitizeSelection(selection: Partial<Record<FacetKey, readonly string[]>>): FacetSelection {
  const pick = (key: FacetKey) => values({ [key]: [...(selection[key] ?? [])] }, key);
  return {
    severity: allowed(pick("severity"), SEVERITIES),
    status: allowed(pick("status"), ANALYST_STATUSES),
    rule: pick("rule").filter(isRuleId).sort(),
    asset: pick("asset").filter(isAssetId).sort(),
    sim: allowed(pick("sim"), SIMULATION_VALUES),
  };
}

/** Everything a Detections URL can carry (the facet values as strings). */
export interface DetectionsLocation extends FacetSelection {
  range: TimeRangeKey;
  offset: number;
  tab: DetectionsTab;
}

/**
 * Console URL search string (repeated parameters, only non-default values). Callers pass
 * values that were validated (parseDetectionsQuery, sanitizeSelection).
 */
export function detectionsSearch(query: Partial<DetectionsLocation>): string {
  const params = new URLSearchParams();
  for (const key of FACET_KEYS) for (const value of query[key] ?? []) params.append(key, value);
  if (query.range && query.range !== DEFAULT_RANGE) params.set("range", query.range);
  if (query.offset) params.set("offset", String(query.offset));
  if (query.tab === "rules") params.set("tab", "rules");
  const search = params.toString();
  return search ? `?${search}` : "";
}

export function hasFacetFilters(selection: FacetSelection): boolean {
  return FACET_KEYS.some((key) => selection[key].length > 0);
}

/**
 * The part of a selection the API can apply itself: severities and statuses as arrays, a
 * rule or an asset only when exactly one is selected (the API takes one of each). The
 * simulation facet has no API parameter. `partial` says some of the selection could only be
 * applied to the loaded rows.
 */
export function apiFilters(selection: FacetSelection): {
  severity: Severity[];
  status: AnalystStatus[];
  ruleId: string | null;
  assetId: string | null;
  partial: boolean;
} {
  return {
    severity: selection.severity as Severity[],
    status: selection.status as AnalystStatus[],
    ruleId: selection.rule.length === 1 ? (selection.rule[0] ?? null) : null,
    assetId: selection.asset.length === 1 ? (selection.asset[0] ?? null) : null,
    partial: selection.rule.length > 1 || selection.asset.length > 1 || selection.sim.length > 0,
  };
}

// ── Rows ────────────────────────────────────────────────────────────────────────────

/** The fields of an alert the table needs (keeps the page payload small). */
export interface AlertRow {
  id: string;
  ruleId: string;
  ruleTitle: string;
  ruleVersion: string;
  severity: Severity;
  confidence: string;
  assetId: string;
  assetType: string;
  summary: string;
  firstSeen: string;
  lastSeen: string;
  events: number;
  services: number;
  simulationRunIds: string[];
  sim: SimulationFacet;
  status: AnalystStatus;
  statusRecorded: boolean;
}

export function toAlertRow(item: AlertListItem): AlertRow {
  return {
    id: item.alert_id,
    ruleId: item.rule_id,
    ruleTitle: item.rule_title,
    ruleVersion: item.rule_version,
    severity: item.severity,
    confidence: item.confidence,
    assetId: item.asset_id,
    assetType: item.asset_type,
    summary: item.summary,
    firstSeen: item.first_seen,
    lastSeen: item.last_seen,
    events: item.event_count,
    services: item.service_ids.length,
    simulationRunIds: item.simulation_run_ids,
    sim: item.simulation_run_ids.length > 0 ? "yes" : "no",
    status: item.analyst_status,
    statusRecorded: item.analyst_state_recorded,
  };
}

/** The value a row has for a facet (the same token the URL carries). */
export function facetValue(row: AlertRow, key: FacetKey): string {
  switch (key) {
    case "severity":
      return row.severity;
    case "rule":
      return row.ruleId;
    case "asset":
      return row.assetId;
    case "status":
      return row.status;
    case "sim":
      return row.sim;
  }
}

/** Facet semantics: OR within a facet, AND across facets; an empty facet keeps every row. */
export function matchesSelection(row: AlertRow, selection: FacetSelection): boolean {
  return FACET_KEYS.every((key) => selection[key].length === 0 || selection[key].includes(facetValue(row, key)));
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// ── Headline figures ───────────────────────────────────────────────────────────────

export interface AlertFigures {
  /**
   * Alerts in the range: the API's total; the rows loaded when they are the whole range;
   * null when more exist and the API gave no total (show the loaded count as a lower bound).
   */
  total: number | null;
  /** False when the API holds more alerts than were loaded (the split figures are partial). */
  complete: boolean;
  loaded: number;
  bySeverity: Record<Severity, number>;
  open: number;
  untriaged: number;
  investigating: number;
  acknowledged: number;
  closed: number;
  openBySeverity: Record<Severity, number>;
  simulated: number;
  assets: { assetId: string; assetType: string; count: number }[];
  rulesFiring: number;
  /** First activity of the oldest open alert (the age of the open backlog); null when none is open. */
  oldestOpenSince: string | null;
}

function zeroSeverities(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function alertFigures(items: AlertListItem[], apiTotal: number | null | undefined, hasMore: boolean): AlertFigures {
  const bySeverity = zeroSeverities();
  const openBySeverity = zeroSeverities();
  const assets = new Map<string, { assetId: string; assetType: string; count: number }>();
  const rules = new Set<string>();
  let open = 0;
  let untriaged = 0;
  let investigating = 0;
  let acknowledged = 0;
  let simulated = 0;
  let oldestOpenSince: string | null = null;
  for (const item of items) {
    bySeverity[item.severity] += 1;
    if (!isClosedStatus(item.analyst_status)) {
      open += 1;
      if (oldestOpenSince === null || Date.parse(item.first_seen) < Date.parse(oldestOpenSince)) oldestOpenSince = item.first_seen;
      openBySeverity[item.severity] += 1;
      if (item.analyst_status === "new") untriaged += 1;
      if (item.analyst_status === "investigating") investigating += 1;
      if (item.analyst_status === "acknowledged") acknowledged += 1;
    }
    if (item.simulation_run_ids.length > 0) simulated += 1;
    rules.add(item.rule_id);
    const asset = assets.get(item.asset_id) ?? { assetId: item.asset_id, assetType: item.asset_type, count: 0 };
    asset.count += 1;
    assets.set(item.asset_id, asset);
  }
  return {
    total: apiTotal ?? (hasMore ? null : items.length),
    complete: !hasMore,
    loaded: items.length,
    bySeverity,
    open,
    untriaged,
    investigating,
    acknowledged,
    closed: items.length - open,
    openBySeverity,
    simulated,
    assets: [...assets.values()].sort((a, b) => b.count - a.count || a.assetId.localeCompare(b.assetId)),
    rulesFiring: rules.size,
    oldestOpenSince,
  };
}

export interface RuleFigures {
  total: number;
  enabled: number;
  /** Last run succeeded / skipped / failed; never ran (each rule counted once). */
  succeededNow: number;
  skippedNow: number;
  failingNow: number;
  neverRan: number;
  overdue: number;
  failures24h: number;
  runs24h: number;
  /** Rules whose last run found no events at all from at least one required source. */
  quietSources: number;
}

export function ruleFigures(rules: RuleListItem[]): RuleFigures {
  let failures24h = 0;
  let runs24h = 0;
  for (const rule of rules) {
    failures24h += rule.last_run?.failures_24h ?? 0;
    runs24h += rule.last_run?.runs_24h ?? 0;
  }
  return {
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    succeededNow: rules.filter((r) => r.last_run?.last_status === "succeeded").length,
    skippedNow: rules.filter((r) => r.last_run !== null && r.last_run !== undefined && !["succeeded", "failed"].includes(r.last_run.last_status)).length,
    failingNow: rules.filter((r) => r.last_run?.last_status === "failed").length,
    neverRan: rules.filter((r) => r.enabled && !r.last_run).length,
    overdue: rules.filter((r) => r.run_stale === true).length,
    failures24h,
    runs24h,
    quietSources: rules.filter((r) => (r.last_run?.missing_sources.length ?? 0) > 0).length,
  };
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return `${formatCount(count)} ${count === 1 ? one : many}`;
}

/** The page's one-line finding: what fired in the range and whether the rules run. */
export function detectionsFinding(
  alerts: AlertFigures | null,
  rules: RuleFigures | null,
  range: TimeRangeKey,
): string {
  const parts: string[] = [];
  if (alerts) {
    const window = TIME_RANGES[range].label.toLowerCase();
    parts.push(
      alerts.total === null
        ? `More than ${formatCount(alerts.loaded)} alerts with activity in the ${window}`
        : `${plural(alerts.total, "alert")} with activity in the ${window}`,
    );
    if (alerts.complete) parts.push(alerts.open === 0 ? "none open" : `${formatCount(alerts.open)} open`);
  }
  if (rules) {
    const failing =
      rules.failingNow > 0
        ? `${formatCount(rules.failingNow)} failing`
        : rules.neverRan > 0
          ? `${formatCount(rules.neverRan)} never ran`
          : "none failing";
    parts.push(`${formatCount(rules.enabled)} of ${plural(rules.total, "rule")} enabled, ${failing}`);
  }
  return parts.join(" · ");
}

/** Run outcome of a rule's last evaluation as a health tone. */
export function runTone(status: string | null | undefined): "ok" | "warn" | "bad" | "off" {
  if (status === "succeeded") return "ok";
  if (status === "failed") return "bad";
  if (status === "skipped") return "warn";
  return "off";
}

export function ruleStatusLabel(status: string): string {
  if (status === "stable") return "Stable";
  if (status === "experimental") return "Experimental";
  if (status === "deprecated") return "Deprecated";
  return status;
}

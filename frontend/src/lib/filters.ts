/**
 * URL search-parameter parsing for list filters. Every value is validated against an
 * allow-list or a strict pattern; anything else is ignored (never forwarded upstream).
 */
import {
  ANALYST_STATUSES,
  type AnalystStatus,
  SEVERITIES,
  type Severity,
} from "@/lib/api/schemas";
import { isAssetId, isRuleId } from "@/lib/security/ids";

export const TIME_RANGES = {
  "1h": { seconds: 3600, label: "Last hour" },
  "24h": { seconds: 86400, label: "Last 24 hours" },
  "7d": { seconds: 7 * 86400, label: "Last 7 days" },
  "30d": { seconds: 30 * 86400, label: "Last 30 days" },
} as const;
export type TimeRangeKey = keyof typeof TIME_RANGES;
export const DEFAULT_RANGE: TimeRangeKey = "7d";

export const ALERT_PAGE_SIZE = 50;

export interface AlertFilters {
  asset: string | null;
  severity: Severity | null;
  rule: string | null;
  status: AnalystStatus | null;
  range: TimeRangeKey;
  offset: number;
}

type RawParams = Record<string, string | string[] | undefined>;

function first(params: RawParams, key: string): string | null {
  const value = params[key];
  const single = Array.isArray(value) ? value[0] : value;
  return typeof single === "string" && single.length > 0 && single.length <= 200 ? single : null;
}

function oneOf<T extends string>(value: string | null, allowed: readonly T[]): T | null {
  return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : null;
}

export function parseAlertFilters(params: RawParams): AlertFilters {
  const asset = first(params, "asset");
  const rule = first(params, "rule");
  const rangeRaw = first(params, "range");
  const offsetRaw = Number.parseInt(first(params, "offset") ?? "0", 10);
  return {
    asset: asset && isAssetId(asset) ? asset : null,
    severity: oneOf(first(params, "severity"), SEVERITIES),
    rule: rule && isRuleId(rule) ? rule : null,
    status: oneOf(first(params, "status"), ANALYST_STATUSES),
    range: rangeRaw && rangeRaw in TIME_RANGES ? (rangeRaw as TimeRangeKey) : DEFAULT_RANGE,
    offset: Number.isFinite(offsetRaw) && offsetRaw > 0 && offsetRaw <= 100000 ? offsetRaw : 0,
  };
}

/** Console URL search string for a filter set (only non-default values). */
export function alertFiltersToSearch(filters: Partial<AlertFilters>): string {
  const params = new URLSearchParams();
  if (filters.asset) params.set("asset", filters.asset);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.rule) params.set("rule", filters.rule);
  if (filters.status) params.set("status", filters.status);
  if (filters.range && filters.range !== DEFAULT_RANGE) params.set("range", filters.range);
  if (filters.offset) params.set("offset", String(filters.offset));
  const search = params.toString();
  return search ? `?${search}` : "";
}

export function rangeBounds(range: TimeRangeKey, now: Date = new Date()): { since: string; until: string } {
  const until = now.toISOString();
  const since = new Date(now.getTime() - TIME_RANGES[range].seconds * 1000).toISOString();
  return { since, until };
}

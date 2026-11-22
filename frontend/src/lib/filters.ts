/**
 * Time ranges and alert-filter URLs. The Detections page parses its URL with the allow-lists
 * in `src/components/views/detections/model.ts` (`parseDetectionsQuery`); values that fail
 * them are ignored, never forwarded upstream.
 */
import type { AnalystStatus, Severity } from "@/lib/api/schemas";

export const TIME_RANGES = {
  "1h": { seconds: 3600, label: "Last hour" },
  "24h": { seconds: 86400, label: "Last 24 hours" },
  "7d": { seconds: 7 * 86400, label: "Last 7 days" },
  "30d": { seconds: 30 * 86400, label: "Last 30 days" },
} as const;
export type TimeRangeKey = keyof typeof TIME_RANGES;
export const DEFAULT_RANGE: TimeRangeKey = "7d";

/** Alerts per API request (the API's page maximum). */
export const ALERTS_PER_REQUEST = 200;

export interface AlertFilters {
  asset: string | null;
  severity: Severity | null;
  rule: string | null;
  status: AnalystStatus | null;
  range: TimeRangeKey;
  offset: number;
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

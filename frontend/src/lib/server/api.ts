import "server-only";

import {
  type AnalystStatus,
  zAlertDetailResponse,
  zAlertListResponse,
  zAlertStateResponse,
  zAssessmentListResponse,
  zAssetDetailResponse,
  zAssetListResponse,
  zAssetServicesResponse,
  zContextResponse,
  zEventDetailResponse,
  zEventListResponse,
  zFindingListResponse,
  zHealthResponse,
  zOverviewResponse,
  zRuleListResponse,
  zServiceDetailResponse,
  zSummaryResponse,
  zTimeSeriesResponse,
} from "@/lib/api/schemas";
import type { Session } from "@/lib/auth/token";
import { ALERT_PAGE_SIZE, type AlertFilters, rangeBounds } from "@/lib/filters";
import { isAssetId, isHexId } from "@/lib/security/ids";

import { apiRequest, type ApiResult } from "./api-client";
import { summaryTimeoutMs } from "./config";

/**
 * Typed endpoint functions for the analyst API (PLAN §5.2, base /api/v1).
 * Identifiers are validated before they are placed in a path, and encoded as a single
 * path segment, so callers cannot alter the upstream route.
 */

function seg(value: string): string {
  return encodeURIComponent(value);
}

function invalidId<T>(what: string): ApiResult<T> {
  return {
    ok: false,
    error: { kind: "not_found", status: null, requestId: "-", detail: null, message: `Invalid ${what}` },
  };
}

export function getOverview(session: Session) {
  return apiRequest(session, zOverviewResponse, {
    method: "GET",
    path: "/api/v1/overview",
    route: "/api/v1/overview",
  });
}

export function listAssets(session: Session) {
  return apiRequest(session, zAssetListResponse, {
    method: "GET",
    path: "/api/v1/assets",
    route: "/api/v1/assets",
    query: { limit: 200 },
  });
}

export function getAsset(session: Session, assetId: string) {
  if (!isAssetId(assetId)) return Promise.resolve(invalidId<never>("asset id"));
  return apiRequest(session, zAssetDetailResponse, {
    method: "GET",
    path: `/api/v1/assets/${seg(assetId)}`,
    route: "/api/v1/assets/{id}",
  });
}

export function listFindings(session: Session, query: { assetId?: string; limit?: number } = {}) {
  return apiRequest(session, zFindingListResponse, {
    method: "GET",
    path: "/api/v1/findings",
    route: "/api/v1/findings",
    query: {
      asset_id: query.assetId && isAssetId(query.assetId) ? query.assetId : undefined,
      limit: query.limit ?? 200,
    },
  });
}

export function listRules(session: Session) {
  return apiRequest(session, zRuleListResponse, {
    method: "GET",
    path: "/api/v1/rules",
    route: "/api/v1/rules",
    query: { limit: 200 },
  });
}

export function listAlerts(session: Session, filters: AlertFilters) {
  const { since, until } = rangeBounds(filters.range);
  return apiRequest(session, zAlertListResponse, {
    method: "GET",
    path: "/api/v1/alerts",
    route: "/api/v1/alerts",
    query: {
      asset_id: filters.asset,
      severity: filters.severity,
      rule_id: filters.rule,
      status: filters.status,
      since,
      until,
      limit: ALERT_PAGE_SIZE,
      offset: filters.offset,
    },
  });
}

export function getAlert(session: Session, alertId: string) {
  if (!isHexId(alertId)) return Promise.resolve(invalidId<never>("alert id"));
  return apiRequest(session, zAlertDetailResponse, {
    method: "GET",
    path: `/api/v1/alerts/${seg(alertId)}`,
    route: "/api/v1/alerts/{id}",
  });
}

export function getAlertContext(session: Session, alertId: string) {
  if (!isHexId(alertId)) return Promise.resolve(invalidId<never>("alert id"));
  return apiRequest(session, zContextResponse, {
    method: "GET",
    path: `/api/v1/alerts/${seg(alertId)}/context`,
    route: "/api/v1/alerts/{id}/context",
  });
}

export function listAssessments(session: Session, alertId: string) {
  if (!isHexId(alertId)) return Promise.resolve(invalidId<never>("alert id"));
  return apiRequest(session, zAssessmentListResponse, {
    method: "GET",
    path: `/api/v1/alerts/${seg(alertId)}/assessments`,
    route: "/api/v1/alerts/{id}/assessments",
  });
}

export function requestSummary(session: Session, alertId: string) {
  if (!isHexId(alertId)) return Promise.resolve(invalidId<never>("alert id"));
  return apiRequest(session, zSummaryResponse, {
    method: "POST",
    path: `/api/v1/alerts/${seg(alertId)}/summary`,
    route: "/api/v1/alerts/{id}/summary",
    timeoutMs: summaryTimeoutMs(),
  });
}

export interface AlertStateChange {
  status: AnalystStatus;
  note: string | null;
  expectedUpdatedAt: string | null;
}

export function updateAlertState(session: Session, alertId: string, change: AlertStateChange) {
  if (!isHexId(alertId)) return Promise.resolve(invalidId<never>("alert id"));
  return apiRequest(session, zAlertStateResponse, {
    method: "POST",
    path: `/api/v1/alerts/${seg(alertId)}/state`,
    route: "/api/v1/alerts/{id}/state",
    body: {
      status: change.status,
      note: change.note,
      ...(change.expectedUpdatedAt ? { expected_updated_at: change.expectedUpdatedAt } : {}),
    },
  });
}

export function listEvents(
  session: Session,
  query: { assetId?: string; since?: string; until?: string; limit?: number } = {},
) {
  return apiRequest(session, zEventListResponse, {
    method: "GET",
    path: "/api/v1/events",
    route: "/api/v1/events",
    query: {
      asset_id: query.assetId && isAssetId(query.assetId) ? query.assetId : undefined,
      since: query.since,
      until: query.until,
      limit: query.limit ?? 25,
    },
  });
}

export function getEvent(session: Session, eventId: string) {
  if (!isHexId(eventId)) return Promise.resolve(invalidId<never>("event id"));
  return apiRequest(session, zEventDetailResponse, {
    method: "GET",
    path: `/api/v1/events/${seg(eventId)}`,
    route: "/api/v1/events/{id}",
  });
}

export function getHealth(session: Session) {
  return apiRequest(session, zHealthResponse, {
    method: "GET",
    path: "/api/v1/health",
    route: "/api/v1/health",
  });
}

/** Bucket width that yields roughly 12-30 buckets for a range. */
export function bucketSecondsFor(rangeSeconds: number): number {
  if (rangeSeconds <= 3600) return 300;
  if (rangeSeconds <= 86400) return 3600;
  if (rangeSeconds <= 7 * 86400) return 6 * 3600;
  return 86400;
}

export function getTimeseries(
  session: Session,
  metric: "alerts" | "events",
  query: { since: string; until: string; groupBy?: string; assetId?: string; bucketSeconds?: number },
) {
  return apiRequest(session, zTimeSeriesResponse, {
    method: "GET",
    path: `/api/v1/timeseries/${metric}`,
    route: "/api/v1/timeseries/{metric}",
    query: {
      since: query.since,
      until: query.until,
      bucket_seconds: query.bucketSeconds,
      group_by: query.groupBy,
      asset_id: query.assetId && isAssetId(query.assetId) ? query.assetId : undefined,
    },
  });
}

// ── Services (PLAN §10, contracts 1.1) ──────────────────────────────────────────────

export function listAssetServices(session: Session, assetId: string, options: { includeRemoved?: boolean } = {}) {
  if (!isAssetId(assetId)) return Promise.resolve(invalidId<never>("asset id"));
  return apiRequest(session, zAssetServicesResponse, {
    method: "GET",
    path: `/api/v1/assets/${seg(assetId)}/services`,
    route: "/api/v1/assets/{id}/services",
    query: { limit: 200, include_removed: options.includeRemoved ? "true" : undefined },
  });
}

export function getService(session: Session, serviceId: string) {
  if (!isHexId(serviceId)) return Promise.resolve(invalidId<never>("service id"));
  return apiRequest(session, zServiceDetailResponse, {
    method: "GET",
    path: `/api/v1/services/${seg(serviceId)}`,
    route: "/api/v1/services/{id}",
  });
}

import "server-only";

import { ALERTS_PER_REQUEST } from "@/components/views/detections/model";
import { type AnalystStatus, type Severity, zAlertListResponse } from "@/lib/api/schemas";
import type { Session } from "@/lib/auth/token";
import { rangeBounds, type TimeRangeKey } from "@/lib/filters";
import { apiRequest } from "@/lib/server/api-client";
import { isAssetId, isRuleId } from "@/lib/security/ids";

/**
 * Alerts with activity in a time range, up to the API's page maximum (200), through the
 * console's only API client. Differs from `listAlerts` (src/lib/server/api.ts, 50 rows,
 * single values) in two ways the Detections table needs: one request usually holds the whole
 * range, so facets and counts run on complete data, and severities/statuses are sent as the
 * arrays the API accepts. Every value was validated by the caller (parseDetectionsQuery) and
 * is checked again here before it becomes a query parameter.
 */
export function listAlertsInRange(
  session: Session,
  query: {
    range: TimeRangeKey;
    offset?: number;
    severity?: Severity[];
    status?: AnalystStatus[];
    ruleId?: string | null;
    assetId?: string | null;
  },
) {
  const { since, until } = rangeBounds(query.range);
  return apiRequest(session, zAlertListResponse, {
    method: "GET",
    path: "/api/v1/alerts",
    route: "/api/v1/alerts",
    query: {
      since,
      until,
      severity: query.severity && query.severity.length > 0 ? query.severity : undefined,
      status: query.status && query.status.length > 0 ? query.status : undefined,
      rule_id: query.ruleId && isRuleId(query.ruleId) ? query.ruleId : undefined,
      asset_id: query.assetId && isAssetId(query.assetId) ? query.assetId : undefined,
      sort: "last_seen",
      limit: ALERTS_PER_REQUEST,
      offset: query.offset && query.offset > 0 ? query.offset : undefined,
    },
  });
}

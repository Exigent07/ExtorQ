import "server-only";

import { cache } from "react";

import { zAlertListResponse } from "@/lib/api/schemas";
import type { Session } from "@/lib/auth/token";
import { assetTypeLabel } from "@/lib/format";
import type { PaletteData } from "@/lib/palette";
import { sanitizeForDisplay, truncateText } from "@/lib/security/display";
import { assetHref, investigationHref } from "@/lib/security/ids";

import { listAssets } from "./api";
import { apiRequest } from "./api-client";

/**
 * Data for the console shell (command palette). Fetched on the server through the API
 * client like every other block; the client component receives plain, already sanitised
 * lists as props and never calls the API.
 *
 * Both reads are memoised per request (React `cache`, keyed by the per-request session
 * object), so a page that needs the asset list as well (the Overview) shares one API call
 * with the shell on a full page load.
 */

export const PALETTE_ALERT_LIMIT = 40;
export const PALETTE_ALERT_WINDOW_DAYS = 30;
const LABEL_LIMIT = 80;

/** The asset list (at most 200), once per request. */
export const listAssetsOnce = cache((session: Session) => listAssets(session));

/** The newest alerts of the last 30 days by last activity, once per request. */
export const listRecentAlertsOnce = cache((session: Session) => {
  const until = new Date();
  const since = new Date(until.getTime() - PALETTE_ALERT_WINDOW_DAYS * 86_400_000);
  return apiRequest(session, zAlertListResponse, {
    method: "GET",
    path: "/api/v1/alerts",
    route: "/api/v1/alerts",
    query: {
      limit: PALETTE_ALERT_LIMIT,
      since: since.toISOString(),
      until: until.toISOString(),
      sort: "last_seen",
    },
  });
});

function displayLabel(value: string): string {
  return truncateText(sanitizeForDisplay(value).text, LABEL_LIMIT).text;
}

export async function getPaletteData(session: Session): Promise<PaletteData> {
  const [assets, alerts] = await Promise.all([listAssetsOnce(session), listRecentAlertsOnce(session)]);
  return {
    assets: assets.ok
      ? assets.data.items.map((asset) => ({
          id: asset.asset_id,
          href: assetHref(asset.asset_id),
          label: displayLabel(asset.display_name ?? asset.name),
          typeLabel: assetTypeLabel(asset.asset_type),
          coverage: asset.coverage_status,
        }))
      : null,
    alerts: alerts.ok
      ? alerts.data.items.flatMap((alert) => {
          const href = investigationHref(alert.alert_id);
          if (!href) return [];
          return [
            {
              id: alert.alert_id,
              href,
              ruleId: alert.rule_id,
              title: displayLabel(alert.rule_title),
              severity: alert.severity,
              assetId: alert.asset_id,
              lastSeen: alert.last_seen,
              status: alert.analyst_status,
            },
          ];
        })
      : null,
  };
}

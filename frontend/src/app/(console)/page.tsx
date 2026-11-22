import { ArrowRight } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { PageHeader } from "@/components/console/page-header";
import { ErrorState } from "@/components/console/states";
import { Button } from "@/components/ui/button";
import { AlertActivityCard } from "@/components/views/overview/alert-activity";
import { AssetCoverageCard } from "@/components/views/overview/asset-coverage";
import { CollectionHealthCard } from "@/components/views/overview/collection-health";
import { FindingsBySeverityCard } from "@/components/views/overview/findings-severity";
import { KpiRow } from "@/components/views/overview/kpi-row";
import { RecentAlertsCard } from "@/components/views/overview/recent-alerts";
import { ServiceCoverageCard } from "@/components/views/overview/service-coverage";
import {
  activitySeries,
  alertKpi,
  assetKpi,
  classRows,
  collectionKpi,
  findingsKpi,
  importantAlerts,
  otherClasses,
  overviewFinding,
} from "@/lib/overview";
import { bucketSecondsFor, getOverview, getTimeseries } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";
import { listAssetsOnce } from "@/lib/server/shell";

export const metadata: Metadata = { title: "Overview" };

const WEEK_SECONDS = 7 * 86400;

/**
 * Overview: what needs attention now (open alerts, the alert trend, the most important recent
 * alerts) and whether the telemetry behind it can be trusted (coverage per asset class,
 * service coverage, collection health), plus posture findings. Three API reads in parallel:
 * the overview, the asset list (shared with the shell's palette on a full load) and the
 * 7-day alert series for the range toggle.
 */
export default async function OverviewPage() {
  const session = await requireSession();
  const until = new Date();
  const since = new Date(until.getTime() - WEEK_SECONDS * 1000);
  const [result, assets, week] = await Promise.all([
    getOverview(session),
    listAssetsOnce(session),
    getTimeseries(session, "alerts", {
      since: since.toISOString(),
      until: until.toISOString(),
      groupBy: "severity",
      bucketSeconds: bucketSecondsFor(WEEK_SECONDS),
    }),
  ]);

  if (!result.ok) {
    return (
      <>
        <PageHeader title="Overview" subtitle="Coverage, detections and posture across the lab" />
        <ErrorState what="the overview" error={result.error} />
      </>
    );
  }

  const data = result.data;
  const now = data.generated_at;
  const classes = classRows(data.asset_coverage, assets.ok ? assets.data.items : null);

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={overviewFinding(data)}
        freshness={result.receivedAt}
        actions={
          <Button asChild size="lg" className="h-9 px-3.5">
            <Link href="/detections">
              Review alerts
              <ArrowRight data-icon="inline-end" aria-hidden="true" />
            </Link>
          </Button>
        }
      />

      <div className="grid gap-6">
        <KpiRow
          alerts={alertKpi(data.open_alerts)}
          assets={assetKpi(classes)}
          classes={classes}
          findings={findingsKpi(data.open_findings)}
          collection={collectionKpi(data.collection_health)}
          health={data.collection_health}
        />

        <div className="grid gap-6 xl:grid-cols-12">
          <AlertActivityCard
            day={activitySeries(data.alerts_over_time)}
            week={week.ok ? activitySeries(week.data) : null}
            className="xl:col-span-8"
          />
          <AssetCoverageCard
            rows={classes}
            others={otherClasses(data.asset_coverage)}
            now={now}
            assetsUnavailable={!assets.ok}
            retiredHidden={data.lifecycle && !data.lifecycle.include_retired ? data.lifecycle.retired : 0}
            className="xl:col-span-4"
          />
        </div>

        <div className="grid gap-6 xl:grid-cols-12">
          <RecentAlertsCard
            alerts={importantAlerts(data.recent_important_alerts, 5)}
            openTotal={data.open_alerts.total}
            now={now}
            className="xl:col-span-8"
          />
          <CollectionHealthCard summary={data.collection_health} className="xl:col-span-4" />
        </div>

        <div className="grid gap-6 xl:grid-cols-12">
          <ServiceCoverageCard summary={data.service_coverage} className="xl:col-span-8" />
          <FindingsBySeverityCard summary={data.open_findings} className="xl:col-span-4" />
        </div>
      </div>
    </>
  );
}

import type { Metadata } from "next";

import { Freshness } from "@/components/console/freshness";
import { MetricStrip } from "@/components/console/key-values";
import { PageHeader } from "@/components/console/page-header";
import { Panel } from "@/components/console/panel";
import { EmptyState, ErrorState } from "@/components/console/states";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { AlertRows } from "@/components/views/alerts/alert-rows";
import { EventsTable } from "@/components/views/events/events-table";
import { FindingsTable } from "@/components/views/findings/findings-table";
import { LifecycleNotice } from "@/components/views/overview/posture-panel";
import { RemovedTag, ReportStaleTag, ServiceCoveragePill } from "@/components/views/services/service-badges";
import {
  AuthActivityPanel,
  CoveragePanel,
  EndpointsPanel,
  InstancesPanel,
  TelemetryPanel,
} from "@/components/views/services/service-sections";
import type { ServiceDetailResponse } from "@/lib/api/schemas";
import { formatCount, formatRelative, formatUtcShort, isClosedStatus } from "@/lib/format";
import { assetHref, parseHexIdSegment } from "@/lib/security/ids";
import { getService } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";
import { categoryLabel, serviceCoverage, serviceKindLabel } from "@/lib/services";

export const metadata: Metadata = { title: "Service" };

/**
 * Latest service telemetry: the discovery record's own timestamp or the newest attributed
 * event per source, whichever is later (either may be missing).
 */
function lastTelemetry(data: ServiceDetailResponse): string | null {
  const times = [data.service.last_telemetry_at, ...data.telemetry.map((t) => t.last_event_at)].filter(
    (t): t is string => typeof t === "string" && !Number.isNaN(Date.parse(t)),
  );
  if (times.length === 0) return null;
  return times.reduce((a, b) => (Date.parse(a) >= Date.parse(b) ? a : b));
}

function finding(data: ServiceDetailResponse, now: string): string {
  const s = data.service;
  const parts = [serviceCoverage(s).label];
  const last = lastTelemetry(data);
  parts.push(last ? `last service telemetry ${formatRelative(last, now)}` : "no service telemetry in the window");
  if (data.auth_activity.total > 0) {
    const failed = (data.auth_activity.by_outcome.failure ?? 0) + (data.auth_activity.by_outcome.denied ?? 0);
    parts.push(`${formatCount(failed)} failed or denied authentications from ${formatCount(data.auth_activity.distinct_sources)} sources`);
  }
  const open = data.alerts.filter((a) => !isClosedStatus(a.analyst_status)).length;
  parts.push(`${formatCount(open)} open alert${open === 1 ? "" : "s"}`);
  parts.push(`${formatCount(data.findings_total)} finding${data.findings_total === 1 ? "" : "s"}`);
  return parts.join(" · ");
}

export default async function ServicePage({ params }: PageProps<"/services/[serviceId]">) {
  const session = await requireSession();
  const { serviceId: rawId } = await params;
  const serviceId = parseHexIdSegment(rawId);
  const crumbs = [{ label: "Assets", href: "/assets" }];

  if (!serviceId) {
    return (
      <>
        <PageHeader title="Service" crumbs={crumbs} />
        <ErrorState what="this service" error={{ kind: "not_found", message: "The service id in the address is not valid.", requestId: "-" }} />
      </>
    );
  }

  const result = await getService(session, serviceId);
  if (!result.ok) {
    const routeMissing = result.error.status === 404 && result.error.detail === "Not Found";
    return (
      <>
        <PageHeader title="Service" crumbs={crumbs} />
        {routeMissing ? (
          <EmptyState>
            The analyst API on this deployment does not provide service details yet (
            <span className="font-mono">GET /api/v1/services/&#123;id&#125;</span> answered 404).
          </EmptyState>
        ) : (
          <ErrorState what="this service" error={result.error} />
        )}
      </>
    );
  }

  const data = result.data;
  const s = data.service;
  const now = result.receivedAt;
  const assetName = data.asset ? (data.asset.display_name ?? data.asset.name) : s.asset_id;
  const openAlerts = data.alerts.filter((a) => !isClosedStatus(a.analyst_status)).length;
  const serviceNames = { [s.service_id]: s.name };
  const servicesTab = `${assetHref(s.asset_id)}?tab=services`;

  return (
    <>
      <PageHeader
        title={<UntrustedText value={s.name} limit={80} />}
        crumbs={[...crumbs, { label: assetName, href: assetHref(s.asset_id) }, { label: "Services", href: servicesTab }]}
        titleMeta={
          <span className="flex flex-wrap items-center gap-3 text-sm text-muted-foreground">
            {serviceKindLabel(s.service_kind)} · {categoryLabel(s.category)}
            <ServiceCoveragePill service={s} />
            {!s.present ? <RemovedTag /> : null}
            {s.present && s.report_stale ? <ReportStaleTag ageSeconds={s.report_age_seconds} /> : null}
          </span>
        }
        finding={finding(data, now)}
        actions={<Freshness at={result.receivedAt} />}
      />

      <MetricStrip
        className="mb-6"
        items={[
          {
            label: "Instances",
            value: <span className="font-mono">{formatCount(data.instances_total)}</span>,
            sub: s.service_kind === "k8s_service" ? "logical object, no instances" : "currently observed",
          },
          {
            label: "Ports",
            value: <span className="font-mono">{formatCount(s.endpoints.length)}</span>,
            sub: `${formatCount(s.endpoints.filter((e) => e.attribution === "confirmed").length)} with confirmed owner`,
          },
          {
            label: "Last telemetry",
            value: <RelativeTime value={lastTelemetry(data)} now={now} className="text-lg" />,
            sub: "newest attributed event or discovery report",
          },
          {
            label: "Alerts",
            value: <span className="font-mono">{formatCount(data.alerts_total)}</span>,
            sub: `${formatCount(openAlerts)} open in the list below`,
          },
          {
            label: "Findings",
            value: <span className="font-mono">{formatCount(data.findings_total)}</span>,
            sub: data.findings_lifecycle_available ? "lifecycle available" : "lifecycle unavailable",
          },
        ]}
      />

      <div className="grid gap-6">
        <div className="grid items-start gap-6 xl:grid-cols-2">
          <CoveragePanel service={s} />
          <div className="grid gap-6">
            <TelemetryPanel service={s} telemetry={data.telemetry} range={data.telemetry_range} now={now} />
            <EndpointsPanel service={s} />
          </div>
        </div>

        <div className="grid items-start gap-6 xl:grid-cols-2">
          <InstancesPanel service={s} instances={data.instances} total={data.instances_total} now={now} />
          <AuthActivityPanel auth={data.auth_activity} now={now} />
        </div>

        <Panel
          title="Alerts"
          titleId="service-alerts-title"
          meta={
            <span>
              Evidence from this service · {formatUtcShort(data.alerts_range.since)} to {formatUtcShort(data.alerts_range.until)} UTC
            </span>
          }
        >
          {data.alerts.length === 0 ? (
            <EmptyState>No detection alert in this window lists this service as an evidence source.</EmptyState>
          ) : (
            <>
              <AlertRows alerts={data.alerts} now={now} showAsset={false} />
              {data.alerts_total > data.alerts.length ? (
                <p className="mt-2 text-xs text-muted-foreground">
                  Showing {formatCount(data.alerts.length)} of {formatCount(data.alerts_total)} alerts.
                </p>
              ) : null}
            </>
          )}
        </Panel>

        <Panel title="Findings" titleId="service-findings-title" meta={<span>Attributed to this service</span>}>
          <LifecycleNotice summary={{ lifecycle_available: data.findings_lifecycle_available, note: null }} />
          <div className={data.findings_lifecycle_available ? undefined : "mt-3"}>
            {data.findings.length === 0 ? (
              <EmptyState>No finding is attributed to this service. Findings on the whole asset are listed on the asset page.</EmptyState>
            ) : (
              <FindingsTable findings={data.findings} now={now} serviceNames={serviceNames} />
            )}
          </div>
          {data.findings_total > data.findings.length ? (
            <p className="mt-2 text-xs text-muted-foreground">
              Showing {formatCount(data.findings.length)} of {formatCount(data.findings_total)} findings.
            </p>
          ) : null}
        </Panel>

        <Panel title="Recent events" titleId="service-events-title" meta={<span>Events the adapter attributed to this service</span>}>
          {data.recent_events.length === 0 ? (
            <EmptyState>No event attributed to this service was stored in the telemetry window.</EmptyState>
          ) : (
            <EventsTable events={data.recent_events} showService={false} />
          )}
        </Panel>

        {data.notes.length > 0 ? (
          <Panel title="Notes from the API" titleId="service-notes-title">
            <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-ink-2">
              {data.notes.map((note) => (
                <li key={note}>
                  <UntrustedText value={note} limit={300} />
                </li>
              ))}
            </ul>
          </Panel>
        ) : null}
      </div>
    </>
  );
}

import type { Metadata } from "next";

import { PageHeader } from "@/components/console/page-header";
import { PageCrumbs } from "@/components/console/route-breadcrumbs";
import { EmptyState, ErrorState } from "@/components/console/states";
import { serviceFinding } from "@/components/views/services/model";
import { RemovedTag } from "@/components/views/services/service-badges";
import { ServiceHeaderCard, ServiceTitle } from "@/components/views/services/service-header";
import {
  AlertsPanel,
  AttributesPanel,
  EndpointsPanel,
  EventsPanel,
  FindingsPanel,
  InstancesPanel,
  TelemetryPanel,
} from "@/components/views/services/service-panels";
import { ServiceTabs } from "@/components/views/services/service-tabs";
import { crumbLabel } from "@/lib/navigation";
import { assetHref, isAssetId, parseHexIdSegment } from "@/lib/security/ids";
import { getService } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";
import { serviceKindLabel } from "@/lib/services";

export const metadata: Metadata = { title: "Service" };

/**
 * Service drill-down: where the service runs, how it was discovered and how well it is
 * covered (header card), then its telemetry sources with freshness, instances, ports and
 * exposure, findings, alerts (to the investigations), events and attributes. One API read;
 * the tabs switch on the client without further calls.
 */
export default async function ServicePage({ params, searchParams }: PageProps<"/services/[serviceId]">) {
  const session = await requireSession();
  const [{ serviceId: rawId }, query] = await Promise.all([params, searchParams]);
  const serviceId = parseHexIdSegment(rawId);
  const tab = typeof query.tab === "string" ? query.tab : "";

  if (!serviceId) {
    return (
      <>
        <PageHeader title="Service" />
        <ErrorState
          what="this service"
          error={{ kind: "not_found", message: "The service id in the address is not valid.", requestId: "-" }}
        />
      </>
    );
  }

  const result = await getService(session, serviceId);
  if (!result.ok) {
    const routeMissing = result.error.status === 404 && result.error.detail === "Not Found";
    return (
      <>
        <PageHeader title="Service" />
        {routeMissing ? (
          <EmptyState compact={false}>
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

  return (
    <>
      <PageCrumbs
        crumbs={[
          ...(isAssetId(s.asset_id) ? [{ label: crumbLabel(s.asset_id), href: assetHref(s.asset_id), mono: true }] : []),
          { label: crumbLabel(s.name) },
        ]}
      />
      <PageHeader
        title={<ServiceTitle kind={s.service_kind} name={s.name} />}
        titleMeta={
          <span className="flex flex-wrap items-center gap-2">
            <span className="inline-flex h-5 items-center rounded-md px-1.5 text-xs font-medium text-fg-2 ring-1 ring-hairline-strong ring-inset">
              {serviceKindLabel(s.service_kind)}
            </span>
            {!s.present ? <RemovedTag /> : null}
          </span>
        }
        subtitle={serviceFinding(data, now)}
        freshness={result.receivedAt}
      />

      <ServiceHeaderCard data={data} now={now} />

      <ServiceTabs
        label="Service views"
        initial={tab}
        tabs={[
          { key: "telemetry", label: "Telemetry", count: data.telemetry.length, content: <TelemetryPanel data={data} now={now} /> },
          { key: "instances", label: "Instances", count: data.instances_total, content: <InstancesPanel data={data} now={now} /> },
          { key: "endpoints", label: "Ports and exposure", count: s.endpoints.length, content: <EndpointsPanel service={s} /> },
          { key: "findings", label: "Findings", count: data.findings_total, content: <FindingsPanel data={data} now={now} /> },
          { key: "alerts", label: "Alerts", count: data.alerts_total, content: <AlertsPanel data={data} now={now} /> },
          { key: "events", label: "Events", count: data.recent_events.length, content: <EventsPanel data={data} now={now} /> },
          { key: "attributes", label: "Attributes", content: <AttributesPanel data={data} /> },
        ]}
      />
    </>
  );
}

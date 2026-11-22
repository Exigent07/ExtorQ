import { cn } from "cn";
import { Box, FileWarning, Info, KeyRound, Plug, Radio, ScrollText, ShieldAlert, Tags } from "lucide-react";

import { Hint } from "@/components/console/hint";
import { KeyValueList } from "@/components/console/key-values";
import { SplitBar } from "@/components/console/kpi-card";
import { SectionCard } from "@/components/console/section-card";
import { EmptyState, Notice } from "@/components/console/states";
import { HealthBadge, StatusPill } from "@/components/console/status-badge";
import { RelativeTime } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ServiceDetailResponse, ServiceRecord } from "@/lib/api/schemas";
import { DASH, formatCount, formatUtcShort, humanize, keyLabel } from "@/lib/format";
import { attributionOf, exposureOf } from "@/lib/services";

import { AlertList } from "../assets/alert-list";
import { LifecycleUnavailable } from "../assets/asset-findings";
import { EventsDataTable } from "../assets/events-data-table";
import { FindingsDataTable } from "../assets/findings-data-table";
import { windowLabel } from "../assets/model";
import { FreshnessMeter } from "../assets/telemetry-sources";
import { InstancesDataTable } from "./instances-data-table";
import { instanceHeadline, instanceRows, staleSentence, staleSummary } from "./model";

const COLLECTION: Record<string, { label: string; tone: "ok" | "warn" | "off"; detail: string }> = {
  fresh: { label: "Fresh", tone: "ok", detail: "At least one collector reporting this source is fresh." },
  stale: { label: "Stale", tone: "warn", detail: "Every collector reporting this source is stale." },
  no_collector_health: {
    label: "No collector health",
    tone: "off",
    detail: "No collector health record mentions this source for the asset; its freshness is unknown.",
  },
};

/** Service categories where an empty authentication card is still informative. */
const AUTH_CATEGORIES = new Set(["ssh", "web_application", "http_server", "ftp", "database"]);

function secondsSince(iso: string | null | undefined, now: string): number | null {
  if (!iso) return null;
  const delta = (Date.parse(now) - Date.parse(iso)) / 1000;
  return Number.isFinite(delta) ? Math.max(0, delta) : null;
}

/** Telemetry sources of the service with collection freshness, then its authentication activity. */
export function TelemetryPanel({ data, now }: { data: ServiceDetailResponse; now: string }) {
  const s = data.service;
  const auth = data.auth_activity;
  const failed = (auth.by_outcome.failure ?? 0) + (auth.by_outcome.denied ?? 0);
  const success = auth.by_outcome.success ?? 0;
  const other = Math.max(0, auth.total - failed - success);
  return (
    <div className="grid gap-6">
      <SectionCard
        title="Telemetry sources"
        titleId="telemetry-title"
        icon={Radio}
        description={
          <>
            Sources of this service and how fresh their collection is · events {windowLabel(data.telemetry_range, now)} (since{" "}
            {formatUtcShort(data.telemetry_range.since)} UTC)
          </>
        }
        flush
      >
        {data.telemetry.length === 0 ? (
          <div className="px-5 pb-3">
            <EmptyState>
              {s.adapter_support === "implemented"
                ? "No telemetry source is declared for this service, and no stored event is attributed to it."
                : "No service-specific telemetry is collected: there is no implemented adapter for this service."}
            </EmptyState>
          </div>
        ) : (
          <Table aria-label="Telemetry sources of the service">
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Collection</TableHead>
                <TableHead className="hidden md:table-cell">Collectors and freshness</TableHead>
                <TableHead className="text-right">Events</TableHead>
                <TableHead className="hidden text-right sm:table-cell">Last event</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.telemetry.map((t) => {
                const collection = COLLECTION[t.collection];
                return (
                  <TableRow key={t.source_type} className="align-top">
                    <TableCell className="py-3">
                      <div className="font-mono text-xs text-foreground">
                        <UntrustedText value={t.source_type} plain limit={48} />
                      </div>
                      <div className="mt-1 text-xs text-muted-foreground">
                        {t.declared ? "Declared by the adapter" : "Seen in attributed events only"}
                      </div>
                    </TableCell>
                    <TableCell className="py-3">
                      {collection ? (
                        <Hint content={collection.detail}>
                          <StatusPill tone={collection.tone} label={collection.label} />
                        </Hint>
                      ) : (
                        <span className="text-xs text-fg-2">
                          <UntrustedText value={t.collection} plain limit={32} />
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="hidden py-3 md:table-cell">
                      {t.collectors.length === 0 ? (
                        <span className="text-xs text-muted-foreground">No collector reports this source</span>
                      ) : (
                        <ul className="grid gap-2">
                          {t.collectors.map((c) => (
                            <li key={`${c.collector_id}|${c.asset_id}`} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                              <span className="max-w-56 min-w-0 font-mono text-xs text-fg-2">
                                <UntrustedText value={c.collector_id} oneLine mono />
                              </span>
                              <HealthBadge status={c.status} className="text-xs" />
                              <FreshnessMeter
                                collector={{ ...c, seconds_since_success: secondsSince(c.last_success_at, now) }}
                                now={now}
                              />
                            </li>
                          ))}
                        </ul>
                      )}
                    </TableCell>
                    <TableCell className="py-3 text-right">
                      <span className={cn("text-sm tabular-nums", t.events > 0 ? "font-medium text-foreground" : "text-muted-foreground")}>
                        {formatCount(t.events)}
                      </span>
                    </TableCell>
                    <TableCell className="hidden py-3 text-right sm:table-cell">
                      <RelativeTime value={t.last_event_at} now={now} className="text-xs" />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </SectionCard>

      {auth.total > 0 || AUTH_CATEGORIES.has(s.category) ? (
      <SectionCard
        title="Authentication activity"
        titleId="auth-title"
        icon={KeyRound}
        description={`Authentication events attributed to this service, ${windowLabel(auth.range, now)} (since ${formatUtcShort(auth.range.since)} UTC)`}
        flush={auth.top_sources.length > 0}
      >
        {auth.total === 0 ? (
          <EmptyState>No authentication event is attributed to this service in this window.</EmptyState>
        ) : (
          <div className="grid gap-4">
            <dl className={cn("grid grid-cols-2 gap-4 sm:grid-cols-4", auth.top_sources.length > 0 && "px-5")}>
              {[
                { label: "Events", value: auth.total, warn: false },
                { label: "Failed or denied", value: failed, warn: failed > 0 },
                { label: "Distinct actors", value: auth.distinct_actors, warn: false },
                { label: "Distinct sources", value: auth.distinct_sources, warn: false },
              ].map((f) => (
                <div key={f.label}>
                  <dt className="text-xs text-muted-foreground">{f.label}</dt>
                  <dd className={cn("mt-1 text-xl leading-7 font-semibold tracking-tight tabular-nums", f.warn ? "text-health-warn" : "text-foreground")}>
                    {formatCount(f.value)}
                  </dd>
                </div>
              ))}
            </dl>
            <div className={cn("grid gap-1.5", auth.top_sources.length > 0 && "px-5")}>
              <SplitBar
                className="h-2"
                label={`Outcomes: ${success} success, ${failed} failed or denied, ${other} other`}
                parts={[
                  { key: "success", value: success, className: "bg-fg-2" },
                  { key: "failed", value: failed, className: "bg-health-warn" },
                  { key: "other", value: other, className: "bg-health-off" },
                ]}
              />
              <p className="text-xs text-muted-foreground">
                By outcome:{" "}
                {Object.entries(auth.by_outcome)
                  .sort((a, b) => b[1] - a[1])
                  .map(([outcome, count]) => `${humanize(outcome)} ${formatCount(count)}`)
                  .join(" · ")}
              </p>
            </div>
            {auth.top_sources.length > 0 ? (
              <Table aria-label="Top authentication sources">
                <TableHeader>
                  <TableRow>
                    <TableHead>Source address</TableHead>
                    <TableHead className="text-right">Events</TableHead>
                    <TableHead className="text-right">Failures</TableHead>
                    <TableHead className="text-right">Last seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {auth.top_sources.map((src) => (
                    <TableRow key={src.src_ip}>
                      <TableCell className="font-mono text-xs text-foreground">
                        <UntrustedText value={src.src_ip} plain limit={48} />
                      </TableCell>
                      <TableCell className="text-right text-sm text-fg-2 tabular-nums">{formatCount(src.events)}</TableCell>
                      <TableCell className={cn("text-right text-sm tabular-nums", src.failures > 0 ? "text-health-warn" : "text-muted-foreground")}>
                        {formatCount(src.failures)}
                      </TableCell>
                      <TableCell className="text-right">
                        <RelativeTime value={src.last_seen} now={now} className="text-xs" />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : null}
          </div>
        )}
      </SectionCard>
      ) : null}
    </div>
  );
}

/** Processes, Pods and containers of the service; staleness stated once above the table. */
export function InstancesPanel({ data, now }: { data: ServiceDetailResponse; now: string }) {
  const s = data.service;
  const kubernetes = s.service_kind === "k8s_workload" || s.service_kind === "k8s_service";
  const rows = instanceRows(data.instances).map((r) => ({ id: r.instance.instance_id, instance: r.instance, children: r.children }));
  const headline = instanceHeadline(data.instances, data.instances_total);
  const stale = staleSentence(staleSummary(data.instances), now);
  return (
    <SectionCard
      title="Instances"
      titleId="instances-title"
      icon={Box}
      description={
        kubernetes
          ? "Pods of the workload with their containers, node, Pod UID and container id"
          : "Processes of the service as discovery last reported them"
      }
      meta={
        data.instances.length > 0 ? (
          <span className="tabular-nums">
            {headline.capped
              ? `${formatCount(data.instances.length)} of ${formatCount(data.instances_total)} listed`
              : `${formatCount(headline.value)} ${headline.label === "Pods" ? (headline.value === 1 ? "Pod" : "Pods") : "current"}${headline.sub ? ` · ${headline.sub}` : ""}`}
          </span>
        ) : null
      }
      flush
    >
      {data.instances.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>
            {s.service_kind === "k8s_service"
              ? "A Kubernetes Service is a logical object (virtual IP and ports); it has no process or container of its own. Its backing Pods belong to workloads."
              : "No instance of this service is currently reported."}
          </EmptyState>
        </div>
      ) : (
        <>
          {stale || data.instances_total > data.instances.length ? (
            <div className="grid gap-2 px-5 pb-3">
              {stale ? (
                <Notice tone="warn" icon={Info}>
                  {stale}
                </Notice>
              ) : null}
              {data.instances_total > data.instances.length ? (
                <Notice icon={Info}>
                  Showing {formatCount(data.instances.length)} of {formatCount(data.instances_total)} instances (the API returns a
                  bounded list).
                </Notice>
              ) : null}
            </div>
          ) : null}
          <InstancesDataTable rows={rows} now={now} kubernetes={kubernetes} label="Instances of this service" />
        </>
      )}
    </SectionCard>
  );
}

/** Listening endpoints with exposure and how confidently each port is attributed. */
export function EndpointsPanel({ service }: { service: ServiceRecord }) {
  const exposedAny = service.endpoints.filter((e) => e.exposure === "any").length;
  return (
    <SectionCard
      title="Ports and exposure"
      titleId="endpoints-title"
      icon={Plug}
      description="A port is attributed to a service only with evidence; an unknown owner is stated, never assumed"
      meta={service.endpoints.length > 0 ? <span className="tabular-nums">{formatCount(exposedAny)} on all interfaces</span> : null}
      flush
    >
      {service.endpoints.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No listening port is attributed to this service. A process is never assumed to be a network service.</EmptyState>
        </div>
      ) : (
        <Table aria-label="Listening endpoints of the service">
          <TableHeader>
            <TableRow>
              <TableHead>Endpoint</TableHead>
              <TableHead>Exposure</TableHead>
              <TableHead>Port owner</TableHead>
              <TableHead className="hidden md:table-cell">Basis</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {service.endpoints.map((e, i) => {
              const exposure = exposureOf(e.exposure);
              const attribution = attributionOf(e.attribution);
              return (
                <TableRow key={`${e.protocol}-${e.address ?? "*"}-${e.port}-${i}`}>
                  <TableCell className="font-mono text-xs text-foreground">
                    {e.address ? (
                      <>
                        {e.address.includes(":") ? "[" : null}
                        <UntrustedText value={e.address} plain limit={48} />
                        {e.address.includes(":") ? "]" : null}
                      </>
                    ) : (
                      <span className="text-muted-foreground">*</span>
                    )}
                    {`:${e.port}/${e.protocol}`}
                  </TableCell>
                  <TableCell>
                    <Hint content={exposure.detail}>
                      <StatusPill tone={exposure.tone === "warn" ? "warn" : "off"} label={exposure.label} />
                    </Hint>
                  </TableCell>
                  <TableCell>
                    <Hint content={attribution.detail}>
                      <span className={cn("text-xs whitespace-nowrap", e.attribution === "confirmed" ? "text-fg-2" : "text-muted-foreground")}>
                        {attribution.label}
                      </span>
                    </Hint>
                  </TableCell>
                  <TableCell className="hidden max-w-0 w-1/2 md:table-cell">
                    {e.attribution_basis ? (
                      <span className="block min-w-0 text-xs text-muted-foreground">
                        <UntrustedText value={e.attribution_basis} oneLine />
                      </span>
                    ) : (
                      <span className="text-muted-foreground">{DASH}</span>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
      {service.invalid_endpoints > 0 ? (
        <div className="px-5 pt-2 pb-3">
          <Notice tone="warn" icon={Info}>
            {formatCount(service.invalid_endpoints)} stored endpoint entr{service.invalid_endpoints === 1 ? "y" : "ies"} failed validation
            and {service.invalid_endpoints === 1 ? "is" : "are"} not shown.
          </Notice>
        </div>
      ) : null}
    </SectionCard>
  );
}

/** Findings attributed to the service. */
export function FindingsPanel({ data, now }: { data: ServiceDetailResponse; now: string }) {
  const s = data.service;
  return (
    <SectionCard
      title="Findings"
      titleId="service-findings-title"
      icon={FileWarning}
      description="Vulnerabilities and misconfigurations attributed to this service; findings of the whole asset are on the asset page"
      flush
    >
      {!data.findings_lifecycle_available || data.findings_total > data.findings.length ? (
        <div className="grid gap-2 px-5 pb-3">
          {!data.findings_lifecycle_available ? <LifecycleUnavailable /> : null}
          {data.findings_total > data.findings.length ? (
            <Notice icon={Info}>
              Showing {formatCount(data.findings.length)} of {formatCount(data.findings_total)} findings; filters apply to these rows.
            </Notice>
          ) : null}
        </div>
      ) : null}
      {data.findings.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No finding is attributed to this service.</EmptyState>
        </div>
      ) : (
        <FindingsDataTable findings={data.findings} now={now} serviceNames={{ [s.service_id]: s.name }} label="Findings of this service" />
      )}
    </SectionCard>
  );
}

/** Alerts whose evidence includes this service, linking to their investigations. */
export function AlertsPanel({ data, now }: { data: ServiceDetailResponse; now: string }) {
  return (
    <SectionCard
      title="Alerts"
      titleId="service-alerts-title"
      icon={ShieldAlert}
      description={`Detections with evidence from this service, ${formatUtcShort(data.alerts_range.since)} to ${formatUtcShort(data.alerts_range.until)} UTC`}
      flush
      footer={
        data.alerts_total > data.alerts.length ? (
          <span>
            Showing {formatCount(data.alerts.length)} of {formatCount(data.alerts_total)} alerts.
          </span>
        ) : undefined
      }
    >
      {data.alerts.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No detection alert in this window lists this service as an evidence source.</EmptyState>
        </div>
      ) : (
        <AlertList alerts={data.alerts} now={now} label="Alerts with evidence from this service" />
      )}
    </SectionCard>
  );
}

/** The API returns at most this many recent events per service (`RECENT_EVENTS_LIMIT`). */
export const SERVICE_EVENTS_LIMIT = 50;

/** Events the adapter attributed to the service. */
export function EventsPanel({ data, now }: { data: ServiceDetailResponse; now: string }) {
  const capped = data.recent_events.length >= SERVICE_EVENTS_LIMIT;
  return (
    <SectionCard
      title="Recent events"
      titleId="service-events-title"
      icon={ScrollText}
      description={`Events the adapter attributed to this service, ${windowLabel(data.telemetry_range, now)}`}
      meta={capped ? <span>Newest {formatCount(data.recent_events.length)} shown</span> : undefined}
      flush
    >
      {capped ? (
        <div className="px-5 pb-3">
          <Notice icon={Info}>
            The API returns the newest {formatCount(SERVICE_EVENTS_LIMIT)} events of a service; older events of the window are on the
            asset&apos;s Events tab.
          </Notice>
        </div>
      ) : null}
      {data.recent_events.length === 0 ? (
        <div className="px-5 pb-3">
          <EmptyState>No event attributed to this service was stored in the telemetry window.</EmptyState>
        </div>
      ) : (
        <EventsDataTable events={data.recent_events} showService={false} label="Recent events of this service" />
      )}
    </SectionCard>
  );
}

function attributeText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) return value.map((v) => (typeof v === "string" ? v : JSON.stringify(v))).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/** Attributes the collector reported for the service, plus the API's notes. */
export function AttributesPanel({ data }: { data: ServiceDetailResponse }) {
  const entries = Object.entries(data.service.attributes ?? {});
  return (
    <div className="grid gap-6">
      <SectionCard title="Attributes" titleId="service-attributes-title" icon={Tags} description="As reported by the collector">
        {entries.length === 0 ? (
          <EmptyState>The collector reported no attributes for this service.</EmptyState>
        ) : (
          <KeyValueList
            rows={entries.map(([key, value]) => {
              const text = attributeText(value);
                            return {
                label: keyLabel(key),
                value: text === "" ? <span className="text-muted-foreground">{DASH}</span> : <UntrustedText value={text} limit={240} mono={typeof value !== "string"} />,
              };
            })}
          />
        )}
      </SectionCard>
      {data.notes.length > 0 ? (
        <SectionCard title="Notes from the API" titleId="service-notes-title" icon={Info}>
          <ul className="grid list-disc gap-1 pl-5 text-sm text-fg-2">
            {data.notes.map((note) => (
              <li key={note}>
                <UntrustedText value={note} limit={300} />
              </li>
            ))}
          </ul>
        </SectionCard>
      ) : null}
    </div>
  );
}

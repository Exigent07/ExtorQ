import { KeyValueList } from "@/components/console/key-values";
import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import { HealthStatusDot, StaleBadge, StatusPill } from "@/components/console/status-badge";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ServiceAuthActivity, ServiceInstance, ServiceRecord, ServiceTelemetrySource } from "@/lib/api/schemas";
import { DASH, formatCount, formatUtcShort, humanize } from "@/lib/format";
import { discoveryLabel, INSTANCE_KIND_LABEL, serviceCoverage } from "@/lib/services";

import { EndpointLine } from "./service-badges";

/** What ExtorQ can and does collect for this service, and why. */
export function CoveragePanel({ service }: { service: ServiceRecord }) {
  const badge = serviceCoverage(service);
  return (
    <Panel title="Coverage" titleId="coverage-title">
      <p className="mb-3 text-sm text-ink-2">{badge.detail}</p>
      <KeyValueList
        rows={[
          { label: "Adapter", value: service.adapter_id ? <UntrustedText value={service.adapter_id} limit={48} mono /> : "none" },
          { label: "Adapter support", value: <UntrustedText value={service.adapter_support} limit={32} /> },
          {
            label: "Reported monitoring status",
            value: <UntrustedText value={service.monitoring_status} limit={32} />,
          },
          ...(service.coverage_note
            ? [{ label: "Collector note", value: <UntrustedText value={service.coverage_note} limit={200} /> }]
            : []),
          {
            label: "Discovered via",
            value: service.discovered_via.length ? service.discovered_via.map(discoveryLabel).join(", ") : DASH,
          },
          { label: "Product", value: <UntrustedText value={service.product} limit={64} /> },
          {
            label: "Version",
            value: service.version ? (
              <UntrustedText value={service.version} limit={48} />
            ) : (
              <span className="text-muted-foreground">not observed</span>
            ),
          },
          { label: "First seen", value: <Timestamp value={service.first_seen} /> },
          {
            label: "Last discovery report",
            value: (
              <span className="inline-flex flex-wrap items-center justify-end gap-2">
                <Timestamp value={service.last_seen} />
                {service.report_stale ? <StaleBadge reason="Discovery has not refreshed this record within its staleness threshold" /> : null}
              </span>
            ),
          },
          { label: "Observed by", value: <UntrustedText value={service.observed_by} limit={64} mono /> },
        ]}
      />
      {service.config_refs.length > 0 ? (
        <div className="mt-4">
          <h3 className="mb-1 text-xs text-muted-foreground">Configuration references (paths only; contents are never collected)</h3>
          <ul className="flex flex-col gap-0.5">
            {service.config_refs.map((ref) => (
              <li key={ref} className="text-xs">
                <UntrustedText value={ref} limit={160} mono />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Panel>
  );
}

const COLLECTION: Record<string, { label: string; tone: "ok" | "warn" | "off"; detail: string }> = {
  fresh: { label: "Fresh", tone: "ok", detail: "At least one collector reporting this source is fresh." },
  stale: { label: "Stale", tone: "warn", detail: "Every collector reporting this source is stale." },
  no_collector_health: {
    label: "No collector health",
    tone: "off",
    detail: "No collector health record mentions this source for the asset; freshness is unknown.",
  },
};

/** Telemetry sources of the service, their collection freshness and attributed events. */
export function TelemetryPanel({
  service,
  telemetry,
  range,
  now,
}: {
  service: ServiceRecord;
  telemetry: ServiceTelemetrySource[];
  range: { since: string; until: string };
  now: string;
}) {
  return (
    <Panel
      title="Telemetry"
      titleId="telemetry-title"
      meta={
        <span>
          Events {formatUtcShort(range.since)} to {formatUtcShort(range.until)} UTC
        </span>
      }
    >
      {telemetry.length === 0 ? (
        <EmptyState>
          {service.adapter_support === "implemented"
            ? "No telemetry source is declared for this service, and no stored event is attributed to it."
            : "No service-specific telemetry is collected: there is no implemented adapter for this service."}
        </EmptyState>
      ) : (
        <Table aria-label="Telemetry sources of the service">
          <TableHeader>
            <TableRow>
              <TableHead>Source type</TableHead>
              <TableHead>Collection</TableHead>
              <TableHead className="text-right">Events</TableHead>
              <TableHead className="hidden text-right sm:table-cell">Last event</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {telemetry.map((t) => {
              const collection = COLLECTION[t.collection];
              return (
                <TableRow key={t.source_type}>
                  <TableCell className="py-2 whitespace-normal">
                    <div className="font-mono text-xs text-ink">
                      <UntrustedText value={t.source_type} limit={48} />
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {t.declared ? "declared by the adapter" : "seen in attributed events only"}
                    </div>
                    {t.collectors.map((c) => (
                      <div key={c.collector_id} className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                        <UntrustedText value={c.collector_id} limit={48} mono />
                        <HealthStatusDot status={c.status} />
                        <span>
                          success <RelativeTime value={c.last_success_at} now={now} className="text-xs" />
                        </span>
                        {c.stale ? <StaleBadge reason={c.stale_reason} /> : null}
                      </div>
                    ))}
                  </TableCell>
                  <TableCell className="align-top pt-3">
                    {collection ? (
                      <span title={collection.detail}>
                        <StatusPill tone={collection.tone} label={collection.label} />
                      </span>
                    ) : (
                      <UntrustedText value={t.collection} limit={32} />
                    )}
                  </TableCell>
                  <TableCell className="align-top pt-3 text-right font-mono text-xs text-ink-2">{formatCount(t.events)}</TableCell>
                  <TableCell className="hidden align-top pt-3 text-right sm:table-cell">
                    <RelativeTime value={t.last_event_at} now={now} className="text-xs" />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}

/** Authentication events attributed to the service: outcomes, actors and source addresses. */
export function AuthActivityPanel({ auth, now }: { auth: ServiceAuthActivity; now: string }) {
  const outcomes = Object.entries(auth.by_outcome).sort((a, b) => b[1] - a[1]);
  const failed = (auth.by_outcome.failure ?? 0) + (auth.by_outcome.denied ?? 0);
  return (
    <Panel
      title="Authentication activity"
      titleId="auth-title"
      meta={
        <span>
          {formatUtcShort(auth.range.since)} to {formatUtcShort(auth.range.until)} UTC
        </span>
      }
    >
      {auth.total === 0 ? (
        <EmptyState>No authentication event is attributed to this service in this window.</EmptyState>
      ) : (
        <>
          <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <dt className="text-xs text-muted-foreground">Events</dt>
              <dd className="mt-0.5 font-mono text-lg text-ink">{formatCount(auth.total)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Failed or denied</dt>
              <dd className={`mt-0.5 font-mono text-lg ${failed > 0 ? "text-warn" : "text-ink"}`}>{formatCount(failed)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Distinct actors</dt>
              <dd className="mt-0.5 font-mono text-lg text-ink">{formatCount(auth.distinct_actors)}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground">Distinct sources</dt>
              <dd className="mt-0.5 font-mono text-lg text-ink">{formatCount(auth.distinct_sources)}</dd>
            </div>
          </dl>
          {outcomes.length > 0 ? (
            <p className="mt-2 text-xs text-muted-foreground">
              By outcome: {outcomes.map(([outcome, count]) => `${humanize(outcome)} ${formatCount(count)}`).join(" · ")}
            </p>
          ) : null}
          {auth.top_sources.length > 0 ? (
            <Table aria-label="Top authentication sources" className="mt-3">
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
                    <TableCell className="font-mono text-xs text-ink">
                      <UntrustedText value={src.src_ip} limit={48} />
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs text-ink-2">{formatCount(src.events)}</TableCell>
                    <TableCell className={`text-right font-mono text-xs ${src.failures > 0 ? "text-warn" : "text-muted-foreground"}`}>
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
        </>
      )}
    </Panel>
  );
}

/** Listening endpoints with exposure and attribution confidence. */
export function EndpointsPanel({ service }: { service: ServiceRecord }) {
  const exposedAny = service.endpoints.filter((e) => e.exposure === "any").length;
  return (
    <Panel
      title="Ports and exposure"
      titleId="endpoints-title"
      meta={service.endpoints.length > 0 ? <span>{formatCount(exposedAny)} on all interfaces</span> : null}
    >
      {service.endpoints.length === 0 ? (
        <EmptyState>No listening port is attributed to this service. A process is never assumed to be a network service.</EmptyState>
      ) : (
        <ul className="divide-y divide-rule">
          {service.endpoints.map((endpoint, i) => (
            <li key={`${endpoint.protocol}-${endpoint.address ?? "*"}-${endpoint.port}-${i}`} className="py-2">
              <EndpointLine endpoint={endpoint} />
            </li>
          ))}
        </ul>
      )}
      {service.invalid_endpoints > 0 ? (
        <p className="mt-2 text-xs text-warn">
          {formatCount(service.invalid_endpoints)} stored endpoint entr{service.invalid_endpoints === 1 ? "y" : "ies"} failed validation and
          {service.invalid_endpoints === 1 ? " is" : " are"} not shown.
        </p>
      ) : null}
    </Panel>
  );
}

function instanceTitle(instance: ServiceInstance): string {
  return instance.pod_name ?? instance.container_name ?? instance.process_name ?? instance.instance_key;
}

const STATE_CLASS: Record<string, string> = {
  running: "text-ink-2",
  failed: "text-bad",
  pending: "text-warn",
  stopped: "text-muted-foreground",
};

/** Processes, containers and Pods of the service; containers sit under their Pod. */
export function InstancesPanel({
  service,
  instances,
  total,
  now,
}: {
  service: ServiceRecord;
  instances: ServiceInstance[];
  total: number;
  now: string;
}) {
  const ids = new Set(instances.map((i) => i.instance_id));
  const roots = instances.filter((i) => !i.parent_instance_id || !ids.has(i.parent_instance_id));
  const ordered: { instance: ServiceInstance; depth: number }[] = [];
  for (const root of roots) {
    ordered.push({ instance: root, depth: 0 });
    for (const child of instances.filter((i) => i.parent_instance_id === root.instance_id)) {
      ordered.push({ instance: child, depth: 1 });
    }
  }
  const isK8s = service.service_kind === "k8s_workload" || service.service_kind === "k8s_service";

  return (
    <Panel
      title="Instances"
      titleId="instances-title"
      meta={
        instances.length > 0 ? (
          <span>
            {formatCount(instances.length)}
            {total > instances.length ? ` of ${formatCount(total)}` : ""} current
          </span>
        ) : null
      }
    >
      {instances.length === 0 ? (
        <EmptyState>
          {service.service_kind === "k8s_service"
            ? "A Kubernetes Service is a logical object (virtual IP and ports); it has no process or container of its own. Its backing Pods belong to workloads."
            : "No instance of this service is currently reported."}
        </EmptyState>
      ) : (
        <Table aria-label="Service instances">
          <TableHeader>
            <TableRow>
              <TableHead>Instance</TableHead>
              <TableHead className="hidden md:table-cell">{isK8s ? "Node and namespace" : "Process"}</TableHead>
              <TableHead className="hidden lg:table-cell">{isK8s ? "Pod UID and container id" : "User"}</TableHead>
              <TableHead>State</TableHead>
              <TableHead className="hidden text-right sm:table-cell">Observed</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {ordered.map(({ instance: i, depth }) => (
              <TableRow key={i.instance_id}>
                <TableCell className="py-2 whitespace-normal">
                  <div className={depth > 0 ? "border-l border-border pl-3" : undefined}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs text-muted-foreground">{INSTANCE_KIND_LABEL[i.instance_kind] ?? i.instance_kind}</span>
                      <span className="text-ink">
                        <UntrustedText value={instanceTitle(i)} limit={64} />
                      </span>
                      {i.stale ? <StaleBadge reason="Not re-observed within the service staleness threshold" /> : null}
                    </div>
                    {i.image ? (
                      <div className="mt-0.5 font-mono text-xs text-muted-foreground">
                        <UntrustedText value={i.image} limit={96} />
                      </div>
                    ) : null}
                    {i.workload_kind || i.workload_name ? (
                      <div className="mt-0.5 text-xs text-muted-foreground">
                        <UntrustedText value={[i.workload_kind, i.workload_name].filter(Boolean).join(" ")} limit={80} />
                      </div>
                    ) : null}
                  </div>
                </TableCell>
                <TableCell className="hidden text-xs whitespace-normal text-ink-2 md:table-cell">
                  {isK8s ? (
                    <>
                      <UntrustedText value={i.node_name} limit={48} />
                      {i.namespace ? (
                        <span className="text-muted-foreground">
                          {" · "}
                          <UntrustedText value={i.namespace} limit={48} />
                        </span>
                      ) : null}
                    </>
                  ) : (
                    <>
                      {i.process_name ? <UntrustedText value={i.process_name} limit={48} /> : DASH}
                      {i.pid !== null && i.pid !== undefined ? <span className="font-mono text-muted-foreground"> pid {i.pid}</span> : null}
                    </>
                  )}
                </TableCell>
                <TableCell className="hidden max-w-72 text-xs whitespace-normal lg:table-cell">
                  {isK8s ? (
                    <div className="flex flex-col gap-0.5 font-mono text-muted-foreground">
                      {i.pod_uid ? <UntrustedText value={i.pod_uid} limit={40} /> : null}
                      {i.container_id ? <UntrustedText value={i.container_id} limit={48} /> : null}
                      {!i.pod_uid && !i.container_id ? DASH : null}
                    </div>
                  ) : (
                    <UntrustedText value={i.user} limit={48} />
                  )}
                </TableCell>
                <TableCell className={`text-xs ${STATE_CLASS[i.state] ?? "text-muted-foreground"}`}>
                  <UntrustedText value={i.state} limit={16} />
                </TableCell>
                <TableCell className="hidden text-right sm:table-cell">
                  <RelativeTime value={i.observed_at} now={now} className="text-xs" />
                  {i.started_at ? (
                    <div className="text-xs text-muted-foreground">
                      started <RelativeTime value={i.started_at} now={now} className="text-xs" />
                    </div>
                  ) : null}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  );
}

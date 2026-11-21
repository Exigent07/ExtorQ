import { Info } from "lucide-react";
import Link from "next/link";

import { KeyValueList } from "@/components/console/key-values";
import { Panel } from "@/components/console/panel";
import { SeverityTag } from "@/components/console/severity";
import { EmptyState } from "@/components/console/states";
import { HealthStatusDot, StaleBadge, StatusPill } from "@/components/console/status-badge";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ServiceCoverageDot } from "@/components/views/services/service-badges";
import type { AlertDetailResponse, InvestigationContext } from "@/lib/api/schemas";
import { FINDING_STATE } from "@/lib/findings";
import { assetTypeLabel, formatDuration, humanize } from "@/lib/format";
import { assetHref, serviceHref } from "@/lib/security/ids";
import { categoryLabel, serviceKindLabel } from "@/lib/services";

/** Coverage of the telemetry the rule needs, gaps in the window, and the rule's known limits. */
export function CoverageGapsPanel({
  context,
  now,
}: {
  context: InvestigationContext;
  now: string;
}) {
  const coverage = context.coverage;
  const gaps = coverage.filter((c) => c.stale || c.gap_during_window).length;
  return (
    <Panel
      title="Coverage and known gaps"
      titleId="coverage-gaps-title"
      meta={<span>{gaps > 0 ? `${gaps} source${gaps === 1 ? "" : "s"} stale or gapped` : "No source gap recorded"}</span>}
    >
      {coverage.length === 0 ? (
        <EmptyState>The investigation context records no source coverage for this alert.</EmptyState>
      ) : (
        <Table aria-label="Telemetry source coverage during the alert window">
          <TableHeader>
            <TableRow>
              <TableHead>Source</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="text-right">Last success</TableHead>
              <TableHead className="hidden text-right sm:table-cell">Lag</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {coverage.map((c) => (
              <TableRow key={`${c.source_type}|${c.collector_id ?? ""}`}>
                <TableCell className="py-2 whitespace-normal">
                  <div className="font-mono text-xs text-ink">
                    <UntrustedText value={c.source_type} limit={40} />
                  </div>
                  {c.note ? (
                    <div className="text-xs text-muted-foreground">
                      <UntrustedText value={c.note} limit={160} />
                    </div>
                  ) : null}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap items-center gap-2">
                    <HealthStatusDot status={c.status} />
                    {c.stale ? <StaleBadge /> : null}
                    {c.gap_during_window ? <StatusPill tone="warn" label="Gap in window" /> : null}
                  </div>
                </TableCell>
                <TableCell className="text-right">
                  <RelativeTime value={c.last_success_at} now={now} className="text-xs" />
                </TableCell>
                <TableCell className="hidden text-right font-mono text-xs text-ink-2 sm:table-cell">
                  {formatDuration(c.lag_seconds)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {context.missing_telemetry.length > 0 ? (
        <div className="mt-4">
          <h3 className="mb-1 text-sm font-medium text-ink">Missing telemetry</h3>
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-warn">
            {context.missing_telemetry.map((m) => (
              <li key={m}>
                <UntrustedText value={m} limit={240} />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {context.limitations.length > 0 ? (
        <div className="mt-4">
          <h3 className="mb-1 text-sm font-medium text-ink">Limitations of this context</h3>
          <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-ink-2">
            {context.limitations.map((m) => (
              <li key={m}>
                <UntrustedText value={m} limit={240} />
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {context.rule.blind_spots.length > 0 || context.rule.false_positives.length > 0 ? (
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          {context.rule.blind_spots.length > 0 ? (
            <div>
              <h3 className="mb-1 text-sm font-medium text-ink">Rule blind spots</h3>
              <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-ink-2">
                {context.rule.blind_spots.map((b) => (
                  <li key={b}>
                    <UntrustedText value={b} limit={240} />
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {context.rule.false_positives.length > 0 ? (
            <div>
              <h3 className="mb-1 text-sm font-medium text-ink">Known false positives</h3>
              <ul className="flex list-disc flex-col gap-1 pl-5 text-sm text-ink-2">
                {context.rule.false_positives.map((b) => (
                  <li key={b}>
                    <UntrustedText value={b} limit={240} />
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </Panel>
  );
}

/** Posture findings on the alert's asset, as captured in the investigation context. */
const MAX_SIDE_FINDINGS = 8;

export function ContextFindingsPanel({ context, now }: { context: InvestigationContext; now: string }) {
  const findings = context.findings.slice(0, MAX_SIDE_FINDINGS);
  const more = context.findings.length - findings.length;
  return (
    <Panel
      title="Findings on the asset"
      titleId="context-findings-title"
      action={
        <Link href={`${assetHref(context.asset.asset_id)}?tab=findings`} className="hover:text-ink">
          All findings
        </Link>
      }
    >
      {findings.length === 0 ? (
        <EmptyState>No posture finding on this asset was captured in the investigation context.</EmptyState>
      ) : (
        <ul className="divide-y divide-rule">
          {findings.map((f) => (
            <li key={f.finding_id} className="flex items-start justify-between gap-4 py-2">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityTag severity={f.severity} className="text-xs" />
                  <span className="text-sm text-ink">
                    <UntrustedText value={f.title} limit={120} />
                  </span>
                </div>
                <div className="mt-0.5 font-mono text-xs text-muted-foreground">
                  <UntrustedText value={`${f.scanner} · ${f.check_id}`} limit={96} />
                </div>
              </div>
              <div className="flex-none text-right text-xs">
                <span className={FINDING_STATE[f.state]?.className ?? "text-muted-foreground"} title={FINDING_STATE[f.state]?.detail}>
                  {FINDING_STATE[f.state]?.label ?? f.state}
                </span>
                <div>
                  <RelativeTime value={f.last_observed_at} now={now} className="text-xs" />
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
      {more > 0 || context.truncated.findings ? (
        <p className="mt-2 text-xs text-muted-foreground">
          {more > 0 ? `${more} more in the investigation context; ` : ""}
          {context.truncated.findings ? "the context builder truncated this list; " : ""}
          the asset page lists them all.
        </p>
      ) : null}
    </Panel>
  );
}

/** Services and other assets involved in the investigation (contracts 1.1). */
export function InvolvedPanel({ context }: { context: InvestigationContext }) {
  const services = [...context.services].sort((a, b) => (a.role === b.role ? a.name.localeCompare(b.name) : a.role === "evidence" ? -1 : 1));
  return (
    <Panel title="Involved services and assets" titleId="involved-title">
      {services.length === 0 ? (
        <EmptyState>No service is attributed to this alert&apos;s evidence or related activity.</EmptyState>
      ) : (
        <ul className="divide-y divide-rule">
          {services.map((s) => {
            const href = serviceHref(s.service_id);
            return (
              <li key={s.service_id} className="py-2">
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="min-w-0">
                    {href ? (
                      <Link href={href} className="text-ink hover:underline">
                        <UntrustedText value={s.name} limit={64} />
                      </Link>
                    ) : (
                      <UntrustedText value={s.name} limit={64} />
                    )}
                    <span className="ml-2 text-xs text-muted-foreground">
                      {serviceKindLabel(s.service_kind)} · {categoryLabel(s.category)}
                    </span>
                  </span>
                  <span className={s.role === "evidence" ? "text-xs text-ink-2" : "text-xs text-muted-foreground"}>
                    {s.role === "evidence" ? "Evidence source" : "Related activity"}
                  </span>
                </div>
                <div className="mt-0.5 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                  <ServiceCoverageDot service={s} />
                  <UntrustedText value={s.asset_id} limit={64} mono />
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {context.related_assets.length > 0 ? (
        <div className="mt-4">
          <h3 className="mb-1 text-xs text-muted-foreground">Other assets with related activity</h3>
          <ul className="flex flex-col gap-1">
            {context.related_assets.map((a) => (
              <li key={a.asset_id} className="text-sm">
                <Link href={assetHref(a.asset_id)} className="text-ink-2 hover:text-ink hover:underline">
                  <UntrustedText value={a.name} limit={64} />
                </Link>
                <span className="ml-2 text-xs text-muted-foreground">{assetTypeLabel(a.asset_type)}</span>
              </li>
            ))}
          </ul>
          <p className="mt-2 flex items-start gap-1.5 text-xs text-muted-foreground">
            <Info className="mt-0.5 size-3 flex-none" aria-hidden="true" />
            Cross-asset links are drawn only with identity evidence; see each observation&apos;s basis.
          </p>
        </div>
      ) : null}
    </Panel>
  );
}

/** Grouping entities and features the detector recorded (deterministic, from stored telemetry). */
export function EntitiesPanel({ detail, context }: { detail: AlertDetailResponse; context: InvestigationContext | null }) {
  const entities = Object.entries(detail.alert.entities);
  const features = Object.entries(context?.features ?? detail.alert.features ?? {}).slice(0, 16);
  return (
    <Panel title="Entities and features" titleId="entities-title">
      {entities.length === 0 ? (
        <p className="text-xs text-muted-foreground">The rule recorded no grouping entity.</p>
      ) : (
        <KeyValueList
          rows={entities.map(([k, v]) => ({ label: humanize(k), value: <UntrustedText value={v} limit={120} mono /> }))}
        />
      )}
      {features.length > 0 ? (
        <div className="mt-4">
          <h3 className="mb-1 text-xs text-muted-foreground">Features computed by the detector</h3>
          <KeyValueList
            rows={features.map(([k, v]) => ({
              label: humanize(k),
              value: (
                <UntrustedText value={typeof v === "string" ? v : JSON.stringify(v)} limit={120} mono={typeof v !== "string"} />
              ),
            }))}
          />
        </div>
      ) : null}
    </Panel>
  );
}

/** Audit trail of analyst actions on this alert. */
export function ActionsLogPanel({ detail }: { detail: AlertDetailResponse }) {
  return (
    <Panel title="Analyst activity" titleId="actions-title">
      {detail.actions.length === 0 ? (
        <p className="text-xs text-muted-foreground">No analyst action has been recorded on this alert.</p>
      ) : (
        <ol className="divide-y divide-rule">
          {detail.actions.map((a) => (
            <li key={a.action_id} className="py-2 text-xs">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="text-ink-2">
                  <UntrustedText value={a.actor} limit={40} /> <span className="text-muted-foreground">({a.role})</span>{" "}
                  {humanize(a.action)}
                </span>
                <Timestamp value={a.occurred_at} />
              </div>
              {a.details && Object.keys(a.details).length > 0 ? (
                <div className="mt-0.5 font-mono text-muted-foreground">
                  <UntrustedText value={JSON.stringify(a.details)} limit={200} />
                </div>
              ) : null}
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}

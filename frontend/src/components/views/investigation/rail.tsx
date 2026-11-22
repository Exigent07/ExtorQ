import { History, Info, UserCheck } from "lucide-react";
import Link from "next/link";

import { IdText } from "@/components/console/id-text";
import { KeyValueList } from "@/components/console/key-values";
import { SectionCard } from "@/components/console/section-card";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { AlertDetailResponse, InvestigationContext } from "@/lib/api/schemas";
import { assetTypeLabel, DASH, formatCount, formatDuration, formatVersion, humanize } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";

import { StatusMark } from "./marks";
import { actionView, secondsBetween } from "./model";
import { StatusForm } from "./status-controls";

/** Analyst status: current state, note and (analysts only) the status + note form. */
export function AnalystStatusCard({ detail, canEdit }: { detail: AlertDetailResponse; canEdit: boolean }) {
  return (
    <SectionCard title="Analyst status" titleId="state-title" icon={UserCheck}>
      <StatusForm alertId={detail.alert.alert_id} state={detail.analyst_state} canEdit={canEdit} />
    </SectionCard>
  );
}

/** Identifiers and provenance of the alert and of its investigation context. */
export function KeyFactsCard({
  detail,
  context,
  contextSource,
}: {
  detail: AlertDetailResponse;
  context: InvestigationContext | null;
  contextSource: "stored" | "built_on_demand" | null;
}) {
  const alert = detail.alert;
  const asset = detail.asset;
  const window = secondsBetween(alert.window_start, alert.window_end);
  return (
    <SectionCard title="Key facts" titleId="facts-title" icon={Info}>
      <KeyValueList
        rows={[
          { label: "Alert", value: <IdText id={alert.alert_id} /> },
          {
            label: "Rule",
            value: (
              <span className="font-mono text-xs">
                {alert.rule_id} {formatVersion(alert.rule_version)}
              </span>
            ),
          },
          {
            label: "Asset",
            value: (
              <Link href={assetHref(alert.asset_id)} className="inline-block max-w-44 truncate align-bottom hover:text-foreground hover:underline">
                <UntrustedText value={asset ? asset.name : alert.asset_id} limit={48} plain />
              </Link>
            ),
          },
          { label: "Asset type", value: assetTypeLabel(asset?.asset_type ?? alert.asset_type) },
          {
            label: "Criticality",
            value: asset ? <UntrustedText value={humanize(asset.criticality)} limit={32} /> : <span className="text-muted-foreground">{DASH}</span>,
          },
          { label: "Detected", value: <Timestamp value={alert.created_at} /> },
          { label: "Updated", value: <Timestamp value={alert.updated_at} /> },
          { label: "Rule window", value: <span className="font-mono text-xs">{formatDuration(window)}</span> },
          { label: "Services", value: <span className="font-mono text-xs tabular-nums">{formatCount(alert.service_ids.length)}</span> },
          {
            label: "Context",
            value: context ? (
              contextSource === "built_on_demand" ? "Built on demand" : "Stored"
            ) : (
              <span className="text-muted-foreground">Unavailable</span>
            ),
          },
          ...(context
            ? [
                {
                  label: "Builder",
                  value: (
                    <span className="font-mono text-xs">
                      <UntrustedText value={context.builder_version} limit={40} />
                    </span>
                  ),
                },
                { label: "Input hash", value: <IdText id={context.input_hash} head={10} /> },
              ]
            : []),
        ]}
      />
    </SectionCard>
  );
}

/** Audit trail of analyst actions on this alert (newest first, as the API returns it). */
export function ActivityCard({ detail }: { detail: AlertDetailResponse }) {
  const actions = detail.actions;
  return (
    <SectionCard
      title="Analyst activity"
      titleId="actions-title"
      icon={History}
      meta={actions.length > 0 ? <span className="tabular-nums">{formatCount(actions.length)}</span> : undefined}
    >
      {actions.length === 0 ? (
        <p className="text-sm text-muted-foreground">No analyst action has been recorded on this alert.</p>
      ) : (
        <ol className="relative grid gap-4">
          {actions.map((action) => {
            const view = actionView(action);
            return (
              <li key={action.action_id} className="grid grid-cols-[12px_minmax(0,1fr)] gap-x-3">
                <span aria-hidden="true" className="mt-1.5 size-2 rounded-full bg-fg-2 ring-2 ring-card" />
                <div className="min-w-0">
                  <p className="text-sm text-fg-2">
                    <span className="font-medium text-foreground">
                      <UntrustedText value={action.actor} limit={40} />
                    </span>{" "}
                    {view.verb}
                    {view.status ? (
                      <>
                        {" to "}
                        <StatusMark status={view.status} className="text-foreground" />
                      </>
                    ) : null}
                  </p>
                  <p className="mt-0.5 text-xs text-muted-foreground">
                    <Timestamp value={action.occurred_at} className="text-xs text-muted-foreground" /> · {humanize(action.role)}
                  </p>
                  {view.note ? (
                    <p className="mt-1.5 rounded-lg bg-white/[0.02] px-3 py-2 text-sm leading-relaxed text-fg-2 ring-1 ring-hairline ring-inset">
                      <UntrustedText value={view.note} limit={280} />
                    </p>
                  ) : null}
                  {view.details.length > 0 ? (
                    <p className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-muted-foreground">
                      {view.details.map(([key, value]) => (
                        <span key={key}>
                          {humanize(key)}{" "}
                          <span className="text-fg-2">
                            <UntrustedText value={value} limit={60} />
                          </span>
                        </span>
                      ))}
                    </p>
                  ) : null}
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </SectionCard>
  );
}

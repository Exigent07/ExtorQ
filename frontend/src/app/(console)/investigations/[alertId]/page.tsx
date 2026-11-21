import type { Metadata } from "next";
import Link from "next/link";

import { Freshness } from "@/components/console/freshness";
import { MetricStrip } from "@/components/console/key-values";
import { PageHeader } from "@/components/console/page-header";
import { Panel } from "@/components/console/panel";
import { SeverityPill } from "@/components/console/severity";
import { EmptyState, ErrorState } from "@/components/console/states";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { AnalystStatusText, ConfidenceText, SimulationTag } from "@/components/views/alerts/alert-bits";
import {
  ActionsLogPanel,
  ContextFindingsPanel,
  CoverageGapsPanel,
  EntitiesPanel,
  InvolvedPanel,
} from "@/components/views/investigation/context-sections";
import { EvidenceTable } from "@/components/views/investigation/evidence-table";
import { GeminiPanel } from "@/components/views/investigation/gemini-panel";
import { JevPanel } from "@/components/views/investigation/jev-panel";
import { AnalystStateControl } from "@/components/views/investigation/state-control";
import { CorrelationsPanel, TimelinePanel } from "@/components/views/investigation/timeline";
import type { AIAssessment } from "@/lib/api/schemas";
import { permissions } from "@/lib/auth/roles";
import { formatCount, formatDuration } from "@/lib/format";
import { assetHref, parseHexIdSegment } from "@/lib/security/ids";
import { getAlert, getAlertContext, listAssessments } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "Investigation" };

function latest(items: AIAssessment[], task: "triage" | "summary"): AIAssessment | null {
  const ofTask = items.filter((a) => a.task === task);
  ofTask.sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at));
  return ofTask[0] ?? null;
}

export default async function InvestigationPage({ params }: PageProps<"/investigations/[alertId]">) {
  const session = await requireSession();
  const { alertId: rawId } = await params;
  const alertId = parseHexIdSegment(rawId);
  const crumbs = [{ label: "Detections", href: "/detections" }];

  if (!alertId) {
    return (
      <>
        <PageHeader title="Investigation" crumbs={crumbs} />
        <ErrorState what="this alert" error={{ kind: "not_found", message: "The alert id in the address is not valid.", requestId: "-" }} />
      </>
    );
  }

  const [detailResult, contextResult, assessmentsResult] = await Promise.all([
    getAlert(session, alertId),
    getAlertContext(session, alertId),
    listAssessments(session, alertId),
  ]);

  if (!detailResult.ok) {
    return (
      <>
        <PageHeader title="Investigation" crumbs={crumbs} />
        <ErrorState what="this alert" error={detailResult.error} />
      </>
    );
  }

  const detail = detailResult.data;
  const alert = detail.alert;
  const now = detailResult.receivedAt;
  const context = contextResult.ok ? contextResult.data.context : null;
  const assessments = assessmentsResult.ok ? assessmentsResult.data.items : [];
  const evidenceIds = new Set(detail.evidence.map((e) => e.event_id));
  const windowSeconds = (Date.parse(alert.last_seen) - Date.parse(alert.first_seen)) / 1000;
  const assetName = detail.asset ? (detail.asset.display_name ?? detail.asset.name) : alert.asset_id;

  return (
    <>
      <PageHeader
        title={<UntrustedText value={alert.rule_title} limit={120} />}
        crumbs={[...crumbs, { label: alert.rule_id }]}
        titleMeta={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityPill severity={alert.severity} />
            <span className="font-mono text-xs text-muted-foreground">
              {alert.rule_id} v{alert.rule_version}
            </span>
            <SimulationTag runIds={alert.simulation_run_ids} />
          </span>
        }
        finding={<UntrustedText value={alert.summary} limit={400} />}
        actions={<Freshness at={detailResult.receivedAt} />}
      />

      <MetricStrip
        className="mb-6"
        items={[
          {
            label: "Evidence confidence",
            value: <ConfidenceText confidence={alert.confidence} />,
            sub: "deterministic completeness, not a maliciousness score",
          },
          {
            label: "Asset",
            value: (
              <Link href={assetHref(alert.asset_id)} className="text-base text-ink hover:underline">
                <UntrustedText value={assetName} limit={40} />
              </Link>
            ),
            sub: <UntrustedText value={alert.asset_id} limit={48} mono />,
          },
          {
            label: "Activity window",
            value: <span className="font-mono">{formatDuration(windowSeconds)}</span>,
            sub: (
              <>
                <Timestamp value={alert.first_seen} className="text-muted-foreground" /> to{" "}
                <Timestamp value={alert.last_seen} className="text-muted-foreground" />
              </>
            ),
          },
          {
            label: "Evidence events",
            value: <span className="font-mono">{formatCount(alert.event_count)}</span>,
            sub: alert.evidence_truncated ? "evidence list truncated by the detector" : `${formatCount(detail.evidence_total)} stored`,
          },
          {
            label: "Analyst status",
            value: <AnalystStatusText status={detail.analyst_state.status} recorded={detail.analyst_state.recorded} />,
          },
        ]}
      />

      <div className="grid items-start gap-6 xl:grid-cols-3">
        <div className="grid min-w-0 gap-6 xl:col-span-2">
          <Panel title="Why this rule fired" titleId="established-title">
            {detail.rule ? (
              <p className="text-sm text-ink-2">
                <UntrustedText value={detail.rule.description} limit={800} />
              </p>
            ) : (
              <p className="text-sm text-muted-foreground">The rule definition is not available from the API.</p>
            )}
            <p className="mt-3 text-xs text-muted-foreground">
              Detector {alert.detector_version} · group key <UntrustedText value={alert.group_key} limit={80} mono />
              {alert.mitre_techniques.length > 0 ? ` · MITRE ATT&CK ${alert.mitre_techniques.join(", ")}` : ""}
            </p>
            {context ? (
              <p className="mt-1 text-xs text-muted-foreground">
                Investigation context {contextResult.ok && contextResult.data.source === "built_on_demand" ? "built on demand" : "stored"} ·
                input hash <span className="font-mono break-all">{context.input_hash}</span>
              </p>
            ) : null}
          </Panel>

          {context ? (
            <TimelinePanel context={context} evidenceIds={evidenceIds} />
          ) : (
            <ErrorState what="the investigation context" error={!contextResult.ok ? contextResult.error : { kind: "server", message: "No context", requestId: "-" }} />
          )}

          <Panel
            title="Supporting evidence"
            titleId="evidence-title"
            meta={
              <span>
                {formatCount(detail.evidence.length)} of {formatCount(detail.evidence_total)} shown
                {detail.evidence_capped ? " (capped)" : ""}
              </span>
            }
          >
            {detail.evidence.length === 0 ? (
              <EmptyState>No evidence event could be resolved from storage for this alert.</EmptyState>
            ) : (
              <EvidenceTable evidence={detail.evidence} />
            )}
            {detail.unresolved_evidence_ids.length > 0 ? (
              <p className="mt-2 text-xs text-warn">
                {formatCount(detail.unresolved_evidence_ids.length)} cited evidence id
                {detail.unresolved_evidence_ids.length === 1 ? " was" : "s were"} not found in storage (retention or not yet
                written).
              </p>
            ) : null}
          </Panel>

          {context ? <CoverageGapsPanel context={context} now={now} /> : null}

          <JevPanel assessment={latest(assessments, "triage")} currentInputHash={context?.input_hash ?? null} />
          <GeminiPanel
            alertId={alert.alert_id}
            assessment={latest(assessments, "summary")}
            canRequest={permissions.requestSummary(session.role)}
            evidenceOnPage={evidenceIds}
          />
          {!assessmentsResult.ok ? <ErrorState what="the AI assessments" error={assessmentsResult.error} /> : null}
          {context ? <CorrelationsPanel context={context} /> : null}
        </div>

        <aside className="grid min-w-0 gap-6" aria-label="Alert facts and actions">
          <Panel title="Analyst status" titleId="state-title">
            <AnalystStateControl
              alertId={alert.alert_id}
              state={detail.analyst_state}
              canEdit={permissions.changeAlertState(session.role)}
            />
          </Panel>
          <EntitiesPanel detail={detail} context={context} />
          {context ? <InvolvedPanel context={context} /> : null}
          {context ? <ContextFindingsPanel context={context} now={now} /> : null}
          <ActionsLogPanel detail={detail} />
        </aside>
      </div>
    </>
  );
}

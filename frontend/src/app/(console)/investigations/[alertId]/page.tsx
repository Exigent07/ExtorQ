import type { Metadata } from "next";

import { Freshness } from "@/components/console/freshness";
import { PageHeader } from "@/components/console/page-header";
import { PageCrumbs } from "@/components/console/route-breadcrumbs";
import { SectionCard } from "@/components/console/section-card";
import { ErrorState } from "@/components/console/states";
import { AiPanel } from "@/components/views/investigation/ai-panel";
import { ContextPanel } from "@/components/views/investigation/context-panel";
import { CorrelationPanel } from "@/components/views/investigation/correlation-panel";
import { EvidencePanel } from "@/components/views/investigation/evidence-panel";
import { HeaderCard } from "@/components/views/investigation/header-card";
import { InvestigationTabs, type TabSpec } from "@/components/views/investigation/investigation-tabs";
import { coverageIssues, latestAssessment, relatedRows } from "@/components/views/investigation/model";
import { OverviewPanel } from "@/components/views/investigation/overview-panel";
import { ActivityCard, AnalystStatusCard, KeyFactsCard } from "@/components/views/investigation/rail";
import { TimelinePanel } from "@/components/views/investigation/timeline-panel";
import { permissions } from "@/lib/auth/roles";
import { formatCount } from "@/lib/format";
import { shortId } from "@/lib/security/display";
import { isRuleId, parseHexIdSegment } from "@/lib/security/ids";
import { getAlert, getAlertContext, listAssessments } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "Investigation" };

const NO_CONTEXT = { kind: "server" as const, message: "No investigation context was returned.", requestId: "-" };

/**
 * Investigation of one alert: a header card (rule, severity, simulation marker, evidence
 * confidence, asset, first/last seen, event count, analyst status), tabs for the overview,
 * timeline, evidence, correlation, advisory AI and context, and a right rail with the
 * analyst status, key facts and the activity log. Three API reads in parallel; each block
 * shows its own error. Switching tabs never calls the API (all panels render here).
 */
export default async function InvestigationPage({ params }: PageProps<"/investigations/[alertId]">) {
  const session = await requireSession();
  const { alertId: rawId } = await params;
  const alertId = parseHexIdSegment(rawId);

  if (!alertId) {
    return (
      <>
        <PageHeader title="Investigation" />
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
        <PageHeader title="Investigation" />
        <ErrorState what="this alert" error={detailResult.error} />
      </>
    );
  }

  const detail = detailResult.data;
  const alert = detail.alert;
  const now = detailResult.receivedAt;
  const context = contextResult.ok ? contextResult.data.context : null;
  const contextError = contextResult.ok ? null : contextResult.error;
  const assessments = assessmentsResult.ok ? assessmentsResult.data.items : [];
  const triage = latestAssessment(assessments, "triage");
  const summary = latestAssessment(assessments, "summary");
  const evidenceRows = new Set(detail.evidence.map((e) => e.event_id));
  const canEdit = permissions.changeAlertState(session.role);
  const inputHash = context?.input_hash ?? null;
  const aiOutdated = [triage, summary].some((a) => a !== null && inputHash !== null && a.context_input_hash !== inputHash);
  const issues = context ? coverageIssues(context) : 0;

  const tabs: TabSpec[] = [
    { key: "overview", label: "Overview" },
    { key: "timeline", label: "Timeline", count: context?.timeline.length ?? null },
    { key: "evidence", label: "Evidence", count: detail.evidence.length },
    { key: "correlation", label: "Correlation", count: context ? relatedRows(context).length : null },
    { key: "ai", label: "AI", attention: aiOutdated ? "AI output was made on an earlier investigation context" : null },
    {
      key: "context",
      label: "Context",
      attention: issues > 0 ? `${formatCount(issues)} coverage issue${issues === 1 ? "" : "s"} recorded` : null,
    },
  ];

  const panels = {
    overview: <OverviewPanel detail={detail} context={context} contextError={contextError} />,
    timeline: context ? (
      <TimelinePanel
        context={context}
        evidence={detail.evidence}
        evidenceIds={evidenceRows}
        firstSeen={alert.first_seen}
        lastSeen={alert.last_seen}
      />
    ) : (
      <SectionCard title="Event timeline" titleId="timeline-title">
        <ErrorState what="the investigation context" error={contextError ?? NO_CONTEXT} />
      </SectionCard>
    ),
    evidence: <EvidencePanel detail={detail} />,
    correlation: <CorrelationPanel context={context} contextError={contextError} />,
    ai: (
      <AiPanel
        alertId={alert.alert_id}
        assessments={assessments}
        assessmentsError={assessmentsResult.ok ? null : assessmentsResult.error}
        currentInputHash={inputHash}
        canRequest={permissions.requestSummary(session.role)}
        evidenceRows={evidenceRows}
        triage={triage}
        summary={summary}
      />
    ),
    context: <ContextPanel context={context} contextError={contextError} now={now} />,
  };

  return (
    <>
      <Freshness at={detailResult.receivedAt} />
      <PageCrumbs
        crumbs={[
          ...(isRuleId(alert.rule_id)
            ? [{ label: alert.rule_id, href: `/detections?rule=${encodeURIComponent(alert.rule_id)}`, mono: true }]
            : []),
          { label: `Alert ${shortId(alert.alert_id, 8)}`, mono: true },
        ]}
      />
      <HeaderCard detail={detail} now={now} canEdit={canEdit} />
      <div className="mt-6 grid items-start gap-6 xl:grid-cols-[minmax(0,1fr)_19rem] 2xl:grid-cols-[minmax(0,1fr)_21rem]">
        <InvestigationTabs tabs={tabs} panels={panels} />
        <aside aria-label="Alert status and facts" className="grid min-w-0 gap-6">
          <AnalystStatusCard detail={detail} canEdit={canEdit} />
          <KeyFactsCard detail={detail} context={context} contextSource={contextResult.ok ? contextResult.data.source : null} />
          <ActivityCard detail={detail} />
        </aside>
      </div>
    </>
  );
}

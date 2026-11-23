import type { Metadata } from "next";

import { Freshness } from "@/components/console/freshness";
import { PageHeader } from "@/components/console/page-header";
import { PageCrumbs } from "@/components/console/route-breadcrumbs";
import { SectionCard } from "@/components/console/section-card";
import { ErrorState, NotFoundState } from "@/components/console/states";
import { AiPanel } from "@/components/views/investigation/ai-panel";
import { ContextPanel } from "@/components/views/investigation/context-panel";
import { CorrelationPanel } from "@/components/views/investigation/correlation-panel";
import { EvidencePanel } from "@/components/views/investigation/evidence-panel";
import { HeaderCard } from "@/components/views/investigation/header-card";
import { InvestigationTabs, type TabSpec } from "@/components/views/investigation/investigation-tabs";
import {
  coverageIssues,
  latestAssessment,
  natSharedCount,
  providerAvailability,
  relatedRows,
} from "@/components/views/investigation/model";
import { OverviewPanel } from "@/components/views/investigation/overview-panel";
import { ActivityCard, AnalystStatusCard, KeyFactsCard } from "@/components/views/investigation/rail";
import { TimelinePanel } from "@/components/views/investigation/timeline-panel";
import { permissions } from "@/lib/auth/roles";
import { formatCount } from "@/lib/format";
import { shortId } from "@/lib/security/display";
import { isRuleId, parseHexIdSegment } from "@/lib/security/ids";
import { getAlert, getAlertContext, getHealth, listAssessments } from "@/lib/server/api";
import { requireSession } from "@/lib/server/session";

export const metadata: Metadata = { title: "Investigation" };

const NO_CONTEXT = { kind: "server" as const, message: "No investigation context was returned.", requestId: "-" };

/**
 * Investigation of one alert: a header card (rule, severity, ATT&CK techniques, evidence
 * confidence, asset, first/last seen, event count, analyst status), tabs for the overview,
 * timeline, evidence, correlation, advisory AI (Jev triage) and context, and a right rail with
 * the analyst status, key facts and the activity log. Four API reads in parallel; each block
 * shows its own error. Switching tabs never calls the API (all panels render here).
 */
export default async function InvestigationPage({ params }: PageProps<"/investigations/[alertId]">) {
  const session = await requireSession();
  const { alertId: rawId } = await params;
  const alertId = parseHexIdSegment(rawId);

  if (!alertId) {
    return (
      <>
        <PageHeader title="Alert not found" />
        <NotFoundState backHref="/detections" backLabel="Back to Detections">
          The address does not hold a valid alert id (32 hexadecimal characters).
        </NotFoundState>
      </>
    );
  }

  // Health is read for Jev's flags only (cached by the API for 15 s): the AI tab says when Jev
  // is turned off, which explains a missing assessment.
  const [detailResult, contextResult, assessmentsResult, healthResult] = await Promise.all([
    getAlert(session, alertId),
    getAlertContext(session, alertId),
    listAssessments(session, alertId),
    getHealth(session),
  ]);

  if (!detailResult.ok) {
    if (detailResult.error.kind === "not_found") {
      return (
        <>
          <PageHeader title="Alert not found" />
          <NotFoundState backHref="/detections" backLabel="Back to Detections" requestId={detailResult.error.requestId}>
            No alert <span className="font-mono text-foreground">{shortId(alertId, 8)}</span> exists in the alert store; it may have
            aged out of retention, or the link is wrong.
          </NotFoundState>
        </>
      );
    }
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
  const evidenceRows = new Set(detail.evidence.map((e) => e.event_id));
  const canEdit = permissions.changeAlertState(session.role);
  const inputHash = context?.input_hash ?? null;
  const aiOutdated = triage !== null && inputHash !== null && triage.context_input_hash !== inputHash;
  const issues = context ? coverageIssues(context) : 0;
  const providers = healthResult.ok ? healthResult.data.ai : null;
  const related = context ? relatedRows(context) : [];
  const detectorFeatures = context?.alert.features ?? alert.features ?? {};
  const natShared =
    detectorFeatures.src_ip_shared_nat === true || detectorFeatures.source_ip_shared_nat === true || natSharedCount(related) > 0;
  const natSources = natShared
    ? [...new Set(detail.evidence.map((e) => e.src_ip).filter((ip): ip is string => Boolean(ip)))].slice(0, 2)
    : null;

  const tabs: TabSpec[] = [
    { key: "overview", label: "Overview" },
    { key: "timeline", label: "Timeline", count: context?.timeline.length ?? null },
    { key: "evidence", label: "Evidence", count: detail.evidence.length },
    { key: "correlation", label: "Correlation", count: context ? related.length : null },
    { key: "ai", label: "AI", attention: aiOutdated ? "Jev's triage was made on an earlier investigation context" : null },
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
        assessments={assessments.filter((a) => a.task === "triage")}
        assessmentsError={assessmentsResult.ok ? null : assessmentsResult.error}
        currentInputHash={inputHash}
        triage={triage}
        triageAvailability={providerAvailability(providers, "triage")}
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
      <HeaderCard detail={detail} now={now} canEdit={canEdit} natSources={natSources} />
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

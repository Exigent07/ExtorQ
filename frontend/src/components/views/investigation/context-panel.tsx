import { FileWarning, RadioTower, TriangleAlert } from "lucide-react";
import Link from "next/link";

import { Disclosure } from "@/components/console/disclosure";
import { Hint } from "@/components/console/hint";
import { SplitBar } from "@/components/console/kpi-card";
import { CardLink, SectionCard } from "@/components/console/section-card";
import { SeverityBadge } from "@/components/console/severity";
import { EmptyState, ErrorState, Notice } from "@/components/console/states";
import { HealthBadge, StatusPill } from "@/components/console/status-badge";
import { RelativeTime, Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ApiFailure } from "@/lib/api/result";
import type { InvestigationContext } from "@/lib/api/schemas";
import { FINDING_STATE } from "@/lib/findings";
import { formatCount, formatDuration } from "@/lib/format";
import { assetHref } from "@/lib/security/ids";

import { Eyebrow } from "./marks";
import { resolvePlurals } from "./model";

const MAX_FINDINGS = 10;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const SEV_BAR: Record<(typeof SEVERITIES)[number], string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

/**
 * One status per source row: stale (with what else is known in its hint), else a gap in the
 * window, else the reported health. Never two badges for one source.
 */
function SourceStatus({ c }: { c: InvestigationContext["coverage"][number] }) {
  const health = c.status === "unknown" ? "health unknown" : `last health ${c.status}`;
  if (c.stale) {
    const detail = [
      "No successful collection within the staleness budget when the context was built",
      health,
      c.gap_during_window ? "a gap was also reported in the alert window" : null,
    ]
      .filter(Boolean)
      .join("; ");
    return (
      <Hint content={`${detail}.`}>
        <StatusPill tone="warn" label="Stale" />
      </Hint>
    );
  }
  if (c.gap_during_window) {
    return (
      <Hint content={`The source reported a gap (lost or delayed data) during the alert window; ${health}.`}>
        <StatusPill tone="warn" label="Gap in window" />
      </Hint>
    );
  }
  return <HealthBadge status={c.status} />;
}

function BulletList({ items, tone = "neutral" }: { items: string[]; tone?: "neutral" | "warn" }) {
  return (
    <ul className="grid list-disc gap-1.5 pl-4 text-sm leading-relaxed text-fg-2 marker:text-fg-faint">
      {items.map((item, i) => (
        <li key={i} className={tone === "warn" ? "marker:text-health-warn" : undefined}>
          <UntrustedText value={item} limit={320} />
        </li>
      ))}
    </ul>
  );
}

/**
 * Context tab: the telemetry the investigation depends on (coverage per source with staleness
 * and gaps in the window, missing telemetry), the limits of the context and of the rule, and
 * posture findings on the asset as captured with the context.
 */
export function ContextPanel({
  context,
  contextError,
  now,
}: {
  context: InvestigationContext | null;
  contextError: ApiFailure | null;
  now: string;
}) {
  if (!context) {
    return (
      <SectionCard title="Coverage and known gaps" titleId="coverage-gaps-title" icon={RadioTower}>
        <ErrorState what="the investigation context" error={contextError ?? { kind: "server", message: "No context was returned.", requestId: "-" }} />
      </SectionCard>
    );
  }
  const coverage = context.coverage;
  const gaps = coverage.filter((c) => c.stale || c.gap_during_window).length;
  const notes = context.missing_telemetry.length;
  const findings = context.findings.slice(0, MAX_FINDINGS);
  const moreFindings = context.findings.length - findings.length;
  const bySeverity = SEVERITIES.map((sev) => ({ sev, n: context.findings.filter((f) => f.severity === sev).length })).filter(
    (p) => p.n > 0,
  );
  const issueParts = [
    gaps > 0 ? `${formatCount(gaps)} source${gaps === 1 ? "" : "s"} stale or gapped` : null,
    notes > 0 ? `${formatCount(notes)} missing-telemetry note${notes === 1 ? "" : "s"}` : null,
  ].filter(Boolean);

  return (
    <div className="grid gap-6">
      <SectionCard
        title="Coverage and known gaps"
        titleId="coverage-gaps-title"
        icon={RadioTower}
        description={
          <>
            Sources the rule reads, as recorded when the context was built (<Timestamp value={context.created_at} className="text-xs" />
            ); live collector health is on the asset and System health pages.
          </>
        }
        meta={
          <span className={issueParts.length > 0 ? "text-health-warn" : undefined}>
            {issueParts.length > 0 ? issueParts.join(" · ") : "No gap or missing telemetry recorded"}
          </span>
        }
        flush
      >
        {coverage.length === 0 ? (
          <div className="px-5 pb-3">
            <EmptyState>The investigation context records no source coverage for this alert.</EmptyState>
          </div>
        ) : (
          <Table aria-label="Telemetry source coverage during the alert window">
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Last success (UTC)</TableHead>
                <TableHead className="hidden text-right sm:table-cell">Lag</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {coverage.map((c) => (
                <TableRow key={`${c.source_type}|${c.collector_id ?? ""}`} className="hover:bg-transparent">
                  <TableCell className="w-full max-w-0 min-w-48 py-3 whitespace-normal">
                    <div className="font-mono text-xs text-foreground">
                      <UntrustedText value={c.source_type} limit={48} />
                    </div>
                    <div className="mt-0.5 text-xs text-muted-foreground">
                      {c.collector_id ? (
                        <span className="font-mono">
                          <UntrustedText value={c.collector_id} limit={64} />
                        </span>
                      ) : (
                        "No collector recorded"
                      )}
                      {c.note ? (
                        <>
                          {" · "}
                          <UntrustedText value={c.note} limit={200} />
                        </>
                      ) : null}
                    </div>
                  </TableCell>
                  <TableCell className="py-3">
                    <div className="flex items-center text-sm">
                      <SourceStatus c={c} />
                    </div>
                  </TableCell>
                  <TableCell className="py-3 text-right">
                    <Timestamp value={c.last_success_at} />
                  </TableCell>
                  <TableCell className="hidden py-3 text-right text-sm text-fg-2 tabular-nums sm:table-cell">
                    {c.lag_seconds === null || c.lag_seconds === undefined ? (
                      <span className="text-muted-foreground">{formatDuration(c.lag_seconds)}</span>
                    ) : (
                      formatDuration(c.lag_seconds)
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <div className="grid gap-6 px-5 pt-5 pb-3">
          {context.missing_telemetry.length > 0 ? (
            <div className="grid gap-2">
              <Eyebrow>Missing telemetry</Eyebrow>
              <Notice tone="warn" icon={TriangleAlert}>
                <span className="grid gap-1">
                  {context.missing_telemetry.map((m, i) => (
                    <span key={i}>
                      <UntrustedText value={resolvePlurals(m)} limit={320} />
                    </span>
                  ))}
                </span>
              </Notice>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {gaps > 0
                ? "No missing-telemetry note was stored for the alert window; the source status above still reports a gap or staleness."
                : "No missing telemetry was recorded for the alert window."}
            </p>
          )}
          {context.limitations.length > 0 ? (
            <div className="grid gap-2">
              <Eyebrow>Limitations of this context</Eyebrow>
              <BulletList items={context.limitations} />
            </div>
          ) : null}
          {context.rule.version !== context.alert.rule_version ? (
            <Notice tone="warn">Blind spots and known false positives for this alert&apos;s rule version are unavailable.</Notice>
          ) : context.rule.blind_spots.length > 0 || context.rule.false_positives.length > 0 ? (
            <div className="grid gap-6 border-t border-hairline-soft pt-5 @container">
              <div className="grid gap-6 @2xl:grid-cols-2">
                <div className="grid content-start gap-2">
                  <Eyebrow>Rule blind spots</Eyebrow>
                  {context.rule.blind_spots.length > 0 ? (
                    <BulletList items={context.rule.blind_spots} />
                  ) : (
                    <p className="text-sm text-muted-foreground">None documented.</p>
                  )}
                </div>
                <div className="grid content-start gap-2">
                  <Eyebrow>Known false positives</Eyebrow>
                  {context.rule.false_positives.length > 0 ? (
                    <BulletList items={context.rule.false_positives} />
                  ) : (
                    <p className="text-sm text-muted-foreground">None documented.</p>
                  )}
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </SectionCard>

      <SectionCard
        title="Findings on the asset"
        titleId="context-findings-title"
        icon={FileWarning}
        description="Posture findings captured with the investigation context"
        action={
          <Link href={`${assetHref(context.asset.asset_id)}?tab=findings`} className="group/link">
            <CardLink>All findings</CardLink>
          </Link>
        }
        meta={
          context.findings.length > 0 ? (
            <span className="tabular-nums">
              {formatCount(context.findings.length)} captured{context.truncated.findings ? " (capped)" : ""}
            </span>
          ) : undefined
        }
        flush
      >
        {findings.length === 0 ? (
          <div className="px-5 pb-3">
            <EmptyState>No posture finding on this asset was captured in the investigation context.</EmptyState>
          </div>
        ) : (
          <div className="grid gap-3 px-5 pb-3">
            <SplitBar
              parts={bySeverity.map((p) => ({ key: p.sev, value: p.n, className: SEV_BAR[p.sev] }))}
              label={bySeverity.map((p) => `${p.n} ${p.sev}`).join(", ")}
            />
            <p className="text-sm text-fg-2 tabular-nums">
              {bySeverity.map((p, i) => (
                <span key={p.sev}>
                  {i > 0 ? <span className="text-fg-faint"> · </span> : null}
                  {formatCount(p.n)} <span className="text-muted-foreground">{p.sev}</span>
                </span>
              ))}
              <span className="text-muted-foreground">
                {" "}
                on this asset as captured with the context{context.truncated.findings ? " (the builder capped the list)" : ""}. Posture
                context only: nothing links these findings to the alert.
              </span>
            </p>
            <Disclosure label={`Show the ${formatCount(findings.length)} first findings`} openLabel="Hide the findings">
              <div className="-mx-5 mt-3">
          <Table aria-label="Findings on the asset" className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="w-28">Severity</TableHead>
                <TableHead>Finding</TableHead>
                <TableHead className="hidden w-28 sm:table-cell">State</TableHead>
                <TableHead className="w-28 text-right">Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((f) => {
                const state = FINDING_STATE[f.state];
                return (
                  <TableRow key={f.finding_id} className="hover:bg-transparent">
                    <TableCell className="py-2.5">
                      <SeverityBadge severity={f.severity} />
                    </TableCell>
                    <TableCell className="py-2.5">
                      <div className="min-w-0 text-sm text-foreground">
                        <UntrustedText value={f.title} limit={240} oneLine />
                      </div>
                      <div className="min-w-0 text-xs text-muted-foreground">
                        <UntrustedText value={`${f.scanner} · ${f.check_id}`} limit={120} oneLine mono />
                      </div>
                    </TableCell>
                    <TableCell className="hidden py-2.5 text-sm sm:table-cell">
                      {state ? (
                        <Hint content={state.detail}>
                          <span className={f.state === "unverified" ? "text-health-warn" : f.state === "resolved" ? "text-muted-foreground" : "text-fg-2"}>
                            {state.label}
                          </span>
                        </Hint>
                      ) : (
                        <span className="text-fg-2">{f.state}</span>
                      )}
                    </TableCell>
                    <TableCell className="py-2.5 text-right text-sm">
                      <RelativeTime value={f.last_observed_at} now={now} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
              </div>
              {moreFindings > 0 ? (
                <p className="pt-3 text-xs text-muted-foreground">
                  {formatCount(moreFindings)} more in the investigation context. The asset page lists every finding.
                </p>
              ) : null}
            </Disclosure>
          </div>
        )}
      </SectionCard>
    </div>
  );
}

import { cn } from "cn";
import { FileWarning } from "lucide-react";
import Link from "next/link";

import { CardLink, SectionCard } from "@/components/console/section-card";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/components/console/severity";
import { LifecycleNotice } from "@/components/views/findings/lifecycle-notice";
import type { FindingsSummary, Severity } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

const BAR: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const DOT: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

/**
 * Posture findings by severity as a bar list on one scale (bar length = count / largest
 * count), the count and its share of the total on the right. Lifecycle-less data is labelled.
 */
export function FindingsBySeverityCard({ summary, className }: { summary: FindingsSummary; className?: string }) {
  const { counts } = summary;
  const max = Math.max(0, ...SEVERITY_ORDER.map((s) => counts[s]));
  const total = counts.total;
  return (
    <SectionCard
      title="Findings by severity"
      titleId="posture-title"
      icon={FileWarning}
      description={
        <>
          <span className="text-fg-2 tabular-nums">{formatCount(total)}</span>{" "}
          {summary.lifecycle_available ? "open posture findings" : "findings observed within retention"} from scans
        </>
      }
      className={className}
      action={
        <Link href="/assets" className="group/link">
          <CardLink>Per asset</CardLink>
        </Link>
      }
    >
      <ul className="grid gap-3" aria-label="Findings by severity">
        {SEVERITY_ORDER.map((severity) => {
          const count = counts[severity];
          const width = max > 0 ? (count / max) * 100 : 0;
          const share = total > 0 ? (count / total) * 100 : 0;
          return (
            <li key={severity} className="grid grid-cols-[76px_minmax(0,1fr)_auto] items-center gap-3">
              <span className="flex items-center gap-2 text-sm text-fg-2">
                <span aria-hidden="true" className={cn("size-2 rounded-full", DOT[severity])} />
                {SEVERITY_LABEL[severity]}
              </span>
              <span className="h-2 overflow-hidden rounded-full bg-hairline-soft" aria-hidden="true">
                {count > 0 ? (
                  <span
                    className={cn("block h-full min-w-1 rounded-full opacity-90", BAR[severity])}
                    style={{ width: `${width}%` }}
                  />
                ) : null}
              </span>
              <span className="text-right text-sm tabular-nums">
                <span className={count > 0 ? "font-medium text-foreground" : "text-muted-foreground"}>{formatCount(count)}</span>
                <span className="ml-2 inline-block w-11 text-xs text-muted-foreground">
                  {total > 0 ? `${share > 0 && share < 0.1 ? "<0.1" : share.toFixed(1)}%` : "—"}
                </span>
              </span>
            </li>
          );
        })}
      </ul>
      {summary.unverified && summary.unverified.total > 0 ? (
        <p className="mt-4 text-xs text-muted-foreground">
          <span className="text-fg-2 tabular-nums">{formatCount(summary.unverified.total)}</span> unverified: the latest scan was
          partial or failed, so their current state cannot be confirmed.
        </p>
      ) : null}
      <LifecycleNotice summary={summary} />
      <p className="mt-4 text-xs text-muted-foreground">Vulnerabilities and misconfigurations from the scanners are listed on each asset.</p>
    </SectionCard>
  );
}

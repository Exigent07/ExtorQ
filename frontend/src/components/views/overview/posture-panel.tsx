import { Info } from "lucide-react";

import { Panel } from "@/components/console/panel";
import { SEVERITY_ORDER, SeverityTag } from "@/components/console/severity";
import type { FindingsSummary } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";

/** Notice shown whenever finding lifecycle (open / resolved) cannot be derived. */
export function LifecycleNotice({ summary }: { summary: Pick<FindingsSummary, "lifecycle_available" | "note"> }) {
  if (summary.lifecycle_available) return null;
  return (
    <p className="mt-3 flex items-start gap-2 rounded-md border border-warn/30 bg-warn-bg px-3 py-2 text-xs text-warn">
      <Info className="mt-0.5 size-3.5 flex-none" aria-hidden="true" />
      <span>
        Finding lifecycle is unavailable: counts are distinct findings observed within retention, not
        their open or resolved state.
        {summary.note ? <span className="block text-ink-2">{summary.note}</span> : null}
      </span>
    </p>
  );
}

export function PosturePanel({ summary }: { summary: FindingsSummary }) {
  const { counts } = summary;
  const label = summary.lifecycle_available ? "Open findings" : "Observed findings";
  return (
    <Panel
      titleId="posture-title"
      title="Security posture"
      meta={<span>{label}</span>}
    >
      <ul className="divide-y divide-rule">
        {SEVERITY_ORDER.map((severity) => (
          <li key={severity} className="flex h-8 items-center justify-between">
            <SeverityTag severity={severity} />
            <span className={counts[severity] > 0 ? "font-mono text-sm text-ink" : "font-mono text-sm text-muted-foreground"}>
              {formatCount(counts[severity])}
            </span>
          </li>
        ))}
        <li className="flex h-9 items-center justify-between">
          <span className="text-ink-2">Total</span>
          <span className="font-mono text-base text-ink">{formatCount(counts.total)}</span>
        </li>
      </ul>
      <LifecycleNotice summary={summary} />
      <p className="mt-3 text-xs text-muted-foreground">
        Source: <span className="font-mono">{summary.source}</span>. Per-asset vulnerabilities and
        misconfigurations are listed on each asset.
      </p>
    </Panel>
  );
}

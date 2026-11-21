import { cn } from "cn";
import Link from "next/link";

import { Panel } from "@/components/console/panel";
import { EmptyState } from "@/components/console/states";
import type { ServicesSummary } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { SERVICE_GROUPS, serviceKindLabel } from "@/lib/services";

const PARTS = [
  { key: "monitored", label: "Monitored", fill: "bg-ok", text: "text-ok" },
  { key: "degraded", label: "Degraded", fill: "bg-warn", text: "text-warn" },
  { key: "unmonitored", label: "Unmonitored", fill: "bg-warn/50", text: "text-warn" },
  { key: "planned", label: "Planned adapter", fill: "bg-control", text: "text-ink-2" },
  { key: "unsupported", label: "Unsupported", fill: "bg-raised", text: "text-ink-2" },
] as const;

/**
 * Service coverage across every asset: one 100% bar (true proportions, 2px seams) and the
 * same counts per service kind. Unsupported and unmonitored services are shown, not hidden.
 */
export function ServiceCoveragePanel({ summary }: { summary: ServicesSummary | null | undefined }) {
  return (
    <Panel
      title="Service coverage"
      titleId="service-coverage-title"
      meta={summary?.reported ? <span>{formatCount(summary.coverage.total)} services discovered across all assets</span> : null}
      action={
        <Link href="/assets" className="hover:text-ink">
          Assets
        </Link>
      }
    >
      {!summary ? (
        <EmptyState>The analyst API did not report service coverage.</EmptyState>
      ) : !summary.reported ? (
        <EmptyState>Service discovery has not reported for any asset yet, so service coverage is unknown.</EmptyState>
      ) : (
        <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div>
            <div className="flex h-3 w-full gap-0.5 overflow-hidden rounded-sm" role="img" aria-label={PARTS.map((p) => `${p.label} ${summary.coverage[p.key]}`).join(", ")}>
              {PARTS.map((p) =>
                summary.coverage[p.key] > 0 ? (
                  <span
                    key={p.key}
                    className={cn("h-full", p.fill)}
                    style={{ width: `${(summary.coverage[p.key] / Math.max(1, summary.coverage.total)) * 100}%` }}
                  />
                ) : null,
              )}
            </div>
            <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5 text-xs">
              {PARTS.map((p) => (
                <li key={p.key} className="flex items-center gap-1.5">
                  <span aria-hidden="true" className={cn("size-2 rounded-[2px]", p.fill)} />
                  <span className="text-muted-foreground">{p.label}</span>
                  <span className={cn("font-mono", summary.coverage[p.key] > 0 ? p.text : "text-muted-foreground")}>
                    {formatCount(summary.coverage[p.key])}
                  </span>
                </li>
              ))}
            </ul>
            {summary.removed > 0 || summary.truncated || summary.note ? (
              <p className="mt-2 text-xs text-muted-foreground">
                {summary.removed > 0 ? `${formatCount(summary.removed)} removed services not counted. ` : ""}
                {summary.truncated ? "More service records exist than the API evaluated. " : ""}
                {summary.note ?? ""}
              </p>
            ) : null}
          </div>
          <table className="w-full text-sm" aria-label="Service coverage by kind">
            <thead>
              <tr className="text-left text-xs text-muted-foreground">
                <th className="pb-1.5 font-normal">Kind</th>
                <th className="pb-1.5 text-right font-normal">Discovered</th>
                <th className="pb-1.5 text-right font-normal">Monitored</th>
                <th className="pb-1.5 text-right font-normal" title="Degraded or unmonitored: an adapter exists but its telemetry is not fully collected">
                  Gaps
                </th>
              </tr>
            </thead>
            <tbody>
              {[...summary.by_kind]
                .sort(
                  (a, b) =>
                    SERVICE_GROUPS.findIndex((g) => g.kind === a.service_kind) -
                    SERVICE_GROUPS.findIndex((g) => g.kind === b.service_kind),
                )
                .map((k) => {
                  const gaps = k.coverage.degraded + k.coverage.unmonitored;
                  return (
                    <tr key={k.service_kind} className="border-t border-rule">
                      <td className="py-1.5 text-ink-2">
                        {SERVICE_GROUPS.find((g) => g.kind === k.service_kind)?.title ?? serviceKindLabel(k.service_kind)}
                      </td>
                      <td className="py-1.5 text-right font-mono text-xs text-ink">{formatCount(k.coverage.total)}</td>
                      <td className="py-1.5 text-right font-mono text-xs text-ink-2">{formatCount(k.coverage.monitored)}</td>
                      <td className={cn("py-1.5 text-right font-mono text-xs", gaps > 0 ? "text-warn" : "text-muted-foreground")}>
                        {formatCount(gaps)}
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

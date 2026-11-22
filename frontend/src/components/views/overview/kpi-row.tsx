import { Activity, FileWarning, ShieldAlert, Waypoints } from "lucide-react";

import { CoverageMark, type ArcTone } from "@/components/console/brand-mark";
import { KpiCard, SplitBar } from "@/components/console/kpi-card";
import { SEVERITY_LABEL } from "@/components/console/severity";
import type { CollectionHealthSummary, Severity } from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import {
  type AlertKpi,
  type AssetKpi,
  type ClassRow,
  type CollectionKpi,
  type FindingsKpi,
  plural,
} from "@/lib/overview";

const SEV_FILL: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

const STATUS_LABEL = { ok: "Healthy", warn: "Degraded", bad: "Failing", off: "Unknown" } as const;

function Figures({ items }: { items: { label: string; value: number; strong?: boolean }[] }) {
  return (
    <span className="flex flex-wrap gap-x-3 gap-y-1">
      {items.map((item) => (
        <span key={item.label} className="whitespace-nowrap">
          <span className={item.value > 0 && item.strong ? "text-foreground tabular-nums" : "text-fg-2 tabular-nums"}>
            {formatCount(item.value)}
          </span>{" "}
          {item.label}
        </span>
      ))}
    </span>
  );
}

/**
 * Headline figures: open alerts by severity, assets reporting per class, critical + high
 * findings, collectors reporting OK. Each card states what its number is made of and links
 * to the page that explains it.
 */
export function KpiRow({
  alerts,
  assets,
  classes,
  findings,
  collection,
  health,
}: {
  alerts: AlertKpi;
  assets: AssetKpi;
  classes: ClassRow[];
  findings: FindingsKpi;
  collection: CollectionKpi;
  health: CollectionHealthSummary;
}) {
  const arcTones = classes.map((c) => c.tone as ArcTone);
  const coverageLabel = classes.map((c) => `${c.label} ${c.statusLabel.toLowerCase()}`).join(", ");
  const severityParts = alerts.parts.filter((p) => p.severity !== "info" || p.count > 0);

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <KpiCard
        label="Open alerts"
        icon={ShieldAlert}
        value={formatCount(alerts.total)}
        status={
          alerts.total === 0
            ? { tone: "ok", label: "None open" }
            : alerts.tone === "bad"
              ? { tone: "bad", label: "Critical open" }
              : alerts.tone === "warn"
                ? { tone: "warn", label: "High open" }
                : undefined
        }
        footer={
          <SplitBar
            label={severityParts.map((p) => `${p.count} ${SEVERITY_LABEL[p.severity].toLowerCase()}`).join(", ")}
            parts={severityParts.map((p) => ({ key: p.severity, value: p.count, className: SEV_FILL[p.severity] }))}
          />
        }
        sub={
          <Figures
            items={severityParts.map((p) => ({
              label: SEVERITY_LABEL[p.severity].toLowerCase(),
              value: p.count,
              strong: p.severity === "critical" || p.severity === "high",
            }))}
          />
        }
        href="/detections"
      />

      <KpiCard
        label="Assets reporting"
        icon={Waypoints}
        value={formatCount(assets.reporting)}
        unit={`/ ${formatCount(assets.total)}`}
        status={{ tone: assets.tone, label: STATUS_LABEL[assets.tone] }}
        visual={
          arcTones.length === 4 ? (
            <CoverageMark
              tones={{ top: arcTones[0] ?? "off", right: arcTones[1] ?? "off", bottom: arcTones[2] ?? "off", left: arcTones[3] ?? "off" }}
              label={`Coverage by asset class: ${coverageLabel}`}
              className="size-11"
            />
          ) : null
        }
        sub={
          <>
            <span className="text-fg-2 tabular-nums">{formatCount(assets.classesHealthy)}</span> of{" "}
            {plural(assets.classesTotal, "monitored class", "monitored classes")} healthy
          </>
        }
        href="/assets"
      />

      <KpiCard
        label={findings.lifecycle ? "Critical + high findings" : "Critical + high findings (observed)"}
        icon={FileWarning}
        value={formatCount(findings.serious)}
        unit={`/ ${formatCount(findings.total)}`}
        footer={
          <SplitBar
            label={`${findings.critical} critical, ${findings.high} high, ${findings.total - findings.serious} medium, low or info`}
            parts={[
              { key: "critical", value: findings.critical, className: SEV_FILL.critical },
              { key: "high", value: findings.high, className: SEV_FILL.high },
              { key: "rest", value: Math.max(0, findings.total - findings.serious), className: "bg-hairline-strong" },
            ]}
          />
        }
        sub={
          <Figures
            items={[
              { label: "critical", value: findings.critical, strong: true },
              { label: "high", value: findings.high, strong: true },
              ...(findings.unverified > 0 ? [{ label: "unverified", value: findings.unverified }] : []),
            ]}
          />
        }
        href="/assets"
      />

      <KpiCard
        label="Collectors OK"
        icon={Activity}
        value={health.no_collector_reports ? "0" : formatCount(collection.ok)}
        unit={health.no_collector_reports ? undefined : `/ ${formatCount(collection.total)}`}
        status={{ tone: collection.tone, label: collection.statusLabel }}
        footer={
          <SplitBar
            label={`${health.collectors_ok} OK, ${health.collectors_stale} stale, ${health.collectors_failing} failing`}
            parts={[
              { key: "ok", value: health.collectors_ok, className: "bg-health-ok" },
              { key: "stale", value: health.collectors_stale, className: "bg-health-warn" },
              { key: "failing", value: health.collectors_failing, className: "bg-health-bad" },
            ]}
          />
        }
        sub={
          health.no_collector_reports ? (
            "No collector has reported yet."
          ) : (
            <Figures
              items={[
                { label: "stale", value: health.collectors_stale, strong: true },
                { label: "failing", value: health.collectors_failing, strong: true },
                { label: `of ${formatCount(health.pipeline_components)} pipeline parts not OK`, value: health.pipeline_unhealthy, strong: true },
              ]}
            />
          )
        }
        href="/health"
      />
    </div>
  );
}

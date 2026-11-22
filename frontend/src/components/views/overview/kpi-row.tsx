import { Activity, FileWarning, ShieldAlert, Waypoints } from "lucide-react";

import { CoverageMark, type ArcTone } from "@/components/console/brand-mark";
import { KpiCard, KpiFigures, SplitBar } from "@/components/console/kpi-card";
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
    <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
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
          <KpiFigures
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
              className="size-8"
            />
          ) : null
        }
        sub={
          <span title="Kubernetes nodes report through their cluster and are not counted on their own (the Assets page counts the same way).">
            <span className="text-fg-2 tabular-nums">{formatCount(assets.classesHealthy)}</span> of{" "}
            {plural(assets.classesTotal, "class", "classes")} healthy
          </span>
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
          <KpiFigures
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
            <>
              <KpiFigures
                items={[
                  { label: "stale", value: health.collectors_stale, strong: true },
                  { label: "failing", value: health.collectors_failing, strong: true },
                ]}
              />
              <span className="text-fg-faint"> · </span>
              pipeline{" "}
              <span className={health.pipeline_unhealthy > 0 ? "text-foreground tabular-nums" : "text-fg-2 tabular-nums"}>
                {formatCount(health.pipeline_components - health.pipeline_unhealthy)} / {formatCount(health.pipeline_components)}
              </span>{" "}
              OK
            </>
          )
        }
        href="/health"
      />
    </div>
  );
}

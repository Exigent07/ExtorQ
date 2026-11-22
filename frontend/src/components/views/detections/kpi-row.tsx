import { Inbox, ListChecks, ServerCog, ShieldAlert } from "lucide-react";

import { KpiCard, KpiFigures, SplitBar } from "@/components/console/kpi-card";
import { SEVERITY_LABEL, SEVERITY_ORDER } from "@/components/console/severity";
import type { Tone } from "@/components/console/status-badge";
import { UntrustedText } from "@/components/console/untrusted-text";
import type { Severity } from "@/lib/api/schemas";
import { DASH, formatCount, formatRelative } from "@/lib/format";

import { type AlertFigures, plural, type RuleFigures } from "./model";

const SEV_FILL: Record<Severity, string> = {
  critical: "bg-sev-critical",
  high: "bg-sev-high",
  medium: "bg-sev-medium",
  low: "bg-sev-low",
  info: "bg-sev-info",
};

/**
 * Detections headline figures for the selected range: alerts by severity, open alerts by
 * workflow state, the assets they concern, and whether the rules behind them run. Counts come
 * from the alerts the API returned for the range (complete unless the card says otherwise)
 * and from the rule list; nothing is estimated.
 */
export function DetectionsKpiRow({
  alerts,
  rules,
  rangeLabel,
  now,
}: {
  alerts: AlertFigures | null;
  rules: RuleFigures | null;
  /** "last 7 days" */
  rangeLabel: string;
  /** When the alert list was received (relative times). */
  now: string;
}) {
  const present = alerts ? SEVERITY_ORDER.filter((s) => alerts.bySeverity[s] > 0) : [];
  const partial = alerts && !alerts.complete ? `of the ${formatCount(alerts.loaded)} newest loaded` : null;

  const openTone: { tone: Tone; label: string } | undefined = !alerts
    ? undefined
    : alerts.openBySeverity.critical > 0
      ? { tone: "bad", label: "Critical open" }
      : alerts.openBySeverity.high > 0
        ? { tone: "warn", label: "High open" }
        : alerts.open === 0
          ? { tone: "ok", label: "None open" }
          : undefined;

  const ruleTone: { tone: Tone; label: string } | undefined = !rules
    ? undefined
    : rules.failingNow > 0
      ? { tone: "bad", label: `${formatCount(rules.failingNow)} failing` }
      : rules.overdue > 0
        ? { tone: "warn", label: `${formatCount(rules.overdue)} overdue` }
        : rules.neverRan > 0
          ? { tone: "warn", label: `${formatCount(rules.neverRan)} never ran` }
          : rules.quietSources > 0
            ? // A rule whose input went silent is a blind spot, not a green state.
              { tone: "warn", label: `${formatCount(rules.quietSources)} quiet source${rules.quietSources === 1 ? "" : "s"}` }
            : rules.total > 0
              ? { tone: "ok", label: "All running" }
              : undefined;

  return (
    <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
      <KpiCard
        label="Alerts in range"
        icon={ShieldAlert}
        value={alerts ? (alerts.total === null ? `${formatCount(alerts.loaded)}+` : formatCount(alerts.total)) : DASH}
        footer={
          alerts ? (
            <SplitBar
              label={present.map((s) => `${alerts.bySeverity[s]} ${SEVERITY_LABEL[s].toLowerCase()}`).join(", ") || "No alerts"}
              parts={SEVERITY_ORDER.map((s) => ({ key: s, value: alerts.bySeverity[s], className: SEV_FILL[s] }))}
            />
          ) : null
        }
        sub={
          !alerts ? (
            "The alert list could not be loaded."
          ) : alerts.loaded === 0 ? (
            `No alert with activity in the ${rangeLabel}.`
          ) : (
            <>
              <KpiFigures
                items={present.map((s) => ({
                  label: SEVERITY_LABEL[s].toLowerCase(),
                  value: alerts.bySeverity[s],
                  strong: s === "critical" || s === "high",
                }))}
              />
              <span className="mt-1 block">
                <span className="text-fg-2 tabular-nums">{formatCount(alerts.rulesFiring)}</span>{" "}
                {alerts.rulesFiring === 1 ? "rule" : "rules"} fired ·{" "}
                <span className="text-fg-2 tabular-nums">{formatCount(alerts.simulated)}</span> simulation-tagged
              </span>
              {partial ? <span className="mt-1 block text-xs">Counted {partial}</span> : null}
            </>
          )
        }
      />

      <KpiCard
        label="Open"
        icon={Inbox}
        value={alerts ? formatCount(alerts.open) : DASH}
        unit={alerts ? `/ ${formatCount(alerts.loaded)}` : undefined}
        status={openTone}
        footer={
          alerts ? (
            <SplitBar
              label={`${alerts.untriaged} new, ${alerts.acknowledged} acknowledged, ${alerts.investigating} investigating, ${alerts.closed} closed`}
              parts={[
                { key: "new", value: alerts.untriaged, className: "bg-fg-2" },
                { key: "acknowledged", value: alerts.acknowledged, className: "bg-fg-2/50" },
                { key: "investigating", value: alerts.investigating, className: "bg-sev-medium" },
                { key: "closed", value: alerts.closed, className: "bg-hairline-strong" },
              ]}
            />
          ) : null
        }
        sub={
          alerts ? (
            <>
              <KpiFigures
                items={[
                  { label: "new", value: alerts.untriaged, strong: true },
                  { label: "investigating", value: alerts.investigating },
                  { label: "closed", value: alerts.closed },
                ]}
              />
              <span className="mt-1 block">
                {alerts.oldestOpenSince ? (
                  <>
                    Oldest open since <span className="text-fg-2">{formatRelative(alerts.oldestOpenSince, now)}</span>
                  </>
                ) : (
                  "No open alert in this range"
                )}
              </span>
              {partial ? <span className="mt-1 block text-xs">Counted {partial}</span> : null}
            </>
          ) : (
            "Unknown while the alert list is unavailable."
          )
        }
      />

      <KpiCard
        label="Assets with alerts"
        icon={ServerCog}
        value={alerts ? formatCount(alerts.assets.length) : DASH}
        sub={
          !alerts ? (
            "Unknown while the alert list is unavailable."
          ) : alerts.assets.length === 0 ? (
            `No asset raised an alert in the ${rangeLabel}.`
          ) : (
            <span className="grid gap-1">
              {alerts.assets.slice(0, 2).map((asset) => (
                <span key={asset.assetId} className="flex min-w-0 items-baseline justify-between gap-3">
                  <span className="min-w-0 truncate font-mono text-xs">
                    <UntrustedText value={asset.assetId} plain limit={64} />
                  </span>
                  <span className="flex-none text-fg-2 tabular-nums">{plural(asset.count, "alert")}</span>
                </span>
              ))}
              {alerts.assets.length > 2 ? (
                <span className="text-xs">and {plural(alerts.assets.length - 2, "more asset")}</span>
              ) : null}
            </span>
          )
        }
      />

      <KpiCard
        label="Rules"
        icon={ListChecks}
        value={rules ? formatCount(rules.enabled) : DASH}
        unit={rules ? `/ ${formatCount(rules.total)} enabled` : undefined}
        status={ruleTone}
        footer={
          rules ? (
            <SplitBar
              label={`Last run: ${rules.succeededNow} succeeded, ${rules.skippedNow} skipped, ${rules.failingNow} failed, ${rules.total - rules.succeededNow - rules.skippedNow - rules.failingNow} never ran`}
              parts={[
                { key: "succeeded", value: rules.succeededNow, className: "bg-health-ok" },
                { key: "skipped", value: rules.skippedNow, className: "bg-health-warn" },
                { key: "failed", value: rules.failingNow, className: "bg-health-bad" },
                {
                  key: "never",
                  value: rules.total - rules.succeededNow - rules.skippedNow - rules.failingNow,
                  className: "bg-health-off",
                },
              ]}
            />
          ) : null
        }
        sub={
          rules ? (
            <KpiFigures
              items={[
                { label: rules.failures24h === 1 ? "failure" : "failures", value: rules.failures24h, strong: true },
                { label: "runs in 24 h", value: rules.runs24h },
              ]}
            />
          ) : (
            "The rule list could not be loaded."
          )
        }
        href={rules && rules.quietSources > 0 ? "/detections?tab=rules" : "/health#rule-health-title"}
      />
    </div>
  );
}

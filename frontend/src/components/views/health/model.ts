/**
 * System health view model: collector freshness against the staleness budget, the KPI
 * figures, gateway rejections and the Jev status labels. Pure and isomorphic; every figure is
 * taken or summed from the API's health response, never estimated.
 */
import type { Tone } from "@/components/console/status-badge";
import type {
  CollectorStatus,
  HealthResponse,
  PipelineComponentHealth,
  RuleHealthItem,
} from "@/lib/api/schemas";
import { formatCount } from "@/lib/format";
import { spoolBacklog } from "@/lib/health";

/** A collector is stale after this many collection intervals without a success (API rule). */
export const STALE_INTERVALS = 3;

const OTEL_DELIVERY_STATES = {
  delivering: { label: "Delivering", tone: "ok" },
  running_not_delivering: { label: "Running without delivery", tone: "warn" },
  degraded: { label: "Delivery degraded", tone: "warn" },
  backlogged: { label: "Delivery backlogged", tone: "warn" },
  dropping_records: { label: "Dropping records", tone: "bad" },
  unavailable: { label: "Delivery unavailable", tone: "bad" },
  unknown: { label: "Delivery unknown", tone: "off" },
} satisfies Record<string, { label: string; tone: Tone }>;

const OTEL_MEASURES = {
  queue_requests: "Queued requests",
  queue_capacity_requests: "Request capacity",
  accepted_records: "Source records accepted",
  sent_records: "Exporter records sent",
  send_failed_records: "Exporter send failures",
  enqueue_failed_records: "Exporter enqueue failures",
};

export function otelDelivery(c: Pick<CollectorStatus, "collector_type" | "details">) {
  if (c.collector_type !== "k8s_otel") return null;
  const state = c.details?.delivery_state;
  const status = typeof state === "string" && Object.hasOwn(OTEL_DELIVERY_STATES, state)
    ? OTEL_DELIVERY_STATES[state as keyof typeof OTEL_DELIVERY_STATES]
    : OTEL_DELIVERY_STATES.unknown;
  const measures = Object.entries(OTEL_MEASURES).map(([key, label]) => {
    const value = c.details?.[key];
    return { label, value: typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null };
  });
  return { ...status, measures };
}

export interface Freshness {
  /** Share of the staleness budget (3 intervals) used since the last success, 0..1. */
  ratio: number | null;
  tone: Tone;
  ageSeconds: number | null;
  budgetSeconds: number | null;
}

/**
 * Freshness of a collector: time since its last successful collection against 3 collection
 * intervals. The tone is the API's verdict (failed: red, stale: amber), not a guess from the
 * ratio; an unknown age leaves the bar empty.
 */
export function collectorFreshness(
  c: Pick<CollectorStatus, "seconds_since_success" | "last_success_at" | "interval_seconds" | "stale" | "status">,
  now: string,
): Freshness {
  const budget = c.interval_seconds > 0 ? c.interval_seconds * STALE_INTERVALS : null;
  let age: number | null = null;
  if (typeof c.seconds_since_success === "number" && Number.isFinite(c.seconds_since_success)) {
    age = Math.max(0, c.seconds_since_success);
  } else if (c.last_success_at) {
    const delta = (Date.parse(now) - Date.parse(c.last_success_at)) / 1000;
    age = Number.isFinite(delta) ? Math.max(0, delta) : null;
  }
  const ratio = budget !== null && age !== null ? Math.min(1, age / budget) : null;
  const tone: Tone = c.status === "failed" ? "bad" : c.stale ? "warn" : age === null ? "off" : "ok";
  return { ratio, tone, ageSeconds: age, budgetSeconds: budget };
}

export interface CollectorCounts {
  total: number;
  /** Status OK and not stale (the Overview's "Collectors OK"). */
  healthy: number;
  failed: number;
  /** Stale and not failed. */
  stale: number;
  /** Degraded and not stale. */
  degraded: number;
  /** Disabled or unknown and not stale. */
  other: number;
  tone: Tone;
  label: string;
}

/** Collectors partitioned so the parts add up to the total (each collector counted once). */
export function collectorCounts(collectors: Pick<CollectorStatus, "status" | "stale">[]): CollectorCounts {
  let healthy = 0;
  let failed = 0;
  let stale = 0;
  let degraded = 0;
  let other = 0;
  for (const c of collectors) {
    if (c.status === "failed") failed += 1;
    else if (c.stale) stale += 1;
    else if (c.status === "ok") healthy += 1;
    else if (c.status === "degraded") degraded += 1;
    else other += 1;
  }
  const total = collectors.length;
  const [tone, label]: [Tone, string] =
    total === 0
      ? ["bad", "No reports"]
      : failed > 0
        ? ["bad", "Failing"]
        : stale > 0 || degraded > 0
          ? ["warn", "Degraded"]
          : other > 0
            ? ["off", "Partly unknown"]
            : ["ok", "Healthy"];
  return { total, healthy, failed, stale, degraded, other, tone, label };
}

export function currentPipeline(pipeline: PipelineComponentHealth[]): {
  current: PipelineComponentHealth[];
  superseded: number;
} {
  const current = pipeline.filter((p) => !p.superseded);
  return { current, superseded: pipeline.length - current.length };
}

/** Gateway audit decisions that are not acceptances (all of them today: unauthenticated, forbidden). */
const ACCEPTED_DECISIONS = new Set(["accepted", "allowed", "ok"]);

export function gatewayRejections(ingest: HealthResponse["ingest"]): {
  rejected: number;
  decisions: { decision: string; count: number; rejection: boolean }[];
} | null {
  if (!ingest) return null;
  const decisions = Object.entries(ingest.audit_decisions)
    .map(([decision, count]) => ({ decision, count, rejection: !ACCEPTED_DECISIONS.has(decision) }))
    .sort((a, b) => b.count - a.count || a.decision.localeCompare(b.decision));
  return { rejected: decisions.filter((d) => d.rejection).reduce((sum, d) => sum + d.count, 0), decisions };
}

export interface RuleExecution {
  total: number;
  failures24h: number;
  runs24h: number;
  failingNow: number;
  neverRan: number;
  overdue: number;
  quiet: number;
}

export function ruleExecution(rules: RuleHealthItem[]): RuleExecution {
  let failures24h = 0;
  let runs24h = 0;
  for (const r of rules) {
    failures24h += r.last_run?.failures_24h ?? 0;
    runs24h += r.last_run?.runs_24h ?? 0;
  }
  return {
    total: rules.length,
    failures24h,
    runs24h,
    failingNow: rules.filter((r) => r.last_run?.last_status === "failed").length,
    neverRan: rules.filter((r) => r.enabled !== false && !r.last_run).length,
    overdue: rules.filter((r) => r.run_stale === true).length,
    quiet: rules.filter((r) => (r.last_run?.missing_sources.length ?? 0) > 0).length,
  };
}

/** Jev (TypeSafe System One) is the one AI provider since contracts 2.0. */
const PROVIDER_NAME: Record<string, string> = {
  "typesafe-jev": "Jev",
};

/** Display name of an AI provider token; unknown tokens are shown as reported. */
export function providerName(provider: string): string {
  return PROVIDER_NAME[provider] ?? provider;
}

const AI_STATUS_LABEL: Record<string, string> = {
  ok: "OK",
  insufficient_context: "Insufficient context",
  invalid_output: "Invalid output",
  timeout: "Timed out",
  rate_limited: "Rate limited",
  error: "Error",
  disabled: "Disabled",
  budget_exceeded: "Budget exhausted",
};

export function aiStatusLabel(status: string): string {
  return AI_STATUS_LABEL[status] ?? status;
}

/**
 * The state of the worker that runs an AI provider (the ai-worker for Jev), from its newest
 * fresh health report. This says whether assessments are being produced; null means no fresh
 * report, which is shown as unknown, never as running or disabled.
 */
export function runtimeView(status: string | null | undefined): { tone: Tone; label: string; hint: string } {
  switch (status) {
    case "ok":
      return { tone: "ok", label: "Running", hint: "The ai-worker's latest report is OK: new alerts are assessed within the daily budget." };
    case "degraded":
      return { tone: "warn", label: "Degraded", hint: "The ai-worker reports problems (provider failures, write errors or paused calls)." };
    case "failed":
      return { tone: "bad", label: "Failing", hint: "The ai-worker's last cycle failed: no new assessment is being produced." };
    case "disabled":
      return { tone: "off", label: "Disabled", hint: "The ai-worker reports Jev turned off or without a key: it makes no calls." };
    case null:
    case undefined:
      return { tone: "off", label: "Not reporting", hint: "No fresh ai-worker health report: whether assessments are produced is unknown." };
    default:
      return { tone: "warn", label: status, hint: "Status as the ai-worker reported it." };
  }
}

/** The API process's own flag and key presence, in words ("enabled, key configured"). */
export function apiProcessView(provider: { enabled?: boolean | null; configured?: boolean | null }): string {
  const flag = provider.enabled === true ? "enabled" : provider.enabled === false ? "disabled" : "flag unknown";
  const key =
    provider.configured === true ? "key configured" : provider.configured === false ? "no key" : "key presence unknown";
  return `${flag}, ${key}`;
}

export function aiStatusTone(status: string | null | undefined): Tone {
  if (!status) return "off";
  if (status === "ok") return "ok";
  if (status === "insufficient_context" || status === "disabled") return "off";
  if (status === "error" || status === "invalid_output") return "bad";
  return "warn";
}

/** The page's one-line finding. */
export function healthFinding(data: HealthResponse): string {
  const collectors = collectorCounts(data.collectors);
  const { depth } = spoolBacklog(data.pipeline);
  const rules = ruleExecution(data.rules);
  const parts: string[] = [];
  parts.push(
    collectors.total === 0
      ? "No collector has reported"
      : `${formatCount(collectors.healthy)} of ${formatCount(collectors.total)} collectors healthy and fresh`,
  );
  parts.push(
    depth === null
      ? "ingestion spool depth unknown"
      : `${formatCount(depth)} record${depth === 1 ? "" : "s"} in the ingestion spool`,
  );
  if (data.ingest) parts.push(`${formatCount(data.ingest.quarantined_records)} quarantined in ${data.ingest.window_hours} h`);
  parts.push(`${formatCount(rules.failures24h)} rule failure${rules.failures24h === 1 ? "" : "s"} in 24 h`);
  return parts.join(" · ");
}

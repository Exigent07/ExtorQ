/**
 * The decisive part of an investigation, lifted out of the feature lists (pure; unit-tested in
 * `signals.test.ts`): key signals (true risk flags and non-empty risk lists with their values),
 * threshold checks (observed against the rule's threshold), the ordered stages of a sequence
 * rule (CORR-002) and the remaining features grouped by source. Inputs are the detector's
 * features and the correlation context's features as the API returns them; nothing is inferred
 * beyond them. Values are telemetry-derived: callers render them with UntrustedText.
 */
import { formatCount, formatDuration } from "@/lib/format";

import { classifyFeature, type FeatureView, featureLabel } from "./model";

type Features = Record<string, unknown> | null | undefined;

/** A feature key of the detector ("d") or of the correlation context ("c"). */
export type FeatureRef = `d:${string}` | `c:${string}`;

export type SignalTone = "risk" | "corroboration";

export interface KeySignal {
  id: string;
  tone: SignalTone;
  /** Console text only (never a recorded value). */
  title: string;
  /** Telemetry-derived values (users, scopes, flags): render with UntrustedText. */
  values: string[];
  /** Console text that frames the signal (never a verdict). */
  note: string | null;
  /** Features shown by this signal (left out of the lists below). */
  consumes: FeatureRef[];
}

const isTrue = (v: unknown) => v === true;
const strings = (v: unknown): string[] =>
  Array.isArray(v) ? v.filter((x): x is string | number => typeof x === "string" || typeof x === "number").map(String) : [];
const text = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v : null);

/**
 * Signals in reading order: risks first (what an attacker gained or tried), then what
 * corroborates the evidence. Only true flags and non-empty lists become signals; a false flag
 * stays a plain "No" in the lists.
 */
export function keySignals(detector: Features, context: Features): KeySignal[] {
  const d = detector ?? {};
  const c = context ?? {};
  const out: KeySignal[] = [];
  const push = (signal: Omit<KeySignal, "note"> & { note?: string | null }) => out.push({ note: null, ...signal });

  if (isTrue(c.ssh_success_after_failures)) {
    push({
      id: "ssh-success",
      tone: "risk",
      title: "SSH login succeeded after the failures",
      values: strings(c.ssh_success_users),
      note: "Successful logins in the context window after failed ones (correlation layer); co-occurrence, not proof of a compromise.",
      consumes: ["c:ssh_success_after_failures", "c:ssh_success_users"],
    });
  }
  if (isTrue(c.sudo_after_login)) {
    push({ id: "sudo", tone: "risk", title: "sudo used after a login", values: [], consumes: ["c:sudo_after_login"] });
  }
  if (isTrue(d.write_all_added) || isTrue(c.gh_write_all_added)) {
    const before = text(d.permissions_before);
    const after = text(d.permissions_after);
    push({
      id: "write-all",
      tone: "risk",
      title: "Workflow gained write-all permissions",
      values: before && after ? [`${before} → ${after}`] : [],
      consumes: ["d:write_all_added", "c:gh_write_all_added", ...(before && after ? (["d:permissions_before", "d:permissions_after"] as const) : [])],
    });
  }
  if (isTrue(d.untrusted_checkout_added)) {
    push({
      id: "untrusted-checkout",
      tone: "risk",
      title: "Untrusted checkout added to the workflow",
      values: [],
      note: "The workflow checks out code from the triggering pull request while holding write permissions.",
      consumes: ["d:untrusted_checkout_added"],
    });
  }
  if (strings(d.risky_triggers_added).length > 0) {
    push({ id: "risky-triggers", tone: "risk", title: "Risky trigger added", values: strings(d.risky_triggers_added), consumes: ["d:risky_triggers_added"] });
  }
  if (strings(d.sensitive_scopes_added).length > 0) {
    push({
      id: "sensitive-scopes",
      tone: "risk",
      title: "Sensitive write scopes added",
      values: strings(d.sensitive_scopes_added),
      consumes: ["d:sensitive_scopes_added"],
    });
  }
  if (strings(d.risk_flags).length > 0) {
    // Titles and notes are console text; every recorded value (flags, role, subjects: Kubernetes
    // object fields, attacker-influenced) goes into `values`, rendered as untrusted text.
    const roleRef = text(d.role_ref);
    const subjects = strings(d.subjects);
    push({
      id: "rbac-risk",
      tone: "risk",
      title: "Risky RBAC grant",
      values: [...strings(d.risk_flags), ...(roleRef ? [roleRef] : []), ...subjects],
      note: "Risk flags, then the granted role and the subjects, as the detector recorded them.",
      consumes: ["d:risk_flags", ...(roleRef ? (["d:role_ref"] as const) : []), ...(subjects.length > 0 ? (["d:subjects"] as const) : [])],
    });
  }
  if (strings(d.privileged_flags).length > 0) {
    push({
      id: "privileged",
      tone: "risk",
      title: d.dry_run === true ? "Privileged Pod settings requested (dry run)" : "Privileged Pod settings requested",
      values: strings(d.privileged_flags),
      note: "Pod Security admission denied the request; the attempt itself is the signal.",
      consumes: ["d:privileged_flags"],
    });
  }
  if (strings(d.wanted_by).length > 0 && d.vendor_unit === false) {
    push({
      id: "boot-unit",
      tone: "risk",
      title: "Non-vendor unit enabled to start at boot",
      values: strings(d.wanted_by),
      consumes: ["d:wanted_by", "d:vendor_unit"],
    });
  }
  if (isTrue(d.audit_corroborated) || isTrue(c.auditd_corroborated)) {
    const writers = strings(d.writer_executables).length > 0 ? strings(d.writer_executables) : strings(c.auditd_writers);
    push({
      id: "auditd",
      tone: "corroboration",
      title: "auditd corroborates the file write",
      values: writers,
      note: "Two independent sources (inventory and auditd) recorded the change.",
      consumes: ["d:audit_corroborated", "c:auditd_corroborated", "d:writer_executables", "c:auditd_writers"],
    });
  }
  const sources = strings(d.sources);
  if (sources.includes("audit") && sources.includes("state")) {
    push({
      id: "audit-state",
      tone: "corroboration",
      title: "API audit log and cluster state agree",
      values: [],
      note: "The audit record and the inventory snapshot both show the object.",
      consumes: ["d:sources"],
    });
  }
  return out;
}

export interface ThresholdCheck {
  key: string;
  label: string;
  observed: number;
  threshold: number;
  met: boolean;
}

const THRESHOLD_LABEL: Record<string, string> = {
  connections: "Distinct connections (source IP, port)",
  failures: "“Failed password” attempts",
  requests: "Requests",
  probe_routes: "Probe routes",
};

/**
 * Observed-against-threshold pairs: every `threshold_<x>` the detector recorded with its
 * `peak_window_<x>` (the most the rule saw inside one sliding window). Rules fire when any one
 * check is met, so a check that is not met is shown as such, never as an error.
 */
export function thresholdChecks(detector: Features): ThresholdCheck[] {
  const d = detector ?? {};
  const out: ThresholdCheck[] = [];
  for (const [key, value] of Object.entries(d)) {
    const match = /^threshold_(.+)$/.exec(key);
    if (!match || typeof value !== "number" || !Number.isFinite(value)) continue;
    const name = match[1] ?? "";
    const observed = d[`peak_window_${name}`];
    if (typeof observed !== "number" || !Number.isFinite(observed)) continue;
    out.push({ key: name, label: THRESHOLD_LABEL[name] ?? featureLabel(name), observed, threshold: value, met: observed >= value });
  }
  return out.sort((a, b) => Number(b.met) - Number(a.met) || a.key.localeCompare(b.key));
}

/** Keys a threshold check shows (left out of the lists). */
export function thresholdKeys(checks: readonly ThresholdCheck[]): FeatureRef[] {
  return checks.flatMap((c) => [`d:threshold_${c.key}`, `d:peak_window_${c.key}`] as FeatureRef[]);
}

export interface SequenceStage {
  token: string;
  label: string;
  /** ISO instant of the stage's first event, or null when not recorded or unparsable. */
  at: string | null;
  /** Seconds since the previous stage (null for the first stage or unknown times). */
  sincePrevious: number | null;
  facts: string[];
}

export interface Sequence {
  stages: SequenceStage[];
  totalSeconds: number | null;
  consumes: FeatureRef[];
}

const STAGES: Record<string, { label: string; at: string; facts: (d: Record<string, unknown>) => string[]; keys: string[] }> = {
  http_probe: {
    label: "HTTP probing",
    at: "probe_stage_at",
    facts: (d) => [
      typeof d.probe_requests === "number" ? `${formatCount(d.probe_requests)} client-error requests` : null,
      typeof d.probe_routes_distinct === "number" ? `${formatCount(d.probe_routes_distinct)} probe routes` : null,
    ].filter((x): x is string => x !== null),
    keys: ["probe_requests", "probe_routes_distinct"],
  },
  ssh_auth_failures: {
    label: "SSH authentication failures",
    at: "ssh_stage_at",
    facts: (d) => [
      typeof d.ssh_failed_connections === "number" ? `${formatCount(d.ssh_failed_connections)} failed connections` : null,
      typeof d.ssh_failure_events === "number" ? `${formatCount(d.ssh_failure_events)} failure events` : null,
    ].filter((x): x is string => x !== null),
    keys: ["ssh_failed_connections", "ssh_failure_events"],
  },
  systemd_persistence: {
    label: "systemd persistence",
    at: "persistence_stage_at",
    facts: (d) => [
      strings(d.persistence_units).length > 0 ? `${formatCount(strings(d.persistence_units).length)} units` : null,
      typeof d.persistence_events === "number" ? `${formatCount(d.persistence_events)} events` : null,
    ].filter((x): x is string => x !== null),
    keys: ["persistence_events"],
  },
};

/**
 * A rule time as an ISO instant: "2026-11-21 15:06:52.911" (ClickHouse UTC, no zone) or an ISO
 * string; null for anything else.
 */
export function featureInstant(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const match = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(Z|[+-]\d{2}:?\d{2})?$/.exec(value.trim());
  if (!match) return null;
  const iso = `${match[1]}T${match[2]}${match[3] ?? "Z"}`;
  return Number.isNaN(Date.parse(iso)) ? null : iso;
}

/** The ordered stages of a sequence rule (`stage_order` "a>b>c"), or null for other rules. */
export function sequenceStages(detector: Features): Sequence | null {
  const d = detector ?? {};
  const order = text(d.stage_order);
  if (!order) return null;
  const tokens = order.split(">").map((t) => t.trim()).filter(Boolean);
  if (tokens.length < 2) return null;
  const consumes: FeatureRef[] = ["d:stage_order"];
  let previous: number | null = null;
  const stages: SequenceStage[] = tokens.map((token) => {
    const spec = STAGES[token];
    const at = spec ? featureInstant(d[spec.at]) : null;
    const time = at ? Date.parse(at) : null;
    const sincePrevious = time !== null && previous !== null ? (time - previous) / 1000 : null;
    previous = time;
    if (spec) consumes.push(`d:${spec.at}`, ...spec.keys.map((k) => `d:${k}` as FeatureRef));
    return { token, label: spec?.label ?? featureLabel(token), at, sincePrevious, facts: spec ? spec.facts(d) : [] };
  });
  const total = typeof d.sequence_seconds === "number" && Number.isFinite(d.sequence_seconds) ? d.sequence_seconds : null;
  if (total !== null) consumes.push("d:sequence_seconds");
  return { stages, totalSeconds: total, consumes };
}

/** "+10.5 s" between two stages (one decimal below 20 s, whole seconds below a minute). */
export function stageGap(seconds: number): string {
  if (seconds < 20) return `+${(Math.round(seconds * 10) / 10).toFixed(1)} s`;
  if (seconds < 60) return `+${Math.round(seconds)} s`;
  return `+${formatDuration(seconds)}`;
}

export interface FeatureGroup {
  id: string;
  title: string;
  rows: [string, FeatureView][];
  /** Counters that are exactly 0 (folded behind one line; a real 0 is still shown when opened). */
  zeros: [string, FeatureView][];
}

const GROUPS: { id: string; title: string; test: RegExp }[] = [
  { id: "ssh", title: "SSH", test: /^(ssh_|sudo_)/ },
  { id: "http", title: "HTTP", test: /^http_/ },
  { id: "app", title: "Application", test: /^app_/ },
  { id: "host", title: "Host changes", test: /^(auditd_|persistence_|unit_|package_)/ },
  { id: "k8s", title: "Kubernetes", test: /^k8s_/ },
  { id: "github", title: "GitHub", test: /^gh_/ },
  { id: "scope", title: "Correlation scope", test: /.*/ },
];

const KIND_RANK: Record<FeatureView["kind"], number> = { unknown: 0, boolean: 0, number: 0, text: 1, record: 2, list: 3, structured: 4 };

function sameValue(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) && Array.isArray(b)) return a.length > 0 && a.length === b.length && a.every((x, i) => x === b[i]);
  return typeof a === "string" && a.trim() !== "" && a === b;
}

/**
 * Correlation-context features grouped by source (SSH, HTTP, application, host changes,
 * Kubernetes, GitHub, then the correlation scope), each group's counters first. Left out:
 * keys a signal or check already shows, and keys whose value the detector features already
 * hold (same key, or an identical list or text under another name).
 */
export function contextFeatureGroups(context: Features, detector: Features, consumed: ReadonlySet<string>): FeatureGroup[] {
  const d = detector ?? {};
  const detectorValues = Object.values(d);
  const groups = GROUPS.map((g) => ({ id: g.id, title: g.title, rows: [] as [string, FeatureView][], zeros: [] as [string, FeatureView][] }));
  for (const [key, value] of Object.entries(context ?? {})) {
    if (consumed.has(`c:${key}`)) continue;
    if (Object.hasOwn(d, key) || detectorValues.some((dv) => sameValue(dv, value))) continue;
    const view = classifyFeature(value);
    const index = GROUPS.findIndex((g) => g.test.test(key));
    const group = groups[index < 0 ? groups.length - 1 : index];
    if (!group) continue;
    if (view.kind === "number" && view.value === 0) group.zeros.push([key, view]);
    else group.rows.push([key, view]);
  }
  const order = (a: [string, FeatureView], b: [string, FeatureView]) => KIND_RANK[a[1].kind] - KIND_RANK[b[1].kind] || a[0].localeCompare(b[0]);
  return groups
    .map((g) => ({ ...g, rows: g.rows.sort(order), zeros: g.zeros.sort(order) }))
    .filter((g) => g.rows.length > 0 || g.zeros.length > 0);
}

/** Detector features that no signal, check or stage already shows. */
export function remainingDetectorFeatures(detector: Features, consumed: ReadonlySet<string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(detector ?? {})) {
    if (!consumed.has(`d:${key}`)) out[key] = value;
  }
  return out;
}

/** Clearer names for detector features whose key alone reads ambiguously. */
export const DETECTOR_LABEL: Record<string, string> = {
  distinct_connections: "Distinct connections in the evidence",
  failed_attempts: "“Failed password” lines in the evidence",
  invalid_user_events: "Invalid-user events",
  distinct_usernames: "Distinct usernames",
  window_seconds: "Sliding window",
  src_ip_shared_nat: "Source is a shared NAT address",
  same_non_nat_source_ip: "Same non-NAT source IP",
  source_ip_shared_nat: "Source is a shared NAT address",
};

/**
 * Presentation rules of the investigation page (pure; unit-tested in
 * `investigation-model.test.ts`). Inputs are validated API data. Strings stay untrusted:
 * callers render every telemetry value with UntrustedText.
 */
import type {
  AIAssessment,
  EvidenceEvent,
  InvestigationContext,
  JevAnswer,
  Relationship,
  TimelineEntry,
} from "@/lib/api/schemas";
import { DASH, formatDuration } from "@/lib/format";
import { summaryWithoutType } from "@/lib/investigation";

// ── Tabs ──────────────────────────────────────────────────────────────────────────

export const TABS = ["overview", "timeline", "evidence", "correlation", "ai", "context"] as const;
export type TabKey = (typeof TABS)[number];

/** The `?tab=` value of the address, allow-listed; anything else opens the Overview. */
export function parseTab(raw: unknown): TabKey {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === "string" && (TABS as readonly string[]).includes(value) ? (value as TabKey) : "overview";
}

/** `#evidence-<event_id>` (the anchor of an evidence row) → the event id, or null. */
export function evidenceIdFromHash(hash: string): string | null {
  const match = /^#evidence-([0-9a-f]{32})$/.exec(hash);
  return match ? (match[1] ?? null) : null;
}

// ── AI assessments ────────────────────────────────────────────────────────────────

/** The newest assessment of one task (triage = Jev, summary = Gemini), or null. */
export function latestAssessment(items: readonly AIAssessment[], task: "triage" | "summary"): AIAssessment | null {
  let best: AIAssessment | null = null;
  let bestTime = Number.NEGATIVE_INFINITY;
  for (const item of items) {
    if (item.task !== task) continue;
    const time = Date.parse(item.created_at);
    const value = Number.isNaN(time) ? Number.NEGATIVE_INFINITY : time;
    if (best === null || value > bestTime) {
      best = item;
      bestTime = value;
    }
  }
  return best;
}

export type ChipKind = "evidence" | "context" | "unverified";

/**
 * Evidence chips of one AI statement. `evidence_ids` hold only ids the backend found in the
 * evidence bundle the model received (verified); `unverified_ids` are the rest. A verified
 * id jumps to its evidence row when it is one of this alert's evidence events ("evidence"),
 * otherwise it is a verified related observation of the context ("context", not a link).
 * Unverified ids are flagged and never become links.
 */
export function statementChips(
  statement: { evidence_ids: readonly string[]; unverified_ids: readonly string[] },
  evidenceRows: ReadonlySet<string>,
): { id: string; kind: ChipKind }[] {
  const seen = new Set<string>();
  const chips: { id: string; kind: ChipKind }[] = [];
  for (const id of statement.evidence_ids) {
    if (seen.has(id)) continue;
    seen.add(id);
    chips.push({ id, kind: evidenceRows.has(id) ? "evidence" : "context" });
  }
  for (const id of statement.unverified_ids) {
    if (seen.has(`u:${id}`)) continue;
    seen.add(`u:${id}`);
    chips.push({ id, kind: "unverified" });
  }
  return chips;
}

/**
 * Jev decision bands, as documented for the deterministic triage procedure
 * (docs/ai-integrations.md, extorq.ai.jev): below 0.3 the context is insufficient, 0.3 to
 * 0.7 is the uncertain band where a human decides, above 0.7 the context is sufficient.
 */
export const JEV_BANDS = { insufficientBelow: 0.3, confidentAbove: 0.7 } as const;

export type JevZone = "insufficient" | "uncertain" | "sufficient";

export function jevZone(probability: number): JevZone {
  if (probability < JEV_BANDS.insufficientBelow) return "insufficient";
  if (probability <= JEV_BANDS.confidentAbove) return "uncertain";
  return "sufficient";
}

/** Probability as a bar width in percent (0..100); non-finite values give 0. */
export function percent(probability: number): number {
  if (!Number.isFinite(probability)) return 0;
  return Math.round(Math.max(0, Math.min(1, probability)) * 1000) / 10;
}

/** Options of a choice answer, most probable first, with the chosen one marked. */
export function choiceOptions(answer: JevAnswer): { label: string; probability: number; chosen: boolean }[] {
  return Object.entries(answer.probabilities)
    .filter(([, p]) => Number.isFinite(p))
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([label, probability]) => ({ label, probability, chosen: label === answer.value }));
}

// ── Features (detector and correlation layer) ─────────────────────────────────────

type Primitive = string | number | boolean;

export type FeatureView =
  | { kind: "unknown" }
  | { kind: "boolean"; value: boolean }
  | { kind: "number"; value: number }
  | { kind: "text"; value: string }
  | { kind: "list"; items: Primitive[] }
  | { kind: "record"; entries: [string, Primitive | null][] }
  | { kind: "structured"; size: number };

function isPrimitive(value: unknown): value is Primitive {
  return typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value));
}

/**
 * How a feature value is shown: scalars as themselves, lists of scalars as chips, flat
 * objects as key/value pairs and anything nested deeper as a count of fields (never raw
 * JSON text). null means unknown (a dash); an empty list is a real "none".
 */
export function classifyFeature(value: unknown): FeatureView {
  if (value === null || value === undefined) return { kind: "unknown" };
  if (typeof value === "boolean") return { kind: "boolean", value };
  if (typeof value === "number") return Number.isFinite(value) ? { kind: "number", value } : { kind: "unknown" };
  if (typeof value === "string") return { kind: "text", value };
  if (Array.isArray(value)) {
    return value.every(isPrimitive) ? { kind: "list", items: value } : { kind: "structured", size: value.length };
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    return entries.every(([, v]) => v === null || isPrimitive(v))
      ? { kind: "record", entries: entries as [string, Primitive | null][] }
      : { kind: "structured", size: entries.length };
  }
  return { kind: "unknown" };
}

const RANK: Record<FeatureView["kind"], number> = {
  unknown: 0,
  boolean: 0,
  number: 0,
  text: 1,
  record: 2,
  list: 3,
  structured: 4,
};

/** Feature rows: scalars first, then text, then lists (each group alphabetical). */
export function orderFeatures(features: Record<string, unknown> | null | undefined): [string, FeatureView][] {
  return Object.entries(features ?? {})
    .map(([key, value]) => [key, classifyFeature(value)] as [string, FeatureView])
    .sort((a, b) => RANK[a[1].kind] - RANK[b[1].kind] || a[0].localeCompare(b[0]));
}

const WORDS: Record<string, string> = {
  api: "API",
  cve: "CVE",
  dns: "DNS",
  dst: "destination",
  gh: "GitHub",
  http: "HTTP",
  id: "ID",
  ids: "IDs",
  ip: "IP",
  ips: "IPs",
  k8s: "Kubernetes",
  mitre: "MITRE",
  nat: "NAT",
  pid: "PID",
  psa: "PSA",
  rbac: "RBAC",
  sha: "SHA",
  sha256: "SHA-256",
  src: "source",
  ssh: "SSH",
  tls: "TLS",
  uid: "UID",
  url: "URL",
};

/** "ssh_success_after_failures" → "SSH success after failures" (keys come from rule code). */
export function featureLabel(key: string): string {
  const words = key.split(/[_.\s]+/).filter(Boolean);
  if (words.length === 0) return key;
  return words
    .map((word, index) => {
      const lower = word.toLowerCase();
      const known = WORDS[lower] ?? lower;
      return index === 0 && known === known.toLowerCase() ? `${known.charAt(0).toUpperCase()}${known.slice(1)}` : known;
    })
    .join(" ");
}

// ── Timeline ──────────────────────────────────────────────────────────────────────

export interface TimelineRow {
  key: string;
  eventId: string;
  time: string;
  /** evidence | direct | candidate | unestablished, or the reported token. */
  kind: string;
  eventType: string;
  sourceType: string;
  /** The summary without the repeated event-type prefix. */
  summary: string;
  rel: Relationship | null;
}

export interface TimelineItem {
  key: string;
  kind: string;
  eventType: string;
  sourceType: string;
  first: string;
  last: string;
  /** One row for a single observation; several for a burst of the same kind and type. */
  rows: TimelineRow[];
}

export interface KindCounts {
  evidence: number;
  direct: number;
  candidate: number;
  unestablished: number;
  other: number;
}

export interface TimelineModel {
  items: TimelineItem[];
  /** All entries of the context timeline by kind. */
  totals: KindCounts;
  /** Entries drawn in the list by kind. */
  drawn: KindCounts;
  /** Entries not drawn, and the most frequent event types among them. */
  hidden: number;
  hiddenTypes: [string, number][];
  rows: TimelineRow[];
}

export const TIMELINE_LIMITS = { candidates: 20, unestablished: 10, burstMin: 3, burstGapSeconds: 60 } as const;

const KIND_RANK: Record<string, number> = { evidence: 0, direct: 1, candidate: 2, unestablished: 3 };

function timeOf(iso: string): number {
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? Number.POSITIVE_INFINITY : ms;
}

function emptyCounts(): KindCounts {
  return { evidence: 0, direct: 0, candidate: 0, unestablished: 0, other: 0 };
}

function count(counts: KindCounts, kind: string): void {
  if (kind === "evidence" || kind === "direct" || kind === "candidate" || kind === "unestablished") counts[kind] += 1;
  else counts.other += 1;
}

/** Kind of a timeline entry: evidence, else the relationship type reported for it. */
export function entryKind(entry: TimelineEntry, rel: Relationship | undefined): string {
  if (entry.is_evidence) return "evidence";
  return entry.relationship_type ?? rel?.relationship_type ?? "related";
}

function byTime(a: TimelineRow, b: TimelineRow): number {
  return timeOf(a.time) - timeOf(b.time) || (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9) || a.key.localeCompare(b.key);
}

/**
 * The drawn timeline: every evidence entry and direct link, the candidate and unestablished
 * observations closest in time to the evidence (the rest is counted, listed in Correlation),
 * in time order. Runs of at least `burstMin` entries of the same kind, event type and source
 * with gaps up to `burstGapSeconds` fold into one burst item (its rows stay listed inside).
 */
export function buildTimeline(
  context: Pick<InvestigationContext, "timeline" | "relationships">,
  limits: { candidates: number; unestablished: number; burstMin: number; burstGapSeconds: number } = TIMELINE_LIMITS,
): TimelineModel {
  const relationships = new Map<string, Relationship>(context.relationships.map((r) => [r.event_id, r]));
  const rows: TimelineRow[] = context.timeline.map((entry, index) => {
    const rel = relationships.get(entry.event_id);
    return {
      key: `${entry.event_id}:${entry.time}:${index}`,
      eventId: entry.event_id,
      time: entry.time,
      kind: entryKind(entry, rel),
      eventType: entry.event_type,
      sourceType: entry.source_type,
      summary: summaryWithoutType(entry.summary, entry.event_type),
      rel: rel ?? null,
    };
  });
  const totals = emptyCounts();
  for (const row of rows) count(totals, row.kind);

  const nearest = (kind: string, limit: number) =>
    rows
      .filter((row) => row.kind === kind)
      .sort(
        (a, b) =>
          Math.abs(a.rel?.time_delta_seconds ?? Number.POSITIVE_INFINITY) -
            Math.abs(b.rel?.time_delta_seconds ?? Number.POSITIVE_INFINITY) || byTime(a, b),
      )
      .slice(0, limit);
  const keep = new Set<string>([
    ...rows.filter((row) => row.kind === "evidence" || row.kind === "direct").map((row) => row.key),
    ...nearest("candidate", limits.candidates).map((row) => row.key),
    ...nearest("unestablished", limits.unestablished).map((row) => row.key),
    ...rows.filter((row) => !(row.kind in KIND_RANK)).map((row) => row.key),
  ]);
  const drawnRows = rows.filter((row) => keep.has(row.key)).sort(byTime);
  const hiddenRows = rows.filter((row) => !keep.has(row.key));
  const drawn = emptyCounts();
  for (const row of drawnRows) count(drawn, row.kind);

  // Bursts: per (kind, type, source), consecutive in time with small gaps.
  const clusters: TimelineRow[][] = [];
  const open = new Map<string, TimelineRow[]>();
  for (const row of drawnRows) {
    const groupKey = `${row.kind}|${row.eventType}|${row.sourceType}`;
    const current = open.get(groupKey);
    const last = current?.[current.length - 1];
    if (current && last && timeOf(row.time) - timeOf(last.time) <= limits.burstGapSeconds * 1000) {
      current.push(row);
    } else {
      const cluster = [row];
      clusters.push(cluster);
      open.set(groupKey, cluster);
    }
  }
  const items: TimelineItem[] = [];
  for (const cluster of clusters) {
    const parts = cluster.length >= limits.burstMin ? [cluster] : cluster.map((row) => [row]);
    for (const part of parts) {
      const first = part[0];
      const last = part[part.length - 1];
      if (!first || !last) continue;
      items.push({
        key: part.length > 1 ? `burst:${first.key}` : first.key,
        kind: first.kind,
        eventType: first.eventType,
        sourceType: first.sourceType,
        first: first.time,
        last: last.time,
        rows: part,
      });
    }
  }
  items.sort(
    (a, b) =>
      timeOf(a.first) - timeOf(b.first) || (KIND_RANK[a.kind] ?? 9) - (KIND_RANK[b.kind] ?? 9) || a.key.localeCompare(b.key),
  );
  return {
    items,
    totals,
    drawn,
    hidden: hiddenRows.length,
    hiddenTypes: topTypes(hiddenRows.map((row) => row.eventType), 4),
    rows,
  };
}

/** The most frequent values, largest first (ties alphabetical). */
export function topTypes(types: readonly string[], limit: number): [string, number][] {
  const counts = new Map<string, number>();
  for (const type of types) counts.set(type, (counts.get(type) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit);
}

// ── Activity strip (time axis) ───────────────────────────────────────────────────

const TICK_STEPS_S = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];

/** Axis bounds: the context window, widened to include every entry; never zero-width. */
export function axisBounds(windowStart: string, windowEnd: string, times: readonly string[]): { start: number; end: number } {
  const finite = [windowStart, windowEnd, ...times].map((t) => Date.parse(t)).filter((t) => !Number.isNaN(t));
  if (finite.length === 0) return { start: 0, end: 1 };
  let start = Math.min(...finite);
  let end = Math.max(...finite);
  if (end - start < 1000) {
    start -= 30_000;
    end += 30_000;
  }
  return { start, end };
}

/** Position of a time on the axis in percent (clamped to 0..100). */
export function axisPercent(iso: string, bounds: { start: number; end: number }): number {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return 0;
  const span = bounds.end - bounds.start;
  if (span <= 0) return 0;
  return Math.max(0, Math.min(100, ((t - bounds.start) / span) * 100));
}

/** Round UTC ticks inside the bounds (at most `maxTicks`), and the step used. */
export function axisTicks(bounds: { start: number; end: number }, maxTicks = 6): { ticks: number[]; stepSeconds: number } {
  const spanSeconds = (bounds.end - bounds.start) / 1000;
  const step = TICK_STEPS_S.find((s) => spanSeconds / s <= maxTicks) ?? 86400 * Math.ceil(spanSeconds / 86400 / maxTicks);
  const stepMs = step * 1000;
  const ticks: number[] = [];
  for (let t = Math.ceil(bounds.start / stepMs) * stepMs; t <= bounds.end; t += stepMs) ticks.push(t);
  return { ticks, stepSeconds: step };
}

// ── Correlation ───────────────────────────────────────────────────────────────────

export interface RelatedRow {
  eventId: string;
  type: string;
  strength: string;
  bases: string[];
  offsetSeconds: number;
  explanation: string;
  time: string | null;
  eventType: string | null;
  sourceType: string | null;
  summary: string | null;
}

/**
 * Related observations (everything the correlation layer relates to the alert except the
 * evidence itself), direct first, then candidate, then unestablished; closest in time first.
 */
export function relatedRows(context: Pick<InvestigationContext, "timeline" | "relationships">): RelatedRow[] {
  const entries = new Map<string, TimelineEntry>(context.timeline.map((t) => [t.event_id, t]));
  return context.relationships
    .filter((r) => !r.bases.includes("evidence"))
    .map((r) => {
      const entry = entries.get(r.event_id);
      return {
        eventId: r.event_id,
        type: r.relationship_type,
        strength: r.strength,
        bases: r.bases,
        offsetSeconds: r.time_delta_seconds,
        explanation: r.explanation,
        time: entry?.time ?? null,
        eventType: entry?.event_type ?? null,
        sourceType: entry?.source_type ?? null,
        summary: entry ? summaryWithoutType(entry.summary, entry.event_type) : null,
      };
    })
    .sort(
      (a, b) =>
        (KIND_RANK[a.type] ?? 9) - (KIND_RANK[b.type] ?? 9) ||
        Math.abs(a.offsetSeconds) - Math.abs(b.offsetSeconds) ||
        a.eventId.localeCompare(b.eventId),
    );
}

export interface RelationshipGroup {
  type: "direct" | "candidate" | "unestablished";
  count: number;
  strong: number;
  moderate: number;
  weak: number;
}

/** Counts per relationship type and strength (the three contract types, zeros included). */
export function relationshipGroups(rows: readonly RelatedRow[]): RelationshipGroup[] {
  return (["direct", "candidate", "unestablished"] as const).map((type) => {
    const ofType = rows.filter((r) => r.type === type);
    return {
      type,
      count: ofType.length,
      strong: ofType.filter((r) => r.strength === "strong").length,
      moderate: ofType.filter((r) => r.strength === "moderate").length,
      weak: ofType.filter((r) => r.strength === "weak").length,
    };
  });
}

/** Related observations whose match includes a source IP shared through NAT (not identifying). */
export function natSharedCount(rows: readonly { bases: readonly string[] }[]): number {
  return rows.filter((r) => r.bases.includes("shared_nat_source_ip")).length;
}

/** Offset from the alert's first evidence: "+9 s", "−2 m 05 s", "±0 s". */
export function offsetLabel(seconds: number): string {
  if (!Number.isFinite(seconds)) return DASH;
  if (Math.abs(seconds) < 1) return "±0 s";
  return `${seconds < 0 ? "−" : "+"}${formatDuration(Math.abs(seconds))}`;
}

// ── Evidence ──────────────────────────────────────────────────────────────────────

/** The principal of an evidence event (actor, Kubernetes user or GitHub login). */
export function actorOf(e: EvidenceEvent): string | null {
  return e.actor_name ?? e.k8s_user ?? e.gh_actor_login ?? null;
}

/** Kubernetes / GitHub / HTTP identifiers that make an evidence row checkable at its source. */
export function identifiers(e: EvidenceEvent): string[] {
  const ids: string[] = [];
  if (e.k8s_audit_id) ids.push(`audit ${e.k8s_audit_id}`);
  if (e.k8s_namespace || e.k8s_pod_name) ids.push(`pod ${[e.k8s_namespace, e.k8s_pod_name].filter(Boolean).join("/")}`);
  if (e.k8s_node) ids.push(`node ${e.k8s_node}`);
  if (e.http_request_id) ids.push(`request ${e.http_request_id}`);
  if (e.http_method || e.http_route) ids.push(`${e.http_method ?? ""} ${e.http_route ?? ""}`.trim());
  if (e.gh_repository) ids.push(`repo ${e.gh_repository}`);
  if (e.gh_commit_sha) ids.push(`commit ${e.gh_commit_sha.slice(0, 12)}`);
  if (e.gh_workflow_path) ids.push(`workflow ${e.gh_workflow_path}`);
  if (e.resource_path && e.resource_path !== e.gh_workflow_path) ids.push(e.resource_path);
  return ids;
}

export interface FieldRow {
  label: string;
  value: string | number | null;
  /** Identifier, path or address: figure face. */
  mono?: boolean;
  /** ISO time: shown in UTC. */
  time?: boolean;
}

export interface FieldGroup {
  title: string;
  rows: FieldRow[];
}

function endpoint(ip: string | null | undefined, port: number | null | undefined): string | null {
  if (!ip && (port === null || port === undefined)) return null;
  return port === null || port === undefined ? (ip ?? null) : `${ip ?? DASH}:${port}`;
}

/**
 * Normalised fields of an evidence event for its detail sheet, grouped. The Event group
 * always lists its fields (unknown ones as a dash); the other groups list only the fields the
 * source provided and are left out when empty.
 */
export function evidenceFieldGroups(e: EvidenceEvent): FieldGroup[] {
  const optional = (title: string, rows: FieldRow[]): FieldGroup | null => {
    const present = rows.filter((r) => r.value !== null && r.value !== undefined && r.value !== "");
    return present.length > 0 ? { title, rows: present } : null;
  };
  const groups: (FieldGroup | null)[] = [
    {
      title: "Event",
      rows: [
        { label: "Event id", value: e.event_id, mono: true },
        { label: "Type", value: e.event_type, mono: true },
        { label: "Category", value: e.category },
        { label: "Action", value: e.action ?? null },
        { label: "Outcome", value: e.outcome },
        { label: "Severity hint", value: e.severity_hint ?? null },
        { label: "Event time", value: e.event_time, time: true },
        { label: "Observed", value: e.observed_time ?? null, time: true },
        { label: "Ingested", value: e.ingested_time, time: true },
        { label: "Evidence role", value: e.role ?? null },
        { label: "Cited by the detector", value: e.added_at ?? null, time: true },
      ],
    },
    {
      title: "Source",
      rows: [
        { label: "Asset", value: e.asset_id, mono: true },
        { label: "Source type", value: e.source_type, mono: true },
        { label: "Collector", value: e.collector_id, mono: true },
      ],
    },
    optional("Actor", [
      { label: "Type", value: e.actor_type ?? null },
      { label: "Name", value: e.actor_name ?? null },
      { label: "ID", value: e.actor_id ?? null, mono: true },
    ]),
    optional("Network", [
      { label: "Source", value: endpoint(e.src_ip, e.src_port), mono: true },
      { label: "Destination", value: endpoint(e.dst_ip, e.dst_port), mono: true },
    ]),
    optional("Resource", [
      { label: "Type", value: e.resource_type ?? null },
      { label: "Name", value: e.resource_name ?? null, mono: true },
      { label: "Namespace", value: e.resource_namespace ?? null, mono: true },
      { label: "Path", value: e.resource_path ?? null, mono: true },
    ]),
    optional("Process", [
      { label: "Name", value: e.process_name ?? null, mono: true },
      { label: "PID", value: e.process_pid ?? null, mono: true },
    ]),
    optional("HTTP", [
      { label: "Method", value: e.http_method ?? null, mono: true },
      { label: "Route", value: e.http_route ?? null, mono: true },
      { label: "Status", value: e.http_status ?? null, mono: true },
      { label: "Request id", value: e.http_request_id ?? null, mono: true },
    ]),
    optional("Kubernetes", [
      { label: "Cluster", value: e.k8s_cluster ?? null, mono: true },
      { label: "Namespace", value: e.k8s_namespace ?? null, mono: true },
      { label: "Pod", value: e.k8s_pod_name ?? null, mono: true },
      { label: "Pod UID", value: e.k8s_pod_uid ?? null, mono: true },
      { label: "Container", value: e.k8s_container ?? null, mono: true },
      { label: "Container id", value: e.k8s_container_id ?? null, mono: true },
      { label: "Node", value: e.k8s_node ?? null, mono: true },
      { label: "Verb", value: e.k8s_verb ?? null, mono: true },
      { label: "Resource", value: e.k8s_resource ?? null, mono: true },
      { label: "Object", value: e.k8s_object_name ?? null, mono: true },
      { label: "Response code", value: e.k8s_response_code ?? null, mono: true },
      { label: "User", value: e.k8s_user ?? null },
      { label: "Audit id", value: e.k8s_audit_id ?? null, mono: true },
    ]),
    optional("GitHub", [
      { label: "Repository", value: e.gh_repository ?? null, mono: true },
      { label: "Commit", value: e.gh_commit_sha ?? null, mono: true },
      { label: "Workflow", value: e.gh_workflow_path ?? null, mono: true },
      { label: "Workflow run", value: e.gh_workflow_run_id ?? null, mono: true },
      { label: "Actor", value: e.gh_actor_login ?? null },
    ]),
    optional("Service", [
      { label: "Service", value: e.service_name ?? null },
      { label: "Service id", value: e.service_id ?? null, mono: true },
      { label: "Instance id", value: e.service_instance_id ?? null, mono: true },
      { label: "Adapter", value: e.adapter_id ?? null, mono: true },
    ]),
    optional("Simulation", [
      { label: "Run id", value: e.simulation_run_id ?? null, mono: true },
      { label: "Scenario", value: e.scenario_id ?? null, mono: true },
    ]),
  ];
  return groups.filter((g): g is FieldGroup => g !== null);
}

// ── Analyst actions ───────────────────────────────────────────────────────────────

export interface ActionView {
  /** "changed the status to", "requested an AI overview", or the humanised action. */
  verb: string;
  /** Status token the action set (analyst workflow), when there is one. */
  status: string | null;
  note: string | null;
  /** Remaining detail fields (scalars only), shown as key/value pairs. */
  details: [string, string][];
}

const ACTION_VERB: Record<string, string> = {
  alert_state_changed: "changed the status",
  ai_summary_requested: "requested an AI overview",
};

/** One analyst action for the activity log; details are listed, never dumped as JSON. */
export function actionView(action: { action: string; details?: Record<string, unknown> | null }): ActionView {
  const details = action.details ?? {};
  const status = typeof details.status === "string" ? details.status : null;
  const note = typeof details.note === "string" && details.note.trim() !== "" ? details.note : null;
  const skip = new Set(["status", "note", "previous_status", "previous_assignee", "task"]);
  const rest: [string, string][] = [];
  for (const [key, value] of Object.entries(details)) {
    if (skip.has(key) || value === null || value === undefined || value === "") continue;
    if (isPrimitive(value)) rest.push([key, String(value)]);
  }
  return {
    verb: ACTION_VERB[action.action] ?? action.action.replace(/[_.]+/g, " ").trim(),
    status,
    note,
    details: rest,
  };
}

// ── Misc ──────────────────────────────────────────────────────────────────────────

/** Seconds between two ISO times (null when either is unparsable). */
export function secondsBetween(from: string, to: string): number | null {
  const a = Date.parse(from);
  const b = Date.parse(to);
  return Number.isNaN(a) || Number.isNaN(b) ? null : (b - a) / 1000;
}

/** Sources stale or with a gap during the window, plus missing-telemetry notes. */
export function coverageIssues(context: Pick<InvestigationContext, "coverage" | "missing_telemetry">): number {
  return context.coverage.filter((c) => c.stale || c.gap_during_window).length + context.missing_telemetry.length;
}

/** Presentation rules of the investigation page (src/components/views/investigation/model.ts). */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { AIAssessment, EvidenceEvent, JevAnswer, Relationship, TimelineEntry } from "../../../lib/api/schemas";
import {
  actionView,
  axisBounds,
  axisPercent,
  axisTicks,
  buildTimeline,
  choiceOptions,
  classifyFeature,
  coverageIssues,
  evidenceFieldGroups,
  evidenceIdFromHash,
  featureLabel,
  identifiers,
  jevZone,
  latestAssessment,
  natSharedCount,
  offsetLabel,
  orderFeatures,
  parseTab,
  percent,
  relatedRows,
  relationshipGroups,
  statementChips,
  topTypes,
} from "./model";

const ID = (n: number) => n.toString(16).padStart(32, "0");

function entry(n: number, time: string, type: string, extra: Partial<TimelineEntry> = {}): TimelineEntry {
  return {
    event_id: ID(n),
    time,
    event_type: type,
    source_type: "linux.journald",
    summary: `${type} user=x`,
    is_evidence: false,
    relationship_type: null,
    ...extra,
  };
}

function rel(n: number, type: Relationship["relationship_type"], delta: number, extra: Partial<Relationship> = {}): Relationship {
  return {
    event_id: ID(n),
    relationship_type: type,
    bases: ["same_asset_time_window"],
    strength: "weak",
    time_delta_seconds: delta,
    explanation: "Only temporal proximity.",
    ...extra,
  };
}

describe("tabs and anchors", () => {
  it("allow-lists the tab from the address and defaults to the overview", () => {
    assert.equal(parseTab("evidence"), "evidence");
    assert.equal(parseTab(["ai", "x"]), "ai");
    assert.equal(parseTab("../evil"), "overview");
    assert.equal(parseTab(undefined), "overview");
    assert.equal(parseTab(42), "overview");
  });
  it("accepts only well-formed evidence anchors", () => {
    assert.equal(evidenceIdFromHash(`#evidence-${ID(7)}`), ID(7));
    assert.equal(evidenceIdFromHash(`#evidence-${ID(7)}x`), null);
    assert.equal(evidenceIdFromHash("#evidence-ABC"), null);
    assert.equal(evidenceIdFromHash("#timeline"), null);
  });
});

describe("AI assessments", () => {
  const base = { task: "summary", created_at: "2026-11-21T20:00:00Z" } as AIAssessment;
  it("picks the newest assessment of a task", () => {
    const items = [
      { ...base, assessment_id: "a", created_at: "2026-11-21T20:00:00Z" },
      { ...base, assessment_id: "b", created_at: "2026-11-21T21:00:00Z" },
      { ...base, assessment_id: "c", task: "triage", created_at: "2026-11-21T22:00:00Z" },
    ] as AIAssessment[];
    assert.equal(latestAssessment(items, "summary")?.assessment_id, "b");
    assert.equal(latestAssessment(items, "triage")?.assessment_id, "c");
    assert.equal(latestAssessment([], "triage"), null);
  });
  it("links only verified ids that are evidence rows; flags unverified ones", () => {
    const chips = statementChips(
      { evidence_ids: [ID(1), ID(2), ID(1)], unverified_ids: ["deadbeef"] },
      new Set([ID(1)]),
    );
    assert.deepEqual(chips, [
      { id: ID(1), kind: "evidence" },
      { id: ID(2), kind: "context" },
      { id: "deadbeef", kind: "unverified" },
    ]);
  });
  it("places the sufficient-context probability in the documented bands", () => {
    assert.equal(jevZone(0.1), "insufficient");
    assert.equal(jevZone(0.3), "uncertain");
    assert.equal(jevZone(0.7), "uncertain");
    assert.equal(jevZone(0.84), "sufficient");
    assert.equal(percent(0.845), 84.5);
    assert.equal(percent(1.7), 100);
    assert.equal(percent(Number.NaN), 0);
  });
  it("orders choice options by probability and marks the chosen one", () => {
    const answer: JevAnswer = {
      question_id: "priority_a",
      type: "choice",
      value: "routine_review",
      confidence: null,
      probabilities: { likely_benign_maintenance: 0.2, priority_investigation: 0.3, routine_review: 0.5 },
    };
    assert.deepEqual(
      choiceOptions(answer).map((o) => [o.label, o.chosen]),
      [
        ["routine_review", true],
        ["priority_investigation", false],
        ["likely_benign_maintenance", false],
      ],
    );
  });
});

describe("features", () => {
  it("classifies values without ever producing JSON text", () => {
    assert.deepEqual(classifyFeature(null), { kind: "unknown" });
    assert.deepEqual(classifyFeature(0), { kind: "number", value: 0 });
    assert.deepEqual(classifyFeature(false), { kind: "boolean", value: false });
    assert.deepEqual(classifyFeature("x"), { kind: "text", value: "x" });
    assert.deepEqual(classifyFeature(["a", 1]), { kind: "list", items: ["a", 1] });
    assert.deepEqual(classifyFeature([]), { kind: "list", items: [] });
    assert.deepEqual(classifyFeature({ a: 1, b: null }), { kind: "record", entries: [["a", 1], ["b", null]] });
    assert.deepEqual(classifyFeature({ a: { b: 1 } }), { kind: "structured", size: 1 });
    assert.deepEqual(classifyFeature([{ a: 1 }, { b: 2 }]), { kind: "structured", size: 2 });
  });
  it("orders scalars before text and lists", () => {
    const ordered = orderFeatures({ usernames: ["a"], window_seconds: 300, stage_order: "a>b", nat: true });
    assert.deepEqual(
      ordered.map(([key]) => key),
      ["nat", "window_seconds", "stage_order", "usernames"],
    );
    assert.deepEqual(orderFeatures(null), []);
  });
  it("labels rule keys in plain words with acronyms", () => {
    assert.equal(featureLabel("ssh_success_after_failures"), "SSH success after failures");
    assert.equal(featureLabel("src_ip_shared_nat"), "Source IP shared NAT");
    assert.equal(featureLabel("http_4xx_count"), "HTTP 4xx count");
    assert.equal(featureLabel("gh_write_all_added"), "GitHub write all added");
    assert.equal(featureLabel(""), "");
  });
});

describe("timeline", () => {
  const evidence = (n: number, t: string, type = "auth.ssh.invalid_user") => entry(n, t, type, { is_evidence: true });

  it("draws evidence and direct links, the nearest candidates and folds the rest", () => {
    const timeline = [
      evidence(1, "2026-11-21T15:07:00Z"),
      entry(2, "2026-11-21T15:06:00Z", "system.log.notable", { relationship_type: "direct" }),
      entry(3, "2026-11-21T15:05:00Z", "process.audit.exec"),
      entry(4, "2026-11-21T15:00:00Z", "process.audit.exec"),
      entry(5, "2026-11-21T15:07:30Z", "auth.ssh.login_succeeded"),
    ];
    const relationships = [
      rel(2, "direct", -60, { strength: "strong" }),
      rel(3, "candidate", -120),
      rel(4, "candidate", -420),
      rel(5, "unestablished", 30, { bases: ["shared_nat_source_ip", "same_asset_time_window"] }),
    ];
    const model = buildTimeline({ timeline, relationships }, { candidates: 1, unestablished: 0, burstMin: 3, burstGapSeconds: 60 });
    assert.deepEqual(
      model.items.map((i) => [i.rows[0]?.eventId, i.kind]),
      [
        [ID(3), "candidate"],
        [ID(2), "direct"],
        [ID(1), "evidence"],
      ],
    );
    assert.deepEqual(model.totals, { evidence: 1, direct: 1, candidate: 2, unestablished: 1, other: 0 });
    assert.equal(model.hidden, 2);
    assert.deepEqual(model.hiddenTypes, [
      ["auth.ssh.login_succeeded", 1],
      ["process.audit.exec", 1],
    ]);
    // The summary drops the repeated event type.
    assert.equal(model.items[2]?.rows[0]?.summary, "user=x");
  });

  it("folds bursts of the same kind and type, even when other kinds interleave", () => {
    const timeline = [
      evidence(1, "2026-11-21T15:07:00Z"),
      entry(9, "2026-11-21T15:07:01Z", "system.log.notable", { relationship_type: "unestablished" }),
      evidence(2, "2026-11-21T15:07:02Z"),
      evidence(3, "2026-11-21T15:07:40Z"),
      evidence(4, "2026-11-21T15:09:30Z"),
      evidence(5, "2026-11-21T15:09:31Z", "auth.ssh.preauth_closed"),
    ];
    const model = buildTimeline({ timeline, relationships: [rel(9, "unestablished", 1)] });
    assert.deepEqual(
      model.items.map((i) => [i.kind, i.eventType, i.rows.length]),
      [
        ["evidence", "auth.ssh.invalid_user", 3],
        ["unestablished", "system.log.notable", 1],
        ["evidence", "auth.ssh.invalid_user", 1],
        ["evidence", "auth.ssh.preauth_closed", 1],
      ],
    );
    assert.equal(model.items[0]?.first, "2026-11-21T15:07:00Z");
    assert.equal(model.items[0]?.last, "2026-11-21T15:07:40Z");
  });

  it("keeps an unknown relationship token instead of guessing", () => {
    const model = buildTimeline({ timeline: [entry(1, "2026-11-21T15:07:00Z", "x.y")], relationships: [] });
    assert.equal(model.items[0]?.kind, "related");
    assert.equal(model.totals.other, 1);
  });

  it("counts the most frequent types", () => {
    assert.deepEqual(topTypes(["b", "a", "b", "c", "a", "b"], 2), [
      ["b", 3],
      ["a", 2],
    ]);
  });
});

describe("activity axis", () => {
  it("widens the window to every entry and never returns a zero-width axis", () => {
    const bounds = axisBounds("2026-11-21T15:00:00Z", "2026-11-21T15:10:00Z", ["2026-11-21T15:12:00Z", "garbage"]);
    assert.equal(bounds.end - bounds.start, 12 * 60_000);
    const point = axisBounds("2026-11-21T15:00:00Z", "2026-11-21T15:00:00Z", []);
    assert.equal(point.end - point.start, 60_000);
  });
  it("positions times as clamped percentages", () => {
    const bounds = { start: Date.parse("2026-11-21T15:00:00Z"), end: Date.parse("2026-11-21T15:10:00Z") };
    assert.equal(axisPercent("2026-11-21T15:05:00Z", bounds), 50);
    assert.equal(axisPercent("2026-11-21T16:00:00Z", bounds), 100);
    assert.equal(axisPercent("nope", bounds), 0);
  });
  it("puts round UTC ticks inside the bounds", () => {
    const bounds = { start: Date.parse("2026-11-21T15:02:31Z"), end: Date.parse("2026-11-21T15:12:31Z") };
    const { ticks, stepSeconds } = axisTicks(bounds, 6);
    assert.equal(stepSeconds, 120);
    assert.equal(new Date(ticks[0] ?? 0).toISOString(), "2026-11-21T15:04:00.000Z");
    assert.ok(ticks.every((t) => t >= bounds.start && t <= bounds.end));
    assert.ok(ticks.length <= 6);
  });
});

describe("correlation", () => {
  const context = {
    timeline: [entry(1, "2026-11-21T15:07:00Z", "a.b"), entry(2, "2026-11-21T15:08:00Z", "c.d"), entry(3, "2026-11-21T15:09:00Z", "e.f")],
    relationships: [
      rel(1, "unestablished", 5, { bases: ["shared_nat_source_ip", "same_asset_time_window"] }),
      rel(2, "candidate", -50, { strength: "moderate" }),
      rel(3, "direct", 300, { strength: "strong" }),
      rel(4, "candidate", 2, { bases: ["evidence"] }),
    ],
  };
  it("orders related observations by type, then by distance in time, without the evidence itself", () => {
    const rows = relatedRows(context);
    assert.deepEqual(
      rows.map((r) => [r.eventId, r.type]),
      [
        [ID(3), "direct"],
        [ID(2), "candidate"],
        [ID(1), "unestablished"],
      ],
    );
    assert.equal(rows[0]?.summary, "user=x");
  });
  it("counts each type and strength, zeros included, and NAT-only matches", () => {
    const rows = relatedRows(context);
    assert.deepEqual(relationshipGroups(rows), [
      { type: "direct", count: 1, strong: 1, moderate: 0, weak: 0 },
      { type: "candidate", count: 1, strong: 0, moderate: 1, weak: 0 },
      { type: "unestablished", count: 1, strong: 0, moderate: 0, weak: 1 },
    ]);
    assert.equal(natSharedCount(rows), 1);
  });
  it("writes offsets from the first evidence with a sign", () => {
    assert.equal(offsetLabel(8.63), "+9 s");
    assert.equal(offsetLabel(-125), "−2 m 05 s");
    assert.equal(offsetLabel(0.2), "±0 s");
    assert.equal(offsetLabel(Number.NaN), "—");
  });
});

describe("evidence", () => {
  const event = {
    event_id: ID(1),
    event_type: "k8s.api.request",
    category: "kubernetes_api",
    asset_id: "k8s:extorq-lab",
    asset_type: "kubernetes_cluster",
    source_type: "k8s.audit",
    collector_id: "k8s-otel-extorq-lab",
    event_time: "2026-11-21T15:03:19.357Z",
    ingested_time: "2026-11-21T15:03:20.559Z",
    outcome: "success",
    actor_name: null,
    k8s_user: "kubernetes-admin",
    k8s_audit_id: "ab22efc5",
    src_ip: "172.18.0.1",
    src_port: null,
    resource_path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
  } as EvidenceEvent;

  it("lists the event's identifiers and principal", () => {
    assert.deepEqual(identifiers(event), ["audit ab22efc5", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"]);
  });
  it("groups the normalised fields, always listing the core ones and dropping empty groups", () => {
    const groups = evidenceFieldGroups(event);
    assert.deepEqual(
      groups.map((g) => g.title),
      ["Event", "Source", "Network", "Resource", "Kubernetes"],
    );
    const core = groups[0]?.rows.find((r) => r.label === "Action");
    assert.equal(core?.value, null);
    assert.deepEqual(groups[2]?.rows, [{ label: "Source", value: "172.18.0.1", mono: true }]);
  });
});

describe("analyst actions and coverage", () => {
  it("states what an action did instead of dumping its details", () => {
    const view = actionView({
      action: "alert_state_changed",
      details: { status: "closed_benign", previous_status: null, note: "Lab fixture", assignee: "lead", previous_assignee: null },
    });
    assert.deepEqual(view, { verb: "changed the status", status: "closed_benign", note: "Lab fixture", details: [["assignee", "lead"]] });
    assert.equal(actionView({ action: "something_else", details: null }).verb, "something else");
  });
  it("counts stale or gapped sources and missing telemetry", () => {
    const coverage = [
      { stale: false, gap_during_window: false },
      { stale: true, gap_during_window: false },
      { stale: false, gap_during_window: true },
    ];
    assert.equal(coverageIssues({ coverage, missing_telemetry: ["x"] } as never), 3);
  });
});

/** Detections view model: URL filters (allow-listed, multi-valued), facet semantics, figures. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { type AlertListItem, type RuleListItem, zAlertListItem, zRuleListItem } from "../../../lib/api/schemas";

import {
  alertFigures,
  apiFilters,
  detectionsFinding,
  detectionsSearch,
  emptySelection,
  matchesSelection,
  parseDetectionsQuery,
  ruleFigures,
  sanitizeSelection,
  toAlertRow,
} from "./model";

function alert(overrides: Partial<Record<string, unknown>> = {}): AlertListItem {
  return zAlertListItem.parse({
    alert_id: "0123456789abcdef0123456789abcdef",
    rule_id: "VM-001",
    rule_version: "1.0.0",
    rule_title: "Burst of failed SSH authentication from one source",
    severity: "medium",
    confidence: "medium",
    asset_id: "linux:lab-vm-01",
    asset_type: "linux_host",
    summary: "12 SSH connections failed",
    first_seen: "2026-11-21T14:38:54Z",
    last_seen: "2026-11-21T14:40:00Z",
    event_count: 23,
    entities: {},
    service_ids: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
    mitre_techniques: ["T1110"],
    created_at: "2026-11-21T14:41:00Z",
    updated_at: "2026-11-21T14:41:00Z",
    analyst_status: "new",
    analyst_state_recorded: false,
    ...overrides,
  });
}

function rule(overrides: Partial<Record<string, unknown>> = {}): RuleListItem {
  return zRuleListItem.parse({
    rule_id: "VM-001",
    version: "1.0.0",
    title: "Burst of failed SSH authentication",
    severity: "medium",
    status: "stable",
    enabled: true,
    mitre_techniques: [],
    asset_types: ["linux_host"],
    loaded_at: "2026-11-21T10:00:00Z",
    interval_seconds: 60,
    last_run: {
      rule_version: "1.0.0",
      last_run_at: "2026-11-22T07:00:00Z",
      last_status: "succeeded",
      last_error: null,
      last_duration_ms: 17,
      missing_sources: [],
      runs_24h: 460,
      failures_24h: 0,
    },
    run_stale: false,
    alerts_total: 2,
    alerts_open: 1,
    ...overrides,
  });
}

describe("parseDetectionsQuery", () => {
  it("keeps the single-valued links of the first console working", () => {
    const q = parseDetectionsQuery({ rule: "VM-001", severity: "high", status: "new", asset: "k8s:extorq-lab", range: "30d" });
    assert.deepEqual(q.rule, ["VM-001"]);
    assert.deepEqual(q.severity, ["high"]);
    assert.deepEqual(q.status, ["new"]);
    assert.deepEqual(q.asset, ["k8s:extorq-lab"]);
    assert.equal(q.range, "30d");
    assert.equal(q.tab, "alerts");
    assert.equal(q.offset, 0);
  });

  it("accepts repeated parameters, in canonical order, without duplicates", () => {
    const q = parseDetectionsQuery({ severity: ["low", "critical", "low"], status: ["closed_benign", "new"] });
    assert.deepEqual(q.severity, ["critical", "low"]);
    assert.deepEqual(q.status, ["new", "closed_benign"]);
  });

  it("drops anything outside the allow-lists and patterns", () => {
    const q = parseDetectionsQuery({
      severity: ["urgent", "high"],
      status: "closed",
      rule: ["vm-001", "VM-001'--", "K8S-002"],
      asset: ["../etc/passwd", "linux:lab-vm-01", "a/../b"],
      range: "1y",
      tab: "settings",
      offset: "-5",
    });
    assert.deepEqual(q.severity, ["high"]);
    assert.deepEqual(q.status, []);
    assert.deepEqual(q.rule, ["K8S-002"]);
    assert.deepEqual(q.asset, ["linux:lab-vm-01"]);
    assert.equal(q.range, "7d");
    assert.equal(q.tab, "alerts");
    assert.equal(q.offset, 0);
  });

  it("bounds the number and length of values", () => {
    const many = Array.from({ length: 40 }, (_, i) => `R${String(i).padStart(2, "0")}-001`);
    assert.ok(parseDetectionsQuery({ rule: many }).rule.length <= 12);
    assert.deepEqual(parseDetectionsQuery({ asset: `linux:${"a".repeat(300)}` }).asset, []);
    assert.equal(parseDetectionsQuery({ offset: "999999999" }).offset, 0);
    assert.equal(parseDetectionsQuery({ offset: "400" }).offset, 400);
  });

  it("reads the rules tab", () => {
    assert.equal(parseDetectionsQuery({ tab: "rules" }).tab, "rules");
  });

  it("ignores parameters that are not filters (no unknown key reaches the selection)", () => {
    const q = parseDetectionsQuery({ sim: "yes", category: "x", severity: "high" });
    assert.deepEqual(Object.keys(q).sort(), ["asset", "offset", "range", "rule", "severity", "status", "tab"]);
    assert.deepEqual(q.severity, ["high"]);
  });
});

describe("detectionsSearch", () => {
  it("writes only non-default values and round-trips through the parser", () => {
    assert.equal(detectionsSearch({ range: "7d", tab: "alerts", offset: 0, ...emptySelection() }), "");
    const search = detectionsSearch({ ...emptySelection(), severity: ["critical", "high"], rule: ["VM-001"], range: "30d", tab: "rules" });
    assert.equal(search, "?severity=critical&severity=high&rule=VM-001&range=30d&tab=rules");
    const back = parseDetectionsQuery(Object.fromEntries([...new URLSearchParams(search.slice(1)).keys()].map((k) => [k, new URLSearchParams(search.slice(1)).getAll(k)])));
    assert.deepEqual(back.severity, ["critical", "high"]);
    assert.deepEqual(back.rule, ["VM-001"]);
    assert.equal(back.range, "30d");
    assert.equal(back.tab, "rules");
  });

  it("encodes asset ids as query values", () => {
    assert.equal(detectionsSearch({ asset: ["k8s:extorq-lab"] }), "?asset=k8s%3Aextorq-lab");
  });
});

describe("sanitizeSelection", () => {
  it("re-validates a selection coming back from the browser", () => {
    const out = sanitizeSelection({ severity: ["high", "bogus"], rule: ["VM-001", "<script>"], asset: ["linux:lab-vm-01", " x"] });
    assert.deepEqual(out, { severity: ["high"], rule: ["VM-001"], asset: ["linux:lab-vm-01"], status: [] });
  });
});

describe("apiFilters", () => {
  it("sends arrays for severity and status, one rule or asset only when exactly one is chosen", () => {
    const one = apiFilters({ ...emptySelection(), severity: ["high"], rule: ["VM-001"], asset: ["linux:lab-vm-01"] });
    assert.deepEqual([one.severity, one.ruleId, one.assetId, one.partial], [["high"], "VM-001", "linux:lab-vm-01", false]);
    const several = apiFilters({ ...emptySelection(), rule: ["VM-001", "VM-002"] });
    assert.equal(several.ruleId, null);
    assert.equal(several.partial, true);
  });
});

describe("matchesSelection", () => {
  const rows = [
    toAlertRow(alert({ alert_id: "a".repeat(32), severity: "high", rule_id: "VM-002" })),
    toAlertRow(alert({ alert_id: "b".repeat(32), severity: "medium", rule_id: "VM-001" })),
    toAlertRow(alert({ alert_id: "c".repeat(32), severity: "low", rule_id: "HTTP-001", analyst_status: "closed_benign" })),
  ];
  it("ORs values within a facet and ANDs across facets", () => {
    const pick = (selection: Parameters<typeof matchesSelection>[1]) => rows.filter((r) => matchesSelection(r, selection)).map((r) => r.ruleId);
    assert.deepEqual(pick(emptySelection()), ["VM-002", "VM-001", "HTTP-001"]);
    assert.deepEqual(pick({ ...emptySelection(), severity: ["high", "low"] }), ["VM-002", "HTTP-001"]);
    assert.deepEqual(pick({ ...emptySelection(), severity: ["high", "low"], status: ["new"] }), ["VM-002"]);
    assert.deepEqual(pick({ ...emptySelection(), rule: ["VM-001", "HTTP-001"], status: ["closed_benign"] }), ["HTTP-001"]);
  });
});

describe("alertFigures", () => {
  it("counts by severity and workflow state from the rows, never more", () => {
    const items = [
      alert({ alert_id: "a".repeat(32), severity: "high", analyst_status: "new", asset_id: "k8s:extorq-lab", asset_type: "kubernetes_cluster" }),
      alert({ alert_id: "b".repeat(32), severity: "high", analyst_status: "investigating" }),
      alert({ alert_id: "c".repeat(32), severity: "low", analyst_status: "closed_false_positive" }),
    ];
    const f = alertFigures(items, 3, false);
    assert.equal(f.total, 3);
    assert.equal(f.complete, true);
    assert.deepEqual(f.bySeverity, { critical: 0, high: 2, medium: 0, low: 1, info: 0 });
    assert.deepEqual([f.open, f.untriaged, f.investigating, f.acknowledged, f.closed], [2, 1, 1, 0, 1]);
    assert.equal(f.openBySeverity.high, 2);
    assert.deepEqual(
      f.assets.map((a) => [a.assetId, a.count]),
      [
        ["linux:lab-vm-01", 2],
        ["k8s:extorq-lab", 1],
      ],
    );
    assert.equal(f.rulesFiring, 1);
    // Oldest open alert by first activity; closed alerts do not count.
    assert.equal(f.oldestOpenSince, "2026-11-21T14:38:54Z");
    assert.equal(alertFigures([alert({ analyst_status: "closed_benign" })], 1, false).oldestOpenSince, null);
  });

  it("says when the API holds more alerts than were loaded", () => {
    const f = alertFigures([alert()], 250, true);
    assert.equal(f.total, 250);
    assert.equal(f.loaded, 1);
    assert.equal(f.complete, false);
    assert.equal(alertFigures([], null, false).total, 0);
    // No total from the API and more rows exist: unknown, never the loaded count.
    assert.equal(alertFigures([alert()], null, true).total, null);
  });
});

describe("ruleFigures and detectionsFinding", () => {
  it("sums runs and failures and finds failing, never-run, overdue and quiet rules", () => {
    const rules = [
      rule(),
      rule({ rule_id: "VM-002", last_run: { ...rule().last_run, last_status: "failed", failures_24h: 3, missing_sources: ["linux.auditd"] } }),
      rule({ rule_id: "GH-001", last_run: null, run_stale: true }),
      rule({ rule_id: "K8S-001", enabled: false, last_run: null }),
    ];
    const f = ruleFigures(rules);
    assert.deepEqual(
      [f.total, f.enabled, f.failingNow, f.neverRan, f.overdue, f.failures24h, f.runs24h, f.quietSources],
      [4, 3, 1, 1, 1, 3, 920, 1],
    );
    // Last-run partition for the rule-health bar: each rule counted once.
    assert.deepEqual([f.succeededNow, f.skippedNow, f.failingNow], [1, 0, 1]);
    assert.equal(f.total - f.succeededNow - f.skippedNow - f.failingNow, 2);
  });

  it("states the range, the open count and the rule state in one line", () => {
    const text = detectionsFinding(alertFigures([alert(), alert({ alert_id: "d".repeat(32), analyst_status: "closed_benign" })], 2, false), ruleFigures([rule()]), "7d");
    assert.equal(text, "2 alerts with activity in the last 7 days · 1 open · 1 of 1 rule enabled, none failing");
    assert.equal(detectionsFinding(null, null, "24h"), "");
    assert.match(detectionsFinding(alertFigures([alert()], 900, true), null, "30d"), /^900 alerts with activity in the last 30 days$/);
    assert.equal(detectionsFinding(alertFigures([alert()], null, true), null, "30d"), "More than 1 alerts with activity in the last 30 days");
  });
});

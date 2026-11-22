/** System health view model: freshness budget, collector partition, rejections, AI summary. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { type HealthResponse, zAIProviderHealth, zHealthResponse } from "../../../lib/api/schemas";

import {
  aiStatusTone,
  aiSummary,
  collectorCounts,
  collectorFreshness,
  gatewayRejections,
  healthFinding,
  ruleExecution,
} from "./model";

const NOW = "2026-11-22T07:00:00Z";

describe("collectorFreshness", () => {
  const base = { interval_seconds: 60, stale: false, status: "ok" as const, last_success_at: null };
  it("measures the time since the last success against 3 intervals", () => {
    const f = collectorFreshness({ ...base, seconds_since_success: 90 }, NOW);
    assert.equal(f.budgetSeconds, 180);
    assert.equal(f.ratio, 0.5);
    assert.equal(f.tone, "ok");
  });
  it("caps the bar at the budget and takes the tone from the API's verdict, not the ratio", () => {
    assert.equal(collectorFreshness({ ...base, seconds_since_success: 9000 }, NOW).ratio, 1);
    assert.equal(collectorFreshness({ ...base, seconds_since_success: 30, stale: true }, NOW).tone, "warn");
    assert.equal(collectorFreshness({ ...base, seconds_since_success: 30, status: "failed" }, NOW).tone, "bad");
  });
  it("derives the age from the last success time only when the API gives no age, and never invents one", () => {
    const derived = collectorFreshness({ ...base, seconds_since_success: null, last_success_at: "2026-11-22T06:59:00Z" }, NOW);
    assert.equal(derived.ageSeconds, 60);
    const unknown = collectorFreshness({ ...base, seconds_since_success: null }, NOW);
    assert.equal(unknown.ratio, null);
    assert.equal(unknown.tone, "off");
    assert.equal(collectorFreshness({ ...base, interval_seconds: 0, seconds_since_success: 5 }, NOW).ratio, null);
  });
});

describe("collectorCounts", () => {
  it("partitions collectors so the parts add up to the total", () => {
    const c = collectorCounts([
      { status: "ok", stale: false },
      { status: "ok", stale: true },
      { status: "failed", stale: true },
      { status: "degraded", stale: false },
      { status: "disabled", stale: false },
    ]);
    assert.deepEqual([c.healthy, c.stale, c.failed, c.degraded, c.other, c.total], [1, 1, 1, 1, 1, 5]);
    assert.equal(c.healthy + c.stale + c.failed + c.degraded + c.other, c.total);
    assert.deepEqual([c.tone, c.label], ["bad", "Failing"]);
  });
  it("names an empty report set instead of calling it healthy", () => {
    assert.deepEqual([collectorCounts([]).tone, collectorCounts([]).label], ["bad", "No reports"]);
    assert.equal(collectorCounts([{ status: "ok", stale: true }]).label, "Degraded");
    assert.equal(collectorCounts([{ status: "ok", stale: false }]).label, "Healthy");
  });
});

describe("gatewayRejections", () => {
  it("sums every decision that is not an acceptance, largest first", () => {
    const out = gatewayRejections({ window_hours: 24, quarantined_records: 5, audit_decisions: { unauthenticated: 13, forbidden: 17, accepted: 400 } });
    assert.ok(out);
    assert.equal(out.rejected, 30);
    assert.deepEqual(
      out.decisions.map((d) => [d.decision, d.rejection]),
      [
        ["accepted", false],
        ["forbidden", true],
        ["unauthenticated", true],
      ],
    );
    assert.equal(gatewayRejections(null), null);
    assert.equal(gatewayRejections({ window_hours: 24, quarantined_records: 0, audit_decisions: {} })?.rejected, 0);
  });
});

describe("ruleExecution and aiSummary", () => {
  it("adds runs and failures over the rules that ran", () => {
    const run = (failures: number, status = "succeeded") => ({
      rule_version: "1.0.0",
      last_run_at: NOW,
      last_status: status,
      last_duration_ms: 10,
      missing_sources: failures > 0 ? ["linux.app"] : [],
      runs_24h: 100,
      failures_24h: failures,
    });
    const out = ruleExecution([
      { rule_id: "VM-001", last_run: run(0) },
      { rule_id: "VM-002", last_run: run(2, "failed") },
      { rule_id: "GH-001", enabled: true, last_run: null, run_stale: true },
    ]);
    assert.deepEqual([out.runs24h, out.failures24h, out.failingNow, out.neverRan, out.overdue, out.quiet], [200, 2, 1, 1, 1, 1]);
  });

  it("counts flags as reported (unknown stays unknown) and finds the latest call", () => {
    const provider = (o: Record<string, unknown>) =>
      zAIProviderHealth.parse({ provider: "typesafe-jev", task: "triage", window_hours: 24, status_counts: {}, ...o });
    const out = aiSummary([
      provider({ enabled: false, configured: false, last_assessment_at: "2026-11-21T21:00:00Z", last_status: "ok" }),
      provider({ provider: "google-gemini", task: "summary", enabled: null, configured: true, last_assessment_at: "2026-11-21T22:00:00Z", last_status: "timeout" }),
    ]);
    assert.deepEqual([out.total, out.enabled, out.disabled, out.unknown, out.configured], [2, 0, 1, 1, 1]);
    assert.deepEqual(out.lastCall, { provider: "google-gemini", at: "2026-11-21T22:00:00Z", status: "timeout" });
    assert.equal(aiSummary([]).lastCall, null);
    assert.deepEqual(["ok", "timeout", "error", "disabled", null].map(aiStatusTone), ["ok", "warn", "bad", "off", "off"]);
  });
});

describe("healthFinding", () => {
  const response = (over: Partial<HealthResponse> = {}): HealthResponse =>
    zHealthResponse.parse({
      generated_at: NOW,
      storage: { reachable: true },
      collectors: [],
      pipeline: [],
      rules: [],
      ai: [],
      ai_configuration_source: "settings",
      ingest: { window_hours: 24, quarantined_records: 5, audit_decisions: {} },
      notes: [],
      ...over,
    });
  it("says unknown when no current spool report exists, and 0 only for a real zero", () => {
    assert.equal(
      healthFinding(response()),
      "No collector has reported · ingestion spool depth unknown · 5 quarantined in 24 h · 0 rule failures in 24 h",
    );
  });
});

/** System health view model: freshness budget, collector partition, rejections, Jev status labels. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { type HealthResponse, zAIProviderHealth, zHealthResponse } from "../../../lib/api/schemas";

import {
  aiStatusTone,
  apiProcessView,
  collectorCounts,
  collectorFreshness,
  gatewayRejections,
  healthFinding,
  otelDelivery,
  ruleExecution,
  runtimeView,
} from "./model";

const NOW = "2026-11-22T07:00:00Z";

describe("OpenTelemetry delivery", () => {
  it("renders per-node delivery state and distinguishes missing measurements from zero", () => {
    const delivery = otelDelivery({ collector_type: "k8s_otel", details: {
      delivery_state: "dropping_records", queue_requests: 0, queue_capacity_requests: 100,
      accepted_records: 17, sent_records: "17", send_failed_records: -1,
    } });
    assert.equal(delivery?.label, "Dropping records");
    assert.equal(delivery.tone, "bad");
    assert.deepEqual(delivery.measures.map(({ value }) => value), [0, 100, 17, null, null, null]);
  });

  it("keeps absent or unsupported delivery reports unknown", () => {
    assert.equal(otelDelivery({ collector_type: "k8s_otel" })?.label, "Delivery unknown");
    assert.equal(otelDelivery({ collector_type: "k8s_otel", details: { delivery_state: "constructor" } })?.tone, "off");
    assert.equal(otelDelivery({ collector_type: "linux", details: { delivery_state: "delivering" } }), null);
  });
});

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

describe("ruleExecution and AI status", () => {
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

  it("keeps unknown Jev flags unknown and maps assessment statuses to tones", () => {
    const jev = zAIProviderHealth.parse({ provider: "typesafe-jev", task: "triage", window_hours: 24, status_counts: {} });
    assert.equal(jev.enabled ?? null, null);
    assert.equal(jev.configured ?? null, null);
    assert.deepEqual(["ok", "timeout", "error", "disabled", null].map(aiStatusTone), ["ok", "warn", "bad", "off", "off"]);
  });

  it("takes Jev's running state from the ai-worker and keeps a missing report unknown", () => {
    assert.deepEqual(
      ["ok", "degraded", "failed", "disabled", null, "unknown"].map((s) => runtimeView(s).label),
      ["Running", "Degraded", "Failing", "Disabled", "Not reporting", "unknown"],
    );
    assert.equal(runtimeView(null).tone, "off");
    assert.equal(apiProcessView({ enabled: false, configured: false }), "disabled, no key");
    assert.equal(apiProcessView({}), "flag unknown, key presence unknown");
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

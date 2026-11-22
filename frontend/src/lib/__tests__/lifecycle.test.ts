/** Inventory lifecycle presentation (UI-5): stale / retired assets and collectors. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { zAssetListItem, zAssetListResponse, zCollectorStatus, zHealthResponse } from "../api/schemas";
import { humanizeLifecycleReason, humanizeSeconds, lifecycleView, retiredHiddenText } from "../lifecycle";

describe("humanizeSeconds", () => {
  it("spells second counts in whole units, rounded down", () => {
    assert.equal(humanizeSeconds(45), "45 s");
    assert.equal(humanizeSeconds(3600), "1 h");
    assert.equal(humanizeSeconds(5400), "90 min");
    assert.equal(humanizeSeconds(7200), "2 h");
    assert.equal(humanizeSeconds(61210), "17 h");
    assert.equal(humanizeSeconds(86400), "24 h");
    assert.equal(humanizeSeconds(3 * 86400), "3 d");
  });
});

describe("humanizeLifecycleReason", () => {
  it("rewrites only the API's '<n>s' second counts and keeps its words", () => {
    assert.equal(
      humanizeLifecycleReason(
        "last observed 61210s ago (threshold 3600s); no collector covering it reports; retired once unobserved for 86400s",
      ),
      "last observed 17 h ago (threshold 1 h); no collector covering it reports; retired once unobserved for 24 h",
    );
    assert.equal(humanizeLifecycleReason("sha 12s3"), "sha 12s3");
    assert.equal(humanizeLifecycleReason(null), null);
    assert.equal(humanizeLifecycleReason("   "), null);
  });
  it("caps very long reasons", () => {
    const long = humanizeLifecycleReason("x".repeat(1000));
    assert.ok(long !== null && long.length <= 280 && long.endsWith("…"));
  });
});

describe("lifecycleView", () => {
  it("shows nothing for active or missing states", () => {
    assert.equal(lifecycleView("active"), null);
    assert.equal(lifecycleView(undefined), null);
    assert.equal(lifecycleView(null, "anything"), null);
  });
  it("labels stale (amber, still counted) and retired (muted, left out)", () => {
    const stale = lifecycleView("stale", "last observed 7200s ago");
    assert.equal(stale?.label, "Stale");
    assert.equal(stale?.tone, "warn");
    assert.equal(stale?.reason, "last observed 2 h ago");
    const retired = lifecycleView("retired");
    assert.equal(retired?.label, "Retired");
    assert.equal(retired?.tone, "off");
    assert.equal(retired?.reason, null);
  });
  it("renders an unknown state as its own token, never as a known one", () => {
    assert.equal(lifecycleView("archived")?.label, "archived");
  });
});

describe("retiredHiddenText", () => {
  it("counts what a view left out, and says nothing for zero", () => {
    const noun = { one: "asset", many: "assets" };
    assert.equal(retiredHiddenText(2, noun), "2 retired assets hidden");
    assert.equal(retiredHiddenText(1, noun), "1 retired asset hidden");
    assert.equal(retiredHiddenText(0, noun), null);
  });
});

describe("lifecycle fields in the API schemas", () => {
  const asset = {
    asset_id: "github:octocat/hello-world",
    asset_type: "github_repository",
    name: "octocat/hello-world",
    environment: "lab",
    criticality: "medium",
    labels: {},
    first_seen: "2026-11-21T14:47:29Z",
    last_seen: "2026-11-21T14:47:29Z",
    observed_by: "github-mechanics-test",
    collectors_total: 1,
    collectors_stale: 1,
    coverage_status: "stale",
    open_alerts: 0,
  };
  it("defaults to active / 0 when an older API omits them", () => {
    const parsed = zAssetListItem.parse(asset);
    assert.equal(parsed.lifecycle_state, "active");
    assert.equal(zAssetListResponse.parse({ items: [], page: { limit: 200, offset: 0, returned: 0, total: 0, has_more: false } }).retired_excluded, 0);
  });
  it("keeps the API's values", () => {
    const parsed = zAssetListItem.parse({ ...asset, lifecycle_state: "retired", lifecycle_reason: "r", last_observed_at: "2026-11-21T14:47:29Z" });
    assert.equal(parsed.lifecycle_state, "retired");
    assert.equal(parsed.lifecycle_reason, "r");
  });
  it("parses collector lifecycle and the self-test flag, and the health retired count", () => {
    const collector = zCollectorStatus.parse({
      collector_id: "sdk-heartbeat-example",
      collector_type: "heartbeat",
      asset_id: "macos:workstation-01",
      source_types: ["extorq.pipeline"],
      status: "ok",
      last_reported_at: "2026-11-21T14:47:29Z",
      events_collected: 0,
      records_buffered: 0,
      collector_version: "0.1.0",
      interval_seconds: 60,
      stale: true,
      self_test: true,
      lifecycle_state: "retired",
    });
    assert.equal(collector.self_test, true);
    assert.equal(collector.lifecycle_state, "retired");
    const health = zHealthResponse.safeParse({
      generated_at: "2026-11-22T08:00:00Z",
      storage: { reachable: true },
      collectors: [],
      pipeline: [],
      rules: [],
      ai: [],
      ai_configuration_source: "x",
      notes: [],
    });
    assert.ok(health.success);
    assert.equal(health.data?.collectors_retired, 0);
  });
});

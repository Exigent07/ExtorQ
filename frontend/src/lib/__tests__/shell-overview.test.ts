/** Console shell navigation and Overview presentation rules (UI-1 redesign). */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { AssetClassCoverage, AssetListItem, TimeSeriesResponse } from "../api/schemas";
import { activeNav, routeCrumbs } from "../navigation";
import {
  activitySeries,
  alertKpi,
  assetKpi,
  classRows,
  collectionKpi,
  findingsKpi,
  importantAlerts,
  niceTicks,
  otherClasses,
  overviewFinding,
} from "../overview";

describe("routeCrumbs / activeNav", () => {
  it("maps every console route to its group, section and object", () => {
    assert.deepEqual(routeCrumbs("/"), [{ label: "Monitor" }, { label: "Overview" }]);
    assert.deepEqual(routeCrumbs("/detections"), [{ label: "Detect" }, { label: "Detections" }]);
    assert.deepEqual(routeCrumbs("/health"), [{ label: "Operate" }, { label: "System health" }]);
    assert.deepEqual(routeCrumbs("/assets/linux%3Alab-vm-01"), [
      { label: "Monitor" },
      { label: "Assets", href: "/assets" },
      { label: "linux:lab-vm-01", mono: true },
    ]);
    assert.deepEqual(routeCrumbs("/investigations/e70639259d3044a6da955d9bc79e48cd").at(-1), {
      label: "Alert e7063925…",
      mono: true,
    });
    assert.equal(activeNav("/investigations/abc"), "detections");
    assert.equal(activeNav("/services/abc"), "assets");
    assert.equal(activeNav("/nope"), null);
  });

  it("never echoes an invalid identifier from the URL", () => {
    assert.deepEqual(routeCrumbs("/assets/%3Cscript%3E").at(-1), { label: "Asset" });
    assert.deepEqual(routeCrumbs("/assets/%E0%A4%A").at(-1), { label: "Asset" });
    assert.deepEqual(routeCrumbs("/investigations/not-an-id").at(-1), { label: "Alert" });
    assert.deepEqual(routeCrumbs("/services/..%2F..").at(-1), { label: "Service" });
  });
});

const COVERAGE = (over: Partial<AssetClassCoverage> & { asset_type: string }): AssetClassCoverage => ({
  expected: true,
  assets_total: 1,
  assets_ok: 1,
  assets_degraded: 0,
  assets_stale: 0,
  assets_without_collector: 0,
  assets_retired: 0,
  status: "ok",
  last_event_at: null,
  ...over,
});

const ASSET = (over: Partial<AssetListItem> & { asset_id: string; asset_type: string }): AssetListItem => ({
  name: over.asset_id.split(":")[1] ?? over.asset_id,
  display_name: null,
  parent_asset_id: null,
  environment: "lab",
  criticality: "medium",
  owner: null,
  labels: {},
  first_seen: "2026-11-21T00:00:00Z",
  last_seen: "2026-11-22T00:00:00Z",
  observed_by: "test",
  collectors_total: 1,
  collectors_stale: 0,
  collectors_inherited: 0,
  coverage_status: "ok",
  last_event_at: null,
  open_alerts: 0,
  lifecycle_state: "active",
  last_observed_at: null,
  lifecycle_reason: null,
  ...over,
});

describe("asset class rows", () => {
  const coverage = [
    COVERAGE({ asset_type: "macos_host", assets_ok: 0, assets_degraded: 1, status: "degraded" }),
    COVERAGE({ asset_type: "linux_host" }),
    COVERAGE({
      asset_type: "github_repository",
      assets_total: 3,
      assets_ok: 1,
      assets_stale: 1,
      assets_without_collector: 1,
      status: "degraded",
    }),
    COVERAGE({ asset_type: "github_account", expected: false, assets_total: 3, assets_ok: 0, status: "missing" }),
  ];
  const assets = [
    ASSET({ asset_id: "macos:workstation-01", asset_type: "macos_host", collectors_total: 2, collectors_stale: 1, coverage_status: "degraded" }),
    ASSET({ asset_id: "github:a/old", asset_type: "github_repository", coverage_status: "missing", collectors_total: 0 }),
    ASSET({ asset_id: "github:o/lab", asset_type: "github_repository", coverage_status: "ok" }),
  ];

  it("keeps the four classes in mark order and marks an unreported class unknown, not healthy", () => {
    const rows = classRows(coverage, assets);
    assert.deepEqual(
      rows.map((r) => r.assetType),
      ["macos_host", "linux_host", "kubernetes_cluster", "github_repository"],
    );
    const k8s = rows[2];
    assert.equal(k8s?.coverage, null);
    assert.equal(k8s?.tone, "off");
    assert.equal(k8s?.statusLabel, "Not reported");
  });

  it("explains degraded classes from API counts only", () => {
    const rows = classRows(coverage, assets);
    assert.equal(rows[0]?.reason, "1 of 2 collectors stale");
    assert.equal(rows[3]?.reason, "1 stale · 1 without collector");
    assert.equal(rows[1]?.reason, null);
    // healthiest asset first
    assert.deepEqual(rows[3]?.assets?.map((a) => a.asset_id), ["github:o/lab", "github:a/old"]);
    // without the asset list the reason falls back to the class counts
    assert.equal(classRows(coverage, null)[0]?.reason, "1 host degraded");
  });

  it("counts reporting assets and healthy classes without rounding", () => {
    const kpi = assetKpi(classRows(coverage, assets));
    assert.deepEqual(kpi, { reporting: 3, total: 5, classesHealthy: 1, classesTotal: 4, tone: "warn" });
    assert.deepEqual(
      otherClasses(coverage).map((c) => c.asset_type),
      ["github_account"],
    );
  });
});

describe("KPIs and the page finding", () => {
  const open = { critical: 0, high: 4, medium: 8, low: 2, info: 0, total: 14 };

  it("open alerts: total and tone from the severity counts", () => {
    const kpi = alertKpi(open);
    assert.equal(kpi.total, 14);
    assert.equal(kpi.serious, 4);
    assert.equal(kpi.tone, "warn");
    assert.equal(alertKpi({ ...open, critical: 1 }).tone, "bad");
    assert.equal(alertKpi({ critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 }).tone, "ok");
  });

  it("findings: critical + high and unverified as reported", () => {
    const kpi = findingsKpi({
      lifecycle_available: true,
      source: "v_findings_current",
      counts: { critical: 45, high: 795, medium: 1239, low: 1531, info: 5, total: 3615 },
      unverified: { critical: 0, high: 0, medium: 0, low: 5, info: 0, total: 5 },
      note: null,
    });
    assert.equal(kpi.serious, 840);
    assert.equal(kpi.unverified, 5);
    assert.equal(kpi.tone, "bad");
  });

  it("collection: no reports is a failure, stale is degraded", () => {
    const base = {
      collectors_total: 13,
      collectors_ok: 11,
      collectors_stale: 2,
      collectors_failing: 0,
      pipeline_components: 4,
      pipeline_unhealthy: 0,
      rules_total: 9,
      rules_failing: 0,
      rule_failures_24h: 0,
      no_collector_reports: false,
      no_pipeline_reports: false,
      no_rule_runs: false,
      collectors_retired: 0,
    };
    assert.equal(collectionKpi(base).tone, "warn");
    assert.equal(collectionKpi({ ...base, collectors_stale: 0 }).tone, "ok");
    assert.equal(collectionKpi({ ...base, collectors_failing: 1 }).tone, "bad");
    assert.deepEqual(collectionKpi({ ...base, no_collector_reports: true }), { ok: 0, total: 0, tone: "bad", statusLabel: "No reports" });
  });

  it("states the finding from the data", () => {
    const coverage = [
      COVERAGE({ asset_type: "macos_host", status: "degraded" }),
      COVERAGE({ asset_type: "linux_host" }),
      COVERAGE({ asset_type: "github_repository", status: "degraded" }),
      COVERAGE({ asset_type: "github_account", expected: false, status: "missing" }),
    ];
    assert.equal(
      overviewFinding({ open_alerts: open, asset_coverage: coverage }),
      "14 open alerts, 4 high · macOS host and GitHub repository coverage degraded",
    );
    assert.equal(
      overviewFinding({
        open_alerts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
        asset_coverage: [COVERAGE({ asset_type: "linux_host" })],
      }),
      "No open alerts · all monitored classes reporting",
    );
  });
});

describe("alert activity", () => {
  const series: TimeSeriesResponse = {
    metric: "alerts",
    range: { since: "2026-11-21T00:00:00Z", until: "2026-11-21T04:00:00Z" },
    bucket_seconds: 3600,
    group_by: "severity",
    points: [
      { bucket_start: "2026-11-21T01:00:00Z", group: "high", count: 3 },
      { bucket_start: "2026-11-21T01:00:00Z", group: "medium", count: 1 },
      { bucket_start: "2026-11-21T03:00:00Z", group: "low", count: 2 },
    ],
    truncated: false,
  };

  it("builds dense buckets: empty ones are zero rows, never interpolated", () => {
    const result = activitySeries(series);
    assert.equal(result.rows.length, 4);
    assert.deepEqual(
      result.rows.map((r) => r.total),
      [0, 4, 0, 2],
    );
    assert.equal(result.total, 6);
    assert.equal(result.totals.high, 3);
    assert.equal(result.ungrouped, 0);
  });

  it("picks round y ticks whose top is at or above the maximum", () => {
    assert.deepEqual(niceTicks(0), [0, 1, 2]);
    assert.deepEqual(niceTicks(11), [0, 4, 8, 12]);
    assert.deepEqual(niceTicks(7), [0, 2, 4, 6, 8]);
    assert.deepEqual(niceTicks(130), [0, 50, 100, 150]);
    for (const max of [1, 3, 5, 9, 12, 26, 99, 1234]) {
      const ticks = niceTicks(max);
      assert.ok((ticks.at(-1) ?? 0) >= max, `top tick >= ${max}`);
    }
  });

  it("lists open alerts before closed ones, newest first", () => {
    const alert = (id: string, status: string, last: string) =>
      ({ alert_id: id, analyst_status: status, last_seen: last }) as Parameters<typeof importantAlerts>[0][number];
    const ordered = importantAlerts([
      alert("a", "closed_benign", "2026-11-21T10:00:00Z"),
      alert("b", "new", "2026-11-21T08:00:00Z"),
      alert("c", "investigating", "2026-11-21T09:00:00Z"),
    ]);
    assert.deepEqual(
      ordered.map((a) => a.alert_id),
      ["c", "b", "a"],
    );
  });
});

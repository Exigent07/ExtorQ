/** Assets view rules (UI-4 model, tests by UI-5): health, verdicts, lifecycle, freshness, sources. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  assetHealth,
  assetsFinding,
  assetStatus,
  classOf,
  classStatus,
  collectorFreshness,
  emptyOptionalColumns,
  itemCount,
  openAlertMix,
  relativeParts,
  sortAssets,
  sourceRows,
  windowLabel,
} from "./model";

type Row = Parameters<typeof assetsFinding>[0][number];
const row = (over: Partial<Row> & { asset_type: string }): Row => ({
  coverage_status: "ok",
  collectors_total: 1,
  lifecycle_state: "active",
  ...over,
});

describe("assetHealth", () => {
  it("says 'No collector' instead of a bare 'Missing' when nothing covers the asset", () => {
    assert.deepEqual(assetHealth({ coverage_status: "missing", collectors_total: 0, collectors_stale: 0 }), {
      tone: "bad",
      label: "No collector",
      reason: "No collector reports for this asset",
    });
  });
  it("explains degraded and stale from the API's own counts", () => {
    assert.equal(assetHealth({ coverage_status: "degraded", collectors_total: 2, collectors_stale: 1 }).reason, "1 of 2 collectors stale");
    assert.equal(assetHealth({ coverage_status: "stale", collectors_total: 1, collectors_stale: 1 }).reason, "Its only collector is stale");
    assert.equal(assetHealth({ coverage_status: "ok", collectors_total: 3, collectors_stale: 0 }).label, "Healthy");
  });
});

describe("assetsFinding and classStatus", () => {
  const assets = [
    row({ asset_type: "github_repository" }),
    row({ asset_type: "github_repository", coverage_status: "stale" }),
    row({ asset_type: "github_repository", coverage_status: "missing", collectors_total: 0, lifecycle_state: "retired" }),
    row({ asset_type: "github_account", coverage_status: "missing", collectors_total: 0 }),
  ];
  it("counts monitored assets apart from owner accounts and retired assets", () => {
    assert.equal(
      assetsFinding(assets),
      "1 of 2 monitored assets healthy · 1 with stale collectors · 1 GitHub owner account · 1 retired",
    );
    assert.equal(assetsFinding([]), "No asset has reported an inventory yet");
  });
  it("leaves retired assets out of the class verdict", () => {
    assert.deepEqual(classStatus(assets), { tone: "warn", label: "Degraded", summary: "1 of 2 reporting" });
    assert.deepEqual(classStatus([assets[0]!, assets[2]!]), { tone: "ok", label: "Healthy", summary: "1 of 1 reporting" });
  });
  it("says 'stale' once for assets the API marks stale, never counting them healthy", () => {
    assert.equal(
      assetsFinding([
        row({ asset_type: "linux_host" }),
        row({ asset_type: "github_repository", coverage_status: "ok", lifecycle_state: "stale" }),
        row({ asset_type: "github_repository", coverage_status: "missing", collectors_total: 0, lifecycle_state: "stale" }),
        row({ asset_type: "github_account", coverage_status: "missing", collectors_total: 0, lifecycle_state: "stale" }),
      ]),
      "1 of 3 monitored assets healthy · 2 monitored assets stale · 1 GitHub owner account",
    );
  });
  it("counts a Kubernetes node with its cluster, as the Overview does", () => {
    assert.equal(
      assetsFinding([
        row({ asset_type: "kubernetes_cluster" }),
        row({ asset_type: "kubernetes_node" }),
        row({ asset_type: "linux_host", coverage_status: "degraded" }),
      ]),
      "1 of 2 monitored assets healthy · 1 degraded · 1 Kubernetes node via its cluster",
    );
  });
  it("counts retired assets the API left out of the list as listed apart", () => {
    assert.equal(
      assetsFinding([row({ asset_type: "linux_host" })], 2),
      "1 of 1 monitored asset healthy · 2 retired (listed apart)",
    );
    assert.equal(assetsFinding([], 3), "Only retired assets: 3");
  });
  it("calls a class missing when nothing in it reports", () => {
    assert.equal(classStatus([row({ asset_type: "linux_host", coverage_status: "missing", collectors_total: 0 })]).label, "Missing");
  });
});

describe("classOf and sortAssets", () => {
  it("files accounts under GitHub and unknown types under other", () => {
    assert.equal(classOf("github_account"), "github");
    assert.equal(classOf("kubernetes_node"), "kubernetes");
    assert.equal(classOf("windows_host"), "other");
  });
  it("puts a cluster before its nodes and assets with collectors first", () => {
    const base = {
      name: "x",
      environment: "lab",
      criticality: "medium",
      labels: {},
      first_seen: "2026-11-21T00:00:00Z",
      observed_by: "t",
      collectors_stale: 0,
      collectors_inherited: 0,
      coverage_status: "ok" as const,
      open_alerts: 0,
      lifecycle_state: "active",
    };
    const sorted = sortAssets([
      { ...base, asset_id: "k8s:c/node/n", asset_type: "kubernetes_node", last_seen: "2026-11-22T00:00:00Z", collectors_total: 4 },
      { ...base, asset_id: "k8s:c", asset_type: "kubernetes_cluster", last_seen: "2026-11-21T00:00:00Z", collectors_total: 4 },
    ]);
    assert.deepEqual(
      sorted.map((a) => a.asset_id),
      ["k8s:c", "k8s:c/node/n"],
    );
  });
});

describe("collectorFreshness", () => {
  const base = { stale: false, status: "ok" as const, interval_seconds: 60, seconds_since_success: 30, last_success_at: "2026-11-22T08:00:00Z" };
  it("measures the age against the 3-interval staleness budget", () => {
    const fresh = collectorFreshness(base);
    assert.equal(fresh.label, "Fresh");
    assert.ok(Math.abs((fresh.ratio ?? 0) - 30 / 180) < 1e-9);
    assert.equal(fresh.threshold, "stale after 3 m 00 s");
  });
  it("lets the API's verdict decide the tone", () => {
    assert.equal(collectorFreshness({ ...base, stale: true, seconds_since_success: 9999 }).label, "Stale");
    assert.equal(collectorFreshness({ ...base, last_success_at: null }).label, "Never succeeded");
    assert.equal(collectorFreshness({ ...base, status: "failed" }).tone, "bad");
  });
});

describe("sourceRows", () => {
  it("adds declared sources without events as a real 0 and ignores ancestor collectors", () => {
    const rows = sourceRows(
      [{ source_type: "linux.journald", events: 5 }],
      [
        { asset_id: "linux:vm", source_types: ["linux.journald", "linux.apache"] },
        { asset_id: "k8s:c", source_types: ["k8s.audit"] },
      ],
      "linux:vm",
    );
    assert.deepEqual(
      rows.map((r) => [r.source_type, r.events, r.declared]),
      [
        ["linux.journald", 5, true],
        ["linux.apache", 0, true],
      ],
    );
  });
});

describe("small helpers", () => {
  it("windowLabel names a window that ends now", () => {
    assert.equal(windowLabel({ since: "2026-11-21T08:00:00Z", until: "2026-11-22T08:05:00Z" }, "2026-11-22T08:00:00Z"), "last 24 h");
  });
  it("relativeParts splits a KPI figure from 'ago'", () => {
    assert.deepEqual(relativeParts("4 min ago"), { value: "4 min", unit: "ago" });
    assert.deepEqual(relativeParts("just now"), { value: "just now", unit: null });
  });
  it("itemCount uses the item noun, unknown types as their token", () => {
    assert.equal(itemCount("github_workflow", 1), "1 workflow");
    assert.equal(itemCount("k8s_pod", 12), "12 Pods");
    assert.equal(itemCount("mystery_thing", 2), "2 mystery thing");
  });
  it("openAlertMix only states a mix that adds up to the open total", () => {
    const recent: Parameters<typeof openAlertMix>[0] = [
      { severity: "high", analyst_status: "new" },
      { severity: "medium", analyst_status: "closed_benign" },
    ];
    assert.equal(openAlertMix(recent, 1)?.high, 1);
    assert.equal(openAlertMix(recent, 3), null);
  });
});

describe("assetStatus: one status per asset", () => {
  const base = { coverage_status: "missing" as const, collectors_total: 0, collectors_stale: 0 };
  it("shows the lifecycle state of a stale or retired asset instead of its collector verdict", () => {
    assert.deepEqual(assetStatus({ ...base, lifecycle_state: "stale" }), { kind: "lifecycle", state: "stale" });
    assert.deepEqual(assetStatus({ ...base, lifecycle_state: "retired" }), { kind: "lifecycle", state: "retired" });
  });
  it("shows health for an active asset", () => {
    const status = assetStatus({ ...base, lifecycle_state: "active" });
    assert.equal(status.kind, "health");
    assert.equal(status.kind === "health" ? status.health.label : null, "No collector");
  });
});

describe("emptyOptionalColumns", () => {
  it("hides actor, source address and service columns only when no loaded row fills them", () => {
    assert.deepEqual(emptyOptionalColumns([{ actor_name: null, src_ip: null, service_name: null }]), ["actor", "src", "service"]);
    assert.deepEqual(emptyOptionalColumns([{ k8s_user: "system:admin", src_ip: "10.0.2.2", service_name: "ssh" }, {}]), []);
    assert.deepEqual(emptyOptionalColumns([{ gh_actor_login: "octo" }]), ["src", "service"]);
    assert.deepEqual(emptyOptionalColumns([]), ["actor", "src", "service"]);
  });
});

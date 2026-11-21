/** Filters, time buckets, formatting, the service presentation rules and response schemas. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { zAssetListItem, zServiceItem, zServicesSummary } from "../api/schemas";
import { alertFiltersToSearch, parseAlertFilters, rangeBounds } from "../filters";
import { formatCount, formatDuration, formatInterval, formatRelative, formatUtc, formatVersion } from "../format";
import { buildSeverityLanes } from "../series";
import { attributionOf, coverageCounts, exposureOf, groupServices, serviceCoverage } from "../services";

describe("parseAlertFilters", () => {
  it("keeps only allow-listed or pattern-valid values", () => {
    const filters = parseAlertFilters({
      asset: "linux:lab-vm-01",
      severity: "high",
      rule: "VM-001",
      status: "investigating",
      range: "24h",
      offset: "50",
    });
    assert.deepEqual(filters, {
      asset: "linux:lab-vm-01",
      severity: "high",
      rule: "VM-001",
      status: "investigating",
      range: "24h",
      offset: 50,
    });
  });
  it("drops invalid values instead of forwarding them upstream", () => {
    const filters = parseAlertFilters({
      asset: "../../etc",
      severity: "urgent",
      rule: "drop table",
      status: ["closed_benign", "x"],
      range: "1y",
      offset: "-5",
    });
    assert.deepEqual(filters, { asset: null, severity: null, rule: null, status: "closed_benign", range: "7d", offset: 0 });
  });
  it("serialises only non-default values", () => {
    assert.equal(alertFiltersToSearch({ range: "7d", offset: 0 }), "");
    assert.equal(alertFiltersToSearch({ severity: "critical", range: "1h", offset: 100 }), "?severity=critical&range=1h&offset=100");
  });
  it("computes the range ending now", () => {
    const now = new Date("2026-11-21T12:00:00Z");
    assert.deepEqual(rangeBounds("1h", now), { since: "2026-11-21T11:00:00.000Z", until: "2026-11-21T12:00:00.000Z" });
  });
});

describe("buildSeverityLanes", () => {
  const series = {
    metric: "alerts" as const,
    range: { since: "2026-11-21T00:00:00Z", until: "2026-11-21T06:00:00Z" },
    bucket_seconds: 3600,
    group_by: "severity",
    truncated: false,
    points: [
      { bucket_start: "2026-11-21T01:00:00Z", group: "high", count: 2 },
      { bucket_start: "2026-11-21T01:00:00Z", group: "critical", count: 1 },
      { bucket_start: "2026-11-21T05:00:00Z", group: "high", count: 3 },
      { bucket_start: "2026-11-22T05:00:00Z", group: "high", count: 99 },
    ],
  };
  it("places counts in their buckets, ignores out-of-range points and shares one scale", () => {
    const lanes = buildSeverityLanes(series);
    assert.equal(lanes.buckets.length, 6);
    const high = lanes.lanes.find((l) => l.severity === "high");
    assert.deepEqual(high?.counts, [0, 2, 0, 0, 0, 3]);
    assert.equal(high?.total, 5);
    assert.equal(lanes.max, 3);
    assert.ok(!lanes.lanes.some((l) => l.severity === "info"), "info lane only when present");
  });
  it("draws an empty range honestly (zeros, no padded scale)", () => {
    const lanes = buildSeverityLanes({ ...series, points: [] });
    assert.equal(lanes.max, 0);
    assert.ok(lanes.lanes.every((l) => l.total === 0));
  });
});

describe("format", () => {
  it("prints missing values as a dash and zeros as zeros", () => {
    assert.equal(formatCount(null), "—");
    assert.equal(formatCount(0), "0");
    assert.equal(formatUtc("not a date"), "—");
    assert.equal(formatUtc("2026-11-21T14:32:05.120Z"), "2026-11-21 14:32:05Z");
  });
  it("formats durations, intervals and recency", () => {
    assert.equal(formatDuration(42), "42 s");
    assert.equal(formatDuration(185), "3 m 05 s");
    assert.equal(formatDuration(3 * 86400 + 3600), "3 d 1 h");
    assert.equal(formatInterval(60), "every 60 s");
    assert.equal(formatInterval(300), "every 5 min");
    assert.equal(formatInterval(86400), "every 24 h");
    assert.equal(formatRelative("2026-11-21T12:00:00Z", "2026-11-21T12:04:00Z"), "4 min ago");
    assert.equal(formatRelative(null, "2026-11-21T12:04:00Z"), "—");
  });
  it("prefixes only semver-looking versions", () => {
    assert.equal(formatVersion("0.1.0"), "v0.1.0");
    assert.equal(formatVersion("extorq-scanners 0.1.0"), "extorq-scanners 0.1.0");
  });
});

describe("service coverage rules", () => {
  it("prefers the API's effective coverage state and appends its reasons", () => {
    const badge = serviceCoverage({
      adapter_support: "implemented",
      monitoring_status: "monitored",
      coverage_state: "degraded",
      coverage_reasons: ["telemetry source linux.journald: collector x stale"],
    });
    assert.equal(badge.kind, "degraded");
    assert.ok(badge.detail.includes("Telemetry source linux.journald: collector x stale."));
  });
  it("without an effective state, a planned or missing adapter wins over any monitoring status", () => {
    assert.equal(serviceCoverage({ adapter_support: "planned", monitoring_status: "monitored" }).kind, "planned");
    assert.equal(serviceCoverage({ adapter_support: "none", monitoring_status: "monitored" }).kind, "unsupported");
    assert.equal(serviceCoverage({ adapter_support: "implemented", monitoring_status: "unmonitored" }).kind, "unmonitored");
  });
  it("shows unknown states as reported instead of mapping them to a known one", () => {
    const badge = serviceCoverage({ adapter_support: "experimental", monitoring_status: "sampling" });
    assert.equal(badge.kind, "unknown");
    assert.equal(badge.label, "experimental / sampling");
  });
  it("never implies an attribution that is unknown", () => {
    assert.equal(attributionOf("unknown").label, "Owner unknown");
    assert.ok(attributionOf("unknown").detail.includes("not attributed"));
    assert.equal(exposureOf("any").tone, "warn");
    assert.equal(exposureOf("weird").label, "weird");
  });
  it("counts present services by coverage and tombstones apart", () => {
    const counts = coverageCounts([
      { adapter_support: "implemented", monitoring_status: "monitored", coverage_state: "monitored", present: true },
      { adapter_support: "none", monitoring_status: "unmonitored", coverage_state: "unsupported", present: true },
      { adapter_support: "planned", monitoring_status: "unmonitored", present: true },
      { adapter_support: "implemented", monitoring_status: "monitored", present: false },
    ]);
    assert.equal(counts.discovered, 3);
    assert.equal(counts.monitored, 1);
    assert.equal(counts.unsupported, 1);
    assert.equal(counts.planned, 1);
    assert.equal(counts.removed, 1);
  });
  it("groups Kubernetes workloads and Kubernetes Services separately from host services", () => {
    const groups = groupServices([
      { service_kind: "k8s_service", name: "lab-portal" },
      { service_kind: "host_service", name: "ssh" },
      { service_kind: "k8s_workload", name: "lab-portal" },
      { service_kind: "future_kind", name: "x" },
    ]);
    assert.deepEqual(
      groups.map((g) => g.kind),
      ["host_service", "k8s_workload", "k8s_service", "future_kind"],
    );
  });
});

describe("response schemas", () => {
  const asset = {
    asset_id: "k8s:extorq-lab/node/extorq-lab-control-plane",
    asset_type: "kubernetes_node",
    name: "extorq-lab-control-plane",
    environment: "lab",
    criticality: "medium",
    labels: {},
    first_seen: "2026-11-21T10:00:00Z",
    last_seen: "2026-11-21T10:05:00Z",
    observed_by: "k8s-inventory",
    collectors_total: 1,
    collectors_stale: 0,
    coverage_status: "ok",
    open_alerts: 0,
  };
  it("accepts asset types added by later contract versions", () => {
    assert.equal(zAssetListItem.parse(asset).asset_type, "kubernetes_node");
  });
  it("strips unknown keys so nothing unexpected reaches a component", () => {
    const parsed = zAssetListItem.parse({ ...asset, injected: "<script>" }) as Record<string, unknown>;
    assert.equal("injected" in parsed, false);
  });
  it("rejects wrong types instead of rendering them", () => {
    assert.equal(zAssetListItem.safeParse({ ...asset, open_alerts: "3" }).success, false);
    assert.equal(zAssetListItem.safeParse({ ...asset, last_seen: "yesterday" }).success, false);
  });
  it("parses a service item with endpoints and coverage reasons", () => {
    const service = zServiceItem.parse({
      service_id: "0123456789abcdef0123456789abcdef",
      asset_id: "linux:lab-vm-01",
      service_kind: "host_service",
      service_key: "ssh.service",
      name: "OpenSSH server",
      category: "ssh",
      discovered_via: ["systemd_unit", "listening_socket"],
      adapter_support: "implemented",
      monitoring_status: "monitored",
      coverage_state: "monitored",
      coverage_reasons: [],
      telemetry_sources: ["linux.journald"],
      endpoints: [{ protocol: "tcp", address: "0.0.0.0", port: 22, exposure: "any", attribution: "confirmed" }],
      exposures: ["any"],
      config_refs: ["/etc/ssh/sshd_config"],
      first_seen: "2026-11-21T10:00:00Z",
      last_seen: "2026-11-21T10:05:00Z",
      report_age_seconds: 12,
      report_stale: false,
      present: true,
      observed_by: "linux-ssh-lab-vm-01",
    });
    assert.equal(service.endpoints[0]?.attribution, "confirmed");
  });
  it("defaults missing coverage counts to zero only where the API documents zero defaults", () => {
    const summary = zServicesSummary.parse({ reported: false, coverage: {}, by_kind: [], removed: 0, truncated: false });
    assert.equal(summary.coverage.total, 0);
  });
});

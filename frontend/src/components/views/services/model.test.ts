/** Service view rules: exposure order, Pod/container nesting, one staleness statement, findings line. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { ServiceDetailResponse, ServiceInstance } from "@/lib/api/schemas";

import {
  instanceBreakdown,
  instanceHeadline,
  instanceRows,
  lastTelemetry,
  serviceFinding,
  sortEndpoints,
  staleSentence,
  staleSummary,
  widestExposure,
} from "./model";

const NOW = "2026-11-22T12:00:00Z";

function instance(over: Partial<ServiceInstance> & { instance_id: string; instance_kind: string }): ServiceInstance {
  return {
    service_id: "s1",
    instance_key: over.instance_id,
    state: "running",
    observed_at: "2026-11-22T11:58:00Z",
    observed_by: "k8s-inventory",
    stale: false,
    ...over,
  };
}

describe("exposure", () => {
  const ep = (exposure: string, port: number, address: string | null = null, protocol = "tcp") => ({ exposure, port, address, protocol });
  it("names the widest exposure, 'none' without endpoints", () => {
    assert.equal(widestExposure({ endpoints: [ep("loopback", 1), ep("any", 2), ep("private", 3)] }), "any");
    assert.equal(widestExposure({ endpoints: [], exposures: ["private"] }), "private");
    assert.equal(widestExposure({ endpoints: [] }), "none");
  });
  it("orders endpoints widest exposure first, then port, without dropping any", () => {
    const sorted = sortEndpoints([ep("loopback", 53, "127.0.0.53"), ep("any", 5353, "::", "udp"), ep("loopback", 22), ep("unknown", 80)]);
    assert.deepEqual(
      sorted.map((e) => `${e.exposure}:${e.port}`),
      ["any:5353", "loopback:22", "loopback:53", "unknown:80"],
    );
  });
  it("keeps an unknown exposure token after the known ones (never ranks it as exposed)", () => {
    assert.deepEqual(
      sortEndpoints([ep("weird", 1), ep("private", 2)]).map((e) => e.exposure),
      ["private", "weird"],
    );
  });
});

describe("instanceRows and instanceBreakdown", () => {
  const pod = instance({ instance_id: "p1", instance_kind: "pod", pod_name: "coredns-a" });
  const pod2 = instance({ instance_id: "p2", instance_kind: "pod", pod_name: "coredns-b" });
  const c1 = instance({ instance_id: "c1", instance_kind: "container", container_name: "coredns", parent_instance_id: "p1" });
  const c2 = instance({ instance_id: "c2", instance_kind: "container", container_name: "coredns", parent_instance_id: "p2" });
  const orphan = instance({ instance_id: "c3", instance_kind: "container", container_name: "sidecar", parent_instance_id: "gone" });

  it("nests containers under their Pod whatever the input order; orphans stay rows", () => {
    const rows = instanceRows([c2, orphan, pod2, c1, pod]);
    assert.deepEqual(
      rows.map((r) => [r.instance.instance_id, r.children.map((c) => c.instance_id)]),
      [
        ["p1", ["c1"]],
        ["p2", ["c2"]],
        ["c3", []],
      ],
    );
  });
  it("counts the instances on screen by kind, Pods first", () => {
    assert.equal(instanceBreakdown([c1, pod, c2, pod2]), "2 Pods · 2 containers");
    assert.equal(instanceBreakdown([instance({ instance_id: "x", instance_kind: "process" })]), "1 process");
    assert.equal(instanceBreakdown([instance({ instance_id: "y", instance_kind: "vm" })]), "1 vm");
    assert.equal(instanceBreakdown([]), "");
  });
});

describe("one staleness statement per section", () => {
  it("says nothing when every instance is fresh", () => {
    assert.equal(staleSentence(staleSummary([{ stale: false, observed_at: NOW }]), NOW), null);
  });
  it("states how many are stale and when the newest of them was last observed", () => {
    const summary = staleSummary([
      { stale: true, observed_at: "2026-11-22T08:00:00Z" },
      { stale: true, observed_at: "2026-11-22T10:00:00Z" },
      { stale: false, observed_at: "2026-11-22T11:59:00Z" },
    ]);
    assert.deepEqual(summary, { stale: 2, total: 3, lastObserved: "2026-11-22T10:00:00Z" });
    assert.equal(
      staleSentence(summary, NOW),
      "2 of 3 instances were not re-observed within the staleness threshold (last observed 2 h ago); their current state cannot be confirmed.",
    );
  });
  it("words the single and all-stale cases", () => {
    assert.match(staleSentence(staleSummary([{ stale: true, observed_at: "2026-11-22T08:00:00Z" }]), NOW) ?? "", /^The only instance was/);
    assert.match(
      staleSentence(
        staleSummary([
          { stale: true, observed_at: "x" },
          { stale: true, observed_at: "y" },
        ]),
        NOW,
      ) ?? "",
      /^All 2 instances were not re-observed within the staleness threshold; their/,
    );
  });
});

function detail(over: Partial<ServiceDetailResponse> = {}): ServiceDetailResponse {
  return {
    service: {
      service_id: "s1",
      asset_id: "linux:lab-vm-01",
      service_kind: "host_service",
      service_key: "ssh.service",
      name: "ssh",
      category: "ssh",
      discovered_via: ["systemd_unit"],
      adapter_support: "implemented",
      monitoring_status: "monitored",
      coverage_state: "monitored",
      coverage_reasons: [],
      telemetry_sources: ["linux.journald"],
      endpoints: [],
      exposures: [],
      config_refs: [],
      first_seen: NOW,
      last_seen: NOW,
      report_age_seconds: 60,
      report_stale: false,
      present: true,
      observed_by: "linux-ssh-lab-vm-01",
      invalid_endpoints: 0,
      last_telemetry_at: "2026-11-22T09:00:00Z",
    },
    instances: [],
    instances_total: 0,
    telemetry_range: { since: "2026-11-21T12:00:00Z", until: "2026-11-23T12:00:00Z" },
    telemetry: [],
    auth_activity: {
      range: { since: "2026-11-21T12:00:00Z", until: "2026-11-23T12:00:00Z" },
      total: 0,
      by_outcome: {},
      distinct_actors: 0,
      distinct_sources: 0,
      top_sources: [],
    },
    recent_events: [],
    findings_lifecycle_available: true,
    findings: [],
    findings_total: 0,
    alerts: [],
    alerts_total: 0,
    alerts_range: { since: "2026-10-23T12:00:00Z", until: "2026-11-23T12:00:00Z" },
    notes: [],
    ...over,
  };
}

describe("service page finding", () => {
  it("takes the newer of the discovery record's telemetry time and the newest attributed event", () => {
    const d = detail({
      telemetry: [
        {
          source_type: "linux.journald",
          declared: true,
          collectors: [],
          collection: "fresh",
          events: 3,
          last_event_at: "2026-11-22T11:00:00Z",
        },
      ],
    });
    assert.equal(lastTelemetry(d), "2026-11-22T11:00:00Z");
    assert.equal(lastTelemetry(detail({ service: { ...detail().service, last_telemetry_at: null } })), null);
  });
  it("states coverage, recency, failed authentications, open alerts and findings from API figures", () => {
    const d = detail({
      auth_activity: { ...detail().auth_activity, total: 50, by_outcome: { success: 11, failure: 38, denied: 1 }, distinct_sources: 1 },
      findings_total: 1,
    });
    assert.equal(
      serviceFinding(d, NOW),
      "Monitored · last service telemetry 3 h ago · 39 failed or denied authentications from 1 source · 0 open alerts · 1 finding",
    );
  });
  it("says when no service telemetry was seen instead of inventing a time", () => {
    assert.match(serviceFinding(detail({ service: { ...detail().service, last_telemetry_at: null } }), NOW), /no service telemetry in the window/);
  });
});

describe("instanceHeadline", () => {
  it("counts Pods, with their containers in the sub-label (never Pods + containers as one number)", () => {
    const list = [
      instance({ instance_id: "p1", instance_kind: "pod" }),
      instance({ instance_id: "p2", instance_kind: "pod" }),
      instance({ instance_id: "c1", instance_kind: "container", parent_instance_id: "p1" }),
      instance({ instance_id: "c2", instance_kind: "container", parent_instance_id: "p2" }),
    ];
    assert.deepEqual(instanceHeadline(list, 4), { value: 2, label: "Pods", sub: "2 containers", capped: false });
  });
  it("counts processes as instances", () => {
    const list = [instance({ instance_id: "a", instance_kind: "process" }), instance({ instance_id: "b", instance_kind: "process" })];
    assert.deepEqual(instanceHeadline(list, 2), { value: 2, label: "Instances", sub: "2 processes", capped: false });
  });
  it("keeps an orphan container as its own row", () => {
    const list = [
      instance({ instance_id: "p1", instance_kind: "pod" }),
      instance({ instance_id: "c9", instance_kind: "container", parent_instance_id: "gone" }),
    ];
    assert.deepEqual(instanceHeadline(list, 2), { value: 2, label: "Instances", sub: "1 Pod · 1 container", capped: false });
  });
  it("uses the API total when the list is capped", () => {
    const list = [instance({ instance_id: "p1", instance_kind: "pod" })];
    assert.deepEqual(instanceHeadline(list, 7), { value: 7, label: "Instances", sub: "1 listed", capped: true });
  });
  it("is zero for no instance", () => {
    assert.deepEqual(instanceHeadline([], 0), { value: 0, label: "Instances", sub: "", capped: false });
  });
});

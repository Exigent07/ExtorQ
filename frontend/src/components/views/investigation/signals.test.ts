/** Investigation signals: key signals, threshold checks, sequence stages, grouped context features. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  contextFeatureGroups,
  featureInstant,
  keySignals,
  remainingDetectorFeatures,
  sequenceStages,
  stageGap,
  thresholdChecks,
  thresholdKeys,
} from "./signals";

// Shapes as the live API returned them for the demo alerts (values shortened).
const VM001 = {
  distinct_connections: 9,
  distinct_usernames: 1,
  failed_attempts: 0,
  invalid_user_events: 9,
  peak_window_connections: 9,
  peak_window_failures: 0,
  src_ip_shared_nat: true,
  threshold_connections: 5,
  threshold_failures: 10,
  usernames: ["oracle"],
  window_seconds: 300,
};
const VM001_CTX = {
  app_login_failures: 5,
  causation_established: false,
  http_5xx_count: 0,
  http_events: 12,
  related_candidate: 0,
  ssh_success_after_failures: true,
  ssh_success_users: ["extorq-admin"],
  sudo_after_login: false,
  source_types: ["linux.journald"],
};
const CORR002 = {
  causation_established: false,
  persistence_events: 7,
  persistence_stage_at: "2026-11-21 15:07:11.561",
  persistence_units: ["a.service", "b.service", "lab-portal.service"],
  probe_requests: 23,
  probe_routes: ["/.env", "/admin"],
  probe_routes_distinct: 6,
  probe_stage_at: "2026-11-21 15:06:52.911",
  sequence_seconds: 187,
  ssh_failed_connections: 21,
  ssh_failure_events: 42,
  ssh_stage_at: "2026-11-21 15:07:03.375",
  stage_order: "http_probe>ssh_auth_failures>systemd_persistence",
};

describe("keySignals", () => {
  it("lifts the SSH success after failures with its users", () => {
    const signals = keySignals(VM001, VM001_CTX);
    assert.equal(signals.length, 1);
    assert.equal(signals[0]?.id, "ssh-success");
    assert.equal(signals[0]?.tone, "risk");
    assert.deepEqual(signals[0]?.values, ["extorq-admin"]);
    assert.ok(signals[0]?.consumes.includes("c:ssh_success_users"));
  });
  it("never turns a false flag into a signal", () => {
    assert.deepEqual(keySignals({}, { ssh_success_after_failures: false, sudo_after_login: false }), []);
  });
  it("names GitHub workflow risks with before and after permissions", () => {
    const ids = keySignals(
      {
        write_all_added: true,
        untrusted_checkout_added: true,
        risky_triggers_added: ["pull_request_target"],
        permissions_before: "workflow=contents:read",
        permissions_after: "workflow=write-all",
      },
      { gh_write_all_added: true },
    );
    assert.deepEqual(
      ids.map((s) => s.id),
      ["write-all", "untrusted-checkout", "risky-triggers"],
    );
    assert.deepEqual(ids[0]?.values, ["workflow=contents:read → workflow=write-all"]);
  });
  it("keeps recorded values out of titles (Kubernetes fields are attacker-influenced)", () => {
    const [rbac] = keySignals(
      { risk_flags: ["cluster_admin"], role_ref: "ClusterRole/cluster-admin", subjects: ["ServiceAccount:ns/sa"] },
      null,
    );
    assert.equal(rbac?.title, "Risky RBAC grant");
    assert.deepEqual(rbac?.values, ["cluster_admin", "ClusterRole/cluster-admin", "ServiceAccount:ns/sa"]);
    for (const signal of keySignals({ privileged_flags: ["privileged"], wanted_by: ["x.target"], vendor_unit: false }, null)) {
      assert.ok(!signal.title.includes("privileged_") && !signal.title.includes("x.target"));
    }
  });
  it("marks corroboration apart from risk", () => {
    const signals = keySignals({ audit_corroborated: true, writer_executables: ["/usr/bin/dash"], sources: ["audit", "state"] }, null);
    assert.deepEqual(
      signals.map((s) => [s.id, s.tone]),
      [
        ["auditd", "corroboration"],
        ["audit-state", "corroboration"],
      ],
    );
  });
});

describe("thresholdChecks", () => {
  it("pairs each threshold with its peak window value; met first", () => {
    const checks = thresholdChecks(VM001);
    assert.deepEqual(
      checks.map((c) => [c.key, c.observed, c.threshold, c.met]),
      [
        ["connections", 9, 5, true],
        ["failures", 0, 10, false],
      ],
    );
    assert.deepEqual(thresholdKeys(checks), [
      "d:threshold_connections",
      "d:peak_window_connections",
      "d:threshold_failures",
      "d:peak_window_failures",
    ]);
  });
  it("ignores thresholds without an observed value", () => {
    assert.deepEqual(thresholdChecks({ threshold_x: 3 }), []);
  });
});

describe("sequenceStages", () => {
  it("orders CORR-002's stages with their times, gaps and facts", () => {
    const seq = sequenceStages(CORR002);
    assert.ok(seq);
    assert.deepEqual(
      seq.stages.map((s) => [s.label, s.at, s.sincePrevious === null ? null : Math.round(s.sincePrevious * 10) / 10]),
      [
        ["HTTP probing", "2026-11-21T15:06:52.911Z", null],
        ["SSH authentication failures", "2026-11-21T15:07:03.375Z", 10.5],
        ["systemd persistence", "2026-11-21T15:07:11.561Z", 8.2],
      ],
    );
    assert.deepEqual(seq.stages[0]?.facts, ["23 client-error requests", "6 probe routes"]);
    assert.deepEqual(seq.stages[2]?.facts, ["3 units", "7 events"]);
    assert.equal(seq.totalSeconds, 187);
    assert.ok(seq.consumes.includes("d:stage_order") && seq.consumes.includes("d:ssh_stage_at"));
  });
  it("is null without a stage order", () => {
    assert.equal(sequenceStages(VM001), null);
  });
  it("keeps unknown stage tokens as words without times", () => {
    const seq = sequenceStages({ stage_order: "dns_lookup>exfil_upload" });
    assert.deepEqual(
      seq?.stages.map((s) => [s.label, s.at]),
      [
        ["DNS lookup", null],
        ["Exfil upload", null],
      ],
    );
  });
});

describe("featureInstant / stageGap", () => {
  it("reads ClickHouse UTC times and ISO strings, nothing else", () => {
    assert.equal(featureInstant("2026-11-21 15:07:11.561"), "2026-11-21T15:07:11.561Z");
    assert.equal(featureInstant("2026-11-21T15:07:11Z"), "2026-11-21T15:07:11Z");
    assert.equal(featureInstant("15:07:11"), null);
    assert.equal(featureInstant("2026-13-45 99:99:99"), null);
    assert.equal(featureInstant(42), null);
  });
  it("formats stage gaps", () => {
    assert.equal(stageGap(10.464), "+10.5 s");
    assert.equal(stageGap(8.186), "+8.2 s");
    assert.equal(stageGap(42), "+42 s");
    assert.equal(stageGap(187), "+3 m 07 s");
  });
});

describe("contextFeatureGroups", () => {
  it("groups by source, folds zero counters and drops shown or duplicate keys", () => {
    const consumed = new Set(["c:ssh_success_after_failures", "c:ssh_success_users"]);
    const groups = contextFeatureGroups(VM001_CTX, { ...VM001, causation_established: false }, consumed);
    assert.deepEqual(
      groups.map((g) => [g.id, g.rows.map(([k]) => k), g.zeros.map(([k]) => k)]),
      [
        ["ssh", ["sudo_after_login"], []],
        ["http", ["http_events"], ["http_5xx_count"]],
        ["app", ["app_login_failures"], []],
        ["scope", ["source_types"], ["related_candidate"]],
      ],
    );
  });
  it("drops a context list identical to a detector list under another name", () => {
    const groups = contextFeatureGroups({ http_probe_routes: ["/.env", "/admin"] }, CORR002, new Set());
    assert.deepEqual(groups, []);
  });
});

describe("remainingDetectorFeatures", () => {
  it("keeps only what no signal, check or stage shows", () => {
    const consumed = new Set([...thresholdKeys(thresholdChecks(VM001)), "d:src_ip_shared_nat"]);
    assert.deepEqual(Object.keys(remainingDetectorFeatures(VM001, consumed)), [
      "distinct_connections",
      "distinct_usernames",
      "failed_attempts",
      "invalid_user_events",
      "usernames",
      "window_seconds",
    ]);
  });
});

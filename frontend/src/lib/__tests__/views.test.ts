/** Presentation rules added for demo readiness (session 3): timeline, evidence, coverage, health. */
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { questionTypeLabel } from "../../components/views/investigation/ai-labels";
import { zAssetListItem, zAssetServicesResponse } from "../api/schemas";
import { collectorsSummary } from "../assets";
import { spoolBacklog } from "../health";
import { formatUtc } from "../format";
import { chronological, providerTime, summaryWithoutType } from "../investigation";

describe("summaryWithoutType", () => {
  it("drops the event type the timeline already prints (with or without a colon)", () => {
    assert.equal(
      summaryWithoutType("auth.ssh.invalid_user user=extorq-sim-x from 10.0.2.2:61976", "auth.ssh.invalid_user"),
      "user=extorq-sim-x from 10.0.2.2:61976",
    );
    assert.equal(
      summaryWithoutType("process.audit.exec: auditd exec as euid 0: id -u", "process.audit.exec"),
      "auditd exec as euid 0: id -u",
    );
  });
  it("keeps summaries that only share a prefix, are only the type, or start differently", () => {
    assert.equal(summaryWithoutType("auth.ssh.invalid_users x", "auth.ssh.invalid_user"), "auth.ssh.invalid_users x");
    assert.equal(summaryWithoutType("auth.ssh.invalid_user", "auth.ssh.invalid_user"), "auth.ssh.invalid_user");
    assert.equal(summaryWithoutType("auth.ssh.invalid_user:", "auth.ssh.invalid_user"), "auth.ssh.invalid_user:");
    assert.equal(summaryWithoutType("Workflow modified", "github.workflow.modified"), "Workflow modified");
    assert.equal(summaryWithoutType("anything", ""), "anything");
  });
});

describe("chronological evidence", () => {
  it("orders by event time, then event id, without mutating the input", () => {
    const input = [
      { event_id: "c", event_time: "2026-11-21T15:07:05Z" },
      { event_id: "b", event_time: "2026-11-21T15:07:02Z" },
      { event_id: "a", event_time: "2026-11-21T15:07:05Z" },
    ];
    assert.deepEqual(
      chronological(input).map((e) => e.event_id),
      ["b", "a", "c"],
    );
    assert.deepEqual(
      input.map((e) => e.event_id),
      ["c", "b", "a"],
    );
  });
  it("puts unparsable times last instead of first", () => {
    const out = chronological([
      { event_id: "x", event_time: "not a time" },
      { event_id: "y", event_time: "2026-11-21T15:07:05Z" },
    ]);
    assert.deepEqual(
      out.map((e) => e.event_id),
      ["y", "x"],
    );
  });
});

describe("collectorsSummary", () => {
  it("says when the collectors report for the cluster rather than the node itself", () => {
    const node = { asset_type: "kubernetes_node", collectors_total: 4, collectors_stale: 1, collectors_inherited: 4 };
    assert.equal(collectorsSummary(node), "3 of 4 collectors fresh (via the cluster)");
    assert.equal(collectorsSummary({ ...node, collectors_inherited: 1 }), "3 of 4 collectors fresh (1 via the cluster)");
    assert.equal(
      collectorsSummary({ asset_type: "linux_host", collectors_total: 1, collectors_stale: 0, collectors_inherited: 0 }),
      "1 of 1 collector fresh",
    );
    assert.equal(collectorsSummary({ asset_type: "github_account", collectors_total: 0, collectors_stale: 0 }), "no collector reporting");
  });
  it("accepts list items from an API that does not send the field yet (defaults to own collectors)", () => {
    const item = zAssetListItem.parse({
      asset_id: "linux:lab-vm-01",
      asset_type: "linux_host",
      name: "lab-vm-01",
      environment: "lab",
      criticality: "medium",
      labels: {},
      first_seen: "2026-11-21T10:00:00Z",
      last_seen: "2026-11-21T10:00:00Z",
      observed_by: "linux-ssh-lab-vm-01",
      collectors_total: 2,
      collectors_stale: 0,
      coverage_status: "ok",
      open_alerts: 0,
    });
    assert.equal(item.collectors_inherited, 0);
    assert.equal(collectorsSummary(item), "2 of 2 collectors fresh");
  });
});

describe("spoolBacklog", () => {
  const report = (component: string, queue_depth: number, extra: Record<string, unknown> = {}) => ({
    component,
    queue_depth,
    stale: false,
    superseded: false,
    oldest_queued_age_seconds: null,
    ...extra,
  });
  it("counts the shared spool once and ignores the detector and AI queues", () => {
    const out = spoolBacklog([
      report("ingest", 5, { oldest_queued_age_seconds: 3 }),
      report("writer", 5, { oldest_queued_age_seconds: 4 }),
      report("detector", 9),
      report("ai_worker", 2),
    ]);
    assert.deepEqual(out, { depth: 5, oldestSeconds: 4 });
  });
  it("does not present stale or superseded reports as the current backlog", () => {
    assert.deepEqual(
      spoolBacklog([report("ingest", 7, { stale: true }), report("writer", 3, { superseded: true }), report("ai_worker", 2)]),
      { depth: null, oldestSeconds: null },
    );
    assert.deepEqual(spoolBacklog([report("writer", 0)]), { depth: 0, oldestSeconds: null });
  });
});

describe("Jev question types", () => {
  it("labels the yes/no probability type and shows unknown types as reported", () => {
    assert.equal(questionTypeLabel("noul"), "Yes/no");
    assert.equal(questionTypeLabel("choice"), "Choice");
    assert.equal(questionTypeLabel("ranking"), "ranking");
  });
});

describe("hosted services (Pods on a node)", () => {
  const base = {
    asset_id: "k8s:extorq-lab/node/n1",
    items: [],
    page: { limit: 100, offset: 0, returned: 0, has_more: false, total: 0 },
    summary: { reported: false, coverage: {}, by_kind: [], removed: 0, truncated: false },
  };
  it("defaults to none when the API predates the field (never invented)", () => {
    const parsed = zAssetServicesResponse.parse(base);
    assert.deepEqual(parsed.hosted, []);
    assert.equal(parsed.hosted_truncated, false);
  });
  it("rejects a hosted entry without instances data instead of rendering it", () => {
    assert.throws(() => zAssetServicesResponse.parse({ ...base, hosted: [{ service: {}, instances_on_asset: 1 }] }));
  });
});

describe("providerTime", () => {
  it("formats well-formed ISO instants from the AI provider in the console's UTC style", () => {
    assert.equal(providerTime("2026-11-21T19:58:57.000Z", formatUtc), "2026-11-21 19:58:57Z");
    assert.equal(providerTime("2026-11-21T21:28:57+01:30", formatUtc), "2026-11-21 19:58:57Z");
  });
  it("keeps anything else exactly as the provider wrote it (never guessed)", () => {
    for (const raw of ["shortly after 19:58", "2026-11-21 19:58", "2026-11-21T19:58:57", "2026-13-41T99:99:99Z", ""]) {
      assert.equal(providerTime(raw, formatUtc), raw);
    }
  });
});

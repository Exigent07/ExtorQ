/**
 * The server-side API client at the Fetch boundary. Request and Response exercise the wire
 * shapes without binding a socket. The deployed smoke suite covers the HTTP transport.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, describe, it, mock } from "node:test";

import { z } from "zod";

import type { Session } from "../auth/token";
import { apiRequest } from "../server/api-client";

type Handler = (request: Request) => Response;

const TOKEN = `synthetic-test-token-${randomBytes(24).toString("hex")}`;
const session: Session = { user: "analyst", role: "viewer", sessionId: "s", issuedAt: 0, expiresAt: 0 };
const schema = z.object({ value: z.number() });

let handler: Handler = () => Response.json({});
let hits: Request[] = [];
let dir: string;

before(() => {
  dir = mkdtempSync(join(tmpdir(), "extorq-d2-test-"));
  const tokenFile = join(dir, "api_token");
  writeFileSync(tokenFile, `${TOKEN}\n`, { mode: 0o600 });
  mock.method(globalThis, "fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    hits.push(request);
    return handler(request);
  });
  process.env.EXTORQ_API_BASE_URL = "http://127.0.0.1:1";
  process.env.EXTORQ_API_TOKEN_FILE = tokenFile;
  process.env.EXTORQ_API_TIMEOUT_MS = "1000";
});

after(() => {
  mock.restoreAll();
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  hits = [];
});

const get = () => apiRequest(session, schema, { method: "GET", path: "/api/v1/overview", route: "/api/v1/overview" });

describe("apiRequest", () => {
  it("sends the bearer token and the verified identity, and validates the body", async () => {
    handler = () => Response.json({ value: 7, extra: "stripped" });
    const result = await get();
    assert.ok(result.ok);
    assert.deepEqual(result.data, { value: 7 });
    const req = hits[0]!;
    assert.equal(req.headers.get("authorization"), `Bearer ${TOKEN}`);
    assert.equal(req.headers.get("x-extorq-user"), "analyst");
    assert.equal(req.headers.get("x-extorq-role"), "viewer");
    assert.match(req.headers.get("x-request-id") ?? "", /^[0-9a-f-]{36}$/);
  });

  it("retries idempotent GETs on 503 (bounded) but never retries a POST", async () => {
    handler = () => Response.json({ detail: "storage unavailable" }, { status: 503 });
    const result = await get();
    assert.equal(hits.length, 3);
    assert.ok(!result.ok && result.error.kind === "unavailable");
    assert.ok(!result.ok && result.error.message.includes("storage unavailable"));
    hits = [];
    const post = await apiRequest(session, schema, { method: "POST", path: "/api/v1/alerts/x/state", route: "r", body: {} });
    assert.equal(hits.length, 1);
    assert.ok(!post.ok);
  });

  it("rejects responses that do not match the schema without passing data on", async () => {
    handler = () => Response.json({ value: "seven" });
    const result = await get();
    assert.ok(!result.ok && result.error.kind === "invalid_response");
    assert.ok(!result.ok && result.error.message.includes("value"));
  });

  it("rejects non-JSON and oversized responses", async () => {
    handler = () => new Response("<html>proxy error</html>");
    const result = await get();
    assert.ok(!result.ok && result.error.message === "The API response was not JSON");

    handler = () => new Response(new ReadableStream({
      start(controller) {
        const chunk = Buffer.alloc(1024 * 1024, 0x20);
        for (let i = 0; i < 9; i += 1) controller.enqueue(chunk);
        controller.close();
      },
    }));
    const oversized = await get();
    assert.ok(!oversized.ok && oversized.error.message.includes("size limit"));
  });

  it("requires Fetch to reject redirects when sending credentials", async () => {
    handler = () => { throw new TypeError("redirect rejected"); };
    const result = await apiRequest(session, schema, {
      method: "POST", path: "/api/v1/alerts/x/state", route: "r", body: {},
    });
    assert.ok(!result.ok && result.error.kind === "network");
    assert.equal(hits.length, 1);
    assert.equal(hits[0]?.redirect, "error");
  });

  it("maps 401/403/404/409 to fixed messages", async () => {
    const cases: [number, string][] = [
      [401, "unauthorized"],
      [403, "forbidden"],
      [404, "not_found"],
      [409, "conflict"],
    ];
    for (const [status, kind] of cases) {
      handler = () => Response.json({ detail: "alert not found" }, { status });
      const result = await get();
      assert.ok(!result.ok && result.error.kind === kind, `${status}`);
      if (status === 401) assert.ok(!result.ok && !result.error.message.includes("alert not found"));
    }
  });

  it("refuses paths outside /api/v1 and URLs that escape the configured origin", async () => {
    await assert.rejects(apiRequest(session, schema, { method: "GET", path: "/admin", route: "r" }));
    await assert.rejects(apiRequest(session, schema, { method: "GET", path: "/api/v1/../../x", route: "r" }));
    assert.equal(hits.length, 0);
  });

  it("reports a missing token file by setting name, never by value", async () => {
    const saved = process.env.EXTORQ_API_TOKEN_FILE;
    process.env.EXTORQ_API_TOKEN_FILE = join(dir, "does-not-exist");
    try {
      const result = await get();
      assert.ok(!result.ok && result.error.kind === "config");
      assert.ok(!result.ok && result.error.message.includes("EXTORQ_API_TOKEN_FILE"));
      assert.ok(!result.ok && !result.error.message.includes(TOKEN));
      assert.equal(hits.length, 0);
    } finally {
      process.env.EXTORQ_API_TOKEN_FILE = saved;
    }
  });
});

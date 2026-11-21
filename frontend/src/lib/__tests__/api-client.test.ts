/**
 * The server-side API client against a throwaway local HTTP server: credentials and identity
 * headers, retries, size and schema limits, redirects and configuration errors.
 * The token is synthetic (random per run) and lives in a temporary file.
 */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, beforeEach, describe, it } from "node:test";

import { z } from "zod";

import type { Session } from "../auth/token";
import { apiRequest } from "../server/api-client";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;

const TOKEN = `synthetic-test-token-${randomBytes(24).toString("hex")}`;
const session: Session = { user: "analyst", role: "viewer", sessionId: "s", issuedAt: 0, expiresAt: 0 };
const schema = z.object({ value: z.number() });

let server: Server;
let handler: Handler = (_req, res) => res.end("{}");
let hits: IncomingMessage[] = [];
let dir: string;

before(async () => {
  dir = mkdtempSync(join(tmpdir(), "extorq-d2-test-"));
  const tokenFile = join(dir, "api_token");
  writeFileSync(tokenFile, `${TOKEN}\n`, { mode: 0o600 });
  server = createServer((req, res) => {
    hits.push(req);
    handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  process.env.EXTORQ_API_BASE_URL = `http://127.0.0.1:${port}`;
  process.env.EXTORQ_API_TOKEN_FILE = tokenFile;
  process.env.EXTORQ_API_TIMEOUT_MS = "1000";
});

after(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

beforeEach(() => {
  hits = [];
});

const get = () => apiRequest(session, schema, { method: "GET", path: "/api/v1/overview", route: "/api/v1/overview" });

describe("apiRequest", () => {
  it("sends the bearer token and the verified identity, and validates the body", async () => {
    handler = (_req, res) => res.end(JSON.stringify({ value: 7, extra: "stripped" }));
    const result = await get();
    assert.ok(result.ok);
    assert.deepEqual(result.data, { value: 7 });
    const req = hits[0]!;
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(req.headers["x-extorq-user"], "analyst");
    assert.equal(req.headers["x-extorq-role"], "viewer");
    assert.match(String(req.headers["x-request-id"]), /^[0-9a-f-]{36}$/);
  });

  it("retries idempotent GETs on 503 (bounded) but never retries a POST", async () => {
    handler = (_req, res) => {
      res.statusCode = 503;
      res.end(JSON.stringify({ detail: "storage unavailable" }));
    };
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
    handler = (_req, res) => res.end(JSON.stringify({ value: "seven" }));
    const result = await get();
    assert.ok(!result.ok && result.error.kind === "invalid_response");
    assert.ok(!result.ok && result.error.message.includes("value"));
  });

  it("rejects non-JSON and oversized responses", async () => {
    handler = (_req, res) => res.end("<html>proxy error</html>");
    let result = await get();
    assert.ok(!result.ok && result.error.message === "The API response was not JSON");
    handler = (_req, res) => {
      res.setHeader("content-type", "application/json");
      const chunk = Buffer.alloc(1024 * 1024, 0x20);
      for (let i = 0; i < 9; i += 1) res.write(chunk);
      res.end();
    };
    result = await get();
    assert.ok(!result.ok && result.error.message.includes("size limit"));
  });

  it("does not follow redirects (the token is never replayed to another location)", async () => {
    handler = (req, res) => {
      if (req.url?.startsWith("/elsewhere")) return res.end(JSON.stringify({ value: 1 }));
      res.statusCode = 302;
      res.setHeader("location", "/elsewhere");
      res.end();
    };
    const result = await get();
    assert.ok(!result.ok);
    assert.equal(hits.filter((h) => h.url?.startsWith("/elsewhere")).length, 0);
  });

  it("maps 401/403/404/409 to fixed messages", async () => {
    const cases: [number, string][] = [
      [401, "unauthorized"],
      [403, "forbidden"],
      [404, "not_found"],
      [409, "conflict"],
    ];
    for (const [status, kind] of cases) {
      handler = (_req, res) => {
        res.statusCode = status;
        res.end(JSON.stringify({ detail: "alert not found" }));
      };
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

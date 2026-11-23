/** Credential comparison, login throttling and signed session tokens. Secrets here are synthetic test values. */
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";

import { SignJWT } from "jose";

import { constantTimeEqual, matchAccount } from "../auth/password";
import { FailureLimiter } from "../auth/rate-limit";
import { isRole, permissions } from "../auth/roles";
import { SESSION_TTL_SECONDS, sessionKey, signSessionToken, verifySessionToken } from "../auth/token";

// Synthetic, generated per test run (never a real credential).
const SECRET = randomBytes(32).toString("hex");
const OTHER_SECRET = randomBytes(32).toString("hex");
const ACCOUNTS = [
  { username: "analyst", role: "analyst" as const, password: "synthetic-analyst-pass" },
  { username: "viewer", role: "viewer" as const, password: "synthetic-viewer-pass" },
];

describe("matchAccount", () => {
  it("matches the right account only", () => {
    assert.equal(matchAccount(ACCOUNTS, "analyst", "synthetic-analyst-pass")?.role, "analyst");
    assert.equal(matchAccount(ACCOUNTS, "viewer", "synthetic-viewer-pass")?.role, "viewer");
  });
  it("rejects wrong passwords, swapped passwords and unknown users", () => {
    assert.equal(matchAccount(ACCOUNTS, "analyst", "synthetic-viewer-pass"), null);
    assert.equal(matchAccount(ACCOUNTS, "analyst", ""), null);
    assert.equal(matchAccount(ACCOUNTS, "root", "synthetic-analyst-pass"), null);
    assert.equal(matchAccount(ACCOUNTS, "Analyst", "synthetic-analyst-pass"), null);
  });
  it("never matches a disabled account (no password configured)", () => {
    const disabled = [{ username: "analyst", role: "analyst" as const, password: null }];
    assert.equal(matchAccount(disabled, "analyst", ""), null);
    assert.equal(matchAccount(disabled, "analyst", "anything"), null);
  });
  it("compares strings of different lengths without throwing", () => {
    assert.equal(constantTimeEqual("a", "a".repeat(1000)), false);
    assert.equal(constantTimeEqual("same", "same"), true);
  });
});

describe("FailureLimiter", () => {
  const options = { maxFailures: 3, windowMs: 60_000, lockMs: 30_000, maxKeys: 2 };
  it("locks a key after maxFailures within the window and unlocks after lockMs", () => {
    const limiter = new FailureLimiter(options);
    for (let i = 0; i < 3; i += 1) limiter.recordFailure("analyst", 1000 + i);
    const locked = limiter.check("analyst", 2000);
    assert.equal(locked.allowed, false);
    assert.ok(!locked.allowed && locked.retryAfterSeconds > 0);
    assert.equal(limiter.check("analyst", 1002 + 30_000).allowed, true);
  });
  it("forgets failures outside the window", () => {
    const limiter = new FailureLimiter(options);
    limiter.recordFailure("viewer", 0);
    limiter.recordFailure("viewer", 1);
    limiter.recordFailure("viewer", 120_000);
    assert.equal(limiter.check("viewer", 120_001).allowed, true);
  });
  it("bounds memory by evicting the least recently touched key", () => {
    const limiter = new FailureLimiter({ ...options, maxFailures: 1 });
    limiter.recordFailure("a", 1);
    limiter.recordFailure("b", 2);
    limiter.recordFailure("c", 3);
    assert.equal(limiter.check("a", 4).allowed, true, "evicted");
    assert.equal(limiter.check("c", 4).allowed, false);
  });
  it("reset clears a key after a successful login", () => {
    const limiter = new FailureLimiter({ ...options, maxFailures: 1 });
    limiter.recordFailure("a", 1);
    limiter.reset("a");
    assert.equal(limiter.check("a", 2).allowed, true);
  });
});

describe("roles", () => {
  it("only analysts may mutate (the alert workflow state is the one mutation)", () => {
    assert.equal(permissions.changeAlertState("analyst"), true);
    assert.equal(permissions.changeAlertState("viewer"), false);
    assert.deepEqual(Object.keys(permissions), ["changeAlertState"]);
    assert.equal(isRole("admin"), false);
  });
});

describe("session tokens", () => {
  const key = sessionKey(SECRET);
  it("round-trips a signed session", async () => {
    const { token, session } = await signSessionToken({ user: "analyst", role: "analyst" }, key);
    const verified = await verifySessionToken(token, key);
    assert.deepEqual(verified, session);
    assert.equal(session.expiresAt - session.issuedAt, SESSION_TTL_SECONDS);
  });
  it("rejects a token signed with another key", async () => {
    const { token } = await signSessionToken({ user: "analyst", role: "analyst" }, sessionKey(OTHER_SECRET));
    assert.equal(await verifySessionToken(token, key), null);
  });
  it("rejects expired tokens", async () => {
    const issued = Math.floor(Date.now() / 1000) - SESSION_TTL_SECONDS - 60;
    const { token } = await signSessionToken({ user: "viewer", role: "viewer" }, key, issued);
    assert.equal(await verifySessionToken(token, key), null);
  });
  it("rejects tampered payloads and the 'none' algorithm", async () => {
    const { token } = await signSessionToken({ user: "viewer", role: "viewer" }, key);
    const [header, , signature] = token.split(".");
    const forgedPayload = Buffer.from(JSON.stringify({ sub: "viewer", role: "analyst" })).toString("base64url");
    assert.equal(await verifySessionToken(`${header}.${forgedPayload}.${signature}`, key), null);
    const none = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    assert.equal(await verifySessionToken(`${none}.${forgedPayload}.`, key), null);
  });
  it("rejects validly signed tokens with an unknown role or a bad username", async () => {
    const now = Math.floor(Date.now() / 1000);
    const forge = (sub: string, role: string) =>
      new SignJWT({ role })
        .setProtectedHeader({ alg: "HS256" })
        .setSubject(sub)
        .setIssuer("extorq-console")
        .setAudience("extorq-console")
        .setIssuedAt(now)
        .setExpirationTime(now + 60)
        .setJti("synthetic")
        .sign(key);
    assert.equal(await verifySessionToken(await forge("analyst", "admin"), key), null);
    assert.equal(await verifySessionToken(await forge("bad user\n", "viewer"), key), null);
  });
  it("refuses short signing secrets and oversized tokens", async () => {
    assert.throws(() => sessionKey("too-short"));
    assert.equal(await verifySessionToken("x".repeat(5000), key), null);
    assert.equal(await verifySessionToken(undefined, key), null);
  });
});

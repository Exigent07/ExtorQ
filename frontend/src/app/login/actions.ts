"use server";

import { redirect } from "next/navigation";

import { matchAccount } from "@/lib/auth/password";
import { FailureLimiter } from "@/lib/auth/rate-limit";
import { USERNAME_PATTERN } from "@/lib/auth/roles";
import { safeNextPath } from "@/lib/security/redirect";
import { configuredAccounts, describeConfigError, sessionSecret } from "@/lib/server/config";
import { log } from "@/lib/server/log";
import { createSession } from "@/lib/server/session";

export interface LoginState {
  error: string | null;
}

const MAX_PASSWORD_LENGTH = 512;
const perUser = new FailureLimiter({ maxFailures: 5, windowMs: 5 * 60_000, lockMs: 5 * 60_000, maxKeys: 1000 });
const globalLimiter = new FailureLimiter({ maxFailures: 50, windowMs: 5 * 60_000, lockMs: 60_000, maxKeys: 1 });

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Sign-in. Generic failure message (no username enumeration), constant-time comparison
 * against both local accounts, per-user and global throttling, and a small fixed delay
 * on failure. Passwords and tokens are never logged.
 */
export async function loginAction(_prev: LoginState, formData: FormData): Promise<LoginState> {
  const rawUser = formData.get("username");
  const rawPassword = formData.get("password");
  const next = safeNextPath(formData.get("next"));
  const username = typeof rawUser === "string" ? rawUser.trim() : "";
  const password = typeof rawPassword === "string" ? rawPassword : "";

  if (!username || !password) return { error: "Enter your username and password." };
  if (!USERNAME_PATTERN.test(username) || password.length > MAX_PASSWORD_LENGTH) {
    await sleep(300);
    return { error: "Invalid username or password." };
  }

  const now = Date.now();
  const userKey = username.toLowerCase();
  for (const decision of [globalLimiter.check("all", now), perUser.check(userKey, now)]) {
    if (!decision.allowed) {
      log("warn", "login_throttled", { user: username });
      return {
        error: `Too many failed sign-in attempts. Try again in ${decision.retryAfterSeconds} s.`,
      };
    }
  }

  try {
    sessionSecret();
  } catch (error) {
    log("error", "login_unavailable", { problem: describeConfigError(error) ?? "session secret" });
    return { error: "Sign-in is unavailable: the console is missing its authentication configuration." };
  }
  const accounts = configuredAccounts();
  const enabled = accounts.filter((account) => account.password !== null);
  if (enabled.length === 0) {
    log("error", "login_unavailable", { problem: accounts.map((a) => a.problem).join("; ") });
    return { error: "Sign-in is unavailable: no console account is configured." };
  }

  const match = matchAccount(accounts, username, password);
  if (!match) {
    perUser.recordFailure(userKey, now);
    globalLimiter.recordFailure("all", now);
    log("warn", "login_failed", { user: username });
    await sleep(400);
    return { error: "Invalid username or password." };
  }

  perUser.reset(userKey);
  await createSession(match.username, match.role);
  log("info", "login_succeeded", { user: match.username, role: match.role });
  redirect(next);
}

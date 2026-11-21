import "server-only";

import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";

import {
  HTTPS_HINT_HEADER,
  SECURE_SESSION_COOKIE,
  SESSION_COOKIE,
  sessionCookieName,
} from "@/lib/auth/cookie";
import { permissions, type Role } from "@/lib/auth/roles";
import {
  type Session,
  SESSION_TTL_SECONDS,
  sessionKey,
  signSessionToken,
  verifySessionToken,
} from "@/lib/auth/token";

import { describeConfigError, httpsMode, sessionSecret } from "./config";
import { log } from "./log";

export type { Session };

/**
 * Session handling for server components and server actions.
 *
 * The proxy already redirects unauthenticated requests, but every page and every server
 * action verifies the session again here (defence in depth: a proxy matcher change or a
 * proxy bypass must not expose data or mutations).
 */

async function requestIsHttps(): Promise<boolean> {
  const mode = httpsMode();
  if (mode !== "auto") return mode === "true";
  return (await headers()).get(HTTPS_HINT_HEADER) === "1";
}

function signingKey(): Uint8Array | null {
  try {
    return sessionKey(sessionSecret());
  } catch (error) {
    log("error", "session_secret_unavailable", {
      problem: describeConfigError(error) ?? "invalid session secret",
    });
    return null;
  }
}

/** The verified session of the current request, or null. Memoised per request. */
export const getSession = cache(async (): Promise<Session | null> => {
  const key = signingKey();
  if (!key) return null;
  const store = await cookies();
  const token = store.get(SECURE_SESSION_COOKIE)?.value ?? store.get(SESSION_COOKIE)?.value;
  return verifySessionToken(token, key);
});

/** Session or redirect to the sign-in page. */
export async function requireSession(): Promise<Session> {
  const session = await getSession();
  if (!session) redirect("/login");
  return session;
}

export type ActionDenied = { ok: false; code: "unauthenticated" | "forbidden"; message: string };

/** For server actions: the session if it may perform `action`, else a denial result. */
export async function authorizeAction(
  action: keyof typeof permissions,
): Promise<{ ok: true; session: Session } | ActionDenied> {
  const session = await getSession();
  if (!session) {
    return { ok: false, code: "unauthenticated", message: "Your session has expired. Sign in again." };
  }
  if (!permissions[action](session.role)) {
    log("warn", "action_denied", { action, user: session.user, role: session.role });
    return { ok: false, code: "forbidden", message: "This action requires the analyst role." };
  }
  return { ok: true, session };
}

export async function createSession(user: string, role: Role): Promise<Session> {
  const key = signingKey();
  if (!key) throw new Error("session signing key unavailable");
  const { token, session } = await signSessionToken({ user, role }, key);
  const secure = await requestIsHttps();
  const store = await cookies();
  store.set(sessionCookieName(secure), token, {
    httpOnly: true,
    sameSite: "strict",
    secure,
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
    priority: "high",
  });
  return session;
}

export async function destroySession(): Promise<void> {
  const store = await cookies();
  const expired = { httpOnly: true, sameSite: "strict" as const, path: "/", maxAge: 0 };
  if (store.has(SESSION_COOKIE)) store.set(SESSION_COOKIE, "", { ...expired, secure: false });
  if (store.has(SECURE_SESSION_COOKIE)) {
    store.set(SECURE_SESSION_COOKIE, "", { ...expired, secure: true });
  }
}

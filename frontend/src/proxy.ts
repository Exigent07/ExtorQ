import { type NextRequest, NextResponse } from "next/server";

import { HTTPS_HINT_HEADER, SECURE_SESSION_COOKIE, SESSION_COOKIE } from "@/lib/auth/cookie";
import { sessionKey, verifySessionToken } from "@/lib/auth/token";
import { buildCsp, createNonce, HSTS_HEADER, STATIC_SECURITY_HEADERS } from "@/lib/security/csp";
import { safeNextPath } from "@/lib/security/redirect";
import { httpsMode, sessionSecret } from "@/lib/server/config";

/**
 * Runs before every console route (Node.js runtime):
 *
 * 1. Per-request CSP nonce + strict security headers on every response.
 * 2. Authentication gate: requests without a valid signed session cookie are redirected
 *    to /login (navigations) or rejected with 401 (other methods). Pages and server
 *    actions re-verify the session themselves; this gate is the first layer only.
 * 3. Client-supplied identity/transport hint headers are stripped so they can only ever
 *    be set by this proxy or by the server-side API client.
 */

const PUBLIC_PATHS = new Set(["/login", "/healthz"]);
const STRIPPED_REQUEST_HEADERS = ["x-extorq-user", "x-extorq-role", HTTPS_HINT_HEADER, "x-nonce"];

function isHttps(request: NextRequest): boolean {
  const mode = httpsMode();
  if (mode !== "auto") return mode === "true";
  return request.nextUrl.protocol === "https:";
}

async function hasValidSession(request: NextRequest): Promise<boolean> {
  let key: Uint8Array;
  try {
    key = sessionKey(sessionSecret());
  } catch {
    // Misconfigured secret: fail closed (nobody is authenticated). The login page
    // reports the missing setting by name.
    return false;
  }
  const token =
    request.cookies.get(SECURE_SESSION_COOKIE)?.value ?? request.cookies.get(SESSION_COOKIE)?.value;
  return (await verifySessionToken(token, key)) !== null;
}

function applySecurityHeaders(response: NextResponse, csp: string, https: boolean): NextResponse {
  response.headers.set("Content-Security-Policy", csp);
  for (const { key, value } of STATIC_SECURITY_HEADERS) response.headers.set(key, value);
  if (https) response.headers.set(HSTS_HEADER.key, HSTS_HEADER.value);
  return response;
}

export async function proxy(request: NextRequest): Promise<NextResponse> {
  const https = isHttps(request);
  const nonce = createNonce();
  const csp = buildCsp({ nonce, dev: process.env.NODE_ENV === "development", https });
  const { pathname, search } = request.nextUrl;
  const isPublic = PUBLIC_PATHS.has(pathname);
  const authenticated = await hasValidSession(request);

  if (!authenticated && !isPublic) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      const denied = NextResponse.json(
        { detail: "authentication required" },
        { status: 401, headers: { "Cache-Control": "no-store" } },
      );
      return applySecurityHeaders(denied, csp, https);
    }
    const loginUrl = new URL("/login", request.url);
    const next = safeNextPath(`${pathname}${search}`, "");
    if (next && next !== "/") loginUrl.searchParams.set("next", next);
    return applySecurityHeaders(NextResponse.redirect(loginUrl, 303), csp, https);
  }

  if (authenticated && pathname === "/login" && request.method === "GET") {
    return applySecurityHeaders(NextResponse.redirect(new URL("/", request.url), 303), csp, https);
  }

  const forwarded = new Headers(request.headers);
  for (const name of STRIPPED_REQUEST_HEADERS) forwarded.delete(name);
  forwarded.set("x-nonce", nonce);
  forwarded.set(HTTPS_HINT_HEADER, https ? "1" : "0");
  // Next.js reads the nonce from the request CSP header and applies it to its scripts.
  forwarded.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: forwarded } });
  return applySecurityHeaders(response, csp, https);
}

export const config = {
  matcher: [
    // Everything except immutable build assets and the icon.
    "/((?!_next/static|_next/image|favicon.ico|icon.svg).*)",
  ],
};

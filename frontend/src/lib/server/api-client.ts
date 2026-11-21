import "server-only";

import type { z } from "zod";

import type { Session } from "@/lib/auth/token";
import { zErrorResponse } from "@/lib/api/schemas";

import { apiBaseUrl, apiTimeoutMs, apiToken, describeConfigError } from "./config";
import { log } from "./log";

/**
 * The only way the console talks to the analyst API.
 *
 * - Server-side only: the bearer token is read from its secret file here and never leaves
 *   the server. The browser only ever receives rendered HTML/RSC output.
 * - Identity headers come from the *verified* session passed in by the caller.
 * - Timeouts on every attempt; bounded retries with jittered backoff for idempotent GETs
 *   on connection failures and 502/503/504. Mutations are never retried.
 * - Responses are size-capped and validated with zod before any component sees them.
 */

import type { ApiFailure, ApiResult } from "@/lib/api/result";

export type { ApiErrorKind, ApiFailure, ApiResult } from "@/lib/api/result";

type QueryValue = string | number | boolean | null | undefined;

export interface ApiRequest {
  method: "GET" | "POST";
  /** Path below the origin, starting with /api/v1/. Dynamic parts must be pre-encoded. */
  path: string;
  /** Path template for logs (no ids or filter values), e.g. /api/v1/alerts/{id}. */
  route: string;
  query?: Record<string, QueryValue | QueryValue[]>;
  body?: unknown;
  timeoutMs?: number;
}

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_GET_RETRIES = 2;
const RETRYABLE_STATUS = new Set([502, 503, 504]);

function newRequestId(): string {
  return crypto.randomUUID();
}

function buildUrl(base: URL, path: string, query: ApiRequest["query"]): URL {
  if (!path.startsWith("/api/v1/")) throw new Error("API path must start with /api/v1/");
  const prefix = base.pathname.replace(/\/+$/, "");
  const url = new URL(`${prefix}${path}`, base.origin);
  if (url.origin !== base.origin) throw new Error("API URL escaped the configured origin");
  if (query) {
    for (const [key, raw] of Object.entries(query)) {
      const values = Array.isArray(raw) ? raw : [raw];
      for (const value of values) {
        if (value === undefined || value === null || value === "") continue;
        url.searchParams.append(key, String(value));
      }
    }
  }
  return url;
}

async function readCapped(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > MAX_RESPONSE_BYTES) throw new ResponseTooLarge();
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new ResponseTooLarge();
    }
    chunks.push(value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

class ResponseTooLarge extends Error {}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffMs(attempt: number): number {
  return 200 * 2 ** attempt + Math.floor(Math.random() * 150);
}

/** The API's own `detail` string (fixed, client-safe messages chosen by the API). */
function apiDetail(text: string): string | null {
  try {
    const parsed = zErrorResponse.safeParse(JSON.parse(text));
    if (!parsed.success) return null;
    const { detail } = parsed.data;
    if (typeof detail === "string") return detail.slice(0, 300);
    const first = detail[0];
    const msg = first && typeof first.msg === "string" ? first.msg : null;
    return msg ? msg.slice(0, 300) : null;
  } catch {
    return null;
  }
}

function failureForStatus(status: number, detail: string | null, requestId: string): ApiFailure {
  return { ...failureKind(status, detail, requestId), detail };
}

function failureKind(
  status: number,
  detail: string | null,
  requestId: string,
): Omit<ApiFailure, "detail"> {
  const withDetail = (fallback: string) => (detail ? `${fallback} (${detail})` : fallback);
  switch (status) {
    case 400:
    case 422:
      return { kind: "bad_request", status, requestId, message: withDetail("The API rejected the request") };
    case 401:
      return {
        kind: "unauthorized",
        status,
        requestId,
        message: "The API rejected the console's service credentials",
      };
    case 403:
      return { kind: "forbidden", status, requestId, message: withDetail("Not permitted for your role") };
    case 404:
      return { kind: "not_found", status, requestId, message: withDetail("Not found") };
    case 409:
      return {
        kind: "conflict",
        status,
        requestId,
        message: "Someone else changed this since you loaded it. Reload and try again",
      };
    case 429:
      return { kind: "rate_limited", status, requestId, message: withDetail("Too many requests; try again shortly") };
    case 503:
      return { kind: "unavailable", status, requestId, message: withDetail("A backend dependency is unavailable") };
    default:
      return { kind: "server", status, requestId, message: withDetail(`The API returned HTTP ${status}`) };
  }
}

export async function apiRequest<S extends z.ZodType>(
  session: Session,
  schema: S,
  request: ApiRequest,
): Promise<ApiResult<z.output<S>>> {
  const requestId = newRequestId();
  let base: URL;
  let token: string;
  try {
    base = apiBaseUrl();
    token = apiToken();
  } catch (error) {
    const problem = describeConfigError(error) ?? "API client misconfigured";
    log("error", "api_config_error", { route: request.route, problem, request_id: requestId });
    return {
      ok: false,
      error: { kind: "config", status: null, requestId, detail: null, message: `Console configuration problem: ${problem}` },
    };
  }

  const url = buildUrl(base, request.path, request.query);
  const timeoutMs = request.timeoutMs ?? apiTimeoutMs();
  const maxAttempts = request.method === "GET" ? MAX_GET_RETRIES + 1 : 1;
  const started = Date.now();

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const attemptStarted = Date.now();
    let response: Response;
    try {
      response = await fetch(url, {
        method: request.method,
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          "X-ExtorQ-User": session.user,
          "X-ExtorQ-Role": session.role,
          "X-Request-ID": requestId,
          ...(request.body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: request.body !== undefined ? JSON.stringify(request.body) : undefined,
        cache: "no-store",
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      const timedOut = error instanceof DOMException && error.name === "TimeoutError";
      log("warn", "api_request_failed", {
        route: request.route,
        method: request.method,
        attempt,
        outcome: timedOut ? "timeout" : "network_error",
        duration_ms: Date.now() - attemptStarted,
        request_id: requestId,
      });
      if (timedOut) {
        return {
          ok: false,
          error: {
            kind: "timeout",
            status: null,
            requestId,
            detail: null,
            message: `The API did not respond within ${Math.round(timeoutMs / 1000)} s`,
          },
        };
      }
      if (attempt + 1 < maxAttempts) {
        await sleep(backoffMs(attempt));
        continue;
      }
      return {
        ok: false,
        error: { kind: "network", status: null, requestId, detail: null, message: "Cannot reach the analyst API" },
      };
    }

    let text: string;
    try {
      text = await readCapped(response);
    } catch (error) {
      const tooLarge = error instanceof ResponseTooLarge;
      log("error", "api_response_unreadable", {
        route: request.route,
        status: response.status,
        reason: tooLarge ? "too_large" : "read_error",
        request_id: requestId,
      });
      return {
        ok: false,
        error: {
          kind: "invalid_response",
          status: response.status,
          requestId,
          detail: null,
          message: tooLarge ? "The API response exceeded the size limit" : "The API response could not be read",
        },
      };
    }

    if (!response.ok) {
      log(response.status >= 500 ? "error" : "warn", "api_request_error", {
        route: request.route,
        method: request.method,
        status: response.status,
        attempt,
        duration_ms: Date.now() - attemptStarted,
        request_id: requestId,
      });
      if (RETRYABLE_STATUS.has(response.status) && attempt + 1 < maxAttempts) {
        await sleep(backoffMs(attempt));
        continue;
      }
      return { ok: false, error: failureForStatus(response.status, apiDetail(text), requestId) };
    }

    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      log("error", "api_response_not_json", { route: request.route, request_id: requestId });
      return {
        ok: false,
        error: { kind: "invalid_response", status: response.status, requestId, detail: null, message: "The API response was not JSON" },
      };
    }
    const parsed = schema.safeParse(json);
    if (!parsed.success) {
      const paths = parsed.error.issues.slice(0, 5).map((issue) => issue.path.join(".") || "(root)");
      log("error", "api_response_schema_mismatch", {
        route: request.route,
        request_id: requestId,
        issues: parsed.error.issues.length,
        paths: paths.join(", "),
      });
      return {
        ok: false,
        error: {
          kind: "invalid_response",
          status: response.status,
          requestId,
          detail: null,
          message: `The API response did not match the expected schema (at ${paths[0] ?? "(root)"})`,
        },
      };
    }
    log("info", "api_request", {
      route: request.route,
      method: request.method,
      status: response.status,
      attempt,
      duration_ms: Date.now() - started,
      request_id: requestId,
    });
    return { ok: true, data: parsed.data, requestId, receivedAt: new Date().toISOString() };
  }
  // Unreachable: the loop always returns.
  return { ok: false, error: { kind: "server", status: null, requestId, detail: null, message: "Request failed" } };
}

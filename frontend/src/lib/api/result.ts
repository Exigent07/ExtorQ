/**
 * Result types shared by the server-side API client and the components that render
 * its outcomes. Kept free of server-only imports so client components can use them.
 */
export type ApiErrorKind =
  | "config"
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "bad_request"
  | "rate_limited"
  | "unavailable"
  | "timeout"
  | "network"
  | "invalid_response"
  | "server";

export interface ApiFailure {
  kind: ApiErrorKind;
  status: number | null;
  /** Safe, human-readable message (no secrets, no telemetry). */
  message: string;
  /** The API's own error detail (fixed, client-safe strings chosen by the API), if any. */
  detail: string | null;
  requestId: string;
}

export type ApiResult<T> =
  | { ok: true; data: T; requestId: string; receivedAt: string }
  | { ok: false; error: ApiFailure };

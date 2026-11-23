import "server-only";

import type { Role } from "@/lib/auth/roles";
import { USERNAME_PATTERN } from "@/lib/auth/roles";
import { MIN_SESSION_SECRET_LENGTH } from "@/lib/auth/token";

import { readSecret, SecretConfigError, tryReadSecret } from "./secrets";

/**
 * Server-side configuration. Nothing here is ever exposed to the browser: there are no
 * NEXT_PUBLIC_* variables in this project.
 *
 * | Variable                        | Meaning                                                    |
 * |---------------------------------|------------------------------------------------------------|
 * | EXTORQ_API_BASE_URL             | Analyst API origin, e.g. http://127.0.0.1:8100 (required)  |
 * | EXTORQ_API_TOKEN_FILE           | File holding the API service token (preferred)             |
 * | EXTORQ_API_TOKEN                | The token itself (fallback; avoid)                         |
 * | EXTORQ_ANALYST_PASSWORD_FILE    | File holding the analyst account password                  |
 * | EXTORQ_VIEWER_PASSWORD_FILE     | File holding the viewer account password                   |
 * | EXTORQ_SESSION_SECRET_FILE      | File holding the session-cookie signing secret (>= 32 ch.) |
 * | EXTORQ_ANALYST_USERNAME         | Analyst username (default "analyst")                       |
 * | EXTORQ_VIEWER_USERNAME          | Viewer username (default "viewer")                         |
 * | EXTORQ_HTTPS                    | auto (default) / true / false: Secure cookie, HSTS         |
 * | EXTORQ_API_TIMEOUT_MS           | Per-attempt timeout for API reads (default 8000)           |
 * | EXTORQ_GRAFANA_URL              | Browser URL of Grafana for the sidebar link                |
 * |                                 | (default http://127.0.0.1:3001; http(s) origin only)       |
 */

export const MIN_ACCOUNT_PASSWORD_LENGTH = 12;
export const MIN_API_TOKEN_LENGTH = 32;

export class ConfigError extends Error {
  constructor(
    readonly setting: string,
    readonly problem: string,
  ) {
    super(`${setting}: ${problem}`);
    this.name = "ConfigError";
  }
}

function intFromEnv(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number.parseInt(raw, 10);
  if (!Number.isFinite(value) || value < min || value > max) return fallback;
  return value;
}

/** Validated API origin. Throws ConfigError naming the setting when absent or unsafe. */
export function apiBaseUrl(): URL {
  const raw = process.env.EXTORQ_API_BASE_URL;
  if (!raw) throw new ConfigError("EXTORQ_API_BASE_URL", "not set");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError("EXTORQ_API_BASE_URL", "not a valid URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ConfigError("EXTORQ_API_BASE_URL", "must use http or https");
  }
  if (url.username || url.password) {
    throw new ConfigError("EXTORQ_API_BASE_URL", "must not embed credentials");
  }
  if (url.search || url.hash) {
    throw new ConfigError("EXTORQ_API_BASE_URL", "must not contain a query or fragment");
  }
  return url;
}

export function apiToken(): string {
  return readSecret({
    fileSetting: "EXTORQ_API_TOKEN_FILE",
    envSetting: "EXTORQ_API_TOKEN",
    minLength: MIN_API_TOKEN_LENGTH,
  });
}

export function apiTimeoutMs(): number {
  return intFromEnv("EXTORQ_API_TIMEOUT_MS", 8000, 500, 60000);
}

const DEFAULT_GRAFANA_URL = "http://127.0.0.1:3001/";

/**
 * Browser-facing Grafana URL for the sidebar's external link. Configuration only (never taken
 * from telemetry); anything that is not a plain http(s) URL without credentials falls back to
 * the compose default rather than becoming a link.
 */
export function grafanaUrl(): string {
  const raw = process.env.EXTORQ_GRAFANA_URL?.trim();
  if (!raw) return DEFAULT_GRAFANA_URL;
  try {
    const url = new URL(raw);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password) {
      return DEFAULT_GRAFANA_URL;
    }
    return url.toString();
  } catch {
    return DEFAULT_GRAFANA_URL;
  }
}

export function sessionSecret(): string {
  return readSecret({
    fileSetting: "EXTORQ_SESSION_SECRET_FILE",
    minLength: MIN_SESSION_SECRET_LENGTH,
  });
}

export type HttpsMode = "auto" | "true" | "false";

export function httpsMode(): HttpsMode {
  const raw = (process.env.EXTORQ_HTTPS ?? "auto").toLowerCase();
  return raw === "true" || raw === "false" ? raw : "auto";
}

export interface ConfiguredAccount {
  username: string;
  role: Role;
  password: string | null;
  /** Setting name of a configuration problem (never the value). */
  problem: string | null;
}

function username(setting: string, fallback: string): string {
  const value = process.env[setting]?.trim();
  return value && USERNAME_PATTERN.test(value) ? value : fallback;
}

/** The two local accounts. Passwords are read from their files on every call (cached). */
export function configuredAccounts(): ConfiguredAccount[] {
  const specs: { role: Role; userSetting: string; fallback: string; fileSetting: string }[] = [
    {
      role: "analyst",
      userSetting: "EXTORQ_ANALYST_USERNAME",
      fallback: "analyst",
      fileSetting: "EXTORQ_ANALYST_PASSWORD_FILE",
    },
    {
      role: "viewer",
      userSetting: "EXTORQ_VIEWER_USERNAME",
      fallback: "viewer",
      fileSetting: "EXTORQ_VIEWER_PASSWORD_FILE",
    },
  ];
  return specs.map((spec) => {
    const result = tryReadSecret({
      fileSetting: spec.fileSetting,
      minLength: MIN_ACCOUNT_PASSWORD_LENGTH,
    });
    return {
      username: username(spec.userSetting, spec.fallback),
      role: spec.role,
      password: result.ok ? result.value : null,
      problem: result.ok ? null : `${result.error.setting} is ${result.error.problem.replace("_", " ")}`,
    };
  });
}

export function describeConfigError(error: unknown): string | null {
  if (error instanceof ConfigError) return `${error.setting} ${error.problem}`;
  if (error instanceof SecretConfigError) {
    return `${error.setting} is ${error.problem.replace("_", " ")}`;
  }
  return null;
}

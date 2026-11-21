import "server-only";

import { closeSync, fstatSync, openSync, readSync } from "node:fs";

/**
 * Secret files (API token, account passwords, session signing secret).
 *
 * - Secrets are passed by *file path* (compose mounts them as secrets). The value is
 *   never logged, never put in an error message and never sent to the browser.
 * - Reads are bounded (4 KiB) and cached by (mtime, size), so a rotated file is picked
 *   up on the next request without a restart.
 * - Errors name the setting, never the value or the file content.
 */
const MAX_SECRET_BYTES = 4096;

export type SecretProblem = "unset" | "unreadable" | "empty" | "too_large" | "too_short";

export class SecretConfigError extends Error {
  constructor(
    readonly setting: string,
    readonly problem: SecretProblem,
  ) {
    super(`secret setting ${setting} is ${problem.replace("_", " ")}`);
    this.name = "SecretConfigError";
  }
}

interface CacheEntry {
  value: string;
  mtimeMs: number;
  size: number;
}

const cache = new Map<string, CacheEntry>();

function readBounded(path: string, setting: string): CacheEntry {
  let fd: number;
  try {
    fd = openSync(path, "r");
  } catch {
    throw new SecretConfigError(setting, "unreadable");
  }
  try {
    const stat = fstatSync(fd);
    const cached = cache.get(path);
    if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) return cached;
    if (stat.size > MAX_SECRET_BYTES) throw new SecretConfigError(setting, "too_large");
    const buffer = Buffer.alloc(MAX_SECRET_BYTES + 1);
    const length = readSync(fd, buffer, 0, buffer.length, 0);
    if (length > MAX_SECRET_BYTES) throw new SecretConfigError(setting, "too_large");
    const entry: CacheEntry = {
      value: buffer.subarray(0, length).toString("utf8").trim(),
      mtimeMs: stat.mtimeMs,
      size: stat.size,
    };
    buffer.fill(0);
    cache.set(path, entry);
    return entry;
  } finally {
    closeSync(fd);
  }
}

/**
 * Resolve a secret from `<fileSetting>` (a path) or, only when allowed, from a
 * direct environment variable `<envSetting>`.
 */
export function readSecret(options: {
  fileSetting: string;
  envSetting?: string;
  minLength?: number;
}): string {
  const { fileSetting, envSetting, minLength = 1 } = options;
  const path = process.env[fileSetting];
  let value: string;
  let source = fileSetting;
  if (path) {
    value = readBounded(path, fileSetting).value;
  } else if (envSetting && process.env[envSetting]) {
    value = (process.env[envSetting] ?? "").trim();
    source = envSetting;
  } else {
    throw new SecretConfigError(fileSetting, "unset");
  }
  if (value.length === 0) throw new SecretConfigError(source, "empty");
  if (value.length < minLength) throw new SecretConfigError(source, "too_short");
  return value;
}

/** Like readSecret, but returns the problem instead of throwing. */
export function tryReadSecret(options: {
  fileSetting: string;
  envSetting?: string;
  minLength?: number;
}): { ok: true; value: string } | { ok: false; error: SecretConfigError } {
  try {
    return { ok: true, value: readSecret(options) };
  } catch (error) {
    if (error instanceof SecretConfigError) return { ok: false, error };
    throw error;
  }
}

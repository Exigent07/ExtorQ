import "server-only";

/**
 * Structured JSON logging for the console server (one line per event on stdout/stderr).
 *
 * Field names that look sensitive are redacted defensively, but callers must never pass
 * secret values in the first place: log setting *names*, request ids, statuses and
 * durations only. Telemetry content is never logged.
 */
type Level = "debug" | "info" | "warn" | "error";

const SENSITIVE_KEY = /pass(word)?|secret|token|authori[sz]ation|cookie|api[-_]?key|session/i;
const MAX_FIELD_CHARS = 512;

function clean(value: unknown): unknown {
  if (typeof value === "string") {
    return value.length > MAX_FIELD_CHARS ? `${value.slice(0, MAX_FIELD_CHARS)}…` : value;
  }
  if (typeof value === "number" || typeof value === "boolean" || value === null) return value;
  if (value === undefined) return undefined;
  return String(value).slice(0, MAX_FIELD_CHARS);
}

export function log(level: Level, event: string, fields: Record<string, unknown> = {}): void {
  if (level === "debug" && process.env.EXTORQ_CONSOLE_DEBUG !== "1") return;
  const record: Record<string, unknown> = {
    ts: new Date().toISOString(),
    level,
    component: "console",
    event,
  };
  for (const [key, value] of Object.entries(fields)) {
    record[key] = SENSITIVE_KEY.test(key) ? "[redacted]" : clean(value);
  }
  const line = JSON.stringify(record);
  if (level === "error" || level === "warn") {
    console.error(line);
  } else {
    console.log(line);
  }
}

/**
 * Open-redirect protection for the `next` parameter used after sign-in.
 *
 * Only same-origin absolute paths are accepted. Protocol-relative URLs (`//host`),
 * backslash tricks (`/\host`, browsers normalise `\` to `/`), control characters,
 * schemes and over-long values all fall back to the default.
 */
const MAX_NEXT_LENGTH = 512;
const PROBE_ORIGIN = "http://extorq.invalid";
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

export function safeNextPath(value: unknown, fallback = "/"): string {
  if (typeof value !== "string") return fallback;
  if (value.length === 0 || value.length > MAX_NEXT_LENGTH) return fallback;
  if (!value.startsWith("/") || value.startsWith("//") || value.includes("\\")) return fallback;
  if (CONTROL_CHARS.test(value)) return fallback;
  let parsed: URL;
  try {
    parsed = new URL(value, PROBE_ORIGIN);
  } catch {
    return fallback;
  }
  if (parsed.origin !== PROBE_ORIGIN) return fallback;
  // Never bounce back to the sign-in page itself (avoids loops after login).
  if (parsed.pathname === "/login" || parsed.pathname.startsWith("/login/")) return fallback;
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

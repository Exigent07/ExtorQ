/**
 * Content-Security-Policy and response security headers.
 *
 * Production policy:
 * - scripts: only those carrying the per-request nonce (`'strict-dynamic'` lets them load
 *   their own chunks); no `'unsafe-inline'`, no `'unsafe-eval'`.
 * - `<style>`/`<link>` elements: same-origin or nonce-carrying only.
 * - `style` *attributes* are allowed (`style-src-attr 'unsafe-inline'`): React renders
 *   server-side style props (chart colours, Radix positioning) as attributes, which a
 *   nonce cannot cover. The console has no HTML injection path (React's raw-HTML escape
 *   hatch is banned by lint; all telemetry is rendered as text), so this does not open
 *   a script vector.
 * - nothing may frame the console; forms post only to the console itself.
 *
 * Development additionally allows `'unsafe-eval'` (React dev tooling) and inline styles
 * (the dev server injects styles without nonces). Neither is present in production.
 */
export interface CspOptions {
  nonce: string;
  dev: boolean;
  https: boolean;
}

export function buildCsp({ nonce, dev, https }: CspOptions): string {
  const styleElements = dev ? "'self' 'unsafe-inline'" : `'self' 'nonce-${nonce}'`;
  const directives: (string | null)[] = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    `style-src ${styleElements}`,
    `style-src-elem ${styleElements}`,
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "media-src 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    https ? "upgrade-insecure-requests" : null,
  ];
  return directives.filter((d): d is string => d !== null).join("; ");
}

/** Headers applied to every console response (static assets included via next.config). */
export const STATIC_SECURITY_HEADERS: ReadonlyArray<{ key: string; value: string }> = [
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  { key: "Origin-Agent-Cluster", value: "?1" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  { key: "X-Permitted-Cross-Domain-Policies", value: "none" },
  {
    key: "Permissions-Policy",
    value:
      "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), " +
      "gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), browsing-topics=()",
  },
];

export const HSTS_HEADER = { key: "Strict-Transport-Security", value: "max-age=31536000" };

/** Fresh nonce: 128 random bits, base64 encoded. */
export function createNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

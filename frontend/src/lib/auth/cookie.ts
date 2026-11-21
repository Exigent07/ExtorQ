/**
 * Session cookie naming, shared by the proxy and the server session module.
 *
 * Over HTTPS the cookie uses the `__Host-` prefix (browser-enforced: Secure, Path=/,
 * no Domain). Over plain HTTP on loopback (the compose demo) the prefix cannot be used,
 * so the unprefixed name is set without `Secure`.
 */
export const SESSION_COOKIE = "extorq_session";
export const SECURE_SESSION_COOKIE = "__Host-extorq_session";

export function sessionCookieName(secure: boolean): string {
  return secure ? SECURE_SESSION_COOKIE : SESSION_COOKIE;
}

/**
 * Request header the proxy sets (after deleting any client-supplied value) to tell
 * server components and actions whether the request arrived over HTTPS.
 */
export const HTTPS_HINT_HEADER = "x-extorq-https";

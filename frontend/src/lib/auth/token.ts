/**
 * Signed session tokens (JWS, HS256) carried in the httpOnly session cookie.
 *
 * Pure functions with the key passed in: used by the proxy (every request), by server
 * components/actions (defence in depth) and by unit tests.
 */
import { jwtVerify, SignJWT } from "jose";

import { isRole, type Role, USERNAME_PATTERN } from "./roles";

export const SESSION_TTL_SECONDS = 8 * 60 * 60;
const ISSUER = "extorq-console";
const AUDIENCE = "extorq-console";
const MAX_TOKEN_LENGTH = 4096;
/** Minimum length of the signing secret (32 characters of a random string). */
export const MIN_SESSION_SECRET_LENGTH = 32;

export interface Session {
  user: string;
  role: Role;
  sessionId: string;
  issuedAt: number;
  /** Unix seconds. */
  expiresAt: number;
}

export function sessionKey(secret: string): Uint8Array {
  if (secret.length < MIN_SESSION_SECRET_LENGTH) {
    throw new Error("session secret is too short");
  }
  return new TextEncoder().encode(secret);
}

export async function signSessionToken(
  subject: { user: string; role: Role },
  key: Uint8Array,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<{ token: string; session: Session }> {
  if (!USERNAME_PATTERN.test(subject.user)) throw new Error("invalid username");
  const sessionId = crypto.randomUUID();
  const session: Session = {
    user: subject.user,
    role: subject.role,
    sessionId,
    issuedAt: nowSeconds,
    expiresAt: nowSeconds + SESSION_TTL_SECONDS,
  };
  const token = await new SignJWT({ role: subject.role })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setSubject(subject.user)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt(nowSeconds)
    .setNotBefore(nowSeconds - 5)
    .setExpirationTime(session.expiresAt)
    .setJti(sessionId)
    .sign(key);
  return { token, session };
}

/** Returns the session for a valid, unexpired token signed with `key`; otherwise null. */
export async function verifySessionToken(
  token: string | undefined | null,
  key: Uint8Array,
  now: Date = new Date(),
): Promise<Session | null> {
  if (!token || token.length > MAX_TOKEN_LENGTH) return null;
  try {
    const { payload } = await jwtVerify(token, key, {
      algorithms: ["HS256"],
      issuer: ISSUER,
      audience: AUDIENCE,
      currentDate: now,
      maxTokenAge: SESSION_TTL_SECONDS,
      clockTolerance: 5,
    });
    const { sub, role, jti, iat, exp } = payload;
    if (typeof sub !== "string" || !USERNAME_PATTERN.test(sub)) return null;
    if (!isRole(role)) return null;
    if (typeof jti !== "string" || typeof iat !== "number" || typeof exp !== "number") return null;
    return { user: sub, role, sessionId: jti, issuedAt: iat, expiresAt: exp };
  } catch {
    return null;
  }
}

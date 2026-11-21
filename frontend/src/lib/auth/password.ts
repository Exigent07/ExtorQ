/**
 * Constant-time credential comparison.
 *
 * Both inputs are reduced to an HMAC-SHA-256 digest under a random per-process key
 * before `timingSafeEqual`, so the comparison time depends neither on where the
 * strings differ nor on their lengths.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const COMPARE_KEY = randomBytes(32);

function digest(value: string): Buffer {
  return createHmac("sha256", COMPARE_KEY).update(value, "utf8").digest();
}

export function constantTimeEqual(a: string, b: string): boolean {
  return timingSafeEqual(digest(a), digest(b));
}

export interface Account<R extends string = string> {
  username: string;
  role: R;
  /** null when the account's password is not configured (the account is disabled). */
  password: string | null;
}

/**
 * Check a username/password pair against every configured account.
 *
 * Every account is compared (username and password) on every attempt, with no early
 * exit, so timing does not reveal which usernames exist. Disabled accounts are compared
 * against a random value and can never match.
 */
export function matchAccount<R extends string>(
  accounts: readonly Account<R>[],
  username: string,
  password: string,
): Account<R> | null {
  let matched: Account<R> | null = null;
  for (const account of accounts) {
    const expected = account.password ?? randomBytes(24).toString("base64");
    const userOk = constantTimeEqual(username, account.username);
    const passOk = constantTimeEqual(password, expected);
    if (userOk && passOk && account.password !== null && matched === null) {
      matched = account;
    }
  }
  return matched;
}

/**
 * In-memory failed-login limiter (per username, plus a global ceiling).
 *
 * The console runs as a single Node process, so process memory is the right scope.
 * State is lost on restart, which is acceptable: the passwords are random secrets and
 * the limiter only has to make online guessing impractical.
 */
export interface LimiterOptions {
  maxFailures: number;
  windowMs: number;
  lockMs: number;
  maxKeys: number;
}

interface Entry {
  failures: number[];
  lockedUntil: number;
}

export type LimitDecision = { allowed: true } | { allowed: false; retryAfterSeconds: number };

export class FailureLimiter {
  private readonly entries = new Map<string, Entry>();

  constructor(private readonly options: LimiterOptions) {}

  check(key: string, now: number): LimitDecision {
    const entry = this.entries.get(key);
    if (!entry) return { allowed: true };
    if (entry.lockedUntil > now) {
      return { allowed: false, retryAfterSeconds: Math.ceil((entry.lockedUntil - now) / 1000) };
    }
    return { allowed: true };
  }

  recordFailure(key: string, now: number): void {
    const entry = this.entries.get(key) ?? { failures: [], lockedUntil: 0 };
    entry.failures = entry.failures.filter((t) => now - t < this.options.windowMs);
    entry.failures.push(now);
    if (entry.failures.length >= this.options.maxFailures) {
      entry.lockedUntil = now + this.options.lockMs;
      entry.failures = [];
    }
    // Re-insert to keep Map order = least recently touched first.
    this.entries.delete(key);
    this.entries.set(key, entry);
    while (this.entries.size > this.options.maxKeys) {
      const oldest = this.entries.keys().next().value;
      if (oldest === undefined) break;
      this.entries.delete(oldest);
    }
  }

  reset(key: string): void {
    this.entries.delete(key);
  }
}

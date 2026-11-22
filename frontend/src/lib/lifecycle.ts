/**
 * Inventory lifecycle presentation (assets and collectors; API 2026-11-22).
 *
 * The API marks an asset `stale` when it was not observed within the stale window and
 * `retired` when, in addition, no collector covering it reports and it was not observed within
 * the retirement window (24 h by default). Retired items are never deleted: lists and rollups
 * leave them out unless `include_retired=true`, and every view says how many it left out.
 * Pure and unit-tested (src/lib/__tests__/lifecycle.test.ts).
 */
import { formatCount } from "@/lib/format";

export interface LifecycleView {
  /** The state as the API sent it. */
  state: string;
  /** "Stale", "Retired", or the unknown token itself. */
  label: string;
  tone: "warn" | "off";
  /** What the state means, in console words (for a tooltip). */
  meaning: string;
  /** The API's reason with second counts in words; null when the API gave none. */
  reason: string | null;
}

const REASON_LIMIT = 280;

/** "45 s", "12 min", "17 h", "3 d": whole units, rounded down (like "4 min ago"). */
export function humanizeSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return `${seconds} s`;
  const s = Math.floor(seconds);
  if (s < 120) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 120) return m % 60 === 0 ? `${m / 60} h` : `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 72) return `${h} h`;
  return `${formatCount(Math.floor(h / 24))} d`;
}

/**
 * The API's lifecycle reason ("last observed 61210s ago (threshold 3600s); ...") with every
 * "<digits>s" second count spelled as a duration, capped in length. The text stays the API's
 * own: nothing is added or inferred.
 */
export function humanizeLifecycleReason(reason: string | null | undefined): string | null {
  if (!reason) return null;
  const text = reason.replace(/\b(\d{1,9})s\b/g, (_, digits: string) => humanizeSeconds(Number(digits))).trim();
  if (!text) return null;
  return text.length > REASON_LIMIT ? `${text.slice(0, REASON_LIMIT - 1)}…` : text;
}

/** Presentation of a lifecycle state; null for `active` and for a missing value. */
export function lifecycleView(state: string | null | undefined, reason?: string | null): LifecycleView | null {
  if (!state || state === "active") return null;
  const humanReason = humanizeLifecycleReason(reason);
  if (state === "stale") {
    return {
      state,
      label: "Stale",
      tone: "warn",
      meaning: "Not observed recently. It still counts in coverage until it is retired.",
      reason: humanReason,
    };
  }
  if (state === "retired") {
    return {
      state,
      label: "Retired",
      tone: "off",
      meaning:
        "No collector reports for it and it was not observed within the retirement window. Kept, never deleted; left out of rollups.",
      reason: humanReason,
    };
  }
  return { state, label: state, tone: "off", meaning: "Lifecycle state reported by the API.", reason: humanReason };
}

/** "2 retired assets hidden" (null when nothing was left out). */
export function retiredHiddenText(count: number, noun: { one: string; many: string }): string | null {
  if (!Number.isFinite(count) || count <= 0) return null;
  return `${formatCount(count)} retired ${count === 1 ? noun.one : noun.many} hidden`;
}

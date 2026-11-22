/**
 * Presentation rules of the investigation view that are worth unit-testing. Inputs are API
 * data (untrusted strings stay strings: callers still render them with UntrustedText).
 */

/**
 * The correlation layer's timeline summaries usually begin with the event type itself
 * ("auth.ssh.invalid_user user=x from 10.0.2.2:61976", "process.audit.exec: auditd exec ...").
 * The timeline already prints the type in its own column, so the repeated prefix is dropped.
 * Anything else (including a summary that is only the type) is returned unchanged.
 */
export function summaryWithoutType(summary: string, eventType: string): string {
  if (!eventType || !summary.startsWith(eventType)) return summary;
  const rest = summary.slice(eventType.length);
  const match = /^:?\s+/.exec(rest);
  if (!match) return summary; // e.g. "auth.ssh.invalid_user_x": a different token, keep it
  const trimmed = rest.slice(match[0].length);
  return trimmed.length > 0 ? trimmed : summary;
}

/**
 * Evidence rows in time order (oldest first; event id breaks ties), so a burst reads as it
 * happened. The API orders evidence by role for selection (trigger first) when it caps the
 * list; the display order is chronological. Unparsable times sort last, never first.
 */
export function chronological<T extends { event_time: string; event_id: string }>(events: readonly T[]): T[] {
  const time = (value: string) => {
    const ms = Date.parse(value);
    return Number.isNaN(ms) ? Number.POSITIVE_INFINITY : ms;
  };
  return [...events].sort((a, b) => {
    const delta = time(a.event_time) - time(b.event_time);
    if (delta !== 0 && !Number.isNaN(delta)) return delta;
    return a.event_id < b.event_id ? -1 : a.event_id > b.event_id ? 1 : 0;
  });
}

const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:?\d{2})$/;

/**
 * A time written by an AI provider (untrusted text): shown in the console's UTC format when
 * it is a well-formed ISO-8601 instant with a zone, otherwise returned exactly as written
 * (never guessed). The caller still renders the result as untrusted text.
 */
export function providerTime(raw: string, format: (iso: string) => string): string {
  const value = raw.trim();
  if (!ISO_INSTANT.test(value) || Number.isNaN(Date.parse(value))) return raw;
  return format(value);
}

/**
 * Display hygiene for attacker-controlled telemetry.
 *
 * React already escapes text, so HTML injection is not the concern here. What remains
 * is *visual* deception: bidirectional overrides that reorder what an analyst reads
 * (Trojan Source, CVE-2021-42574), zero-width characters that hide content, and
 * terminal/C0/C1 control characters (ANSI escapes) that a log line can carry.
 * Each such code point is replaced by a visible marker such as `⟨U+202E⟩`, so the
 * analyst sees that the source contained it instead of being misled by it.
 */

// Escapes only (no literal invisible characters in source: Trojan Source review hazard).
// Bidi embeddings/overrides/isolates and directional marks.
const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/;
// Zero-width and invisible formatting characters, Unicode tag characters (invisible
// "ASCII smuggling"), interlinear annotations and the line/paragraph separators that
// can fake line breaks in single-line cells.
const INVISIBLE = /[\u00ad\u180e\u200b-\u200d\u2028\u2029\u2060-\u2064\ufeff\ufff9-\ufffb]|[\u{e0000}-\u{e007f}]/u;
// C0 controls except TAB/LF/CR (handled separately), DEL and C1 controls.
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;

function marker(char: string): string {
  const code = char.codePointAt(0) ?? 0;
  return `⟨U+${code.toString(16).toUpperCase().padStart(4, "0")}⟩`;
}

export interface SanitizedText {
  text: string;
  /** Number of code points replaced by a visible marker. */
  replaced: number;
}

/**
 * Make untrusted text safe to *look at*.
 *
 * @param multiline keep `\n` and `\t` (raw excerpts); otherwise line breaks become a
 *   visible `⏎` so a single-line cell cannot fake extra rows.
 */
export function sanitizeForDisplay(input: string, multiline = false): SanitizedText {
  let replaced = 0;
  let out = "";
  for (const char of input) {
    if (char === "\r") {
      // CRLF/CR collapse into the LF handling below; a lone CR could overwrite text.
      continue;
    }
    if (char === "\n") {
      if (multiline) {
        out += "\n";
      } else {
        out += " ⏎ ";
      }
      continue;
    }
    if (char === "\t") {
      out += multiline ? "\t" : " ";
      continue;
    }
    if (BIDI.test(char) || INVISIBLE.test(char) || CONTROL.test(char)) {
      replaced += 1;
      out += marker(char);
      continue;
    }
    out += char;
  }
  return { text: out, replaced };
}

/** Truncate by code points (never splitting a surrogate pair). */
export function truncateText(input: string, limit: number): { text: string; truncated: boolean } {
  const chars = Array.from(input);
  if (chars.length <= limit) return { text: input, truncated: false };
  return { text: `${chars.slice(0, Math.max(0, limit)).join("")}…`, truncated: true };
}

/** Shorten an identifier for dense tables: first `head` characters plus an ellipsis. */
export function shortId(id: string, head = 8): string {
  return id.length > head + 1 ? `${id.slice(0, head)}…` : id;
}

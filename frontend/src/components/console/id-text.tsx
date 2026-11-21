"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { shortId } from "@/lib/security/display";

/**
 * An identifier in the figure face, shortened for dense rows, with a copy button.
 * Only call with identifiers (hex ids, hashes), never with free-form telemetry.
 */
export function IdText({ id, head = 8, full = false }: { id: string; head?: number; full?: boolean }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }
  return (
    <span className="inline-flex items-center gap-1 font-mono text-xs whitespace-nowrap text-ink-2">
      <span title={id}>{full ? id : shortId(id, head)}</span>
      <button
        type="button"
        onClick={copy}
        aria-label={copied ? "Copied" : `Copy ${id}`}
        className="flex size-5 items-center justify-center rounded-sm text-muted-foreground hover:text-ink"
      >
        {copied ? <Check className="size-3" aria-hidden="true" /> : <Copy className="size-3" aria-hidden="true" />}
      </button>
    </span>
  );
}

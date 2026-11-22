/**
 * Command-palette data shapes. Built on the server (src/lib/server/shell.ts) from validated API
 * responses, with display strings already sanitised; passed to the client palette as props.
 */
import type { Severity } from "@/lib/api/schemas";

export interface PaletteAsset {
  id: string;
  href: string;
  /** Display name, sanitised and truncated on the server (inventory text is untrusted). */
  label: string;
  typeLabel: string;
  coverage: string;
}

export interface PaletteAlert {
  id: string;
  href: string;
  ruleId: string;
  title: string;
  severity: Severity;
  assetId: string;
  lastSeen: string;
  status: string;
}

export interface PaletteData {
  /** null: the list could not be loaded (the palette says so). */
  assets: PaletteAsset[] | null;
  alerts: PaletteAlert[] | null;
}

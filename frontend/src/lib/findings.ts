/**
 * Findings lifecycle states (C3's v_findings_current, infra/clickhouse/migrations/0003).
 * Shared by server and client components (kept out of "use client" modules on purpose).
 */
export const FINDING_STATE: Record<string, { label: string; detail: string; className: string }> = {
  open: {
    label: "Open",
    detail: "Observed in the latest successful scan of its scope.",
    className: "text-foreground",
  },
  unverified: {
    label: "Unverified",
    detail:
      "Observed, but the latest scan attempt of its scope was partial or failed (or only partial scans saw it), so its current state cannot be confirmed.",
    className: "text-health-warn",
  },
  resolved: {
    label: "Resolved",
    detail: "A newer successful scan of the same scope did not observe it.",
    className: "text-muted-foreground",
  },
};

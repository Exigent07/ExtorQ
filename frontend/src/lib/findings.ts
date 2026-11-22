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

/**
 * A finding title without a doubled prefix ("urllib3: urllib3: HTTPS proxy" -> "urllib3: HTTPS
 * proxy"; "CVE-… in urllib3 1.26: urllib3: urllib3: Denial" -> "…: urllib3: Denial"), as scanners
 * concatenate package and advisory titles. Display only: the sheet keeps the stored title.
 */
export function displayFindingTitle(title: string): string {
  return title.replace(/(^|: )([^\s:]+): (?=\2: )/gi, "$1");
}

/**
 * The advisory a finding reports, for spotting one advisory listed by several scanners: the
 * first CVE/GHSA id (or the check id) with the package, case-insensitive. Null without either.
 */
const ADVISORY_ID = /\b(CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3})\b/i;

export function advisoryKey(f: { check_id: string; cve_ids: readonly string[]; package_name?: string | null }): string | null {
  // Ids may carry a scanner prefix ("dependabot:GHSA-…"): the advisory id is found inside.
  const id = [...f.cve_ids, f.check_id].map((value) => ADVISORY_ID.exec(value)?.[1]).find(Boolean);
  if (!id) return null;
  return `${id.toUpperCase()}|${(f.package_name ?? "").toLowerCase()}`;
}

/** Scanners per advisory key, for the "2 scanners" mark (keys seen by one scanner left out). */
export function scannersByAdvisory(
  findings: readonly { check_id: string; cve_ids: readonly string[]; package_name?: string | null; scanner: string }[],
): Map<string, string[]> {
  const map = new Map<string, Set<string>>();
  for (const f of findings) {
    const key = advisoryKey(f);
    if (!key) continue;
    map.set(key, (map.get(key) ?? new Set()).add(f.scanner));
  }
  return new Map([...map].filter(([, scanners]) => scanners.size > 1).map(([key, scanners]) => [key, [...scanners].sort()]));
}

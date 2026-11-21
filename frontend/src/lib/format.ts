/**
 * Formatting for figures and times. All times are shown in UTC (the API's timezone);
 * missing values render as an em dash, never as 0 or a placeholder.
 */
export const DASH = "—";

const pad = (n: number) => String(n).padStart(2, "0");

/** "2026-11-21 14:32:05Z". */
export function formatUtc(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return DASH;
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`
  );
}

/** "14:32:05" (UTC). */
export function formatUtcTime(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return DASH;
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

/** "Nov 21 14:32" (UTC), for chart axes and compact cells. */
export function formatUtcShort(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return DASH;
  const month = d.toLocaleString("en-US", { month: "short", timeZone: "UTC" });
  return `${month} ${d.getUTCDate()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

/** Compact duration: "42 s", "3 m 05 s", "2 h 10 m", "4 d 3 h". */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return DASH;
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} m ${pad(s % 60)} s`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ${pad(m % 60)} m`;
  const d = Math.floor(h / 24);
  return `${d} d ${h % 24} h`;
}

/** "4 min ago" relative to `now` (pass the fetch time to keep server and client equal). */
export function formatRelative(iso: string | null | undefined, now: Date | string): string {
  if (!iso) return DASH;
  const then = new Date(iso).getTime();
  const ref = typeof now === "string" ? new Date(now).getTime() : now.getTime();
  if (Number.isNaN(then) || Number.isNaN(ref)) return DASH;
  const delta = Math.round((ref - then) / 1000);
  if (delta < -60) return `in ${formatDuration(-delta)}`;
  if (delta < 10) return "just now";
  if (delta < 60) return `${delta} s ago`;
  const m = Math.floor(delta / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.floor(h / 24)} d ago`;
}

const numberFormat = new Intl.NumberFormat("en-US");

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return numberFormat.format(value);
}

/** Probability 0..1 as "0.73" (two decimals, fixed). */
export function formatProbability(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return value.toFixed(2);
}

export function formatMs(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return DASH;
  return value < 1000 ? `${Math.round(value)} ms` : `${(value / 1000).toFixed(1)} s`;
}

export const ASSET_TYPE_LABEL: Record<string, string> = {
  macos_host: "macOS host",
  linux_host: "Linux VM",
  kubernetes_cluster: "Kubernetes cluster",
  kubernetes_namespace: "Kubernetes namespace",
  kubernetes_workload: "Kubernetes workload",
  github_account: "GitHub account",
  github_repository: "GitHub repository",
};

export function assetTypeLabel(type: string): string {
  return ASSET_TYPE_LABEL[type] ?? type;
}

export const ANALYST_STATUS_LABEL: Record<string, string> = {
  new: "New",
  acknowledged: "Acknowledged",
  investigating: "Investigating",
  closed_true_positive: "Closed: true positive",
  closed_benign: "Closed: benign",
  closed_false_positive: "Closed: false positive",
};

export function analystStatusLabel(status: string): string {
  return ANALYST_STATUS_LABEL[status] ?? status;
}

export function isClosedStatus(status: string): boolean {
  return status.startsWith("closed_");
}

/** Humanise a snake_case token from the API ("pod_security_violation" → "pod security violation"). */
export function humanize(token: string): string {
  return token.replace(/[_.]+/g, " ").trim();
}

import Link from "next/link";

import { SEVERITY_LABEL } from "@/components/console/severity";
import { ANALYST_STATUSES, SEVERITIES } from "@/lib/api/schemas";
import { analystStatusLabel } from "@/lib/format";
import { type AlertFilters, TIME_RANGES } from "@/lib/filters";

const SELECT =
  "h-8 w-full min-w-0 rounded-md border border-control bg-ground px-2 text-sm text-ink outline-none focus-visible:border-ring";

/**
 * Alert history filters as a plain GET form: works without JavaScript, every control has a
 * visible label, and the server validates every value again (src/lib/filters.ts).
 */
export function AlertFilterForm({
  filters,
  assets,
  rules,
}: {
  filters: AlertFilters;
  assets: { id: string; label: string }[];
  rules: { id: string; label: string }[];
}) {
  const assetMissing = filters.asset && !assets.some((a) => a.id === filters.asset);
  const ruleMissing = filters.rule && !rules.some((r) => r.id === filters.rule);
  return (
    <form method="get" action="/detections" className="grid gap-3 sm:grid-cols-2 lg:grid-cols-[repeat(5,minmax(0,1fr))_auto]">
      <label className="flex min-w-0 flex-col gap-1 text-xs text-muted-foreground">
        Asset
        <select name="asset" defaultValue={filters.asset ?? ""} className={SELECT}>
          <option value="">All assets</option>
          {assetMissing ? <option value={filters.asset ?? ""}>{filters.asset}</option> : null}
          {assets.map((a) => (
            <option key={a.id} value={a.id}>
              {a.label}
            </option>
          ))}
        </select>
      </label>
      <label className="flex min-w-0 flex-col gap-1 text-xs text-muted-foreground">
        Severity
        <select name="severity" defaultValue={filters.severity ?? ""} className={SELECT}>
          <option value="">Any severity</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
            </option>
          ))}
        </select>
      </label>
      <label className="flex min-w-0 flex-col gap-1 text-xs text-muted-foreground">
        Rule
        <select name="rule" defaultValue={filters.rule ?? ""} className={SELECT}>
          <option value="">All rules</option>
          {ruleMissing ? <option value={filters.rule ?? ""}>{filters.rule}</option> : null}
          {rules.map((r) => (
            <option key={r.id} value={r.id}>
              {r.label}
            </option>
          ))}
        </select>
      </label>
      <label className="flex min-w-0 flex-col gap-1 text-xs text-muted-foreground">
        Analyst status
        <select name="status" defaultValue={filters.status ?? ""} className={SELECT}>
          <option value="">Any status</option>
          {ANALYST_STATUSES.map((s) => (
            <option key={s} value={s}>
              {analystStatusLabel(s)}
            </option>
          ))}
        </select>
      </label>
      <label className="flex min-w-0 flex-col gap-1 text-xs text-muted-foreground">
        Time range
        <select name="range" defaultValue={filters.range} className={SELECT}>
          {Object.entries(TIME_RANGES).map(([key, value]) => (
            <option key={key} value={key}>
              {value.label}
            </option>
          ))}
        </select>
      </label>
      <div className="flex items-end gap-2">
        <button
          type="submit"
          className="inline-flex h-8 items-center rounded-full bg-primary px-4 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90"
        >
          Apply
        </button>
        <Link href="/detections" className="inline-flex h-8 items-center px-2 text-sm text-muted-foreground hover:text-ink">
          Reset
        </Link>
      </div>
    </form>
  );
}

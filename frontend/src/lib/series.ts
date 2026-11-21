/**
 * Dense time buckets from the API's sparse time series.
 *
 * The API omits empty buckets. Absent buckets are drawn as no bar (zero stored rows),
 * never interpolated. Callers must still say that "no rows stored" is not proof of no
 * activity when collection was unhealthy.
 */
import type { Severity, TimeSeriesResponse } from "@/lib/api/schemas";

export interface Bucket {
  start: string;
  end: string;
}

export interface SeverityLane {
  severity: Severity | "all";
  total: number;
  counts: number[];
}

export interface LaneData {
  buckets: Bucket[];
  lanes: SeverityLane[];
  /** Largest single-bucket count across all lanes (shared scale). */
  max: number;
  bucketSeconds: number;
  grouped: boolean;
}

const LANE_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
const MAX_BUCKETS = 400;

export function buildSeverityLanes(series: TimeSeriesResponse): LaneData {
  const step = Math.max(60, series.bucket_seconds) * 1000;
  const since = Date.parse(series.range.since);
  const until = Date.parse(series.range.until);
  const first = Math.floor(since / step) * step;
  const buckets: Bucket[] = [];
  for (let t = first; t < until && buckets.length < MAX_BUCKETS; t += step) {
    buckets.push({ start: new Date(t).toISOString(), end: new Date(t + step).toISOString() });
  }
  const index = (iso: string): number => {
    const t = Date.parse(iso);
    return Number.isNaN(t) ? -1 : Math.floor((t - first) / step);
  };

  const grouped = series.group_by === "severity";
  const lanes = new Map<Severity | "all", number[]>();
  const laneFor = (key: Severity | "all") => {
    let counts = lanes.get(key);
    if (!counts) {
      counts = new Array<number>(buckets.length).fill(0);
      lanes.set(key, counts);
    }
    return counts;
  };

  for (const point of series.points) {
    const i = index(point.bucket_start);
    if (i < 0 || i >= buckets.length) continue;
    const key: Severity | "all" =
      grouped && point.group && (LANE_ORDER as string[]).includes(point.group)
        ? (point.group as Severity)
        : "all";
    const counts = laneFor(key);
    counts[i] = (counts[i] ?? 0) + point.count;
  }

  const ordered: SeverityLane[] = [];
  if (grouped) {
    for (const severity of LANE_ORDER) {
      const counts = lanes.get(severity);
      // Critical..low are always shown (an explicit zero is information); info only if present.
      if (!counts && severity === "info") continue;
      const filled = counts ?? new Array<number>(buckets.length).fill(0);
      ordered.push({ severity, counts: filled, total: filled.reduce((a, b) => a + b, 0) });
    }
    const other = lanes.get("all");
    if (other) ordered.push({ severity: "all", counts: other, total: other.reduce((a, b) => a + b, 0) });
  } else {
    const counts = lanes.get("all") ?? new Array<number>(buckets.length).fill(0);
    ordered.push({ severity: "all", counts, total: counts.reduce((a, b) => a + b, 0) });
  }

  const max = Math.max(0, ...ordered.flatMap((lane) => lane.counts));
  return { buckets, lanes: ordered, max, bucketSeconds: step / 1000, grouped };
}

/** Indices of buckets that get an axis label: 4-8 evenly stepped labels. */
export function axisTickIndices(count: number, target = 6): number[] {
  if (count <= 0) return [];
  const step = Math.max(1, Math.ceil(count / target));
  const ticks: number[] = [];
  for (let i = 0; i < count; i += step) ticks.push(i);
  return ticks;
}

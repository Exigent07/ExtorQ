/**
 * Ingestion spool backlog for the health summary.
 *
 * The gateway (`ingest`) and the writer (`writer`) both report the depth of the SAME SQLite
 * spool, so their depths are not added up; the detector's backlog and the ai-worker's
 * pending triage queue are not ingestion and are left out. Superseded and stale reports
 * describe the past, not the current backlog. `null` means "no current report", which the
 * view shows as unknown rather than as an empty queue.
 */
export const SPOOL_COMPONENTS: readonly string[] = ["ingest", "writer"];

interface PipelineReport {
  component: string;
  stale: boolean;
  superseded: boolean;
  queue_depth: number;
  oldest_queued_age_seconds?: number | null;
}

export function spoolBacklog(pipeline: readonly PipelineReport[]): { depth: number | null; oldestSeconds: number | null } {
  const current = pipeline.filter((p) => SPOOL_COMPONENTS.includes(p.component) && !p.superseded && !p.stale);
  if (current.length === 0) return { depth: null, oldestSeconds: null };
  const ages = current.map((p) => p.oldest_queued_age_seconds).filter((a): a is number => typeof a === "number");
  return {
    depth: Math.max(...current.map((p) => p.queue_depth)),
    oldestSeconds: ages.length > 0 ? Math.max(...ages) : null,
  };
}

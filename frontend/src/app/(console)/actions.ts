"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";

import { ANALYST_STATUSES, type AnalystStatus } from "@/lib/api/schemas";
import type { ApiFailure } from "@/lib/api/result";
import { isHexId } from "@/lib/security/ids";
import { getAlert, getEvent, requestSummary, updateAlertState } from "@/lib/server/api";
import { log } from "@/lib/server/log";
import { authorizeAction, destroySession, getSession } from "@/lib/server/session";

/**
 * Server actions of the console. Each one re-verifies the session (and the role for
 * mutations) itself; the proxy gate is never relied on alone. Next.js additionally
 * rejects cross-origin action calls (Origin vs Host check) and the session cookie is
 * SameSite=Strict.
 */

type Failure = { ok: false; message: string };

function failure(error: ApiFailure, fallback?: string): Failure {
  return { ok: false, message: fallback && !error.detail ? fallback : error.message };
}

export async function logoutAction(): Promise<void> {
  const session = await getSession();
  await destroySession();
  if (session) log("info", "logout", { user: session.user });
  redirect("/login");
}

// ── Analyst workflow state ───────────────────────────────────────────────────────

export interface StateActionResult {
  ok: boolean;
  message: string | null;
  savedAt: string | null;
}

const NOTE_MAX = 2048;
const NOTE_FORBIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export async function updateAlertStateAction(
  alertId: string,
  _prev: StateActionResult,
  formData: FormData,
): Promise<StateActionResult> {
  const auth = await authorizeAction("changeAlertState");
  if (!auth.ok) return { ok: false, message: auth.message, savedAt: null };
  if (!isHexId(alertId)) return { ok: false, message: "Invalid alert id.", savedAt: null };

  const status = formData.get("status");
  if (typeof status !== "string" || !(ANALYST_STATUSES as readonly string[]).includes(status)) {
    return { ok: false, message: "Choose a valid status.", savedAt: null };
  }
  const rawNote = formData.get("note");
  const note = typeof rawNote === "string" ? rawNote.trim() : "";
  if (note.length > NOTE_MAX) {
    return { ok: false, message: `The note is limited to ${NOTE_MAX} characters.`, savedAt: null };
  }
  if (NOTE_FORBIDDEN.test(note)) {
    return { ok: false, message: "The note contains control characters.", savedAt: null };
  }
  const expected = formData.get("expected_updated_at");
  const expectedUpdatedAt = typeof expected === "string" && ISO_TIME.test(expected) ? expected : null;

  const result = await updateAlertState(auth.session, alertId, {
    status: status as AnalystStatus,
    note: note.length > 0 ? note : null,
    expectedUpdatedAt,
  });
  if (!result.ok) {
    return { ok: false, message: result.error.message, savedAt: null };
  }
  log("info", "alert_state_changed", { user: auth.session.user, alert_id: alertId, status });
  revalidatePath(`/investigations/${alertId}`);
  return { ok: true, message: null, savedAt: result.data.state.updated_at ?? new Date().toISOString() };
}

// ── On-demand Gemini overview ────────────────────────────────────────────────────

export type SummaryActionResult =
  | { ok: true; assessmentId: string; status: string; error: string | null }
  | Failure;

export async function requestSummaryAction(alertId: string): Promise<SummaryActionResult> {
  const auth = await authorizeAction("requestSummary");
  if (!auth.ok) return { ok: false, message: auth.message };
  if (!isHexId(alertId)) return { ok: false, message: "Invalid alert id." };
  const result = await requestSummary(auth.session, alertId);
  if (!result.ok) {
    const { error } = result;
    log("warn", "ai_summary_unavailable", {
      user: auth.session.user,
      alert_id: alertId,
      kind: error.kind,
      status: error.status,
    });
    if (error.kind === "conflict") {
      return { ok: false, message: "A summary for this alert is already being generated. Try again shortly." };
    }
    if (error.kind === "timeout") {
      return {
        ok: false,
        message: "The AI provider did not answer in time. The deterministic investigation above is unaffected.",
      };
    }
    return failure(error);
  }
  revalidatePath(`/investigations/${alertId}`);
  const { assessment } = result.data;
  return {
    ok: true,
    assessmentId: assessment.assessment_id,
    status: assessment.status,
    // The API's refusal / failure reason (budget, cooldown); bounded, rendered as text only.
    error: assessment.status === "ok" || !assessment.error ? null : assessment.error.slice(0, 300),
  };
}

// ── Read-only drill-downs (any signed-in role) ───────────────────────────────────

export interface EvidenceRow {
  eventId: string;
  eventTime: string;
  eventType: string;
  sourceType: string;
  role: string | null;
  actor: string | null;
  srcIp: string | null;
  message: string | null;
}

export type EvidenceActionResult =
  | { ok: true; rows: EvidenceRow[]; total: number; capped: boolean; unresolved: number }
  | Failure;

export async function loadEvidenceAction(alertId: string): Promise<EvidenceActionResult> {
  const session = await getSession();
  if (!session) return { ok: false, message: "Your session has expired. Sign in again." };
  if (!isHexId(alertId)) return { ok: false, message: "Invalid alert id." };
  const result = await getAlert(session, alertId);
  if (!result.ok) return failure(result.error);
  const { evidence, evidence_total, evidence_capped, unresolved_evidence_ids } = result.data;
  return {
    ok: true,
    total: evidence_total,
    capped: evidence_capped,
    unresolved: unresolved_evidence_ids.length,
    rows: evidence.slice(0, 50).map((event) => ({
      eventId: event.event_id,
      eventTime: event.event_time,
      eventType: event.event_type,
      sourceType: event.source_type,
      role: event.role ?? null,
      actor: event.actor_name ?? event.k8s_user ?? event.gh_actor_login ?? null,
      srcIp: event.src_ip ?? null,
      message: event.message ?? null,
    })),
  };
}

export interface RawExcerpt {
  raw: string | null;
  message: string | null;
  rawSha256: string | null;
  parser: string;
  parserVersion: string;
  truncated: boolean;
  redactionCount: number;
  sourceNativeId: string | null;
  collectorId: string;
  ingestedTime: string;
}

export type RawExcerptResult = { ok: true; excerpt: RawExcerpt } | Failure;

export async function loadRawExcerptAction(eventId: string): Promise<RawExcerptResult> {
  const session = await getSession();
  if (!session) return { ok: false, message: "Your session has expired. Sign in again." };
  if (!isHexId(eventId)) return { ok: false, message: "Invalid event id." };
  const result = await getEvent(session, eventId);
  if (!result.ok) return failure(result.error);
  const { event, ingest } = result.data;
  return {
    ok: true,
    excerpt: {
      raw: event.raw ?? null,
      message: event.message ?? null,
      rawSha256: event.provenance.raw_sha256 ?? null,
      parser: event.provenance.parser,
      parserVersion: event.provenance.parser_version,
      truncated: event.provenance.truncated,
      redactionCount: event.provenance.redaction_count,
      sourceNativeId: event.source.source_native_id ?? null,
      collectorId: event.source.collector_id,
      ingestedTime: ingest.ingested_time,
    },
  };
}

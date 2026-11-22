/** Labels for AI assessment fields (contracts/ai.py; question sets triage-v1/v2 in extorq.ai.jev). */

export const RECOMMENDATION_LABEL: Record<string, string> = {
  priority_investigation: "Priority investigation",
  routine_review: "Routine review",
  likely_benign_maintenance: "Likely benign maintenance",
  insufficient_context: "Insufficient context",
};

export function recommendationLabel(token: string): string {
  return RECOMMENDATION_LABEL[token] ?? token.replace(/_+/g, " ");
}

export const QUESTION_LABEL: Record<string, string> = {
  sufficient_context: "Enough context to judge",
  priority_a: "Priority (option order A)",
  priority_b: "Priority (option order B)",
  maintenance_consistent: "Consistent with maintenance or authorised administration",
  joint_investigation: "Related observations warrant joint investigation",
  change_appears_reviewed: "Workflow change appears reviewed",
  coordinated_activity: "SSH and HTTP activity look coordinated",
  privilege_escalation_attempt: "Attempt to obtain elevated privileges",
};

/** Jev answer types (extorq.ai.jev QuestionSpec.kind): "noul" is a yes/no probability. */
export const QUESTION_TYPE_LABEL: Record<string, string> = {
  noul: "Yes/no",
  choice: "Choice",
  score: "Score",
};

export function questionTypeLabel(type: string): string {
  return QUESTION_TYPE_LABEL[type] ?? type;
}

export const AI_STATUS_TEXT: Record<string, string> = {
  ok: "Completed",
  insufficient_context: "The provider judged the context insufficient",
  invalid_output: "The provider's output failed validation and was discarded",
  timeout: "The provider did not answer in time",
  rate_limited: "The provider rate-limited the request",
  error: "The provider call failed",
  disabled: "This AI provider is disabled",
  budget_exceeded: "The AI budget refused the request (daily cap reached or per-alert cooldown active)",
};

export function aiStatusText(status: string): string {
  return AI_STATUS_TEXT[status] ?? status;
}

/**
 * What an analyst is told after "Generate overview" did not produce one. Refusals
 * (budget, cooldown, disabled) are not stored; provider failures are stored as assessments.
 */
export const SUMMARY_OUTCOME: Record<string, string> = {
  budget_exceeded:
    "Refused before any provider call: this alert's summary cooldown is active or today's Gemini cap is reached. Try again later.",
  rate_limited: "Gemini rate-limited the request. Try again in a minute.",
  timeout: "Gemini did not answer in time. No overview was produced.",
  invalid_output: "Gemini's output failed validation and was discarded.",
  insufficient_context: "Gemini judged the investigation context insufficient for an overview.",
  error: "The Gemini call failed. The deterministic investigation is unaffected.",
  disabled: "AI overviews are disabled on this deployment.",
};

/**
 * Which budget refused an overview request, from the API's refusal text
 * ("cooldown_active (per-alert summary cooldown; retry in 87 s)" or
 * "daily_cap_reached (20/20 gemini calls today, UTC)"). Null when the text is neither, so the
 * caller keeps its generic sentence instead of guessing.
 */
export function refusalDetail(error: string | null | undefined): string | null {
  if (!error) return null;
  const cooldown = /^cooldown_active\b.*?retry in (\d{1,6}) s/.exec(error);
  if (cooldown) {
    const seconds = Number(cooldown[1]);
    const wait = seconds < 120 ? `${seconds} s` : `${Math.ceil(seconds / 60)} min`;
    return `This alert's overview cooldown is active: try again in ${wait}.`;
  }
  const cap = /^daily_cap_reached \((\d{1,6})\/(\d{1,6}) /.exec(error);
  if (cap) return `Today's Gemini cap is reached (${cap[1]} of ${cap[2]} calls, UTC day). Try again tomorrow.`;
  return null;
}

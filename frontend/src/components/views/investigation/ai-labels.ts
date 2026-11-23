/** Labels for Jev triage assessment fields (contracts/ai.py; question sets in extorq.ai.jev). */

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
  budget_exceeded: "The AI budget refused the request (the daily call cap is reached)",
};

export function aiStatusText(status: string): string {
  return AI_STATUS_TEXT[status] ?? status;
}

/** Jev rationale codes (extorq.ai.jev `decide`) in words; the code itself stays in a hint. */
export const RATIONALE_LABEL: Record<string, string> = {
  context_insufficient: "Context insufficient (below 0.30)",
  context_borderline: "Context borderline (0.30 to 0.70)",
  context_sufficient: "Context sufficient (above 0.70)",
  priority_order_consistent: "Same priority in both option orders",
  priority_order_sensitive: "Priority changed with option order",
  priority_priority_investigation: "Priority answer: priority investigation",
  priority_routine_review: "Priority answer: routine review",
  priority_likely_benign_maintenance: "Priority answer: likely benign maintenance",
  benign_requires_sufficient_context: "Benign call needs sufficient context: lowered to routine review",
  benign_conflicts_maintenance: "Benign call conflicts with the maintenance answer: lowered to routine review",
  benign_conflicts_privilege_escalation: "Benign call conflicts with a likely privilege escalation",
  priority_conflicts_maintenance: "Priority call conflicts with a maintenance-consistent answer",
  maintenance_consistent: "Consistent with maintenance",
  maintenance_inconsistent: "Not consistent with maintenance",
  joint_investigation_warranted: "Related observations warrant joint investigation",
  change_reviewed: "Change appears reviewed",
  change_not_reviewed: "Change does not appear reviewed",
  coordinated_activity: "SSH and HTTP activity look coordinated",
  privilege_escalation_likely: "Privilege escalation attempt likely",
};

/** Words for a known rationale code, or null (unknown codes are shown as untrusted text). */
export function rationaleLabel(code: string): string | null {
  return Object.hasOwn(RATIONALE_LABEL, code) ? (RATIONALE_LABEL[code] ?? null) : null;
}

/** Labels for AI assessment fields (contracts/ai.py; question set triage-v1 in extorq.ai.jev). */

export const RECOMMENDATION_LABEL: Record<string, string> = {
  priority_investigation: "Priority investigation",
  routine_review: "Routine review",
  likely_benign_maintenance: "Likely benign maintenance",
  insufficient_context: "Insufficient context",
};

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

export const AI_STATUS_TEXT: Record<string, string> = {
  ok: "Completed",
  insufficient_context: "The provider judged the context insufficient",
  invalid_output: "The provider's output failed validation and was discarded",
  timeout: "The provider did not answer in time",
  rate_limited: "The provider rate-limited the request",
  error: "The provider call failed",
  disabled: "This AI provider is disabled",
  budget_exceeded: "The daily AI budget is exhausted",
};

export function aiStatusText(status: string): string {
  return AI_STATUS_TEXT[status] ?? status;
}

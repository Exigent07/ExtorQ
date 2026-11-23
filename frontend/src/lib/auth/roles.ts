/**
 * Console roles. The same names are sent to the API in `X-ExtorQ-Role`, where they are
 * enforced again (backend/src/extorq/api/auth.py): the console checks first so a viewer
 * never even issues a mutation, and the API remains the authority.
 */
export const ROLES = ["analyst", "viewer"] as const;
export type Role = (typeof ROLES)[number];

export function isRole(value: unknown): value is Role {
  return typeof value === "string" && (ROLES as readonly string[]).includes(value);
}

/** Usernames accepted in sessions; identical to the API's X-ExtorQ-User pattern. */
export const USERNAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._@+-]{0,127}$/;

export const permissions = {
  /** Change analyst workflow state (acknowledge, investigate, close): the only mutation. */
  changeAlertState: (role: Role): boolean => role === "analyst",
} as const;

export const ROLE_LABEL: Record<Role, string> = {
  analyst: "Analyst",
  viewer: "Viewer (read-only)",
};

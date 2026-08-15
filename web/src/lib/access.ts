import type { Me } from "@/lib/api";

export const wildcardPermission = "*";

// hasPermission fails CLOSED on an unknown permission set.
//
// This used to `return true` when permissions were absent, which made every gated
// control visible to a user whose permission list had not loaded — or had been
// omitted by the API for any reason. There is no reading of "absent" that means
// "allowed": /api/v1/me always populates the list, and unrestricted access is
// expressed as the "*" wildcard, which is handled explicitly below.
//
// The server is what actually enforces authorization, so this is about not
// showing someone controls they cannot use. The cost of failing closed is a
// briefly empty nav while `me` loads; the cost of failing open is an operator
// clicking an action that then 403s, or believing they hold access they do not.
export function hasPermission(user: Pick<Me, "permissions"> | null | undefined, permission: string): boolean {
  const permissions = user?.permissions;
  if (!permissions) return false;
  return permissions.includes(wildcardPermission) || permissions.includes(permission);
}

// hasAnyPermission takes the permissions a destination REQUIRES, so an empty list
// means "this needs no permission" and correctly returns true. That is a
// different question from hasPermission's, where an empty set means the user
// holds nothing.
export function hasAnyPermission(user: Pick<Me, "permissions"> | null | undefined, permissions: readonly string[] | undefined): boolean {
  if (!permissions || permissions.length === 0) return true;
  return permissions.some((permission) => hasPermission(user, permission));
}

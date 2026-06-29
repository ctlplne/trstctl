import type { Me } from "@/lib/api";

export const wildcardPermission = "*";

export function hasPermission(user: Pick<Me, "permissions"> | null | undefined, permission: string): boolean {
  const permissions = user?.permissions;
  if (!permissions) return true;
  return permissions.includes(wildcardPermission) || permissions.includes(permission);
}

export function hasAnyPermission(user: Pick<Me, "permissions"> | null | undefined, permissions: readonly string[] | undefined): boolean {
  if (!permissions || permissions.length === 0) return true;
  return permissions.some((permission) => hasPermission(user, permission));
}

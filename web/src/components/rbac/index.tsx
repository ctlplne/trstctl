import { createContext, useContext, useMemo, type ReactNode } from "react";

const RbacContext = createContext<ReadonlySet<string> | null>(null);

export function RbacProvider({ permissions, children }: { permissions: readonly string[] | null; children: ReactNode }) {
  const value = useMemo<ReadonlySet<string> | null>(() => (permissions ? new Set(permissions) : null), [permissions]);
  return <RbacContext.Provider value={value}>{children}</RbacContext.Provider>;
}

export function useCan(permission: string): boolean {
  const granted = useContext(RbacContext);
  if (granted === null) return true;
  return granted.has("*") || granted.has(permission);
}

export function Can({ permission, children, fallback = null }: { permission: string; children: ReactNode; fallback?: ReactNode }) {
  return <>{useCan(permission) ? children : fallback}</>;
}

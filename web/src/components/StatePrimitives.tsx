import type { ReactNode } from "react";

export function LoadingState({ children }: { children: ReactNode }) {
  return (
    <p role="status" data-state-primitive="loading" className="text-sm text-muted-foreground">
      {children}
    </p>
  );
}

export function ErrorState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div
      role="alert"
      data-state-primitive="error"
      className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-800"
    >
      <p className="font-medium">{title}</p>
      {children && <div className="mt-1 text-red-700">{children}</div>}
    </div>
  );
}

export function PermissionDeniedState({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      data-state-primitive="permission-denied"
      className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900"
    >
      <p className="font-medium">Permission denied</p>
      <div className="mt-1">{children}</div>
    </div>
  );
}

export function UnavailableState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div
      data-state-primitive="unavailable"
      className="rounded-md border border-dashed border-border bg-muted/30 px-3 py-2 text-sm text-muted-foreground"
    >
      <p className="font-medium text-foreground">{title}</p>
      {children && <div className="mt-1">{children}</div>}
    </div>
  );
}

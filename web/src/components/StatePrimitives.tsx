import type { ReactNode } from "react";

export function LoadingState({ children }: { children: ReactNode }) {
  return (
    <p role="status" data-state-primitive="loading" className="flex items-center gap-2 text-sm text-muted-foreground">
      <span
        aria-hidden="true"
        className="h-3.5 w-3.5 rounded-full border-2 border-muted-foreground/30 border-t-brand-accent motion-safe:animate-spin"
      />
      {children}
    </p>
  );
}

export function ErrorState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div role="alert" data-state-primitive="error" className="rounded-control border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm">
      <p className="font-medium text-destructive">{title}</p>
      {children && <div className="mt-1 text-muted-foreground">{children}</div>}
    </div>
  );
}

export function PermissionDeniedState({ children }: { children: ReactNode }) {
  return (
    <div
      role="alert"
      data-state-primitive="permission-denied"
      className="rounded-control border border-status-warning/40 bg-status-warning/10 px-3 py-2 text-sm"
    >
      <p className="font-medium text-status-warning">Permission denied</p>
      <div className="mt-1 text-muted-foreground">{children}</div>
    </div>
  );
}

export function UnavailableState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div data-state-primitive="unavailable" className="rounded-control border border-dashed border-border bg-muted/30 px-3 py-2 text-sm text-muted-foreground">
      <p className="font-medium text-foreground">{title}</p>
      {children && <div className="mt-1">{children}</div>}
    </div>
  );
}

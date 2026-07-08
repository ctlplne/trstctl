import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";

export interface EmptyStateAction {
  label: string;
  to?: string;
  onClick?: () => void;
  icon?: ReactNode;
}

/** EmptyState is a guiding placeholder shown when a view has no data yet. It
 * points the user at the next concrete action rather than leaving a blank
 * screen — a core part of the sub-15-minute first-run target (F12). */
export function EmptyState({
  title,
  children,
  ctaTo,
  ctaLabel,
  icon,
  primaryAction,
  secondaryAction,
  className,
}: {
  title: string;
  children?: ReactNode;
  ctaTo?: string;
  ctaLabel?: string;
  icon?: ReactNode;
  primaryAction?: EmptyStateAction;
  secondaryAction?: EmptyStateAction;
  className?: string;
}) {
  const primary = primaryAction ?? (ctaTo && ctaLabel ? { label: ctaLabel, to: ctaTo } : undefined);
  return (
    <div
      data-state-primitive="empty"
      className={cn(
        "rounded-panel border border-dashed border-border bg-card/70 p-10 text-center shadow-elevation1",
        "flex flex-col items-center justify-center",
        className,
      )}
    >
      {icon ? (
        <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-control border border-border bg-muted/60 text-brand-accent">{icon}</div>
      ) : null}
      <h2 className="mb-1 text-lg font-semibold">{title}</h2>
      {children && <p className="mx-auto mb-5 max-w-md text-sm text-muted-foreground">{children}</p>}
      {(primary || secondaryAction) && (
        <div className="flex flex-wrap items-center justify-center gap-2">
          {primary ? <EmptyStateActionControl action={primary} variant="primary" /> : null}
          {secondaryAction ? <EmptyStateActionControl action={secondaryAction} variant="secondary" /> : null}
        </div>
      )}
    </div>
  );
}

function EmptyStateActionControl({ action, variant }: { action: EmptyStateAction; variant: "primary" | "secondary" }) {
  const className =
    variant === "primary"
      ? "inline-flex min-h-10 items-center justify-center gap-2 rounded-control bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-elevation1 transition hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background"
      : "inline-flex min-h-10 items-center justify-center gap-2 rounded-control border border-border bg-background px-3 py-2 text-sm font-medium transition-colors hover:border-brand-accent/40 hover:bg-muted/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-accent focus-visible:ring-offset-2 focus-visible:ring-offset-background";
  if (action.to) {
    return (
      <Link to={action.to} className={className}>
        {action.icon ? <span aria-hidden="true">{action.icon}</span> : null}
        {action.label}
      </Link>
    );
  }
  return (
    <button type="button" className={className} onClick={action.onClick}>
      {action.icon ? <span aria-hidden="true">{action.icon}</span> : null}
      {action.label}
    </button>
  );
}

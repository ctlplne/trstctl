import type { ReactNode } from "react";
import { Link } from "react-router-dom";

/** EmptyState is a guiding placeholder shown when a view has no data yet. It
 * points the user at the next concrete action rather than leaving a blank
 * screen — a core part of the sub-15-minute first-run target (F12). */
export function EmptyState({
  title,
  children,
  ctaTo,
  ctaLabel,
}: {
  title: string;
  children?: ReactNode;
  ctaTo?: string;
  ctaLabel?: string;
}) {
  return (
    <div data-state-primitive="empty" className="rounded-lg border border-dashed border-border p-10 text-center">
      <h2 className="mb-1 text-lg font-semibold">{title}</h2>
      {children && <p className="mx-auto mb-4 max-w-md text-sm text-muted-foreground">{children}</p>}
      {ctaTo && ctaLabel && (
        <Link
          to={ctaTo}
          className="inline-flex items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
        >
          {ctaLabel}
        </Link>
      )}
    </div>
  );
}

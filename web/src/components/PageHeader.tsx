import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

/** PageHeader is the standard page title block: an optional accent eyebrow, the
 * page title at the display type scale, an optional muted description, and an
 * optional actions slot (buttons) aligned to the right. It replaces the ad-hoc
 * `<h1 className="text-2xl">` headers so every screen shares one hierarchy. Pass
 * `titleId` to keep `aria-labelledby` wiring on the surrounding <section>. */
export function PageHeader({
  title,
  titleId,
  description,
  eyebrow,
  actions,
  className,
}: {
  title: ReactNode;
  titleId?: string;
  description?: ReactNode;
  eyebrow?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("mb-6 flex flex-wrap items-start justify-between gap-x-6 gap-y-3 border-b border-border pb-4", className)}>
      <div className="min-w-0">
        {eyebrow && <p className="mb-1.5 font-mono text-caption font-medium uppercase tracking-wider text-brand-accent">{eyebrow}</p>}
        <h1 id={titleId} className="font-display text-display font-bold tracking-tight text-foreground">
          {title}
        </h1>
        {description && <p className="mt-1.5 max-w-3xl text-body text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex w-full min-w-0 flex-wrap items-center gap-2 sm:w-auto sm:shrink-0">{actions}</div>}
    </div>
  );
}

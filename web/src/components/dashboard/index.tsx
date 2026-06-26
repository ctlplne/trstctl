import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function DashboardGrid({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn("grid gap-3", className)} style={{ gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))" }}>
      {children}
    </div>
  );
}

export function SectionCard({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: string;
  description?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("rounded-panel border border-border bg-card shadow-elevation1", className)}>
      <header className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
        <div>
          <h2 className="text-title font-medium">{title}</h2>
          {description ? <p className="text-caption text-muted-foreground">{description}</p> : null}
        </div>
        {actions ? <div className="shrink-0">{actions}</div> : null}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function AttentionList({ children, ariaLabel }: { children: ReactNode; ariaLabel: string }) {
  return (
    <ul aria-label={ariaLabel} className="divide-y divide-border">
      {children}
    </ul>
  );
}

export function AttentionRow({ children, className }: { children: ReactNode; className?: string }) {
  return <li className={cn("flex items-center gap-3 py-2 text-body", className)}>{children}</li>;
}

import { createElement, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "@/lib/utils";

/** S-C9: the console's typographic refinement rules, named as primitives so
 * the discipline is reusable instead of tribal knowledge (see web/AGENTS.md):
 *
 * - Eyebrow — the ONE tracked-uppercase micro-label style for section
 *   headers, stat labels, chart titles, and definition terms. Pages had four
 *   slightly different hand-rolled versions of this cluster; that drift is
 *   exactly what reads as "unrefined".
 * - Num — data values render in the mono face with tabular figures so
 *   numbers align as columns and read as data; prose stays in the sans face.
 *   Tables already get tabular figures globally (index.css); Num is for the
 *   inline case — counts, serials, TTLs, timestamps inside sans copy.
 */

type EyebrowElement = "span" | "p" | "dt" | "h2" | "h3" | "h4";

export interface EyebrowProps extends HTMLAttributes<HTMLElement> {
  as?: EyebrowElement;
  children: ReactNode;
}

export function Eyebrow({ as = "span", className, children, ...rest }: EyebrowProps) {
  return createElement(as, { ...rest, className: cn("text-caption font-semibold uppercase tracking-wide text-muted-foreground", className) }, children);
}

export interface NumProps extends HTMLAttributes<HTMLElement> {
  children: ReactNode;
}

export function Num({ className, children, ...rest }: NumProps) {
  return (
    <span {...rest} className={cn("font-mono tabular-nums", className)}>
      {children}
    </span>
  );
}

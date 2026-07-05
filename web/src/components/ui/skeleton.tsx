import { cn } from "@/lib/utils";

/** Skeleton is the shared loading placeholder: a dim, softly pulsing block
 * sized by the caller. Prefer skeletons over spinners for tables, cards, and
 * panels so a loading page keeps its shape instead of collapsing to one line.
 * The pulse is gated behind motion-safe for reduced-motion users. */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={cn("rounded-control bg-foreground/[0.07] motion-safe:animate-pulse", className)} />;
}

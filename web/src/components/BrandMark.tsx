import { cn } from "@/lib/utils";

const sizeClasses = {
  sm: "h-7 w-7",
  md: "h-12 w-12",
  lg: "h-16 w-16",
} as const;

const glyphClasses = {
  sm: "h-4 w-4",
  md: "h-7 w-7",
  lg: "h-9 w-9",
} as const;

/** The single trstctl product mark, shared with trstctl.com and the ctlplne
 * studio family. A ring is the custody boundary; a lowercase t, the letter that
 * opens and closes the name, spans it with a crossbar and hangs a plumb line
 * that stops clear of the ring. Read the other way it is a level. The circular
 * container is deliberately quiet: forest carries identity and action. Geometry
 * is generated from trstctl-website/scripts/brand/gen.py; edit it there. */
export function BrandMark({ size = "sm", className }: { size?: keyof typeof sizeClasses; className?: string }) {
  return (
    <span
      aria-hidden="true"
      data-testid="brand-mark"
      className={cn("grid shrink-0 place-items-center rounded-full bg-primary text-primary-foreground ring-1 ring-primary/20", sizeClasses[size], className)}
    >
      <svg viewBox="0 0 32 32" className={glyphClasses[size]} fill="none">
        <circle cx="16" cy="16" r="10" stroke="currentColor" strokeWidth="2.2" />
        <path d="M6.60 12.6H25.40M16 12.6V22.8" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  );
}

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

/** The single trstctl product mark. The circular container is deliberately
 * quiet: forest carries identity and action, while the open center represents
 * a credential whose custody boundary remains visible. */
export function BrandMark({ size = "sm", className }: { size?: keyof typeof sizeClasses; className?: string }) {
  return (
    <span
      aria-hidden="true"
      data-testid="brand-mark"
      className={cn("grid shrink-0 place-items-center rounded-full bg-primary text-primary-foreground ring-1 ring-primary/20", sizeClasses[size], className)}
    >
      <svg viewBox="0 0 32 32" className={glyphClasses[size]} fill="none">
        <path d="M8 11h16M16 6v20M11 21l5 4 5-4" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
        <circle cx="16" cy="16" r="4.2" stroke="currentColor" strokeWidth="1.8" />
      </svg>
    </span>
  );
}

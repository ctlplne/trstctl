import { cva, type VariantProps } from "class-variance-authority";
import { forwardRef, type ButtonHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/* Product controls use the shared 6px radius. Gold remains the single action
 * channel, but marketing-style pills and hover lifts stay out of dense
 * operator workflows. */
export const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 rounded-control text-sm font-medium transition-[color,background-color,border-color,box-shadow,filter] duration-fast disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-background",
  {
    variants: {
      variant: {
        default: "bg-primary text-primary-foreground shadow-elevation1 hover:brightness-105 active:brightness-95",
        secondary: "border border-border bg-foreground/[0.03] text-foreground hover:border-brand-accent/60 hover:text-brand-accent",
        outline: "border border-border bg-background hover:border-brand-accent/40 hover:bg-muted/60",
        ghost: "hover:bg-foreground/[0.05]",
        destructive: "bg-destructive text-destructive-foreground shadow-elevation1 hover:brightness-105 active:brightness-95",
        "destructive-outline": "border border-destructive/50 bg-background text-destructive hover:border-destructive hover:bg-destructive/10",
      },
      size: {
        default: "h-9 px-4 py-2",
        sm: "h-8 px-3",
        icon: "h-9 w-9",
      },
    },
    defaultVariants: { variant: "default", size: "default" },
  },
);

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement>, VariantProps<typeof buttonVariants> {
  /** Shows a spinner, sets aria-busy, and disables the control while an async action runs. */
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(({ className, variant, size, loading = false, disabled, children, ...props }, ref) => (
  <button ref={ref} className={cn(buttonVariants({ variant, size }), className)} aria-busy={loading || undefined} disabled={disabled || loading} {...props}>
    {loading && (
      <span aria-hidden="true" className="h-3.5 w-3.5 shrink-0 rounded-full border-2 border-current border-t-transparent opacity-80 motion-safe:animate-spin" />
    )}
    {children}
  </button>
));
Button.displayName = "Button";

import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** Checkbox — the native checkbox primitive (DESIGN rule 14). The browser
 * keeps its accessible checked/indeterminate behavior while this wrapper owns
 * the shared size, border, and React ref seam. */
export const Checkbox = forwardRef<HTMLInputElement, Omit<InputHTMLAttributes<HTMLInputElement>, "type">>(function Checkbox({ className, ...props }, ref) {
  return <input ref={ref} type="checkbox" className={cn("h-4 w-4 shrink-0 rounded border-border", className)} {...props} />;
});

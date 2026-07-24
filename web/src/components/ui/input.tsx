import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** Input — the text-control primitive (DESIGN rule 14). One class family
 * (.ui-input, index.css) owns the visual; this wrapper owns the React seam so
 * call sites stop hand-assembling control styling. Pair with <Field> for
 * label/description/error wiring. */
export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...props }, ref) {
  return <input ref={ref} className={cn("ui-input", className)} {...props} />;
});

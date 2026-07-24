import { forwardRef, type SelectHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** Select — the native-select primitive (DESIGN rule 14). Styling comes from
 * select.ui-input (index.css): themed field, drawn chevron, themed options.
 * Pair with <Field> for label/description/error wiring. */
export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, ...props }, ref) {
  return <select ref={ref} className={cn("ui-input", className)} {...props} />;
});

import { forwardRef, type TextareaHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

/** Textarea — the multi-line control primitive (DESIGN rule 14). Height is
 * auto (textarea.ui-input); size with min-h-* utilities at the call site.
 * Pair with <Field> for label/description/error wiring. */
export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...props }, ref) {
  return <textarea ref={ref} className={cn("ui-input", className)} {...props} />;
});

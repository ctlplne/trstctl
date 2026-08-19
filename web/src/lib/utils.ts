import { clsx, type ClassValue } from "clsx";
import { extendTailwindMerge } from "tailwind-merge";

/** tailwind-merge only knows Tailwind's stock scale, so the design-token font
 * sizes (text-2xs … text-display) were being classified as unknown text-COLOR
 * classes and silently dropped whenever a color utility followed them through
 * cn() — e.g. cn("text-caption …", "text-muted-foreground") lost the size.
 * Registering the token sizes as a font-size class group fixes the conflict
 * resolution for every cn() call site (found by the S-C9 Eyebrow test). */
const twMerge = extendTailwindMerge({
  extend: {
    classGroups: {
      "font-size": [{ text: ["2xs", "caption", "data", "body", "title", "heading", "display"] }],
    },
  },
});

/** cn merges Tailwind class names, resolving conflicts (the shadcn convention). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
